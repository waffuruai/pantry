use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Default, Deserialize, Serialize)]
pub struct Report {
    pub schema: i64,
    pub scan: Scan,
    pub findings: Vec<Finding>,
    pub fix_plan: Vec<Fix>,
    pub checked: BTreeMap<String, i64>,
    pub unfixed: i64,
    pub history: History,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Scan {
    #[serde(default)]
    pub id: i64,
    pub when: String,
    pub scope: String,
    pub fails: i64,
    pub warns: i64,
    pub unchecked: i64,
}

#[derive(Default, Deserialize, Serialize)]
pub struct History {
    pub scans: Vec<Scan>,
    pub exposures: Vec<Exposure>,
    #[serde(default)]
    pub fixes: Vec<FixRecord>,
}

#[derive(Deserialize, Serialize)]
pub struct FixRecord {
    pub when: String,
    pub command: String,
    pub ok: bool,
    pub verified_scan: Option<i64>,
    pub targets: Vec<String>,
}

impl FixRecord {
    pub fn target_names<'a>(&self, components: &HashMap<String, &'a str>) -> Vec<&'a str> {
        let mut seen = HashSet::new();
        self.targets
            .iter()
            .filter_map(|key| components.get(key).copied())
            .filter(|name| !name.is_empty() && seen.insert(*name))
            .collect()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Exposure {
    #[serde(flatten)]
    pub finding: Finding,
    pub resolved: Option<String>,
    /// The scope of the scan that last saw it, such as `repos:/a`; "" from
    /// an older scanner.
    #[serde(default)]
    pub scope: String,
}

#[derive(Deserialize, Serialize)]
pub struct Finding {
    #[serde(default)]
    pub id: String,
    pub kind: String,
    pub component: String,
    pub version: String,
    pub location: String,
    pub vuln_id: String,
    pub status: String,
    pub note: String,
    pub fixed: String,
    pub severity: String,
    pub kev: bool,
    pub fix_cmd: String,
    #[serde(default)]
    pub fix_auto: bool,
    /// An `unchecked` finding for an area the user chose to skip, such as
    /// personal folders. Not a gap: it never counts as an incomplete check.
    #[serde(default)]
    pub excluded: bool,
    /// The advisory's own one-line summary as published, cleaned by the
    /// scanner; "" from an older scanner or without one.
    #[serde(default)]
    pub summary: String,
    /// The advisory's other ids (CVE, GHSA, OSV).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Weakness types, such as `CWE-787`.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// The advisory range the installed version fell in (`>=1.0, <1.4.9`).
    #[serde(default)]
    pub affected_range: String,
    #[serde(default)]
    pub cvss: Option<f64>,
    #[serde(default)]
    pub cvss_version: String,
    /// The EPSS probability (0 to 1) of exploitation in the next 30 days.
    #[serde(default)]
    pub epss: Option<f64>,
    /// `runtime`, `dev`, `optional` or `unknown`.
    #[serde(default)]
    pub dep_scope: String,
    #[serde(default)]
    pub dep_direct: Option<bool>,
}

#[derive(Deserialize, Serialize)]
pub struct Fix {
    pub id: String,
    pub how: String,
    pub run: String,
    pub fix_cmd: String,
}

#[derive(Deserialize, Serialize)]
pub struct Schedule {
    pub schema: i64,
    pub installed: bool,
    pub backend: String,
    pub enabled: Option<bool>,
    /// macOS: whether launchd still holds the job, even with no plist (a
    /// removal whose bootout failed). Absent from older scanners.
    #[serde(default)]
    pub loaded: Option<bool>,
    pub interval: Option<String>,
    pub every: Option<Period>,
    pub at: Option<String>,
    pub last_run: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Update {
    pub current: String,
    pub latest: String,
    pub available: bool,
    pub assets: Option<Vec<String>>,
    /// When the answer was fetched, `YYYY-MM-DD HH:MM UTC`.
    #[serde(default)]
    pub checked_at: Option<String>,
    /// True when the scanner could not ask and answered from an older copy.
    #[serde(default)]
    pub stale: bool,
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Hour,
    #[default]
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

impl Period {
    pub const ALL: [Self; 6] = [
        Self::Hour,
        Self::Day,
        Self::Week,
        Self::Month,
        Self::Quarter,
        Self::Year,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Quarter => "quarter",
            Self::Year => "year",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hour => "Every hour",
            Self::Day => "Every day",
            Self::Week => "Every week",
            Self::Month => "Every month",
            Self::Quarter => "Every quarter",
            Self::Year => "Every year",
        }
    }
}

impl Finding {
    fn key(&self) -> (&str, &str, &str, &str) {
        (&self.kind, &self.component, &self.location, &self.vuln_id)
    }

    pub fn priority(&self) -> (bool, bool, u8) {
        let severity = match self.severity.to_ascii_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        (!self.kev, self.status != "fail", severity)
    }
}

impl Report {
    pub fn components_by_key(&self) -> HashMap<String, &str> {
        self.history
            .exposures
            .iter()
            .map(|e| &e.finding)
            .chain(&self.findings)
            .map(|f| {
                let (kind, component, location, advisory) = f.key();
                (
                    format!("{kind}|{component}|{location}|{advisory}"),
                    component,
                )
            })
            .collect()
    }

    /// Checks that could not finish in the latest scan. Skipped areas are
    /// left out. Counted from the findings so an older scanner, which has no
    /// `excluded` field, still reports every unchecked source.
    pub fn gaps(&self) -> i64 {
        self.findings.iter().filter(|f| f.is_gap()).count() as i64
    }

    /// True when the latest scan read CISA's list of flaws used in attacks
    /// (KEV). The scanner files the list as an unchecked source named
    /// `CISA KEV (…)` when it could not, and then marks no finding as
    /// exploited, so "not on the list" would claim something unknown.
    pub fn kev_checked(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.kind == "unchecked" && f.component.starts_with("CISA KEV"))
    }

    /// Warnings in the latest scan, not counting skipped areas (the
    /// scanner files those as warnings).
    pub fn warnings(&self) -> i64 {
        let skipped = self.skipped().iter().filter(|f| f.status == "warn").count() as i64;
        (self.scan.warns - skipped).max(0)
    }

    /// Areas the latest scan skipped because the user asked it to.
    pub fn skipped(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.is_skipped()).collect()
    }

    /// The latest scan's problems: what the headline counts.
    pub fn open(&self) -> Vec<(&Finding, String)> {
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for finding in self.findings.iter().filter(|item| item.kind != "unchecked") {
            if seen.insert(finding.key()) {
                rows.push((finding, finding.id.clone()));
            }
        }
        rows.sort_by_key(|(finding, _)| finding.priority());
        rows
    }

    /// Problems earlier scans of other folders found that no scan has
    /// cleared, not in the latest scan and not dismissed (`dismissed`
    /// holds exposure ids). Shown apart, never in the headline.
    pub fn earlier(&self, dismissed: &[String]) -> Vec<&Exposure> {
        self.earlier_all()
            .into_iter()
            .filter(|exposure| !dismissed.contains(&exposure.finding.id))
            .collect()
    }

    /// Every open earlier problem, dismissed or not.
    pub fn earlier_all(&self) -> Vec<&Exposure> {
        let mut seen: HashSet<_> = self
            .findings
            .iter()
            .filter(|item| item.kind != "unchecked")
            .map(|item| item.key())
            .collect();
        let mut rows: Vec<&Exposure> = self
            .history
            .exposures
            .iter()
            .filter(|exposure| {
                exposure.resolved.is_none()
                    && exposure.finding.kind != "unchecked"
                    && seen.insert(exposure.finding.key())
            })
            .collect();
        rows.sort_by_key(|exposure| exposure.finding.priority());
        rows
    }
}

impl Finding {
    /// A source that failed or a path that could not be read.
    pub fn is_gap(&self) -> bool {
        self.kind == "unchecked" && !self.excluded
    }

    /// An area left out on purpose (`--no-personal-files`).
    pub fn is_skipped(&self) -> bool {
        self.kind == "unchecked" && self.excluded
    }

    /// The key the scanner uses to follow one finding across scans.
    pub fn key_string(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.kind, self.component, self.location, self.vuln_id
        )
    }
}

impl Report {
    /// The fix plan entry for a finding id, if the scan planned one.
    pub fn plan_for(&self, id: &str) -> Option<&Fix> {
        self.fix_plan.iter().find(|item| item.id == id)
    }

    /// True when Pantry can run this finding's fix itself.
    pub fn can_fix(&self, finding: &Finding, id: &str) -> bool {
        finding.fix_auto
            && !id.starts_with("earlier-")
            && self.plan_for(id).is_some_and(|plan| plan.how == "wpantry")
    }
}

/// Where the scanner keeps its cache. Mirrors `wpantry::db::path` in the
/// Rust workspace: WPANTRY_DB, else $XDG_CACHE_HOME/wpantry/wpantry.db,
/// else ~/.cache/wpantry/wpantry.db, else %LOCALAPPDATA% on Windows.
pub fn cache_path() -> PathBuf {
    cache_path_from(&|name| std::env::var_os(name))
}

fn cache_path_from(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let var = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(path) = var("WPANTRY_DB") {
        return path;
    }
    let base = var("XDG_CACHE_HOME")
        .or_else(|| var("HOME").map(|home| home.join(".cache")))
        .or_else(|| {
            if cfg!(windows) {
                var("LOCALAPPDATA")
            } else {
                None
            }
        })
        .unwrap_or_else(|| PathBuf::from(".cache"));
    base.join("wpantry").join("wpantry.db")
}

/// The newest modification time of the cache and its SQLite write-ahead
/// log, so a scan from the schedule or a terminal shows up in the window.
pub fn cache_stamp(path: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    [path.to_path_buf(), PathBuf::from(wal)]
        .iter()
        .filter_map(|file| file.metadata().and_then(|m| m.modified()).ok())
        .max()
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), the inverse of the scanner's `civil_from_days`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

/// Seconds since the epoch for the scanner's `2026-11-21 16:30 UTC` stamps
/// (also accepts `T` and `Z`, and seconds).
pub fn parse_utc(text: &str) -> Option<i64> {
    let text = text.trim();
    let text = text
        .strip_suffix(" UTC")
        .or_else(|| text.strip_suffix('Z'))
        .unwrap_or(text);
    let (date, time) = text.split_once([' ', 'T'])?;
    let mut date = date.split('-').map(str::parse::<i64>);
    let (y, m, d) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.split(':').map(str::parse::<i64>);
    let (h, min) = (time.next()?.ok()?, time.next()?.ok()?);
    let s = time.next().transpose().ok()?.unwrap_or(0);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || s > 60 {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s)
}

/// The local time zone's UTC offsets, read once from the system's TZif
/// file. `None` on Windows and wherever the file can't be read.
// TODO: read the Windows offset (GetTimeZoneInformation needs a dependency
// or unsafe code, both avoided here); Windows shows UTC, labelled.
struct Zone {
    /// (transition time, offset in seconds after it), sorted.
    transitions: Vec<(i64, i32)>,
    /// The offset before the first transition.
    initial: i32,
    /// True when the file's footer rule has no daylight saving, so the
    /// last offset holds after the last transition.
    fixed_after: bool,
}

impl Zone {
    fn offset_at(&self, t: i64) -> Option<i32> {
        match self.transitions.partition_point(|(at, _)| *at <= t) {
            0 => Some(self.initial),
            n if n == self.transitions.len() && !self.fixed_after => None,
            n => Some(self.transitions[n - 1].1),
        }
    }
}

/// Parse a TZif (RFC 8536) file, version 2 or later, using the 64-bit
/// section. A slim file whose DST rule lives only in the footer gives
/// `None` past its last transition, and callers then fall back to UTC.
fn parse_tzif(bytes: &[u8]) -> Option<Zone> {
    let be32 = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    let counts = |base: usize| -> Option<[usize; 6]> {
        if bytes.get(base..base + 4)? != b"TZif" {
            return None;
        }
        let mut out = [0; 6];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = be32(base + 20 + 4 * i)? as usize;
        }
        Some(out)
    };
    let [isut, isstd, leap, time, types, chars] = counts(0)?;
    if *bytes.get(4)? < b'2' {
        return None;
    }
    let v1 = time * 5 + types * 6 + chars + leap * 8 + isstd + isut;
    let base = 44 + v1;
    let [isut, isstd, leap, time, types, chars] = counts(base)?;
    let mut at = base + 44;
    let mut times = Vec::with_capacity(time);
    for i in 0..time {
        let raw = bytes.get(at + 8 * i..at + 8 * i + 8)?;
        times.push(i64::from_be_bytes(raw.try_into().ok()?));
    }
    at += time * 8;
    let indices = bytes.get(at..at + time)?.to_vec();
    at += time;
    let mut offsets = Vec::with_capacity(types);
    let mut initial = None;
    for i in 0..types {
        let entry = bytes.get(at + 6 * i..at + 6 * i + 6)?;
        let offset = i32::from_be_bytes(entry[..4].try_into().ok()?);
        if entry[4] == 0 && initial.is_none() {
            initial = Some(offset);
        }
        offsets.push(offset);
    }
    at += types * 6 + chars + leap * 12 + isstd + isut;
    let footer = bytes.get(at..).unwrap_or_default();
    let footer = std::str::from_utf8(footer).unwrap_or_default().trim();
    let transitions = times
        .into_iter()
        .zip(indices)
        .map(|(t, index)| Some((t, *offsets.get(index as usize)?)))
        .collect::<Option<Vec<_>>>()?;
    Some(Zone {
        initial: initial.or_else(|| offsets.first().copied())?,
        fixed_after: !footer.contains(','),
        transitions,
    })
}

fn zone() -> Option<&'static Zone> {
    static ZONE: OnceLock<Option<Zone>> = OnceLock::new();
    ZONE.get_or_init(|| {
        if cfg!(windows) {
            return None;
        }
        let tz = std::env::var("TZ").ok();
        let tz = tz.as_deref().map(|tz| tz.strip_prefix(':').unwrap_or(tz));
        let candidates: Vec<PathBuf> = match tz {
            Some(name) if name.starts_with('/') => vec![PathBuf::from(name)],
            Some(name) if !name.is_empty() && !name.contains("..") => [
                "/usr/share/zoneinfo",
                "/var/db/timezone/zoneinfo",
                "/usr/lib/zoneinfo",
            ]
            .iter()
            .map(|dir| PathBuf::from(dir).join(name))
            .collect(),
            _ => vec![PathBuf::from("/etc/localtime")],
        };
        candidates
            .iter()
            .find_map(|path| std::fs::read(path).ok())
            .and_then(|bytes| parse_tzif(&bytes))
    })
    .as_ref()
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn format_time(t: i64, suffix: &str) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let rem = t.rem_euclid(86_400);
    format!(
        "{d} {} {y}, {:02}:{:02}{suffix}",
        MONTHS[(m - 1) as usize],
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// A scanner stamp in the computer's local time, such as
/// `21 Nov 2026, 10:30`. Where the offset is unknown (Windows, or a zone
/// file Pantry can't read) the time stays in UTC and says so.
pub fn local_time(stamp: &str) -> String {
    local_time_in(stamp, zone())
}

fn local_time_in(stamp: &str, zone: Option<&Zone>) -> String {
    let Some(t) = parse_utc(stamp) else {
        return stamp.to_owned();
    };
    match zone.and_then(|zone| zone.offset_at(t)) {
        Some(offset) => format_time(t + i64::from(offset), ""),
        None => format_time(t, " UTC"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unchecked(component: &str, excluded: Option<bool>) -> serde_json::Value {
        let mut value = serde_json::json!({
            "kind": "unchecked", "component": component, "version": "", "location": "",
            "vuln_id": "", "status": "warn", "note": "", "fixed": "", "severity": "",
            "kev": false, "fix_cmd": "",
        });
        if let Some(excluded) = excluded {
            value["excluded"] = excluded.into();
        }
        value
    }

    /// Oracle: the scanner contract. Exposures another scope left open
    /// are not the latest scan's: they are never in `open` (the headline),
    /// show in `earlier` until dismissed, and a key the latest scan lists
    /// shows once.
    #[test]
    fn earlier_scopes_stay_out_of_the_headline() {
        let finding = |component: &str| {
            serde_json::json!({
                "id": format!("F-{component}"), "kind": "osv", "component": component, "version": "1",
                "location": "/p", "vuln_id": "X-1", "status": "fail", "note": "", "fixed": "2",
                "severity": "high", "kev": false, "fix_cmd": "",
            })
        };
        let exposure = |component: &str, resolved: Option<&str>| {
            let mut value = finding(component);
            value["resolved"] = resolved.into();
            value["scope"] = "repos:/other".into();
            value
        };
        let report: Report = serde_json::from_value(serde_json::json!({
            "schema": 1,
            "scan": {"id": 2, "when": "", "scope": "repos:/p", "fails": 1, "warns": 0, "unchecked": 0},
            "findings": [finding("latest")],
            "fix_plan": [], "checked": {}, "unfixed": 0,
            "history": {"scans": [], "exposures": [
                exposure("latest", None), exposure("other", None), exposure("done", Some("2026-01-01 00:00 UTC")),
            ]},
        }))
        .unwrap();
        let open: Vec<_> = report
            .open()
            .into_iter()
            .map(|(f, _)| f.component.as_str())
            .collect();
        assert_eq!(open, ["latest"]);
        let earlier: Vec<_> = report
            .earlier(&[])
            .iter()
            .map(|e| e.finding.component.as_str())
            .collect();
        assert_eq!(earlier, ["other"]);
        assert_eq!(report.earlier(&[]).first().unwrap().scope, "repos:/other");
        assert!(report.earlier(&["F-other".into()]).is_empty());
        assert_eq!(report.earlier_all().len(), 1, "dismissing only hides it");
    }

    fn earlier_report(exposures: serde_json::Value, findings: serde_json::Value) -> Report {
        serde_json::from_value(serde_json::json!({
            "schema": 1,
            "scan": {"id": 3, "when": "", "scope": "repos:/p", "fails": 0, "warns": 0, "unchecked": 0},
            "findings": findings,
            // Known-bad: a plan even answers to the earlier row's id.
            "fix_plan": [
                {"id": "F-auto", "how": "wpantry", "run": "", "fix_cmd": "npm i auto@2"},
                {"id": "earlier-F-auto", "how": "wpantry", "run": "", "fix_cmd": "npm i auto@2"},
            ],
            "checked": {}, "unfixed": 0,
            "history": {"scans": [], "exposures": exposures},
        }))
        .unwrap()
    }

    /// Oracle: an area an earlier scan could not check is not a problem
    /// anyone has to clear, so it is never listed under earlier scans.
    #[test]
    fn unchecked_exposures_are_never_earlier_problems() {
        let mut gap = unchecked("OSV", Some(false));
        gap["id"] = "F-gap".into();
        gap["scope"] = "repos:/other".into();
        gap["resolved"] = serde_json::Value::Null;
        let report = earlier_report(serde_json::json!([gap]), serde_json::json!([]));
        assert!(report.earlier_all().is_empty());
        assert!(report.earlier(&[]).is_empty());
    }

    /// Oracle: an earlier problem is from another scan, which Pantry cannot
    /// fix from here, even when its fix is automatic and a plan with the
    /// same id exists; the same finding in the latest scan can be fixed.
    #[test]
    fn earlier_problems_cannot_be_auto_fixed() {
        let auto = serde_json::json!({
            "id": "F-auto", "kind": "project", "component": "auto", "version": "1",
            "location": "/other", "vuln_id": "GHSA-aaaa-bbbb-cccc", "status": "fail", "note": "",
            "fixed": "2", "severity": "high", "kev": false, "fix_cmd": "npm i auto@2",
            "fix_auto": true, "scope": "repos:/other", "resolved": null,
        });
        let report = earlier_report(serde_json::json!([auto.clone()]), serde_json::json!([]));
        let earlier = report.earlier_all();
        assert_eq!(earlier.len(), 1);
        let finding = &earlier[0].finding;
        assert!(finding.fix_auto);
        assert!(!report.can_fix(finding, "earlier-F-auto"));
        let latest = earlier_report(serde_json::json!([]), serde_json::json!([auto]));
        assert!(latest.can_fix(&latest.findings[0], "F-auto"));
    }

    /// Oracle: the scanner contract. A skipped area is not a gap, and a
    /// scanner too old to send `excluded` has every unchecked source count.
    #[test]
    fn skipped_areas_are_not_gaps() {
        let findings: Vec<Finding> = serde_json::from_value(serde_json::json!([
            unchecked("Documents", Some(true)),
            unchecked("Feed", Some(false)),
            unchecked("Old feed", None),
        ]))
        .unwrap();
        let report = Report {
            findings,
            ..Default::default()
        };
        assert_eq!(report.gaps(), 2);
        let report = Report {
            scan: Scan {
                warns: 3,
                ..Default::default()
            },
            ..report
        };
        assert_eq!(report.warnings(), 2);
        let skipped: Vec<_> = report.skipped().iter().map(|f| &f.component).collect();
        assert_eq!(skipped, ["Documents"]);
        assert!(report.open().is_empty());
    }

    #[test]
    fn parses_scanner_stamps() {
        assert_eq!(parse_utc("1970-01-01 00:00 UTC"), Some(0));
        assert_eq!(parse_utc("2026-11-21 16:30 UTC"), Some(1_795_278_600));
        assert_eq!(parse_utc("2026-11-21T16:30:05Z"), Some(1_795_278_605));
        for bad in [
            "",
            "yesterday",
            "2026-13-01 00:00 UTC",
            "2026-11-21 25:00 UTC",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn civil_round_trip() {
        for days in [-1, 0, 59, 60, 11_016, 20_778, 50_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    fn fixture(transitions: Vec<(i64, i32)>, fixed_after: bool) -> Zone {
        Zone {
            transitions,
            initial: -21_600,
            fixed_after,
        }
    }

    #[test]
    fn local_time_uses_the_offset_in_effect() {
        // Chicago-like: CDT from 2026-03-08 08:00 UTC, CST from 2026-11-01 07:00 UTC.
        let zone = fixture(
            vec![
                (1_772_956_800, -18_000),
                (1_793_516_400, -21_600),
                (2_000_000_000, -18_000),
            ],
            false,
        );
        assert_eq!(
            local_time_in("2026-11-21 16:30 UTC", Some(&zone)),
            "21 Nov 2026, 10:30"
        );
        assert_eq!(
            local_time_in("2026-07-04 16:30 UTC", Some(&zone)),
            "4 Jul 2026, 11:30"
        );
        // Unknown offset: the time stays UTC and is labelled.
        assert_eq!(
            local_time_in("2026-11-21 16:30 UTC", None),
            "21 Nov 2026, 16:30 UTC"
        );
        // Past the last transition of a slim file with DST rules: UTC.
        let slim = fixture(vec![(0, -21_600)], false);
        assert!(local_time_in("2026-11-21 16:30 UTC", Some(&slim)).ends_with("UTC"));
        // Unparseable text passes through untouched.
        assert_eq!(local_time_in("soon", Some(&zone)), "soon");
    }

    #[test]
    fn reads_the_system_zone_file_when_present() {
        // Oracle: the parsed zone agrees with `date +%z` for now.
        #[cfg(unix)]
        if let (Ok(bytes), Ok(out)) = (
            std::fs::read("/etc/localtime"),
            std::process::Command::new("date").arg("+%z").output(),
        ) {
            let zone = parse_tzif(&bytes).expect("parse /etc/localtime");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let sign = if text.starts_with('-') { -1 } else { 1 };
            let hours: i32 = text[1..3].parse().unwrap();
            let minutes: i32 = text[3..5].parse().unwrap();
            if let Some(offset) = zone.offset_at(now) {
                assert_eq!(offset, sign * (hours * 3600 + minutes * 60));
            }
        }
        assert!(parse_tzif(b"not a zone file").is_none());
    }

    #[test]
    fn cache_path_matches_the_scanner() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.into())
            }
        };
        assert_eq!(
            cache_path_from(&env(&[("WPANTRY_DB", "/x/w.db"), ("HOME", "/h")])),
            PathBuf::from("/x/w.db")
        );
        assert_eq!(
            cache_path_from(&env(&[("HOME", "/h")])),
            PathBuf::from("/h/.cache/wpantry/wpantry.db")
        );
    }
}
