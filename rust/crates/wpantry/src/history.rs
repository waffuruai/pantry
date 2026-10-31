//! What every scan found, kept: the scans themselves, each exposure from
//! the scan that first saw it to the one that no longer did, and the fixes
//! that were applied. `findings` stays the latest view; these tables are
//! the record a report draws on (`wpantry report`): what you were exposed
//! to, for how long, what was done about it and when.
//!
//! An exposure is resolved by a scan of the same scope that no longer
//! lists it: a repo-only scan says nothing about the machine, a scan of one
//! repo says nothing about the others, and a scan without `--licenses` or
//! with other policy files says nothing about what those would have found.
//! A scan with an `unchecked` source resolves nothing: a gap in the evidence
//! is not a fix. A fix is verified only by a complete scan after it ran
//! that no longer lists what it addressed; a failed fix never is.

use crate::check::{Finding, Options};
use crate::db::Cache;
use crate::error::Result;
use crate::system::now;
use rusqlite::params;
use serde_json::{Value, json};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, started_at REAL, finished_at REAL, host TEXT, user TEXT,
  version TEXT, scope TEXT, counts TEXT, fails INTEGER, warns INTEGER, unchecked INTEGER);
CREATE TABLE IF NOT EXISTS exposures (
  key TEXT PRIMARY KEY, scope TEXT, kind TEXT, component TEXT, version TEXT, location TEXT,
  vuln_id TEXT, status TEXT, severity TEXT, kev INTEGER, fixed TEXT, note TEXT,
  first_scan INTEGER, first_at REAL, last_scan INTEGER, last_at REAL,
  resolved_scan INTEGER, resolved_at REAL);
CREATE INDEX IF NOT EXISTS exposures_open ON exposures (resolved_at, scope);
CREATE TABLE IF NOT EXISTS fixes (
  id INTEGER PRIMARY KEY, scan_id INTEGER, at REAL, command TEXT, mode TEXT, ok INTEGER,
  verified_scan INTEGER, targets TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, at REAL, kind TEXT, detail TEXT);
";

/// The scope a scan covers, as a string two scans can be compared by:
/// what it looked at, and what it looked for (`--licenses`, the policy
/// files). Two scans with different scopes say nothing about each other.
pub fn scope_of(opts: &Options) -> String {
    let mut paths: Vec<String> =
        opts.paths.as_deref().unwrap_or(&[]).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    paths.sort();
    let mut scope = format!(
        "{}:{}",
        if opts.machine { "machine" } else { "repos" },
        if paths.is_empty() { "~".into() } else { paths.join(",") }
    );
    if opts.licenses {
        scope.push_str("+licenses");
    }
    let policy: Vec<String> = [
        ("gitleaks", &opts.policy.gitleaks_config),
        ("licenses", &opts.policy.licenses),
        ("install-scripts", &opts.policy.install_scripts),
    ]
    .iter()
    .filter_map(|(name, p)| p.as_ref().map(|p| format!("{name}={}", p.to_string_lossy())))
    .collect();
    if !policy.is_empty() {
        scope.push_str(";policy:");
        scope.push_str(&policy.join(","));
    }
    scope
}

/// The key one exposure is tracked under across scans.
pub fn key_of(f: &Finding) -> String {
    format!("{}|{}|{}|{}", f.kind, f.component, f.location, f.vuln_id)
}

/// Record a finished scan: its row, the exposures it saw (new ones
/// opened, known ones touched) and, when every source answered, the ones
/// of its scope it no longer sees (resolved), plus a `scan` event. A scan
/// with an `unchecked` finding resolves nothing. Returns the scan id.
pub fn record_scan(
    cache: &Cache,
    started_at: f64,
    findings: &[Finding],
    counts: &[(String, i64)],
    opts: &Options,
) -> Result<i64> {
    let at = now();
    let scope = scope_of(opts);
    let fails = findings.iter().filter(|f| f.status == "fail").count() as i64;
    let warns = findings.iter().filter(|f| f.status == "warn").count() as i64;
    let unchecked = findings.iter().filter(|f| f.kind == "unchecked").count() as i64;
    let counts_json = Value::Object(counts.iter().map(|(k, n)| (k.clone(), json!(n))).collect()).to_string();
    cache.conn.execute(
        "INSERT INTO scans (started_at, finished_at, host, user, version, scope, counts, fails, warns, unchecked) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![started_at, at, host(), user(), crate::VERSION, scope, counts_json, fails, warns, unchecked],
    )?;
    let id = cache.conn.last_insert_rowid();
    let mut seen: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked") {
        let key = key_of(f);
        seen.push(key.clone());
        cache.conn.execute(
            "INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id, status, severity, kev, fixed, note, \
             first_scan, first_at, last_scan, last_at, resolved_scan, resolved_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL) \
             ON CONFLICT(key) DO UPDATE SET scope = excluded.scope, status = excluded.status, severity = excluded.severity, \
             kev = excluded.kev, fixed = excluded.fixed, note = excluded.note, last_scan = excluded.last_scan, \
             last_at = excluded.last_at, resolved_scan = NULL, resolved_at = NULL",
            params![
                key, scope, f.kind, f.component, f.version, f.location, f.vuln_id, f.status, f.severity, f.kev as i64,
                f.fixed, f.note, id, at, id, at
            ],
        )?;
    }
    // Open exposures of this scope the scan didn't list are over, when every
    // source answered: a source that couldn't be asked may be where they were.
    if unchecked == 0 {
        let mut stmt = cache.conn.prepare("SELECT key FROM exposures WHERE scope = ? AND resolved_at IS NULL")?;
        let open: Vec<String> = stmt.query_map([&scope], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        for key in open.iter().filter(|k| !seen.contains(k)) {
            cache.conn.execute(
                "UPDATE exposures SET resolved_scan = ?, resolved_at = ? WHERE key = ?",
                params![id, at, key],
            )?;
        }
    }
    event(
        cache,
        "scan",
        &json!({"scan": id, "scope": scope, "fails": fails, "warns": warns, "unchecked": unchecked,
                "seconds": (at - started_at).round()}),
    )?;
    Ok(id)
}

/// Record one applied (or dry-run) fix command, its outcome, and the
/// exposures (`key_of`) it was meant to clear.
pub fn record_fix(
    cache: &Cache,
    scan_id: Option<i64>,
    command: &str,
    mode: &str,
    ok: bool,
    targets: &[String],
) -> Result<()> {
    cache.conn.execute(
        "INSERT INTO fixes (scan_id, at, command, mode, ok, verified_scan, targets) VALUES (?, ?, ?, ?, ?, NULL, ?)",
        params![scan_id, now(), command, mode, ok as i64, json!(targets).to_string()],
    )?;
    event(cache, "fix", &json!({"scan": scan_id, "command": command, "mode": mode, "ok": ok, "targets": targets}))
}

/// The scan after the fixes ran verifies them: a fix is verified when it
/// exited 0, when that scan had every source answer, and when none of the
/// exposures it addressed were still listed by it. A failed fix, an
/// incomplete re-check, or a fix with no known target stays unverified.
/// Returns how many were verified.
pub fn verify_fixes(cache: &Cache, applied_in: i64, verified_by: i64) -> Result<usize> {
    let complete = cache
        .conn
        .query_row("SELECT unchecked FROM scans WHERE id = ?", [verified_by], |r| r.get::<_, Option<i64>>(0))
        .ok()
        .flatten()
        == Some(0);
    if !complete {
        return Ok(0);
    }
    let mut stmt =
        cache.conn.prepare("SELECT id, targets FROM fixes WHERE scan_id = ? AND verified_scan IS NULL AND ok = 1")?;
    let candidates: Vec<(i64, String)> = stmt
        .query_map([applied_in], |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default())))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    let mut verified = 0;
    for (fix_id, targets) in candidates {
        let targets: Vec<String> = serde_json::from_str(&targets).unwrap_or_default();
        if targets.is_empty() {
            continue;
        }
        let still_listed = targets.iter().any(|key| {
            cache
                .conn
                .query_row("SELECT 1 FROM exposures WHERE key = ? AND last_scan = ?", params![key, verified_by], |_| {
                    Ok(())
                })
                .is_ok()
        });
        if still_listed {
            continue;
        }
        cache.conn.execute("UPDATE fixes SET verified_scan = ? WHERE id = ?", params![verified_by, fix_id])?;
        verified += 1;
    }
    Ok(verified)
}

pub fn event(cache: &Cache, kind: &str, detail: &Value) -> Result<()> {
    cache
        .conn
        .execute("INSERT INTO events (at, kind, detail) VALUES (?, ?, ?)", params![now(), kind, detail.to_string()])?;
    Ok(())
}

/// The latest scan's id, if any.
pub fn latest_scan(cache: &Cache) -> Result<Option<i64>> {
    Ok(cache.conn.query_row("SELECT MAX(id) FROM scans", [], |r| r.get::<_, Option<i64>>(0))?)
}

fn host() -> String {
    crate::system::run(&["hostname"], std::time::Duration::from_secs(5)).trim().to_string()
}

fn user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}

// reports ---------------------------------------------------------------

/// One exposure, open or over.
#[derive(Clone, Debug, PartialEq)]
pub struct Exposure {
    pub kind: String,
    pub component: String,
    pub version: String,
    pub location: String,
    pub vuln_id: String,
    pub status: String,
    pub severity: String,
    pub kev: bool,
    pub fixed: String,
    pub note: String,
    pub first_at: f64,
    pub last_at: f64,
    pub resolved_at: Option<f64>,
    /// Days from first seen to resolved (or to now, while open).
    pub days_exposed: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Fix {
    pub at: f64,
    pub command: String,
    pub mode: String,
    pub ok: bool,
    pub scan_id: Option<i64>,
    /// The complete scan that no longer listed what this fix addressed.
    pub verified_scan: Option<i64>,
    /// The exposures (`key_of`) the fix was meant to clear.
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: f64,
    pub kind: String,
    pub detail: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScanRow {
    pub id: i64,
    pub started_at: f64,
    pub finished_at: f64,
    pub host: String,
    pub user: String,
    pub version: String,
    pub scope: String,
    pub fails: i64,
    pub warns: i64,
    /// Sources that couldn't be asked; a scan with any resolves nothing.
    pub unchecked: i64,
}

/// Exposures first seen, last seen or resolved since `since` (seconds
/// since the epoch), open ones first, then by first seen.
pub fn exposures(cache: &Cache, since: f64) -> Result<Vec<Exposure>> {
    let mut stmt = cache.conn.prepare(
        "SELECT kind, component, version, location, vuln_id, status, severity, kev, fixed, note, first_at, last_at, resolved_at \
         FROM exposures WHERE last_at >= ? OR resolved_at >= ? OR resolved_at IS NULL \
         ORDER BY resolved_at IS NOT NULL, first_at",
    )?;
    let t = now();
    let rows = stmt.query_map([since, since], |r| {
        let first_at: f64 = r.get::<_, Option<f64>>(10)?.unwrap_or(0.0);
        let resolved_at: Option<f64> = r.get(12)?;
        Ok(Exposure {
            kind: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            component: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            version: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            location: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            vuln_id: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            status: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            severity: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            kev: r.get::<_, Option<i64>>(7)?.unwrap_or(0) != 0,
            fixed: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
            note: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            first_at,
            last_at: r.get::<_, Option<f64>>(11)?.unwrap_or(0.0),
            resolved_at,
            days_exposed: ((resolved_at.unwrap_or(t) - first_at) / 86400.0 * 10.0).round() / 10.0,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn fixes(cache: &Cache, since: f64) -> Result<Vec<Fix>> {
    let mut stmt = cache.conn.prepare(
        "SELECT at, command, mode, ok, scan_id, verified_scan, targets FROM fixes WHERE at >= ? ORDER BY at",
    )?;
    let rows = stmt.query_map([since], |r| {
        let targets: Option<String> = r.get(6)?;
        Ok(Fix {
            at: r.get::<_, Option<f64>>(0)?.unwrap_or(0.0),
            command: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            mode: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ok: r.get::<_, Option<i64>>(3)?.unwrap_or(0) != 0,
            scan_id: r.get(4)?,
            verified_scan: r.get(5)?,
            targets: targets.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn events(cache: &Cache, since: f64) -> Result<Vec<Event>> {
    let mut stmt = cache.conn.prepare("SELECT at, kind, detail FROM events WHERE at >= ? ORDER BY at")?;
    let rows = stmt.query_map([since], |r| {
        let detail: Option<String> = r.get(2)?;
        Ok(Event {
            at: r.get::<_, Option<f64>>(0)?.unwrap_or(0.0),
            kind: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            detail: detail.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or(Value::Null),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn scans(cache: &Cache, since: f64) -> Result<Vec<ScanRow>> {
    let mut stmt = cache.conn.prepare(
        "SELECT id, started_at, finished_at, host, user, version, scope, fails, warns, unchecked FROM scans \
         WHERE finished_at >= ? ORDER BY id",
    )?;
    let rows = stmt.query_map([since], |r| {
        Ok(ScanRow {
            id: r.get(0)?,
            started_at: r.get::<_, Option<f64>>(1)?.unwrap_or(0.0),
            finished_at: r.get::<_, Option<f64>>(2)?.unwrap_or(0.0),
            host: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            user: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            version: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            scope: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            fails: r.get::<_, Option<i64>>(7)?.unwrap_or(0),
            warns: r.get::<_, Option<i64>>(8)?.unwrap_or(0),
            unchecked: r.get::<_, Option<i64>>(9)?.unwrap_or(0),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

impl Exposure {
    pub fn to_json(&self) -> Value {
        json!({"kind": self.kind, "component": self.component, "version": self.version, "location": self.location,
               "vuln_id": self.vuln_id, "status": self.status, "severity": self.severity, "kev": self.kev,
               "fixed": self.fixed, "note": self.note, "first_at": self.first_at, "last_at": self.last_at,
               "resolved_at": self.resolved_at, "days_exposed": self.days_exposed,
               "first": stamp(self.first_at), "resolved": self.resolved_at.map(stamp)})
    }
}

impl Fix {
    pub fn to_json(&self) -> Value {
        json!({"at": self.at, "when": stamp(self.at), "command": self.command, "mode": self.mode, "ok": self.ok,
               "scan_id": self.scan_id, "verified_scan": self.verified_scan, "targets": self.targets})
    }
}

impl Event {
    pub fn to_json(&self) -> Value {
        json!({"at": self.at, "when": stamp(self.at), "kind": self.kind, "detail": self.detail})
    }
}

impl ScanRow {
    pub fn to_json(&self) -> Value {
        json!({"id": self.id, "started_at": self.started_at, "finished_at": self.finished_at, "when": stamp(self.finished_at),
               "host": self.host, "user": self.user, "version": self.version, "scope": self.scope,
               "fails": self.fails, "warns": self.warns, "unchecked": self.unchecked})
    }
}

/// The report as one JSON document: the sections asked for, since `since`.
pub fn report_json(
    cache: &Cache,
    exposure: bool,
    remediation: bool,
    audit: bool,
    since: f64,
    since_days: i64,
) -> Result<String> {
    let mut o = serde_json::Map::new();
    o.insert("schema".into(), json!(crate::SCHEMA));
    o.insert("version".into(), json!(crate::VERSION));
    o.insert("since_days".into(), json!(since_days));
    if exposure {
        o.insert("exposures".into(), exposures(cache, since)?.iter().map(Exposure::to_json).collect());
    }
    if remediation {
        o.insert("fixes".into(), fixes(cache, since)?.iter().map(Fix::to_json).collect());
    }
    if audit {
        o.insert("scans".into(), scans(cache, since)?.iter().map(ScanRow::to_json).collect());
        o.insert("events".into(), events(cache, since)?.iter().map(Event::to_json).collect());
    }
    Ok(serde_json::to_string_pretty(&Value::Object(o)).expect("a Value serialises") + "\n")
}

/// `YYYY-MM-DD HH:MM UTC` for a timestamp.
pub fn stamp(t: f64) -> String {
    let secs = t.max(0.0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60)
}

/// Howard Hinnant's days-to-civil.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, status: &str) -> Finding {
        Finding {
            kind: "project".into(),
            component: "repo/Cargo.lock".into(),
            version: "1.0.0".into(),
            location: "/r/Cargo.lock".into(),
            vuln_id: id.into(),
            status: status.into(),
            fixed: "1.0.1".into(),
            severity: "HIGH".into(),
            ..Default::default()
        }
    }

    #[test]
    fn exposures_open_touch_and_resolve_within_a_scope() {
        let d = crate::system::TempDir::new("history").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
        let t0 = now() - 3.0 * 86400.0;
        let s1 = record_scan(
            &c,
            t0,
            &[finding("CVE-1", "fail"), finding("CVE-2", "warn")],
            &[("git repos".into(), 1)],
            &opts,
        )
        .unwrap();
        let s2 = record_scan(&c, now(), &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        assert_eq!((s1, s2), (1, 2));
        let open: Vec<_> = exposures(&c, 0.0).unwrap();
        assert_eq!(open.len(), 2);
        let one = open.iter().find(|e| e.vuln_id == "CVE-1").unwrap();
        let two = open.iter().find(|e| e.vuln_id == "CVE-2").unwrap();
        assert!(one.resolved_at.is_none());
        assert_eq!(two.resolved_at.map(|_| true), Some(true), "not seen by the second scan of the same scope");
        assert!(two.days_exposed < 0.01, "{}", two.days_exposed);
        // Another scope never resolves it.
        let other = Options { machine: true, paths: None, ..Default::default() };
        record_scan(&c, now(), &[], &[], &other).unwrap();
        assert!(exposures(&c, 0.0).unwrap().iter().find(|e| e.vuln_id == "CVE-1").unwrap().resolved_at.is_none());
        // Seen again: reopened.
        record_scan(&c, now(), &[finding("CVE-1", "fail"), finding("CVE-2", "warn")], &[], &opts).unwrap();
        assert!(exposures(&c, 0.0).unwrap().iter().all(|e| e.resolved_at.is_none()));
        assert_eq!(scans(&c, 0.0).unwrap().len(), 4);
        assert_eq!(events(&c, 0.0).unwrap().iter().filter(|e| e.kind == "scan").count(), 4);
        // A fix for CVE-2, verified by the next complete scan of the scope that no longer lists it.
        record_fix(&c, Some(4), "brew upgrade x", "auto", true, &[key_of(&finding("CVE-2", "warn"))]).unwrap();
        let s5 = record_scan(&c, now(), &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, 4, s5).unwrap(), 1);
        let f = fixes(&c, 0.0).unwrap();
        assert_eq!((f.len(), f[0].ok, f[0].verified_scan), (1, true, Some(5)));
        assert_eq!(f[0].targets, [key_of(&finding("CVE-2", "warn"))]);
        assert_eq!(scans(&c, 0.0).unwrap()[4].unchecked, 0);
        c.close().unwrap();
    }

    fn gap() -> Finding {
        Finding {
            kind: "unchecked".into(),
            component: "repo dependencies against OSV".into(),
            vuln_id: "UNCHECKED".into(),
            status: "warn".into(),
            note: "offline and not cached".into(),
            ..Default::default()
        }
    }

    #[test]
    fn an_incomplete_recheck_resolves_nothing() {
        let d = crate::system::TempDir::new("history-gap").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
        record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        // The source is down: the scan lists only the gap. The exposure stays open.
        let s2 = record_scan(&c, 2.0, &[gap()], &[], &opts).unwrap();
        let e = exposures(&c, 0.0).unwrap();
        assert_eq!(e.len(), 1);
        assert!(e[0].resolved_at.is_none(), "a source outage is not a fix: {e:?}");
        assert_eq!(scans(&c, 0.0).unwrap()[1].unchecked, 1);
        assert_eq!(events(&c, 0.0).unwrap()[1].detail["unchecked"], 1);
        // Back online and still listed: still open. Back online and gone: resolved.
        record_scan(&c, 3.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
        let s4 = record_scan(&c, 4.0, &[], &[], &opts).unwrap();
        let e = exposures(&c, 0.0).unwrap();
        assert!(e[0].resolved_at.is_some());
        assert!(s2 < s4);
        c.close().unwrap();
    }

    #[test]
    fn scope_includes_what_the_scan_looked_for() {
        let repos = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
        assert_eq!(scope_of(&repos), "repos:/r");
        let licenses = Options { licenses: true, ..repos.clone() };
        assert_eq!(scope_of(&licenses), "repos:/r+licenses");
        let policy = Options {
            policy: crate::check::Policy { install_scripts: Some("/p/allow.txt".into()), ..Default::default() },
            ..repos.clone()
        };
        assert_eq!(scope_of(&policy), "repos:/r;policy:install-scripts=/p/allow.txt");
        // A scan without --licenses never resolves what a licenses scan found.
        let d = crate::system::TempDir::new("history-scope").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let license = Finding { kind: "license".into(), vuln_id: "LICENSE".into(), ..finding("LICENSE", "warn") };
        record_scan(&c, 1.0, &[license], &[], &licenses).unwrap();
        record_scan(&c, 2.0, &[], &[], &repos).unwrap();
        assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
        record_scan(&c, 3.0, &[], &[], &licenses).unwrap();
        assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_some());
        c.close().unwrap();
    }

    #[test]
    fn a_fix_is_verified_only_by_complete_negative_evidence() {
        let d = crate::system::TempDir::new("history-fix").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
        let target = key_of(&finding("CVE-1", "fail"));
        let s1 = record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        // A failed fix is never verified, whatever the re-check says.
        record_fix(&c, Some(s1), "npm install -g x@2", "auto", false, std::slice::from_ref(&target)).unwrap();
        let s2 = record_scan(&c, 2.0, &[], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, s1, s2).unwrap(), 0);
        assert_eq!(fixes(&c, 0.0).unwrap()[0].verified_scan, None, "a failed fix marked verified");
        // A successful fix, re-checked by a scan with a gap: not verified.
        let s3 = record_scan(&c, 3.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        record_fix(&c, Some(s3), "npm install -g x@2", "auto", true, std::slice::from_ref(&target)).unwrap();
        let s4 = record_scan(&c, 4.0, &[gap()], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, s3, s4).unwrap(), 0);
        // Re-checked by a complete scan that still lists it: not verified.
        let s5 = record_scan(&c, 5.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, s3, s5).unwrap(), 0);
        // Re-checked by a complete scan that no longer lists it: verified.
        let s6 = record_scan(&c, 6.0, &[], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, s3, s6).unwrap(), 1);
        let f = fixes(&c, 0.0).unwrap();
        assert_eq!((f[0].verified_scan, f[1].verified_scan), (None, Some(s6)));
        // A fix with no known target has nothing to verify against.
        record_fix(&c, Some(s6), "brew upgrade", "auto", true, &[]).unwrap();
        let s7 = record_scan(&c, 7.0, &[], &[], &opts).unwrap();
        assert_eq!(verify_fixes(&c, s6, s7).unwrap(), 0);
        c.close().unwrap();
    }

    #[test]
    fn stamps_are_utc_dates() {
        assert_eq!(stamp(0.0), "1970-01-01 00:00 UTC");
        assert_eq!(stamp(1_793_348_743.0), "2026-10-30 08:25 UTC");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
