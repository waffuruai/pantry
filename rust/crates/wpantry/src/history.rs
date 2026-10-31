//! What every scan found, kept: the scans themselves, each exposure from
//! the scan that first saw it to the one that no longer did, and the fixes
//! that were applied. `findings` stays the latest view; these tables are
//! the record a report draws on (`wpantry report`): what you were exposed
//! to, for how long, what was done about it and when.
//!
//! An exposure is resolved by a scan of the same scope that no longer
//! lists it: a repo-only scan says nothing about the machine, and a scan
//! of one repo says nothing about the others.

use crate::check::{Finding, Options};
use crate::db::Cache;
use crate::error::Result;
use crate::system::now;
use rusqlite::params;
use serde_json::{Value, json};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, started_at REAL, finished_at REAL, host TEXT, user TEXT,
  version TEXT, scope TEXT, counts TEXT, fails INTEGER, warns INTEGER);
CREATE TABLE IF NOT EXISTS exposures (
  key TEXT PRIMARY KEY, scope TEXT, kind TEXT, component TEXT, version TEXT, location TEXT,
  vuln_id TEXT, status TEXT, severity TEXT, kev INTEGER, fixed TEXT, note TEXT,
  first_scan INTEGER, first_at REAL, last_scan INTEGER, last_at REAL,
  resolved_scan INTEGER, resolved_at REAL,
  dep_scope TEXT, dep_direct INTEGER, affected_range TEXT, fix_cmd TEXT);
CREATE INDEX IF NOT EXISTS exposures_open ON exposures (resolved_at, scope);
CREATE TABLE IF NOT EXISTS fixes (
  id INTEGER PRIMARY KEY, scan_id INTEGER, at REAL, command TEXT, mode TEXT, ok INTEGER,
  verified_scan INTEGER);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, at REAL, kind TEXT, detail TEXT);
";

/// The scope a scan covers, as a string two scans can be compared by.
pub fn scope_of(opts: &Options) -> String {
    let mut paths: Vec<String> =
        opts.paths.as_deref().unwrap_or(&[]).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    paths.sort();
    format!(
        "{}:{}",
        if opts.machine { "machine" } else { "repos" },
        if paths.is_empty() { "~".into() } else { paths.join(",") }
    )
}

/// The key one exposure is tracked under across scans.
pub fn key_of(f: &Finding) -> String {
    format!("{}|{}|{}|{}", f.kind, f.component, f.location, f.vuln_id)
}

/// Record a finished scan: its row, the exposures it saw (new ones
/// opened, known ones touched) and the ones of its scope it no longer
/// sees (resolved), plus a `scan` event. Returns the scan id.
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
    let counts_json = Value::Object(counts.iter().map(|(k, n)| (k.clone(), json!(n))).collect()).to_string();
    cache.conn.execute(
        "INSERT INTO scans (started_at, finished_at, host, user, version, scope, counts, fails, warns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![started_at, at, host(), user(), crate::VERSION, scope, counts_json, fails, warns],
    )?;
    let id = cache.conn.last_insert_rowid();
    let mut seen: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked") {
        let key = key_of(f);
        seen.push(key.clone());
        cache.conn.execute(
            "INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id, status, severity, kev, fixed, note, \
             first_scan, first_at, last_scan, last_at, resolved_scan, resolved_at, dep_scope, dep_direct, affected_range, fix_cmd) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?) \
             ON CONFLICT(key) DO UPDATE SET scope = excluded.scope, status = excluded.status, severity = excluded.severity, \
             kev = excluded.kev, fixed = excluded.fixed, note = excluded.note, last_scan = excluded.last_scan, \
             last_at = excluded.last_at, resolved_scan = NULL, resolved_at = NULL, dep_scope = excluded.dep_scope, \
             dep_direct = excluded.dep_direct, affected_range = excluded.affected_range, fix_cmd = excluded.fix_cmd",
            params![
                key,
                scope,
                f.kind,
                f.component,
                f.version,
                f.location,
                f.vuln_id,
                f.status,
                f.severity,
                f.kev as i64,
                f.fixed,
                f.note,
                id,
                at,
                id,
                at,
                f.dep_scope,
                f.dep_direct.map(i64::from),
                f.affected_range,
                f.fix_cmd
            ],
        )?;
    }
    // Open exposures of this scope the scan didn't list are over.
    let mut stmt = cache.conn.prepare("SELECT key FROM exposures WHERE scope = ? AND resolved_at IS NULL")?;
    let open: Vec<String> = stmt.query_map([&scope], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    for key in open.iter().filter(|k| !seen.contains(k)) {
        cache
            .conn
            .execute("UPDATE exposures SET resolved_scan = ?, resolved_at = ? WHERE key = ?", params![id, at, key])?;
    }
    event(
        cache,
        "scan",
        &json!({"scan": id, "scope": scope, "fails": fails, "warns": warns, "seconds": (at - started_at).round()}),
    )?;
    Ok(id)
}

/// Record one applied (or dry-run) fix command and its outcome.
pub fn record_fix(cache: &Cache, scan_id: Option<i64>, command: &str, mode: &str, ok: bool) -> Result<()> {
    cache.conn.execute(
        "INSERT INTO fixes (scan_id, at, command, mode, ok, verified_scan) VALUES (?, ?, ?, ?, ?, NULL)",
        params![scan_id, now(), command, mode, ok as i64],
    )?;
    event(cache, "fix", &json!({"scan": scan_id, "command": command, "mode": mode, "ok": ok}))
}

/// The scan after the fixes ran verifies them.
pub fn verify_fixes(cache: &Cache, applied_in: i64, verified_by: i64) -> Result<()> {
    cache.conn.execute(
        "UPDATE fixes SET verified_scan = ? WHERE scan_id = ? AND verified_scan IS NULL",
        params![verified_by, applied_in],
    )?;
    Ok(())
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
    /// As on the finding: how the dependency is depended on, whether it is
    /// the project's own, the range matched, and the fix offered.
    pub dep_scope: String,
    pub dep_direct: Option<bool>,
    pub affected_range: String,
    pub fix_cmd: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Fix {
    pub at: f64,
    pub command: String,
    pub mode: String,
    pub ok: bool,
    pub scan_id: Option<i64>,
    pub verified_scan: Option<i64>,
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
}

/// Exposures first seen, last seen or resolved since `since` (seconds
/// since the epoch), open ones first, then by first seen.
pub fn exposures(cache: &Cache, since: f64) -> Result<Vec<Exposure>> {
    let mut stmt = cache.conn.prepare(
        "SELECT kind, component, version, location, vuln_id, status, severity, kev, fixed, note, first_at, last_at, resolved_at, \
         dep_scope, dep_direct, affected_range, fix_cmd \
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
            dep_scope: r.get::<_, Option<String>>(13)?.unwrap_or_default(),
            dep_direct: r.get::<_, Option<i64>>(14)?.map(|d| d != 0),
            affected_range: r.get::<_, Option<String>>(15)?.unwrap_or_default(),
            fix_cmd: r.get::<_, Option<String>>(16)?.unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn fixes(cache: &Cache, since: f64) -> Result<Vec<Fix>> {
    let mut stmt = cache
        .conn
        .prepare("SELECT at, command, mode, ok, scan_id, verified_scan FROM fixes WHERE at >= ? ORDER BY at")?;
    let rows = stmt.query_map([since], |r| {
        Ok(Fix {
            at: r.get::<_, Option<f64>>(0)?.unwrap_or(0.0),
            command: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            mode: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ok: r.get::<_, Option<i64>>(3)?.unwrap_or(0) != 0,
            scan_id: r.get(4)?,
            verified_scan: r.get(5)?,
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
        "SELECT id, started_at, finished_at, host, user, version, scope, fails, warns FROM scans WHERE finished_at >= ? ORDER BY id",
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
               "first": stamp(self.first_at), "resolved": self.resolved_at.map(stamp),
               "dep_scope": if self.dep_scope.is_empty() { "unknown" } else { self.dep_scope.as_str() },
               "dep_direct": self.dep_direct, "affected_range": self.affected_range, "fix_cmd": self.fix_cmd})
    }
}

impl Fix {
    pub fn to_json(&self) -> Value {
        json!({"at": self.at, "when": stamp(self.at), "command": self.command, "mode": self.mode, "ok": self.ok,
               "scan_id": self.scan_id, "verified_scan": self.verified_scan})
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
               "fails": self.fails, "warns": self.warns})
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
        record_fix(&c, Some(4), "brew upgrade x", "auto", true).unwrap();
        verify_fixes(&c, 4, 5).unwrap();
        let f = fixes(&c, 0.0).unwrap();
        assert_eq!((f.len(), f[0].ok, f[0].verified_scan), (1, true, Some(5)));
        c.close().unwrap();
    }

    #[test]
    fn stamps_are_utc_dates() {
        assert_eq!(stamp(0.0), "1970-01-01 00:00 UTC");
        assert_eq!(stamp(1_793_348_743.0), "2026-10-30 08:25 UTC");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
