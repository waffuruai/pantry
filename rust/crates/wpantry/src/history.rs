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

use crate::checks::Options;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::utils::dates::civil_from_days;
use crate::utils::os::now;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, started_at REAL, finished_at REAL, host TEXT, user TEXT,
  version TEXT, scope TEXT, counts TEXT, fails INTEGER, warns INTEGER, unchecked INTEGER);
CREATE TABLE IF NOT EXISTS exposures (
  key TEXT PRIMARY KEY, scope TEXT, kind TEXT, component TEXT, version TEXT, location TEXT,
  vuln_id TEXT, status TEXT, severity TEXT, kev INTEGER, fixed TEXT, note TEXT,
  first_scan INTEGER, first_at REAL, last_scan INTEGER, last_at REAL,
  resolved_scan INTEGER, resolved_at REAL,
  dep_scope TEXT, dep_direct INTEGER, affected_range TEXT, fix_cmd TEXT);
CREATE INDEX IF NOT EXISTS exposures_open ON exposures (resolved_at, scope);
CREATE TABLE IF NOT EXISTS fixes (
  id INTEGER PRIMARY KEY, scan_id INTEGER, at REAL, command TEXT, mode TEXT, ok INTEGER,
  verified_scan INTEGER, targets TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, at REAL, kind TEXT, detail TEXT);
";

/// How many scans keep their findings, the latest included: a month of
/// daily scans. An older one keeps its row in the scan log only.
pub const KEEP_RUNS: i64 = 30;

/// The scope a scan covers, as a string two scans can be compared by:
/// what it looked at, and what it looked for (`--licenses`, the policy
/// files). Two scans with different scopes say nothing about each other.
pub fn scope_of(opts: &Options) -> String {
    let mut paths: Vec<String> =
        opts.paths.as_deref().unwrap_or(&[]).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    paths.sort();
    let mut scope = format!(
        "{}:{}",
        if opts.machine {
            "machine"
        } else if opts.project {
            "project"
        } else {
            "repos"
        },
        if paths.is_empty() { "~".into() } else { paths.join(",") }
    );
    if opts.licenses {
        scope.push_str("+licenses");
    }
    if opts.machine && opts.no_personal_files {
        scope.push_str(";no-personal-files");
    }
    let policy: Vec<String> = [
        ("secret-rules", &opts.policy.secret_rules),
        ("licenses", &opts.policy.licenses),
        ("install-scripts", &opts.policy.install_scripts),
        ("hooks", &opts.policy.hooks),
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
    f.key()
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
    record_scan_totals(cache, started_at, findings, counts, (0, 0), opts)
}

/// [`record_scan`], with the advisories that have no fix yet and the
/// dependencies with no license wpantry knows (`totals`), which the
/// report prints.
pub fn record_scan_totals(
    cache: &Cache,
    started_at: f64,
    findings: &[Finding],
    counts: &[(String, i64)],
    totals: (i64, i64),
    opts: &Options,
) -> Result<i64> {
    let at = now();
    let scope = scope_of(opts);
    let fails = findings.iter().filter(|f| f.status == "fail").count() as i64;
    let warns = findings.iter().filter(|f| f.status == "warn").count() as i64;
    let unchecked = findings.iter().filter(|f| f.kind == "unchecked").count() as i64;
    let counts_json = Value::Object(counts.iter().map(|(k, n)| (k.clone(), json!(n))).collect()).to_string();
    // The counts again in the order they were counted, for the report.
    let checked = Value::Array(counts.iter().map(|(k, n)| json!([k, n])).collect()).to_string();
    let options = crate::reporters::html::scope_json(opts).dumps();
    cache.conn.execute(
        "INSERT INTO scans (started_at, finished_at, host, user, version, scope, counts, fails, warns, unchecked, \
         checked, unfixed, unknown_licenses, options, kept) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        params![
            started_at,
            at,
            host(),
            user(),
            crate::VERSION,
            scope,
            counts_json,
            fails,
            warns,
            unchecked,
            checked,
            totals.0,
            totals.1,
            options
        ],
    )?;
    let id = cache.conn.last_insert_rowid();
    cache.keep_findings(id, findings)?;
    trim_runs(cache, KEEP_RUNS)?;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked") {
        let key = key_of(f);
        seen.insert(key.clone());
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
        cache.conn.execute(
            // The first score is kept as well as the latest: how long a
            // likely-to-be-exploited exposure stayed open.
            "UPDATE exposures SET cvss = ?1, cvss_version = ?2, epss = ?3, epss_percentile = ?4, \
             first_epss_percentile = CASE WHEN first_epss IS NULL THEN ?4 ELSE first_epss_percentile END, \
             first_epss = COALESCE(first_epss, ?3) WHERE key = ?5",
            params![f.cvss, f.cvss_version, f.epss, f.epss_percentile, key],
        )?;
    }
    // Open exposures of this scope the scan didn't list are over, when every
    // source answered: a source that couldn't be asked may be where they were.
    if unchecked == 0 {
        let mut stmt = cache.conn.prepare("SELECT key FROM exposures WHERE scope = ? AND resolved_at IS NULL")?;
        let open: Vec<String> = stmt.query_map([&scope], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        for key in open.iter().filter(|k| !seen.contains(*k)) {
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
        "INSERT INTO fixes (scan_id, at, command, mode, ok, verified_scan, targets, user, host) \
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)",
        params![scan_id, now(), command, mode, ok as i64, json!(targets).to_string(), user(), host()],
    )?;
    event(
        cache,
        "fix",
        &json!({"scan": scan_id, "command": command, "mode": mode, "ok": ok, "targets": targets, "user": user(), "host": host()}),
    )
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
/// The finding keys a fix has been tried for since scan `scan_id` finished.
pub fn tried_since(cache: &Cache, scan_id: i64) -> Result<std::collections::HashSet<String>> {
    let mut st =
        cache.conn.prepare("SELECT targets FROM fixes WHERE at >= (SELECT finished_at FROM scans WHERE id = ?)")?;
    let rows = st.query_map(params![scan_id], |r| r.get::<_, Option<String>>(0))?;
    let mut out = std::collections::HashSet::new();
    for t in rows {
        if let Some(t) = t? {
            out.extend(serde_json::from_str::<Vec<String>>(&t).unwrap_or_default());
        }
    }
    Ok(out)
}

pub fn latest_scan(cache: &Cache) -> Result<Option<i64>> {
    Ok(cache.conn.query_row("SELECT MAX(id) FROM scans WHERE kept = 1", [], |r| r.get::<_, Option<i64>>(0))?)
}

/// The cache key a running scan leaves under its process id until it ends.
const RUNNING: &str = "scan_running:";

/// A scan that began and never recorded its end.
#[derive(Clone, Debug, PartialEq)]
pub struct Unfinished {
    pub pid: u32,
    pub started_at: f64,
    pub scope: String,
    /// Its process is still there: it may yet finish.
    pub running: bool,
}

impl Unfinished {
    /// One line for the user. An interrupted scan saved nothing (a scan
    /// writes its findings and its row together, at the end); one still
    /// running will become the latest when it finishes.
    pub fn line(&self, latest: Option<i64>) -> String {
        let what = format!("the scan of {} started {}", self.scope, stamp(self.started_at));
        if self.running {
            return format!("ℹ {what} is still running (pid {}): when it finishes, wpantry report shows it", self.pid);
        }
        match latest {
            Some(id) => format!("ℹ {what} didn't finish: nothing of it was saved, and wpantry report shows scan {id}"),
            None => format!("ℹ {what} didn't finish: nothing of it was saved"),
        }
    }
}

/// Note that this process began a scan, kept at once (whatever else the
/// scan writes waits for its end): a scan that is interrupted can't say so
/// itself, so the next command does ([`unfinished`]).
pub fn scan_started(cache: &Cache, opts: &Options, started_at: f64) -> Result<()> {
    let detail = json!({"started_at": started_at, "scope": scope_of(opts)}).to_string();
    cache.set(&format!("{RUNNING}{}", std::process::id()), &detail)?;
    cache.commit()
}

/// This process's scan ended, and recorded itself.
pub fn scan_finished(cache: &Cache) -> Result<()> {
    cache.conn.execute("DELETE FROM meta WHERE key = ?", [format!("{RUNNING}{}", std::process::id())])?;
    Ok(())
}

/// The scans that began and didn't end, the oldest first; `alive` says
/// whether a process is still there. One whose process is gone is
/// forgotten here: it is told once.
pub fn unfinished(cache: &Cache, alive: &dyn Fn(u32) -> bool) -> Result<Vec<Unfinished>> {
    let mut stmt = cache.conn.prepare("SELECT key, value FROM meta WHERE substr(key, 1, ?1) = ?2")?;
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map(params![RUNNING.len() as i64, RUNNING], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (key, value) in rows {
        let detail: Value = value.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null);
        let pid = key[RUNNING.len()..].parse::<u32>().unwrap_or(0);
        let running = pid != 0 && pid != std::process::id() && alive(pid);
        if !running {
            cache.conn.execute("DELETE FROM meta WHERE key = ?", [&key])?;
        }
        out.push(Unfinished {
            pid,
            started_at: detail["started_at"].as_f64().unwrap_or(0.0),
            scope: detail["scope"].as_str().unwrap_or("").to_string(),
            running,
        });
    }
    out.sort_by(|a, b| a.started_at.total_cmp(&b.started_at));
    Ok(out)
}

/// A scan whose findings are kept (`wpantry runs`).
#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub row: ScanRow,
    /// How many findings it keeps.
    pub findings: i64,
    /// The one `report` shows.
    pub latest: bool,
}

impl Run {
    pub fn to_json(&self) -> Value {
        json!({"scan": self.row.id, "started": stamp(self.row.started_at), "finished": stamp(self.row.finished_at),
               "seconds": (self.row.finished_at - self.row.started_at).max(0.0).round() as i64,
               "host": self.row.host, "user": self.row.user, "version": self.row.version, "scope": self.row.scope,
               "fails": self.row.fails, "warns": self.row.warns, "unchecked": self.row.unchecked,
               "findings": self.findings, "latest": self.latest})
    }
}

/// `runs --json`: `{"keeps": N, "runs": [run…]}`, the latest first.
pub fn runs_json(runs: &[Run]) -> String {
    json!({"keeps": KEEP_RUNS, "runs": runs.iter().map(Run::to_json).collect::<Vec<_>>()}).to_string()
}

/// The scans whose findings are kept, the latest first.
pub fn runs(cache: &Cache) -> Result<Vec<Run>> {
    let latest = latest_scan(cache)?;
    let mut out = Vec::new();
    for row in scans(cache, f64::MIN)?.into_iter().rev() {
        let (kept, findings): (Option<i64>, i64) = cache.conn.query_row(
            "SELECT kept, (SELECT COUNT(*) FROM run_findings WHERE scan_id = scans.id) FROM scans WHERE id = ?",
            [row.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if kept == Some(1) {
            out.push(Run { latest: Some(row.id) == latest, row, findings });
        }
    }
    Ok(out)
}

/// Whether scan `id` keeps its findings.
pub fn is_kept(cache: &Cache, id: i64) -> Result<bool> {
    let kept: Option<Option<i64>> =
        cache.conn.query_row("SELECT kept FROM scans WHERE id = ?", [id], |r| r.get(0)).optional()?;
    Ok(kept.flatten() == Some(1))
}

/// Forget the findings of every kept scan but the newest `keep`.
fn trim_runs(cache: &Cache, keep: i64) -> Result<()> {
    let mut stmt = cache.conn.prepare("SELECT id FROM scans WHERE kept = 1 ORDER BY id DESC LIMIT -1 OFFSET ?")?;
    let old: Vec<i64> = stmt.query_map([keep], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    for id in old {
        cache.drop_findings(id)?;
        cache.conn.execute("UPDATE scans SET kept = 0 WHERE id = ?", [id])?;
    }
    Ok(())
}

/// Forget scan `id`'s findings (`wpantry prune ID`): it leaves `wpantry
/// runs`, and when it was the latest, `report` shows the kept scan before
/// it again. Its row stays in the scan log, and the exposure and
/// remediation logs keep what they recorded, as a `prune` event says.
/// Returns its row and how many findings went; `None` when no such scan
/// keeps findings.
pub fn prune_run(cache: &Cache, id: i64) -> Result<Option<(ScanRow, usize)>> {
    if !is_kept(cache, id)? {
        return Ok(None);
    }
    let Some(row) = scans(cache, f64::MIN)?.into_iter().find(|s| s.id == id) else { return Ok(None) };
    let was_latest = latest_scan(cache)? == Some(id);
    let gone = cache.drop_findings(id)?;
    cache.conn.execute("UPDATE scans SET kept = 0 WHERE id = ?", [id])?;
    if was_latest {
        cache.restore_findings(latest_scan(cache)?)?;
    }
    event(cache, "prune", &json!({"scan": id, "findings": gone, "user": user(), "host": host()}))?;
    Ok(Some((row, gone)))
}

fn host() -> String {
    crate::utils::process::run(&["hostname"], std::time::Duration::from_secs(5)).trim().to_string()
}

fn user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}

// reports ---------------------------------------------------------------

/// One exposure, open or over.
#[derive(Clone, Debug, Default, PartialEq)]
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
    /// As on the finding: its CVSS score and version, its EPSS score and
    /// percentile.
    pub cvss: Option<f64>,
    pub cvss_version: String,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    /// The first EPSS score and percentile seen for it (None until it had one).
    pub first_epss: Option<f64>,
    pub first_epss_percentile: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
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
    /// Who ran it, and on which machine ("" for fixes recorded before
    /// wpantry kept them).
    pub user: String,
    pub host: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: f64,
    pub kind: String,
    pub detail: Value,
}

#[derive(Clone, Debug, Default, PartialEq)]
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
        "SELECT kind, component, version, location, vuln_id, status, severity, kev, fixed, note, first_at, last_at, resolved_at, \
         dep_scope, dep_direct, affected_range, fix_cmd, cvss, cvss_version, epss, epss_percentile, \
         first_epss, first_epss_percentile \
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
            cvss: r.get(17)?,
            cvss_version: r.get::<_, Option<String>>(18)?.unwrap_or_default(),
            epss: r.get(19)?,
            epss_percentile: r.get(20)?,
            first_epss: r.get(21)?,
            first_epss_percentile: r.get(22)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn fixes(cache: &Cache, since: f64) -> Result<Vec<Fix>> {
    let mut stmt = cache.conn.prepare(
        "SELECT at, command, mode, ok, scan_id, verified_scan, targets, user, host FROM fixes WHERE at >= ? ORDER BY at",
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
            user: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            host: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
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

/// What a report needs of one scan beyond its row: the counts in the
/// order they were counted, the two totals the report prints, and the
/// scope it ran with (as the HTML report shows it).
#[derive(Clone, Debug, Default)]
pub struct ScanDetail {
    pub row: ScanRow,
    pub counts: Vec<(String, i64)>,
    pub unfixed: i64,
    pub unknown_licenses: i64,
    pub options: Value,
}

/// Scan `id`'s row and detail.
pub fn scan_detail(cache: &Cache, id: i64) -> Result<Option<ScanDetail>> {
    let row = scans(cache, f64::MIN)?.into_iter().find(|s| s.id == id);
    let Some(row) = row else { return Ok(None) };
    let (checked, unfixed, unknown, options): (Option<String>, Option<i64>, Option<i64>, Option<String>) =
        cache.conn.query_row(
            "SELECT checked, unfixed, unknown_licenses, options FROM scans WHERE id = ?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    let parse = |t: Option<String>| t.and_then(|t| serde_json::from_str::<Value>(&t).ok()).unwrap_or(Value::Null);
    let counts = parse(checked)
        .as_array()
        .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_i64()?))).collect())
        .unwrap_or_default();
    Ok(Some(ScanDetail {
        row,
        counts,
        unfixed: unfixed.unwrap_or(0),
        unknown_licenses: unknown.unwrap_or(0),
        options: parse(options),
    }))
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
               "first": stamp(self.first_at), "resolved": self.resolved_at.map(stamp),
               "dep_scope": if self.dep_scope.is_empty() { "unknown" } else { self.dep_scope.as_str() },
               "dep_direct": self.dep_direct, "affected_range": self.affected_range, "fix_cmd": self.fix_cmd})
    }
}

impl Fix {
    pub fn to_json(&self) -> Value {
        json!({"at": self.at, "when": stamp(self.at), "command": self.command, "mode": self.mode, "ok": self.ok,
               "scan_id": self.scan_id, "verified_scan": self.verified_scan, "targets": self.targets,
               "user": self.user, "host": self.host})
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

/// `YYYYMMDDTHHMMSSZ` for a timestamp: ISO 8601's basic form, for a file
/// name (no colons; the names sort by time).
pub fn file_stamp(t: f64) -> String {
    let secs = t.max(0.0) as i64;
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(secs.div_euclid(86400));
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
