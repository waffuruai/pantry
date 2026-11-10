//! The local cache: one SQLite file per machine, with the schema the CLI
//! contract fixes (`specs/cli-contract.md#cache-sqlite`), so a cache outlives
//! releases.
//!
//! It holds OSV records for what this machine has (never a mirror of OSV),
//! the answers to "which advisories affect package P at version V" with when
//! we last asked, the latest scan's findings, and the small side feeds. A
//! full-text index over the records lets agents search them.

use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::utils::os::now;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const DAY: f64 = 86400.0;
/// How far ahead of now a cached timestamp may be and still count (clocks
/// drift; a cache edited to the far future does not).
pub const CLOCK_SKEW: f64 = 300.0;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY, aliases TEXT, summary TEXT, details TEXT,
  severity TEXT, published TEXT, modified TEXT, url TEXT, record TEXT);
CREATE TABLE IF NOT EXISTS queries (
  ecosystem TEXT, package TEXT, version TEXT, checked_at REAL, vuln_ids TEXT,
  PRIMARY KEY (ecosystem, package, version));
CREATE TABLE IF NOT EXISTS findings (
  kind TEXT, component TEXT, version TEXT, location TEXT, vuln_id TEXT,
  status TEXT, fixed TEXT, kev INTEGER, severity TEXT, note TEXT, fix_cmd TEXT,
  fix_auto INTEGER, dep_scope TEXT, dep_direct INTEGER, affected_range TEXT);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, added TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS eol (
  product TEXT, cycle TEXT, eol TEXT, latest TEXT, PRIMARY KEY (product, cycle));
CREATE TABLE IF NOT EXISTS casks (app TEXT PRIMARY KEY, token TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS runs (
  source TEXT PRIMARY KEY, fingerprint TEXT, ran_at REAL, result TEXT);
CREATE TABLE IF NOT EXISTS malicious (ecosystem TEXT, name TEXT, id TEXT);
CREATE INDEX IF NOT EXISTS malicious_name ON malicious (ecosystem, name);
CREATE TABLE IF NOT EXISTS persistence (
  key TEXT PRIMARY KEY, source TEXT, location TEXT, program TEXT, first_at REAL, last_at REAL);
";

/// Columns added since a table was first created, as (table, column,
/// type): a cache from an earlier release gains them here. Only additions,
/// never a rename or a type change (the contract's schema rule).
const ADDED: &[(&str, &str, &str)] = &[
    ("findings", "dep_scope", "TEXT"),
    ("findings", "dep_direct", "INTEGER"),
    ("findings", "affected_range", "TEXT"),
    ("exposures", "dep_scope", "TEXT"),
    ("exposures", "dep_direct", "INTEGER"),
    ("exposures", "affected_range", "TEXT"),
    ("exposures", "fix_cmd", "TEXT"),
    ("fixes", "targets", "TEXT"),
    ("scans", "unchecked", "INTEGER"),
    ("scans", "checked", "TEXT"),
    ("scans", "unfixed", "INTEGER"),
    ("scans", "unknown_licenses", "INTEGER"),
    ("scans", "options", "TEXT"),
    ("fixes", "user", "TEXT"),
    ("findings", "cvss", "REAL"),
    ("findings", "cvss_version", "TEXT"),
    ("findings", "epss", "REAL"),
    ("findings", "epss_percentile", "REAL"),
    ("exposures", "cvss", "REAL"),
    ("exposures", "cvss_version", "TEXT"),
    ("exposures", "epss", "REAL"),
    ("exposures", "epss_percentile", "REAL"),
    ("fixes", "host", "TEXT"),
];

fn migrate(conn: &Connection) -> Result<()> {
    for (table, column, kind) in ADDED {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let have: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        if !have.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"))?;
        }
    }
    Ok(())
}

/// WPANTRY_DB, else $XDG_CACHE_HOME/wpantry/wpantry.db, else
/// ~/.cache/wpantry/wpantry.db. The malicious-packages clone sits beside it.
pub fn path() -> PathBuf {
    path_from(&|k| std::env::var_os(k))
}

fn path_from(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(p) = var("WPANTRY_DB") {
        return p;
    }
    let base = var("XDG_CACHE_HOME").unwrap_or_else(|| var("HOME").unwrap_or_default().join(".cache"));
    base.join("wpantry").join("wpantry.db")
}

pub struct Cache {
    pub conn: Connection,
    /// Whether SQLite has FTS5 (the bundled one does).
    pub fts: bool,
    file: PathBuf,
}

impl Cache {
    /// Open (creating) the cache at `file`, or at [`path`]. Writes are
    /// batched in a transaction until [`Cache::commit`] or
    /// [`Cache::close`], as Python's sqlite3 does; dropping a cache without
    /// closing it discards what wasn't committed.
    pub fn open(file: Option<&Path>) -> Result<Cache> {
        let file = file.map(Path::to_path_buf).unwrap_or_else(path);
        if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir)?;
        }
        let conn = Connection::open(&file)?;
        // The cache names what is installed and where secrets sit: ours only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
        }
        // Readers and the writer coexist (a scheduled scan beside a manual
        // one), and a minute of waiting beats failing a scan outright.
        conn.busy_timeout(std::time::Duration::from_secs(60))?;
        let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(crate::history::SCHEMA)?;
        conn.execute_batch(crate::reporters::SCHEMA)?;
        conn.execute_batch(crate::checks::malware::SCHEMA)?;
        conn.execute_batch(crate::checks::files::cache::SCHEMA)?;
        conn.execute_batch(crate::sources::fetch::SCHEMA)?;
        conn.execute_batch(crate::sources::epss::SCHEMA)?;
        conn.execute_batch(crate::sources::cve_scores::SCHEMA)?;
        conn.execute_batch(crate::checks::malware::rulegen::SCHEMA)?;
        conn.execute_batch(crate::sources::hash_lookups::VERDICT_SCHEMA)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS queries_checked_at ON queries(checked_at);\
             CREATE INDEX IF NOT EXISTS vulns_modified ON vulns(modified);",
        )?;
        migrate(&conn)?;
        let fts = conn
            .execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS vulns_fts USING fts5(\
                 id, aliases, summary, details, packages, tokenize='porter')",
            )
            .is_ok();
        conn.execute_batch("BEGIN")?;
        Ok(Cache { conn, fts, file })
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT; BEGIN")?;
        Ok(())
    }

    /// Commit and close, keeping what this process's source fetches came to
    /// ([`crate::sources::fetch::save`]).
    pub fn close(self) -> Result<()> {
        crate::sources::fetch::save(&self)?;
        self.conn.execute_batch("COMMIT")?;
        self.conn.close().map_err(|(_, e)| Error::Cache(e))
    }

    // meta ------------------------------------------------------------------

    pub fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?", [key], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", [key, value])?;
        Ok(())
    }

    pub fn unset(&self, key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM meta WHERE key = ?", [key])?;
        Ok(())
    }

    pub fn fresh(&self, key: &str, max_age: f64) -> Result<bool> {
        Ok(match self.get(key)? {
            Some(stamp) => stamp.trim().parse::<f64>().is_ok_and(|t| now() - t < max_age),
            None => false,
        })
    }

    pub fn touch(&self, key: &str) -> Result<()> {
        self.set(key, &now().to_string())
    }

    // OSV records -----------------------------------------------------------

    pub fn modified(&self, vuln_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT modified FROM vulns WHERE id = ?", [vuln_id], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    pub fn put_vuln(&self, rec: &Value) -> Result<()> {
        let vid = crate::utils::json::str_at(rec, "id");
        let aliases = crate::utils::json::strs_at(rec, "aliases").join(" ");
        let mut packages: Vec<&str> = crate::utils::json::arr_at(rec, "affected")
            .iter()
            .map(|a| a.get("package").map(|p| crate::utils::json::str_at(p, "name")).unwrap_or(""))
            .collect();
        packages.sort_unstable();
        packages.dedup();
        let summary = crate::utils::json::str_at(rec, "summary");
        let details = crate::utils::json::str_at(rec, "details");
        self.conn.execute(
            "INSERT OR REPLACE INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                vid,
                aliases,
                summary,
                details,
                severity_of(rec),
                crate::utils::json::str_at(rec, "published"),
                crate::utils::json::str_at(rec, "modified"),
                format!("https://osv.dev/vulnerability/{vid}"),
                rec.to_string(),
            ],
        )?;
        if self.fts {
            self.conn.execute("DELETE FROM vulns_fts WHERE id = ?", [vid])?;
            self.conn.execute(
                "INSERT INTO vulns_fts VALUES (?, ?, ?, ?, ?)",
                params![vid, aliases, summary, details, packages.join(" ")],
            )?;
        }
        Ok(())
    }

    pub fn vuln(&self, vuln_id: &str) -> Result<Option<Value>> {
        let row: Option<Option<String>> =
            self.conn.query_row("SELECT record FROM vulns WHERE id = ?", [vuln_id], |r| r.get(0)).optional()?;
        // A record another writer left unreadable is as good as missing.
        Ok(row.flatten().and_then(|s| serde_json::from_str(&s).ok()))
    }

    // package queries -------------------------------------------------------

    /// (checked_at, space-separated advisory ids) for one package version.
    pub fn query(&self, eco: &str, pkg: &str, ver: &str) -> Result<Option<(f64, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT checked_at, vuln_ids FROM queries WHERE ecosystem=? AND package=? AND version=?",
                [eco, pkg, ver],
                |r| {
                    Ok((r.get::<_, Option<f64>>(0)?.unwrap_or(0.0), r.get::<_, Option<String>>(1)?.unwrap_or_default()))
                },
            )
            .optional()?)
    }

    /// Every (ecosystem, package, version) ever asked of OSV.
    pub fn queried(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare("SELECT ecosystem, package, version FROM queries ORDER BY 1, 2, 3")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<Vec<(Option<String>, Option<String>, Option<String>)>>>()?;
        Ok(rows
            .into_iter()
            .map(|(e, p, v)| (e.unwrap_or_default(), p.unwrap_or_default(), v.unwrap_or_default()))
            .filter(|(e, p, _)| !e.is_empty() && !p.is_empty())
            .collect())
    }

    /// Every product with end-of-life rows.
    pub fn eol_products(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT product FROM eol ORDER BY 1")?;
        let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().flatten().collect())
    }

    /// Drop what a scan hasn't touched in `max_age` seconds: package
    /// versions not asked about since then (and the advisories only they
    /// referred to), cached runs that old, then compact the file. Returns
    /// (queries, vulns, runs) removed.
    pub fn prune(&self, max_age: f64) -> Result<(usize, usize, usize)> {
        let cutoff = now() - max_age;
        let queries = self.conn.execute("DELETE FROM queries WHERE checked_at < ?", [cutoff])?;
        let runs = self.conn.execute("DELETE FROM runs WHERE ran_at < ?", [cutoff])?;
        let mut keep: HashSet<String> = HashSet::new();
        {
            let mut stmt = self.conn.prepare("SELECT vuln_ids FROM queries")?;
            for ids in stmt.query_map([], |r| r.get::<_, Option<String>>(0))?.flatten().flatten() {
                keep.extend(ids.split_whitespace().map(str::to_string));
            }
            let mut stmt = self.conn.prepare("SELECT vuln_id FROM findings")?;
            keep.extend(stmt.query_map([], |r| r.get::<_, Option<String>>(0))?.flatten().flatten());
        }
        let mut gone: Vec<String> = Vec::new();
        {
            let mut stmt = self.conn.prepare("SELECT id, aliases FROM vulns")?;
            for row in stmt.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)))? {
                let (id, aliases) = row?;
                let Some(id) = id else { continue };
                let referenced =
                    keep.contains(&id) || aliases.as_deref().unwrap_or("").split_whitespace().any(|a| keep.contains(a));
                if !referenced {
                    gone.push(id);
                }
            }
        }
        for id in &gone {
            self.conn.execute("DELETE FROM vulns WHERE id = ?", [id])?;
            if self.fts {
                let _ = self.conn.execute("DELETE FROM vulns_fts WHERE id = ?", [id]);
            }
        }
        self.conn.execute_batch("COMMIT; VACUUM; BEGIN")?;
        Ok((queries, gone.len(), runs))
    }

    /// [`Cache::put_query`] keeping the time the answer was given: a change
    /// applied from OSV's change list updates the answer, not its age.
    pub fn put_query_at(&self, eco: &str, pkg: &str, ver: &str, ids: &[String], at: f64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO queries VALUES (?, ?, ?, ?, ?)",
            params![eco, pkg, ver, at, ids.join(" ")],
        )?;
        Ok(())
    }

    pub fn put_query(&self, eco: &str, pkg: &str, ver: &str, ids: &[String]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO queries VALUES (?, ?, ?, ?, ?)",
            params![eco, pkg, ver, now(), ids.join(" ")],
        )?;
        Ok(())
    }

    // persistence baseline -------------------------------------------------

    /// The keys a source's persistence items had at the last scan that read
    /// it; None before the first.
    pub fn persistence_baseline(&self, source: &str) -> Result<Option<HashSet<String>>> {
        if self.get(&format!("persistence_at:{source}"))?.is_none() {
            return Ok(None);
        }
        let mut stmt = self.conn.prepare("SELECT key FROM persistence WHERE source = ?")?;
        let keys =
            stmt.query_map([source], |r| r.get::<_, Option<String>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(keys.into_iter().flatten().collect()))
    }

    /// Record what a source holds now, as (key, location, program): items
    /// seen again keep when they were first seen, items gone are dropped.
    pub fn persistence_record(&self, source: &str, items: &[(String, String, String)], at: f64) -> Result<()> {
        for (key, location, program) in items {
            self.conn.execute(
                "INSERT INTO persistence VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET location = excluded.location, program = excluded.program, last_at = excluded.last_at",
                params![key, source, location, program, at, at],
            )?;
        }
        self.conn.execute("DELETE FROM persistence WHERE source = ? AND last_at < ?", params![source, at])?;
        self.set(&format!("persistence_at:{source}"), &at.to_string())
    }

    // cached source runs (gitleaks, feeds, tags) ----------------------------

    /// (fingerprint, ran_at, result) for a source.
    pub fn run(&self, source: &str) -> Result<Option<(String, f64, Value)>> {
        let row: Option<(Option<String>, Option<f64>, Option<String>)> = self
            .conn
            .query_row("SELECT fingerprint, ran_at, result FROM runs WHERE source=?", [source], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        Ok(row.and_then(|(fp, at, res)| {
            let res = serde_json::from_str(&res?).ok()?;
            Some((fp.unwrap_or_default(), at.unwrap_or(0.0), res))
        }))
    }

    pub fn put_run(&self, source: &str, fingerprint: &str, result: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)",
            params![source, fingerprint, now(), result.to_string()],
        )?;
        Ok(())
    }

    /// compute()'s result, cached under `key`. Reused while fresh and the
    /// fingerprint of what it read still matches; reused stale, for the same
    /// fingerprint only, when offline or when compute fails as a source (a
    /// result for other input says nothing about this one); otherwise
    /// `Offline`, so the caller reports the source unchecked rather than
    /// clean. Failures are never cached.
    pub fn memo(
        &self,
        key: &str,
        compute: impl FnOnce() -> Result<Value>,
        max_age: f64,
        fingerprint: &str,
        refresh: bool,
        offline: bool,
    ) -> Result<Value> {
        let run = self.run(key)?.filter(|(fp, _, _)| fp == fingerprint);
        // A timestamp in the future is not fresh: an edited cache can't make
        // a result permanent.
        if let Some((_, at, res)) = &run
            && !refresh
            && (offline || (*at > now() - max_age && *at <= now() + CLOCK_SKEW))
        {
            return Ok(res.clone());
        }
        if offline {
            return Err(Error::Offline(format!("{key}: offline and not cached")));
        }
        match compute() {
            Ok(result) => {
                self.put_run(key, fingerprint, &result)?;
                self.commit()?;
                Ok(result)
            }
            Err(e @ (Error::Offline(_) | Error::Invalid(_))) => match run {
                Some((_, _, res)) => Ok(res),
                None => Err(Error::Offline(format!("{key}: {e}"))),
            },
            Err(e) => Err(e),
        }
    }

    // findings --------------------------------------------------------------

    pub fn replace_findings(&self, findings: &[Finding]) -> Result<()> {
        self.conn.execute("DELETE FROM findings", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed, kev, severity, note, \
             fix_cmd, fix_auto, dep_scope, dep_direct, affected_range, cvss, cvss_version, epss, epss_percentile) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )?;
        for f in findings {
            stmt.execute(params![
                f.kind,
                f.component,
                f.version,
                f.location,
                f.vuln_id,
                f.status,
                f.fixed,
                f.kev as i64,
                f.severity,
                f.note,
                f.fix_cmd,
                f.fix_auto as i64,
                f.dep_scope,
                f.dep_direct.map(i64::from),
                f.affected_range,
                f.cvss,
                f.cvss_version,
                f.epss,
                f.epss_percentile
            ])?;
        }
        Ok(())
    }

    pub fn kev_ids(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT cve FROM kev")?;
        let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?;
        let mut out = HashSet::new();
        for r in rows {
            if let Some(id) = r? {
                out.insert(id);
            }
        }
        Ok(out)
    }
}

/// A record's severity in CVSS's words (LOW, MEDIUM, HIGH, CRITICAL): its
/// own label when it carries one, else from its CVSS 3.x or 4.0 vector,
/// else empty.
pub fn severity_of(rec: &Value) -> String {
    if let Some(v) = severity_label_of(rec).map(|l| crate::utils::cvss::word(&l)).filter(|w| !w.is_empty()) {
        return v.to_string();
    }
    crate::utils::cvss::of_record(rec).map(|s| crate::utils::cvss::label(s.value).to_string()).unwrap_or_default()
}

fn severity_label_of(rec: &Value) -> Option<String> {
    if let Some(label) = rec.get("database_specific").and_then(|d| d.get("severity")).and_then(Value::as_str)
        && !label.is_empty()
    {
        return Some(label.to_uppercase());
    }
    for a in crate::utils::json::arr_at(rec, "affected") {
        if let Some(label) = a.get("ecosystem_specific").and_then(|d| d.get("severity")).and_then(Value::as_str)
            && !label.is_empty()
        {
            return Some(label.to_uppercase());
        }
    }
    None
}

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;
