//! The local cache: one SQLite file per machine, the same schema the Python
//! implementation reads and writes (`specs/cli-contract.md#cache-sqlite`), so
//! switching implementation keeps the cache.
//!
//! It holds OSV records for what this machine has (never a mirror of OSV),
//! the answers to "which advisories affect package P at version V" with when
//! we last asked, the latest scan's findings, and the small side feeds. A
//! full-text index over the records lets agents search them.

use crate::check::Finding;
use crate::error::{Error, Result};
use crate::system::now;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const DAY: f64 = 86400.0;

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
  fix_auto INTEGER);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, added TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS eol (
  product TEXT, cycle TEXT, eol TEXT, latest TEXT, PRIMARY KEY (product, cycle));
CREATE TABLE IF NOT EXISTS casks (app TEXT PRIMARY KEY, token TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS runs (
  source TEXT PRIMARY KEY, fingerprint TEXT, ran_at REAL, result TEXT);
CREATE TABLE IF NOT EXISTS malicious (ecosystem TEXT, name TEXT, id TEXT);
CREATE INDEX IF NOT EXISTS malicious_name ON malicious (ecosystem, name);
";

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
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(&file)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(crate::history::SCHEMA)?;
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

    pub fn close(self) -> Result<()> {
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
        let vid = crate::json::str_at(rec, "id");
        let aliases = crate::json::strs_at(rec, "aliases").join(" ");
        let mut packages: Vec<&str> = crate::json::arr_at(rec, "affected")
            .iter()
            .map(|a| a.get("package").map(|p| crate::json::str_at(p, "name")).unwrap_or(""))
            .collect();
        packages.sort_unstable();
        packages.dedup();
        let summary = crate::json::str_at(rec, "summary");
        let details = crate::json::str_at(rec, "details");
        self.conn.execute(
            "INSERT OR REPLACE INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                vid,
                aliases,
                summary,
                details,
                severity_of(rec),
                crate::json::str_at(rec, "published"),
                crate::json::str_at(rec, "modified"),
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

    pub fn put_query(&self, eco: &str, pkg: &str, ver: &str, ids: &[String]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO queries VALUES (?, ?, ?, ?, ?)",
            params![eco, pkg, ver, now(), ids.join(" ")],
        )?;
        Ok(())
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
        if let Some((_, at, res)) = &run
            && !refresh
            && (offline || *at > now() - max_age)
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
        let mut stmt = self.conn.prepare("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")?;
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
                f.fix_auto as i64
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

/// A label (CRITICAL/HIGH/MODERATE/LOW) when the record carries one, else
/// empty.
pub fn severity_of(rec: &Value) -> String {
    if let Some(label) = rec.get("database_specific").and_then(|d| d.get("severity")).and_then(Value::as_str)
        && !label.is_empty()
    {
        return label.to_uppercase();
    }
    for a in crate::json::arr_at(rec, "affected") {
        if let Some(label) = a.get("ecosystem_specific").and_then(|d| d.get("severity")).and_then(Value::as_str)
            && !label.is_empty()
        {
            return label.to_uppercase();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn temp_cache() -> (crate::system::TempDir, Cache) {
        let dir = crate::system::TempDir::new("db").unwrap();
        let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
        (dir, cache)
    }

    #[test]
    fn schema_matches_the_contract() {
        let (_d, c) = temp_cache();
        assert!(c.fts, "the bundled SQLite has FTS5");
        let cols = |t: &str| -> Vec<String> {
            let mut s = c.conn.prepare(&format!("PRAGMA table_info({t})")).unwrap();
            s.query_map([], |r| r.get::<_, String>(1)).unwrap().map(|r| r.unwrap()).collect()
        };
        assert_eq!(cols("queries"), ["ecosystem", "package", "version", "checked_at", "vuln_ids"]);
        assert_eq!(
            cols("findings"),
            [
                "kind",
                "component",
                "version",
                "location",
                "vuln_id",
                "status",
                "fixed",
                "kev",
                "severity",
                "note",
                "fix_cmd",
                "fix_auto"
            ]
        );
    }

    #[test]
    fn records_queries_and_search() {
        let (_d, c) = temp_cache();
        c.put_vuln(&json!({"id": "GHSA-b", "aliases": ["CVE-1"], "summary": "vite dev server path traversal",
                            "modified": "2026-10-01T00:00:00Z", "database_specific": {"severity": "high"},
                            "affected": [{"package": {"ecosystem": "npm", "name": "vite"}}]}))
            .unwrap();
        assert_eq!(c.modified("GHSA-b").unwrap().as_deref(), Some("2026-10-01T00:00:00Z"));
        assert_eq!(c.vuln("GHSA-b").unwrap().unwrap()["summary"], "vite dev server path traversal");
        let sev: String = c.conn.query_row("SELECT severity FROM vulns", [], |r| r.get(0)).unwrap();
        assert_eq!(sev, "HIGH");
        let hit: String =
            c.conn.query_row("SELECT id FROM vulns_fts WHERE vulns_fts MATCH 'traversal'", [], |r| r.get(0)).unwrap();
        assert_eq!(hit, "GHSA-b");
        c.put_query("npm", "zod", "4.4.3", &[]).unwrap();
        let (at, ids) = c.query("npm", "zod", "4.4.3").unwrap().unwrap();
        assert!(at > now() - 5.0 && ids.is_empty());
    }

    #[test]
    fn memo_reuses_fresh_falls_back_stale_and_never_caches_failures() {
        let (_d, c) = temp_cache();
        let off = || Err(Error::Offline("down".into()));
        assert!(matches!(c.memo("k", off, DAY, "", false, true), Err(Error::Offline(_))));
        assert!(matches!(c.memo("k", off, DAY, "", false, false), Err(Error::Offline(_))));
        assert_eq!(c.memo("k", || Ok(json!([1])), DAY, "fp", false, false).unwrap(), json!([1]));
        assert_eq!(c.memo("k", || panic!("fresh"), DAY, "fp", false, false).unwrap(), json!([1]));
        c.conn.execute("UPDATE runs SET ran_at = 0", []).unwrap();
        assert_eq!(c.memo("k", off, DAY, "fp", false, false).unwrap(), json!([1]), "stale beats nothing");
        assert_eq!(c.memo("k", || panic!("offline"), DAY, "fp", false, true).unwrap(), json!([1]));
        // A result for other input is never reused, offline or not.
        assert!(matches!(c.memo("k", || panic!("offline"), DAY, "other", false, true), Err(Error::Offline(_))));
        assert!(matches!(c.memo("k", off, DAY, "other", false, false), Err(Error::Offline(_))));
        assert_eq!(c.memo("k", || Ok(json!([2])), DAY, "fp", true, false).unwrap(), json!([2]));
    }

    #[test]
    fn cache_location() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| std::ffi::OsString::from(v))
        };
        assert_eq!(path_from(&env(&[("WPANTRY_DB", "/x/w.db"), ("HOME", "/h")])), PathBuf::from("/x/w.db"));
        assert_eq!(
            path_from(&env(&[("XDG_CACHE_HOME", "/x"), ("HOME", "/h")])),
            PathBuf::from("/x/wpantry/wpantry.db")
        );
        assert_eq!(
            path_from(&env(&[("XDG_CACHE_HOME", ""), ("HOME", "/h")])),
            PathBuf::from("/h/.cache/wpantry/wpantry.db")
        );
    }
}
