//! A local index of every known malicious package name, from the OpenSSF
//! malicious-packages repo (npm, PyPI, RubyGems, NuGet, crates, Go, Maven,
//! Packagist, VS Code and Open VSX extensions).
//!
//! The repo lays reports out as osv/malicious/<ecosystem>/<package>/MAL-….json,
//! so a blob-less clone gives every name without downloading a single
//! report; `git fetch` keeps it current. A name match fetches just that
//! report, to check whether the version here is affected. This is what
//! catches packages known only by name (an unpinned `npx some-mcp-server`)
//! and keeps working offline.

use crate::compare::Comparator;
use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, arr_at};
use crate::net::{self, Net};
use crate::system::exec;
use rusqlite::params;
use serde_json::Value;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::time::Duration;

pub const REPO: &str = "https://github.com/ossf/malicious-packages.git";

/// The index's directory for an OSV ecosystem.
fn dir_for(eco: &str) -> Option<&'static str> {
    Some(match eco {
        "npm" => "npm",
        "PyPI" => "pypi",
        "RubyGems" => "rubygems",
        "crates.io" => "crates.io",
        "Go" => "go",
        "NuGet" => "nuget",
        "Maven" => "maven",
        "Packagist" => "packagist",
        "VSCode" => "vscode",
        "VSCode:https://open-vsx.org" => "vscode:open-vsx.org",
        _ => return None,
    })
}

/// A package name as the index keys it (PyPI: PEP 503).
pub fn norm(eco: &str, name: &str) -> String {
    if eco != "PyPI" {
        return name.to_lowercase();
    }
    // PEP 503: runs of -, _ and . are one -.
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep {
                out.push('-');
                sep = false;
            }
            out.push(c.to_ascii_lowercase());
        }
    }
    if sep {
        out.push('-');
    }
    out
}

fn git(args: &[&OsStr], timeout: u64) -> Result<String> {
    let mut argv: Vec<&OsStr> = vec![OsStr::new("git")];
    argv.extend_from_slice(args);
    let out = exec(&argv, &[("GIT_TERMINAL_PROMPT", "0")], Duration::from_secs(timeout))
        .map_err(|e| Error::Offline(e.to_string()))?;
    if out.code != Some(0) {
        return Err(Error::Offline(format!("couldn't fetch {REPO}: {}", out.stderr.trim())));
    }
    Ok(out.stdout)
}

/// Refresh the index at most daily; the number of reports indexed. Offline
/// only when it can't be refreshed and there is no earlier index.
pub fn sync(cache: &Cache, offline: bool) -> Result<i64> {
    let have: i64 = cache.conn.query_row("SELECT COUNT(*) FROM malicious", [], |r| r.get(0))?;
    if have > 0 && (offline || cache.fresh("malicious_at", DAY)?) {
        return Ok(have);
    }
    if offline {
        return Err(Error::Offline("the malicious-package index is offline and not cached".into()));
    }
    let clone =
        cache.file().parent().map(|p| p.join("malicious-packages")).unwrap_or_else(|| "malicious-packages".into());
    let c = clone.as_os_str();
    let fetched = if clone.join(".git").exists() {
        git(
            &[
                OsStr::new("-C"),
                c,
                "fetch".as_ref(),
                "-q".as_ref(),
                "--depth".as_ref(),
                "1".as_ref(),
                "--filter=blob:none".as_ref(),
                "origin".as_ref(),
                "HEAD".as_ref(),
            ],
            300,
        )
        .map(|_| "FETCH_HEAD")
    } else {
        git(
            &[
                "clone".as_ref(),
                "-q".as_ref(),
                "--filter=blob:none".as_ref(),
                "--no-checkout".as_ref(),
                "--depth".as_ref(),
                "1".as_ref(),
                REPO.as_ref(),
                c,
            ],
            300,
        )
        .map(|_| "HEAD")
    };
    let listing = fetched.and_then(|r#ref| {
        git(
            &[
                OsStr::new("-C"),
                c,
                "ls-tree".as_ref(),
                "-r".as_ref(),
                "--name-only".as_ref(),
                r#ref.as_ref(),
                "osv/malicious".as_ref(),
            ],
            120,
        )
    });
    let listing = match listing {
        Ok(l) => l,
        Err(_) if have > 0 => return Ok(have),
        Err(e) => return Err(e),
    };
    let mut rows = Vec::new();
    for path in listing.lines() {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 5 && parts[parts.len() - 1].starts_with("MAL-") {
            let file = parts[parts.len() - 1];
            let name = parts[3..parts.len() - 1].join("/"); // npm scopes add a level: @scope/name
            rows.push((
                parts[2].to_string(),
                name.to_lowercase(),
                file.strip_suffix(".json").unwrap_or(file).to_string(),
            ));
        }
    }
    cache.conn.execute("DELETE FROM malicious", [])?;
    {
        let mut stmt = cache.conn.prepare("INSERT INTO malicious VALUES (?, ?, ?)")?;
        for (e, n, i) in &rows {
            stmt.execute(params![e, n, i])?;
        }
    }
    cache.touch("malicious_at")?;
    cache.commit()?;
    Ok(rows.len() as i64)
}

/// What the index says about one package: the reports that cover this
/// version, and the ids whose report couldn't be read (offline, or the fetch
/// failed), so whether they cover it is unknown.
#[derive(Debug, Default, PartialEq)]
pub struct Reports {
    pub matched: Vec<Value>,
    pub unknown: Vec<String>,
}

/// The malicious-package reports that cover this package at this version
/// (any version when `version` is ""), fetched and cached on first use. Only
/// a report OSV actually served is cached; one that couldn't be fetched is
/// `unknown`, and asked again next time.
pub fn reports(cache: &Cache, net: &dyn Net, eco: &str, name: &str, version: &str, offline: bool) -> Result<Reports> {
    let Some(dir) = dir_for(eco) else { return Ok(Reports::default()) };
    let ids: Vec<String> = {
        let mut stmt = cache.conn.prepare("SELECT id FROM malicious WHERE ecosystem = ? AND name = ?")?;
        stmt.query_map(params![dir, norm(eco, name)], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<_>>()?
    };
    let mut out = Reports::default();
    for id in ids {
        let rec = match cache.vuln(&id)? {
            Some(r) => r,
            None if offline => {
                out.unknown.push(id);
                continue;
            }
            None => match net::get_json(net, &format!("https://api.osv.dev/v1/vulns/{id}"), &[]) {
                Ok(Some(r)) if json::str_at(&r, "id") == id => {
                    cache.put_vuln(&r)?;
                    r
                }
                Ok(_) => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) if e.is_source() => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        if version.is_empty() || applies(&rec, version) {
            out.matched.push(rec);
        }
    }
    Ok(out)
}

/// Whether `version` is among those a report covers: listed in `versions`,
/// or inside any of a range's intervals (each `introduced` up to the next
/// `fixed` or `limit`, exclusive, or `last_affected`, inclusive), compared
/// in the package's ecosystem's order. A report listing no ranges or
/// versions covers every version.
pub fn applies(rec: &Value, version: &str) -> bool {
    let affected = arr_at(rec, "affected");
    if affected.is_empty() {
        return true;
    }
    for a in affected {
        let versions = json::strs_at(a, "versions");
        if versions.iter().any(|v| v == version) {
            return true;
        }
        let eco = a.get("package").map(|p| json::str_at(p, "ecosystem")).unwrap_or("");
        let order = Comparator::for_ecosystem(eco);
        let lt = |x: &str, y: &str| order.cmp(x, y) == Ordering::Less;
        for r in arr_at(a, "ranges") {
            let mut start: Option<&str> = None;
            for e in arr_at(r, "events") {
                let at = |k: &str| e.get(k).and_then(Value::as_str);
                if let Some(intro) = at("introduced") {
                    start = Some(intro);
                } else if let Some(intro) = start {
                    let from = intro == "0" || !lt(version, intro);
                    let inside = match (at("fixed").or(at("limit")), at("last_affected")) {
                        (Some(end), _) => lt(version, end),
                        (None, Some(last)) => !lt(last, version),
                        (None, None) => continue,
                    };
                    if from && inside {
                        return true;
                    }
                    start = None;
                }
            }
            if let Some(intro) = start
                && (intro == "0" || !lt(version, intro))
            {
                return true; // introduced, never fixed
            }
        }
        if versions.is_empty() && arr_at(a, "ranges").is_empty() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Fake;
    use serde_json::json;

    #[test]
    fn applies_to_versions_and_ranges() {
        let every = json!({"affected": [{"package": {"name": "x"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]});
        let some = json!({"affected": [{"package": {"name": "chalk"}, "versions": ["5.6.1"]}]});
        assert!(applies(&every, "1.0.0"));
        assert!(applies(&some, "5.6.1"));
        assert!(!applies(&some, "5.6.2"));
        assert!(applies(&json!({"affected": []}), "1.0.0"));
    }

    #[test]
    fn index_lookup_normalises_names() {
        let d = crate::system::TempDir::new("mal").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        for (e, n, i) in [("pypi", "evil-pkg", "MAL-1"), ("npm", "@bad/scope", "MAL-2")] {
            c.conn.execute("INSERT INTO malicious VALUES (?, ?, ?)", params![e, n, i]).unwrap();
        }
        c.put_vuln(&json!({"id": "MAL-1", "summary": "Malicious code in evil_pkg", "affected": []})).unwrap();
        c.put_vuln(&json!({"id": "MAL-2", "affected": [{"versions": ["1.0.0"]}]})).unwrap();
        let net = Fake::offline();
        let ids = |r: Reports| r.matched.iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids(reports(&c, &net, "PyPI", "Evil_Pkg", "", false).unwrap()), ["MAL-1"]);
        assert_eq!(ids(reports(&c, &net, "npm", "@bad/scope", "1.0.0", false).unwrap()), ["MAL-2"]);
        assert_eq!(reports(&c, &net, "npm", "@bad/scope", "2.0.0", false).unwrap(), Reports::default());
        assert_eq!(norm("PyPI", "Foo__Bar.baz"), "foo-bar-baz");
    }

    #[test]
    fn every_interval_counts() {
        let rec = json!({"affected": [{"package": {"ecosystem": "crates.io", "name": "x"}, "ranges": [{"type": "SEMVER",
            "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]}]});
        for (v, want) in [
            ("0.9.0", false),
            ("1.0.0", true),
            ("1.1.0", false),
            ("1.5.0", false),
            ("2.0.0", true),
            ("2.0.9", true),
            ("2.1.0", false),
        ] {
            assert_eq!(applies(&rec, v), want, "{v}");
        }
        let last = json!({"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER",
            "events": [{"introduced": "0"}, {"last_affected": "1.2.0"}, {"introduced": "3.0.0"}]}]}]});
        for (v, want) in [("1.2.0", true), ("1.2.1", false), ("2.9.9", false), ("3.0.0", true), ("9.0.0", true)] {
            assert_eq!(applies(&last, v), want, "{v}");
        }
        // The ecosystem's own order: PEP 440 puts 1.0rc1 before 1.0.
        let py = json!({"affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": [{"type": "ECOSYSTEM",
            "events": [{"introduced": "1.0"}]}]}]});
        assert!(!applies(&py, "1.0rc1"));
        assert!(applies(&py, "1.0.post1"));
    }

    #[test]
    fn an_unread_report_is_unknown_never_assumed_and_never_cached() {
        let d = crate::system::TempDir::new("mal").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        c.conn.execute("INSERT INTO malicious VALUES ('crates.io', 'evil', 'MAL-9')", []).unwrap();
        let unknown = Reports { matched: vec![], unknown: vec!["MAL-9".into()] };
        // Offline: no request at all.
        let no_calls = Fake::new(|_| panic!("offline must not fetch"));
        assert_eq!(reports(&c, &no_calls, "crates.io", "evil", "9.9.0", true).unwrap(), unknown);
        // Online, the fetch fails or OSV serves something that isn't the record.
        assert_eq!(reports(&c, &Fake::offline(), "crates.io", "evil", "9.9.0", false).unwrap(), unknown);
        let wrong = Fake::new(|_| Ok(crate::net::Response::ok("{}")));
        assert_eq!(reports(&c, &wrong, "crates.io", "evil", "9.9.0", false).unwrap(), unknown);
        assert_eq!(c.vuln("MAL-9").unwrap(), None, "nothing invented was cached");
        // Once OSV answers, the real ranges decide.
        let rec = json!({"id": "MAL-9", "affected": [{"package": {"ecosystem": "crates.io", "name": "evil"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}]}]}]});
        let body = rec.to_string();
        let good = Fake::new(move |_| Ok(crate::net::Response::ok(body.clone())));
        assert_eq!(reports(&c, &good, "crates.io", "evil", "9.9.0", false).unwrap(), Reports::default());
        assert_eq!(good.requests().len(), 1);
        assert_eq!(reports(&c, &no_calls, "crates.io", "evil", "1.0.5", true).unwrap().matched, [rec]);
    }

    #[test]
    fn offline_without_an_index_is_unchecked() {
        let d = crate::system::TempDir::new("mal").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        assert!(matches!(sync(&c, true), Err(Error::Offline(_))));
    }
}
