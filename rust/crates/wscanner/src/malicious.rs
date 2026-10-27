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

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, arr_at};
use crate::net::{self, Net};
use crate::system::exec;
use crate::versions::lt;
use rusqlite::params;
use serde_json::{Value, json};
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

fn norm(eco: &str, name: &str) -> String {
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

/// The malicious-package reports that cover this package at this version
/// (any version when `version` is ""), fetched and cached on first use.
pub fn reports(cache: &Cache, net: &dyn Net, eco: &str, name: &str, version: &str) -> Result<Vec<Value>> {
    let Some(dir) = dir_for(eco) else { return Ok(Vec::new()) };
    let ids: Vec<String> = {
        let mut stmt = cache.conn.prepare("SELECT id FROM malicious WHERE ecosystem = ? AND name = ?")?;
        stmt.query_map(params![dir, norm(eco, name)], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<_>>()?
    };
    let mut out = Vec::new();
    for id in ids {
        let rec = match cache.vuln(&id)? {
            Some(r) => Some(r),
            None => {
                let rec = match net::get_json(net, &format!("https://api.osv.dev/v1/vulns/{id}"), &[]) {
                    Ok(r) => r,
                    Err(e) if e.is_source() => {
                        Some(json!({"id": id, "summary": format!("Malicious code in {name} ({eco})"), "affected": []}))
                    }
                    Err(e) => return Err(e),
                };
                if let Some(r) = &rec {
                    cache.put_vuln(r)?;
                }
                rec
            }
        };
        if let Some(r) = rec
            && (version.is_empty() || applies(&r, version))
        {
            out.push(r);
        }
    }
    Ok(out)
}

/// Whether `version` is among those a report covers (every version when
/// the report lists no ranges or versions).
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
        for r in arr_at(a, "ranges") {
            let ev = arr_at(r, "events");
            let first = |k: &str| ev.iter().find_map(|e| e.get(k).and_then(Value::as_str)).map(str::to_string);
            let intro = first("introduced").unwrap_or_else(|| "0".into());
            let fixed = first("fixed").unwrap_or_default();
            let last = first("last_affected").unwrap_or_default();
            if (intro == "0" || !lt(version, &intro))
                && (fixed.is_empty() || lt(version, &fixed))
                && (last.is_empty() || !lt(&last, version))
            {
                return true;
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
        let ids = |v: Vec<Value>| v.iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids(reports(&c, &net, "PyPI", "Evil_Pkg", "").unwrap()), ["MAL-1"]);
        assert_eq!(ids(reports(&c, &net, "npm", "@bad/scope", "1.0.0").unwrap()), ["MAL-2"]);
        assert!(reports(&c, &net, "npm", "@bad/scope", "2.0.0").unwrap().is_empty());
        assert_eq!(norm("PyPI", "Foo__Bar.baz"), "foo-bar-baz");
    }

    #[test]
    fn offline_without_an_index_is_unchecked() {
        let d = crate::system::TempDir::new("mal").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        assert!(matches!(sync(&c, true), Err(Error::Offline(_))));
    }
}
