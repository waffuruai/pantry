//! The OpenSSF malicious-packages index: a blob-less clone of
//! github.com/ossf/malicious-packages beside the cache, kept current with
//! `git fetch`, its report paths (osv/malicious/<ecosystem>/<package>/MAL-….json)
//! read into the cache as names. Works offline once cloned.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::utils::process::exec;
use rusqlite::params;
use std::ffi::OsStr;
use std::time::Duration;

pub const REPO: &str = "https://github.com/ossf/malicious-packages.git";

/// The index's directory for an OSV ecosystem.
pub(crate) fn dir_for(eco: &str) -> Option<&'static str> {
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

/// A clone of the index beside `db` whose origin is a local repository
/// holding `files` (paths under osv/malicious), so [`sync`] fetches from
/// disk; the origin's path, for adding to it.
#[cfg(test)]
pub(crate) fn seed_clone(db: &std::path::Path, files: &[&str]) -> std::path::PathBuf {
    let parent = db.parent().expect("a cache file has a directory");
    let origin = parent.join("origin");
    let sh = |dir: &std::path::Path, args: &[&str]| {
        let mut argv = vec![OsStr::new("git"), OsStr::new("-C"), dir.as_os_str()];
        argv.extend(args.iter().map(OsStr::new));
        let out = exec(&argv, &[("GIT_TERMINAL_PROMPT", "0")], Duration::from_secs(60)).expect("git runs");
        assert_eq!(out.code, Some(0), "git {args:?}: {}", out.stderr);
    };
    std::fs::create_dir_all(&origin).unwrap();
    sh(&origin, &["init", "-q"]);
    for f in files {
        let p = origin.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "{}").unwrap();
    }
    sh(&origin, &["add", "-A"]);
    sh(&origin, &["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "commit", "-qm", "index"]);
    let clone = parent.join("malicious-packages");
    std::fs::create_dir_all(&clone).unwrap();
    sh(&clone, &["init", "-q"]);
    sh(&clone, &["remote", "add", "origin", origin.to_str().unwrap()]);
    origin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_is_fetched_from_the_clone_beside_the_cache() {
        let d = crate::utils::temp::TempDir::new("mal").unwrap();
        let db = d.path().join("w.db");
        let c = Cache::open(Some(&db)).unwrap();
        seed_clone(
            &db,
            &[
                "osv/malicious/npm/evil/MAL-2026-1.json",
                "osv/malicious/npm/@scope/Pkg/MAL-2026-2.json",
                "osv/malicious/pypi/evil-pkg/MAL-2026-3.json",
                "osv/malicious/npm/README.md",
                "osv/malicious/npm/evil/notes.txt",
            ],
        );
        assert_eq!(sync(&c, false).unwrap(), 3);
        let rows = |c: &Cache| -> Vec<(String, String, String)> {
            let mut st = c.conn.prepare("SELECT ecosystem, name, id FROM malicious ORDER BY 3").unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            rows(&c),
            [
                ("npm".to_string(), "evil".to_string(), "MAL-2026-1".to_string()),
                ("npm".into(), "@scope/pkg".into(), "MAL-2026-2".into()),
                ("pypi".into(), "evil-pkg".into(), "MAL-2026-3".into()),
            ]
        );
        // Fresh, or offline: the index is reused without a fetch.
        assert_eq!(sync(&c, false).unwrap(), 3);
        assert_eq!(sync(&c, true).unwrap(), 3);
        // Stale and the fetch fails: the old index stands.
        c.set("malicious_at", "0").unwrap();
        std::fs::remove_dir_all(d.path().join("origin")).unwrap();
        assert_eq!(sync(&c, false).unwrap(), 3);
        c.conn.execute("DELETE FROM malicious", []).unwrap();
        assert!(matches!(sync(&c, false), Err(Error::Offline(m)) if m.contains(REPO)));
    }

    #[test]
    fn offline_without_an_index_is_unchecked() {
        let d = crate::utils::temp::TempDir::new("mal").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        assert!(matches!(sync(&c, true), Err(Error::Offline(_))));
    }
}
