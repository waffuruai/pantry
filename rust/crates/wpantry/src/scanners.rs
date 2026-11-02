//! `brew vulns` (Homebrew formulae), the one scanner still delegated: it
//! reruns only when the installed formulae change or a day passes.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, arr_at, str_at};
use crate::sha256;
use crate::system::{exec, run, which};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The installed formulae and versions, `name v1 v2` per line, read from the
/// Cellar: the cache key `brew list --versions` gave, without starting
/// Homebrew's Ruby (most of a second). None when there's no Cellar to read.
fn cellar(brew: &Path) -> Option<String> {
    let prefix = crate::system::homebrew_prefix(brew)?;
    let dir = std::env::var_os("HOMEBREW_CELLAR").map(PathBuf::from).unwrap_or_else(|| prefix.join("Cellar"));
    cellar_listing(&dir)
}

fn cellar_listing(dir: &Path) -> Option<String> {
    let mut lines = Vec::new();
    for formula in std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()) {
        let mut versions: Vec<String> = std::fs::read_dir(formula.path())
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|v| !v.starts_with('.'))
            .collect();
        versions.sort();
        lines.push(format!("{} {}", formula.file_name().to_string_lossy(), versions.join(" ")));
    }
    lines.sort();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// `brew vulns --json` findings ({findings, checked}), or None without
/// Homebrew. `Missing` when this Homebrew predates `brew vulns`.
/// A `brew vulns` run that is due: its binary and the Cellar fingerprint
/// its result is cached under. [`brew_job`] makes it on the main thread,
/// [`brew_scan`] may run anywhere (minutes, no cache), [`brew_vulns`]
/// finishes with the cache.
pub struct BrewJob {
    exe: PathBuf,
    fingerprint: String,
    /// Whether the cache has nothing fresh for this fingerprint.
    pub stale: bool,
}

impl BrewJob {
    /// A job over any `brew`, for tests.
    #[cfg(test)]
    pub(crate) fn new(exe: &Path, fingerprint: &str, stale: bool) -> BrewJob {
        BrewJob { exe: exe.to_path_buf(), fingerprint: fingerprint.into(), stale }
    }
}

pub fn brew_job(cache: &Cache, refresh: bool, offline: bool) -> Result<Option<BrewJob>> {
    let Some(exe) = which("brew") else { return Ok(None) };
    let listing = cellar(&exe).unwrap_or_else(|| {
        run(&[exe.as_os_str(), OsStr::new("list"), OsStr::new("--versions")], Duration::from_secs(60))
    });
    let fingerprint = sha256::hex(listing.as_bytes());
    let cached = cache.run("brew-vulns")?.filter(|(fp, _, _)| *fp == fingerprint);
    let stale = !offline && (refresh || !cached.is_some_and(|(_, at, _)| at > crate::system::now() - DAY));
    Ok(Some(BrewJob { exe, fingerprint, stale }))
}

/// `brew vulns --json`, parsed: the slow part, with no cache in hand.
pub fn brew_scan(job: &BrewJob) -> Result<Value> {
    let p = exec(&[job.exe.as_os_str(), OsStr::new("vulns"), OsStr::new("--json")], &[], Duration::from_secs(900))?;
    if p.stderr.contains("Unknown command") || p.stderr.contains("Invalid usage") {
        return Err(Error::Missing("brew vulns (run: brew update)".into()));
    }
    json::parse(p.stdout.as_bytes(), json::MAX_DOCUMENT).map_err(|_| {
        let tail = p.stderr.trim().lines().last().unwrap_or("").to_string();
        Error::Failed(format!("brew vulns failed: {tail}"))
    })
}

/// The `brew vulns` result: cached while the Cellar is unchanged and a day
/// old at most, else `ran` (a [`brew_scan`] made ahead), else a scan now.
pub fn brew_vulns(
    cache: &Cache,
    job: Option<&BrewJob>,
    ran: Option<Result<Value>>,
    refresh: bool,
    offline: bool,
) -> Result<Option<Value>> {
    let Some(job) = job else { return Ok(None) };
    let scan = || -> Result<Value> {
        let data = ran.unwrap_or_else(|| brew_scan(job))?;
        for f in arr_at(&data, "findings") {
            for v in arr_at(f, "vulnerabilities") {
                let id = str_at(v, "id");
                if !id.is_empty() && cache.vuln(id)?.is_none() {
                    cache.put_vuln(&json!({"id": id, "aliases": v.get("aliases").cloned().unwrap_or(json!([])),
                                            "summary": str_at(v, "summary"),
                                            "affected": [{"package": {"ecosystem": "Homebrew", "name": str_at(f, "formula")}}],
                                            "database_specific": {"severity": str_at(v, "severity")}}))?;
                }
            }
        }
        Ok(
            json!({"findings": data.get("findings").cloned().unwrap_or(json!([])), "checked": data.get("checked").cloned().unwrap_or(json!(0))}),
        )
    };
    cache.memo("brew-vulns", scan, DAY, &job.fingerprint, refresh, offline).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cellar_lists_formulae_and_versions() {
        let d = crate::system::TempDir::new("cellar").unwrap();
        for v in ["openssl@3/3.6.0", "openssl@3/3.5.4", "jq/1.8.1", "jq/.DS_Store"] {
            std::fs::create_dir_all(d.path().join("Cellar").join(v)).unwrap();
        }
        assert_eq!(cellar_listing(&d.path().join("Cellar")).as_deref(), Some("jq 1.8.1\nopenssl@3 3.5.4 3.6.0"));
        assert_eq!(cellar_listing(&d.path().join("nowhere")), None);
    }

    fn cache() -> (crate::system::TempDir, Cache) {
        let d = crate::system::TempDir::new("brew").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        (d, c)
    }

    fn result() -> Value {
        json!({"checked": 2, "findings": [
            {"formula": "jq", "version": "1.7", "vulnerabilities": [
                {"id": "GHSA-jq", "aliases": ["CVE-2026-7"], "summary": "jq overflow", "severity": "high", "fixed_versions": ["1.8.1"]},
                {"id": "", "summary": "no id"}]}]})
    }

    #[test]
    fn a_cellar_beside_brew() {
        let d = crate::system::TempDir::new("cellar").unwrap();
        std::fs::create_dir_all(d.path().join("bin")).unwrap();
        std::fs::create_dir_all(d.path().join("Cellar/jq/1.8.1")).unwrap();
        let listing = cellar(&d.path().join("bin/brew"));
        // HOMEBREW_PREFIX or HOMEBREW_CELLAR in the environment point at the
        // real Cellar instead, whatever it holds.
        if std::env::var_os("HOMEBREW_PREFIX").is_none() && std::env::var_os("HOMEBREW_CELLAR").is_none() {
            assert_eq!(listing.as_deref(), Some("jq 1.8.1"));
        }
    }

    #[test]
    fn brew_job_is_nothing_without_brew_and_not_stale_offline() {
        let (_d, c) = cache();
        if let Some(job) = brew_job(&c, false, true).unwrap() {
            assert!(!job.stale, "offline never reruns");
            assert_eq!(job.fingerprint.len(), 64);
            assert!(brew_job(&c, true, false).unwrap().unwrap().stale, "--refresh always does");
        } else {
            assert!(which("brew").is_none());
        }
    }

    #[cfg(unix)]
    fn fake_brew(dir: &Path, stdout: &str, stderr: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let exe = dir.join("brew");
        std::fs::write(&exe, format!("#!/bin/sh\necho '{stdout}'\necho '{stderr}' >&2\nexit 1\n")).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        exe
    }

    #[cfg(unix)]
    #[test]
    fn brew_scan_parses_json_and_reports_old_homebrew() {
        let d = crate::system::TempDir::new("brew").unwrap();
        let ok = BrewJob::new(&fake_brew(d.path(), r#"{"checked": 1, "findings": []}"#, "warning"), "fp", true);
        assert_eq!(brew_scan(&ok).unwrap(), json!({"checked": 1, "findings": []}));
        let old = BrewJob::new(&fake_brew(d.path(), "", "Error: Unknown command: vulns"), "fp", true);
        assert!(matches!(brew_scan(&old), Err(Error::Missing(m)) if m.contains("brew update")));
        let broken = BrewJob::new(&fake_brew(d.path(), "not json", "Error: boom\nError: the last line"), "fp", true);
        assert!(matches!(brew_scan(&broken), Err(Error::Failed(m)) if m == "brew vulns failed: Error: the last line"));
        let gone = BrewJob::new(&d.path().join("nowhere/brew"), "fp", true);
        assert!(matches!(brew_scan(&gone), Err(Error::Failed(_))));
    }

    #[test]
    fn brew_vulns_caches_a_run_and_stores_its_advisories() {
        let (_d, c) = cache();
        assert!(brew_vulns(&c, None, None, false, false).unwrap().is_none());
        let job = BrewJob::new(Path::new("/nonexistent/brew"), "fp", true);
        // Offline with nothing cached: unchecked, not clean.
        assert!(matches!(brew_vulns(&c, Some(&job), None, false, true), Err(Error::Offline(_))));
        let got = brew_vulns(&c, Some(&job), Some(Ok(result())), false, false).unwrap().unwrap();
        assert_eq!(got["checked"], 2);
        assert_eq!(got["findings"][0]["formula"], "jq");
        let rec = c.vuln("GHSA-jq").unwrap().expect("stored for the report");
        assert_eq!(rec["aliases"], json!(["CVE-2026-7"]));
        assert_eq!(rec["affected"][0]["package"]["name"], "jq");
        assert_eq!(rec["database_specific"]["severity"], "high");
        assert!(c.vuln("").unwrap().is_none(), "an advisory without an id isn't stored");
        // Fresh for the same Cellar: no scan runs (the exe doesn't exist).
        assert_eq!(brew_vulns(&c, Some(&job), None, false, false).unwrap().unwrap()["checked"], 2);
        assert_eq!(brew_vulns(&c, Some(&job), None, false, true).unwrap().unwrap()["checked"], 2);
        // Known advisories aren't stored again; a scan that fails isn't cached.
        brew_vulns(&c, Some(&job), Some(Ok(result())), true, false).unwrap();
        assert!(matches!(
            brew_vulns(&c, Some(&job), Some(Err(Error::Failed("x".into()))), true, false),
            Err(Error::Failed(_))
        ));
        let other = BrewJob::new(Path::new("/nonexistent/brew"), "other", true);
        assert!(
            matches!(brew_vulns(&c, Some(&other), None, false, false), Err(Error::Failed(_))),
            "a changed Cellar scans again"
        );
    }
}
