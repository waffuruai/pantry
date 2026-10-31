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
}
