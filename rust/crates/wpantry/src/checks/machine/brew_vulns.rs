//! `brew vulns` (Homebrew formulae), the one scanner still delegated: it
//! reruns only when the installed formulae change or a day passes.

use crate::checks::ecosystems::versions;
use crate::checks::machine::manual;
use crate::checks::{REMOVE, Scan, display_id, is_kev, is_malicious};
use crate::component::Component;
use crate::db::severity_of;
use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::osv;
use crate::utils::json::{self, arr_at, str_at};
use crate::utils::process::exec;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::sha256;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The installed formulae and versions, `name v1 v2` per line, read from the
/// Cellar: the cache key `brew list --versions` gave, without starting
/// Homebrew's Ruby (most of a second). None when there's no Cellar to read.
fn cellar(brew: &Path) -> Option<String> {
    let prefix = crate::utils::homebrew::homebrew_prefix(brew)?;
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
    let stale = !offline && (refresh || !cached.is_some_and(|(_, at, _)| at > crate::utils::os::now() - DAY));
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

// Homebrew ----------------------------------------------------------------------

pub fn brew(scan: &mut Scan, job: Option<&BrewJob>, ran: Option<Result<Value>>) -> Result<()> {
    scan.status("Checking Homebrew formulae (brew vulns)");
    let res = match brew_vulns(&scan.cache, job, ran, scan.opts.refresh, scan.opts.offline) {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(Error::Missing(_)) => {
            scan.add(Finding {
                kind: "tool".into(),
                component: "brew vulns".into(),
                vuln_id: "MISSING".into(),
                status: "fail".into(),
                note: "Homebrew formulae can't be checked".into(),
                fix_cmd: "brew update".into(),
                fix_auto: true,
                ..Default::default()
            });
            return Ok(());
        }
        Err(e) if e.is_source() => {
            scan.unchecked("Homebrew formulae (brew vulns)", &e.to_string());
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    scan.count("Homebrew formulae", res.get("checked").and_then(Value::as_i64).unwrap_or(0));
    for f in crate::utils::json::arr_at(&res, "findings") {
        let formula = crate::utils::json::str_at(f, "formula").to_string();
        let version = crate::utils::json::str_at(f, "version").to_string();
        let (fix, auto) = match manual(&formula) {
            Some(m) => (m.to_string(), false),
            None => (format!("brew upgrade {formula}"), true),
        };
        let mut c = Component::new("brew", &formula, &version, "Homebrew");
        c.fix = fix;
        c.auto = auto;
        for v in crate::utils::json::arr_at(f, "vulnerabilities") {
            let rec = serde_json::json!({"id": crate::utils::json::str_at(v, "id"), "aliases": v.get("aliases").cloned().unwrap_or(serde_json::json!([]))});
            let fixes: Vec<String> =
                crate::utils::json::strs_at(v, "fixed_versions").into_iter().filter(|x| osv::released(x)).collect();
            if is_malicious(&rec) {
                scan.add(Finding {
                    vuln_id: crate::utils::json::str_at(v, "id").into(),
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: crate::utils::json::str_at(v, "summary").into(),
                    fix_cmd: REMOVE.replace("{}", &formula),
                    ..Finding::of(&c)
                });
            } else if fixes.is_empty() {
                scan.unfixed += 1;
            } else {
                let sev = crate::utils::json::str_at(v, "severity").to_uppercase();
                scan.add(Finding {
                    vuln_id: display_id(&rec),
                    status: "fail".into(),
                    kev: is_kev(&rec, &scan.kev),
                    fixed: versions::pick_safe(&version, &fixes).unwrap_or_else(|| fixes[0].clone()),
                    severity: if sev.is_empty() { severity_of(&rec) } else { sev },
                    note: crate::utils::json::str_at(v, "summary").into(),
                    fix_cmd: c.fix.clone(),
                    fix_auto: c.auto,
                    ..Finding::of(&c)
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "brew_vulns_tests.rs"]
mod tests;
