//! `brew vulns` (Homebrew formulae), the one scanner still delegated: it
//! reruns only when the installed formulae change or a day passes.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, arr_at, str_at};
use crate::sha256;
use crate::system::{exec, run, which};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::time::Duration;

/// `brew vulns --json` findings ({findings, checked}), or None without
/// Homebrew. `Missing` when this Homebrew predates `brew vulns`.
pub fn brew_vulns(cache: &Cache, refresh: bool, offline: bool) -> Result<Option<Value>> {
    let Some(exe) = which("brew") else { return Ok(None) };
    let listing = run(&[exe.as_os_str(), OsStr::new("list"), OsStr::new("--versions")], Duration::from_secs(60));
    let scan = || -> Result<Value> {
        let p = exec(&[exe.as_os_str(), OsStr::new("vulns"), OsStr::new("--json")], &[], Duration::from_secs(900))?;
        if p.stderr.contains("Unknown command") || p.stderr.contains("Invalid usage") {
            return Err(Error::Missing("brew vulns (run: brew update)".into()));
        }
        let data = json::parse(p.stdout.as_bytes(), json::MAX_DOCUMENT).map_err(|_| {
            let tail = p.stderr.trim().lines().last().unwrap_or("").to_string();
            Error::Failed(format!("brew vulns failed: {tail}"))
        })?;
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
    cache.memo("brew-vulns", scan, DAY, &sha256::hex(listing.as_bytes()), refresh, offline).map(Some)
}
