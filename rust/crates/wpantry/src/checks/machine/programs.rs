//! Windows' installed programs: the entries "Installed apps" (Programs and
//! Features) lists, read from the registry's Uninstall keys with
//! `reg query`, read only. Each entry's DisplayName, DisplayVersion and
//! Publisher; entries without a name, and Windows updates filed under
//! another program, are left out.
//!
//! `reg query <key> /s` prints a key's path on its own line, then one line
//! per value, indented, the name, type and data four spaces apart:
//!
//! ```text
//! HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1234}
//!     DisplayName    REG_SZ    Example Viewer
//!     DisplayVersion    REG_SZ    2.4.1
//!     Publisher    REG_SZ    Example Software, Inc.
//! ```

use crate::checks::Scan;
use crate::checks::machine::settings::Runner;
use crate::checks::machine::software_cves::{self, Subject, vendors_for};
use crate::error::Result;
use std::collections::BTreeMap;

/// What the program check's not-checked lines are called.
pub const WHAT: &str = "installed programs against CVE records";

/// The Uninstall keys, machine-wide (both views) and the user's own.
pub const KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
];

/// One installed program.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Program {
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// The registry key it was read from.
    pub key: String,
}

/// `reg.exe` by its full path, so a `reg` earlier on PATH isn't run.
fn reg_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\reg.exe")
}

/// Every installed program the Uninstall keys list, once each, sorted.
pub fn programs(run: Runner) -> Vec<Program> {
    let reg = reg_exe();
    let mut found: Vec<Program> = Vec::new();
    for key in KEYS {
        for p in parse(&run(&[reg.as_str(), "query", key, "/s"])) {
            if !found.iter().any(|f| f.name == p.name && f.version == p.version && f.publisher == p.publisher) {
                found.push(p);
            }
        }
    }
    found.sort();
    found
}

/// The programs in `reg query /s` output; lines that are neither a key nor
/// a value (an error, a blank) are skipped.
pub fn parse(out: &str) -> Vec<Program> {
    let mut entries: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for line in out.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("HKEY_") {
            entries.push((line.trim().to_string(), BTreeMap::new()));
            continue;
        }
        let Some((_, values)) = entries.last_mut() else { continue };
        let Some((name, rest)) = line.trim_start().split_once("    REG_") else { continue };
        // The data follows the type, four spaces on; an empty value has none.
        let data = rest.split_once("    ").map(|(_, d)| d.trim()).unwrap_or("");
        values.insert(name.trim().to_string(), data.to_string());
    }
    entries
        .into_iter()
        .filter_map(|(key, v)| {
            let name = v.get("DisplayName").map(|s| s.trim()).filter(|s| !s.is_empty())?;
            // An update of another program (a hotfix, a security update).
            if v.get("ParentKeyName").is_some_and(|s| !s.is_empty()) {
                return None;
            }
            Some(Program {
                name: name.to_string(),
                version: v.get("DisplayVersion").cloned().unwrap_or_default(),
                publisher: v.get("Publisher").cloned().unwrap_or_default(),
                key,
            })
        })
        .collect()
}

/// A program as the CVE-record check judges it: its Publisher is the
/// vendor, its DisplayName the product.
pub fn subject(p: &Program) -> Subject {
    Subject {
        kind: "app".into(),
        name: p.name.clone(),
        version: p.version.clone(),
        location: p.key.clone(),
        vendors: vendors_for(&p.publisher),
        product: None,
        released: None,
    }
}

/// The installed programs, counted, against CVE records.
pub fn check(scan: &mut Scan, found: &[Program]) -> Result<()> {
    scan.count("installed programs", found.len() as i64);
    let subjects: Vec<Subject> = found.iter().map(subject).collect();
    software_cves::check(scan, &subjects, WHAT)
}

#[cfg(test)]
#[path = "programs_tests.rs"]
pub(crate) mod tests;
