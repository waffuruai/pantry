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
use crate::checks::machine::software_cves::{self, Subject, product_key, vendor_key, vendors_for};
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

/// Every installed program the Uninstall keys list, once each, sorted; None
/// when the machine's own Uninstall key (the first, always there on Windows)
/// gave nothing back: `reg` failed or timed out, which isn't a machine with
/// nothing installed.
pub fn programs(run: Runner) -> Option<Vec<Program>> {
    let reg = reg_exe();
    let mut found: Vec<Program> = Vec::new();
    for (i, key) in KEYS.iter().enumerate() {
        let out = run(&[reg.as_str(), "query", key, "/s"]);
        if i == 0 && !out.lines().any(|l| l.starts_with("HKEY_")) {
            return None;
        }
        for p in parse(&out) {
            if !found.iter().any(|f| f.name == p.name && f.version == p.version && f.publisher == p.publisher) {
                found.push(p);
            }
        }
    }
    found.sort();
    Some(found)
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

/// The Windows programs checked against CVE records, and nothing else:
/// (publisher, program) as Windows lists them, by [`vendor_key`] of the
/// Publisher and [`product_key`] of the DisplayName (with the record
/// vendor's words dropped from its front), then (vendor, product) as the
/// records name them. Only these vendor and product names are sent to the
/// index; a program not here is counted and never leaves the machine,
/// since a Publisher can be a person or an internal tool.
///
/// Example: `IntelliJ IDEA 2026.2.1` published by `JetBrains s.r.o.` is
/// (`jetbrains`, `intellij idea`), so it is asked about as `jetbrains` /
/// `IntelliJ IDEA`.
///
/// TODO: grow from real misses (reported as issues), one reviewed row at a
/// time; never by fuzzy matching or by sending unlisted publishers.
pub const PROGRAMS: &[(&str, &str, &str, &str)] = &[
    ("asustek computer", "armoury crate", "ASUS", "Armoury Crate"),
    ("broadcom", "workstation", "VMware", "Workstation"),
    ("circutor", "powerstudio scada wave", "Circutor", "PowerStudio SCADA Wave"),
    ("jetbrains", "intellij idea", "JetBrains", "IntelliJ IDEA"),
    ("jetbrains", "intellij idea community edition", "JetBrains", "IntelliJ IDEA"),
    ("jetbrains", "intellij idea ultimate", "JetBrains", "IntelliJ IDEA"),
    ("vmware", "workstation", "VMware", "Workstation"),
];

/// The [`PROGRAMS`] row a program is, if any.
pub fn mapped(p: &Program) -> Option<(&'static str, &'static str)> {
    let publisher = vendor_key(&p.publisher);
    PROGRAMS.iter().find_map(|(pk, nk, vendor, product)| {
        (publisher == *pk && product_key(&p.name, &vendor_key(vendor), &p.version) == *nk)
            .then_some((*vendor, *product))
    })
}

/// A program as the CVE-record check judges it, when [`PROGRAMS`] names
/// it: the row's vendor and product, never the program's own Publisher.
pub fn subject(p: &Program) -> Option<Subject> {
    let (vendor, product) = mapped(p)?;
    Some(Subject {
        kind: "app".into(),
        name: p.name.clone(),
        version: p.version.clone(),
        location: p.key.clone(),
        vendors: vendors_for(vendor),
        product: Some(product.to_string()),
        released: None,
    })
}

/// The installed programs, counted, and the ones [`PROGRAMS`] names
/// against CVE records.
pub fn check(scan: &mut Scan, found: &[Program]) -> Result<()> {
    scan.count("installed programs", found.len() as i64);
    let subjects: Vec<Subject> = found.iter().filter_map(subject).collect();
    software_cves::check(scan, &subjects, WHAT)
}

#[cfg(test)]
#[path = "programs_tests.rs"]
pub(crate) mod tests;
