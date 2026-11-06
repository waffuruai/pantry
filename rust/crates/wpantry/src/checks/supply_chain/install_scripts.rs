//! The install-scripts allowlist: which npm packages may run code at install
//! time without a warning, and at which versions. An entry is `name` (any
//! version, discouraged), `name@1.2.3` (that version), `name@^1.2` or
//! `name@~1.2` (npm's caret and tilde ranges). The list is the only control:
//! OSV and the malicious-package index still check every locked package,
//! but nothing else reads what an allowed script does, so a version outside
//! its entry warns until someone reads the new script and widens the entry.

use crate::checks::Scan;
use crate::checks::ecosystems::semver;
use crate::checks::supply_chain::repos::Repo;
use crate::checks::supply_chain::{INSTALL_SCRIPTS, repos};
use crate::component::Component;
use crate::finding::Finding;
use crate::utils::process::run as sh;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

/// A version's numeric core, padded to three parts.
type Core = [u64; 3];
const PARTS: usize = 3;

/// One allowlist entry: a package, at any version or inside a range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allow {
    pub name: String,
    pub range: Option<Range>,
}

/// The versions an entry accepts, as written and as bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// As written after the `@`: `1.2.3`, `^1.2`, `~0.28`.
    pub shown: String,
    low: Core,
    /// Exclusive, or `None` for an exact version.
    high: Option<Core>,
}

/// What the allowlist says about one package at the versions a lockfile pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    NotListed,
    /// Listed, but a locked version is outside every entry for it.
    OutsideRange {
        allowed: String,
        locked: Vec<String>,
    },
    /// Listed with a range, but no locked version could be read.
    UnknownVersion {
        allowed: String,
    },
}

/// The entries of a policy file's lines (comments and blanks already
/// dropped); a line that isn't an entry is skipped.
pub fn parse_entries(lines: &[String]) -> Vec<Allow> {
    lines.iter().filter_map(|l| parse_entry(l)).collect()
}

/// `name`, `name@1.2.3`, `name@^1.2`, `name@~1.2`; the `@` that splits them
/// is the last one after the first character, so `@swc/core@^1` works.
pub fn parse_entry(line: &str) -> Option<Allow> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (name, spec) = match line[1..].rfind('@') {
        Some(i) => (&line[..i + 1], Some(&line[i + 2..])),
        None => (line, None),
    };
    if name.is_empty() || name == "@" || name.contains(char::is_whitespace) {
        return None;
    }
    let range = match spec {
        None => None,
        Some(s) => Some(Range::parse(s)?),
    };
    Some(Allow { name: name.to_string(), range })
}

impl Range {
    /// `1.2.3`, `=1.2.3`, `^1.2`, `~1.2`, `^0.28`: one to three numeric parts
    /// and no prerelease; anything else is `None`.
    pub fn parse(spec: &str) -> Option<Range> {
        let spec = spec.trim();
        let (op, rest) = match spec.chars().next()? {
            '^' | '~' | '=' => (spec.chars().next()?, &spec[1..]),
            _ => (' ', spec),
        };
        let given: Vec<u64> = rest.split('.').map(|p| p.parse::<u64>().ok()).collect::<Option<Vec<u64>>>()?;
        if given.is_empty() || given.len() > PARTS {
            return None;
        }
        let mut low = [0u64; PARTS];
        low[..given.len()].copy_from_slice(&given);
        let high = match op {
            '^' => {
                // The first non-zero given part is the one that may not change
                // (`^0.28` is `<0.29.0`, `^1.2` is `<2.0.0`); all zero, the last given.
                let i = given.iter().position(|p| *p != 0).unwrap_or(given.len() - 1);
                Some(bump(&low, i))
            }
            '~' => Some(bump(&low, if given.len() >= 2 { 1 } else { 0 })),
            _ => None,
        };
        Some(Range { shown: spec.to_string(), low, high })
    }

    /// Whether `version` is inside: a prerelease never is (npm's rule, and
    /// the cautious one), nor is anything semver can't read.
    pub fn contains(&self, version: &str) -> bool {
        let Some(v) = semver::parse(version) else { return false };
        if !v.pre.is_empty() {
            return false;
        }
        let mut core = [0u64; PARTS];
        for (i, part) in v.core.iter().take(PARTS).enumerate() {
            let Ok(n) = part.parse::<u64>() else { return false };
            core[i] = n;
        }
        match &self.high {
            None => core == self.low,
            Some(high) => core >= self.low && core < *high,
        }
    }
}

/// `core` with part `i` one higher and everything after it zero.
fn bump(core: &Core, i: usize) -> Core {
    let mut out = [0u64; PARTS];
    out[..i].copy_from_slice(&core[..i]);
    out[i] = core[i] + 1;
    out
}

/// The allowlist's answer for `name` at the versions a lockfile pins
/// (`versions` empty when none could be read). Several entries for one name
/// are read together: a version any of them accepts is allowed.
pub fn verdict(allows: &[Allow], name: &str, versions: &[String]) -> Verdict {
    let entries: Vec<&Allow> = allows.iter().filter(|a| a.name == name).collect();
    if entries.is_empty() {
        return Verdict::NotListed;
    }
    if entries.iter().any(|a| a.range.is_none()) {
        return Verdict::Allowed;
    }
    let allowed =
        entries.iter().filter_map(|a| a.range.as_ref()).map(|r| r.shown.as_str()).collect::<Vec<_>>().join(", ");
    if versions.is_empty() {
        return Verdict::UnknownVersion { allowed };
    }
    let locked: Vec<String> = versions
        .iter()
        .filter(|v| !entries.iter().any(|a| a.range.as_ref().is_some_and(|r| r.contains(v))))
        .cloned()
        .collect();
    if locked.is_empty() { Verdict::Allowed } else { Verdict::OutsideRange { allowed, locked } }
}

/// Dependencies that run code at install time, outside the allowlist, and
/// whether npm runs them by default on this machine.
pub fn install_scripts(scan: &mut Scan, repos: &[Repo], found: &[Component]) {
    scan.status("Checking which dependencies run install scripts");
    let allows = parse_entries(&scan.opts.policy.install_scripts());
    let files: Vec<PathBuf> = repos.iter().flat_map(|(_, r)| repos::lockfiles(r)).collect();
    for s in repos::install_scripts(&files) {
        let name = &s.name;
        let (note, fix_cmd) = match verdict(&allows, name, &s.versions) {
            Verdict::Allowed => continue,
            Verdict::NotListed => (
                "runs code when installed".to_string(),
                format!(
                    "Check what {name}'s install script does; then allow it in {INSTALL_SCRIPTS} ({name}@<range>), or drop it from the build allowlist"
                ),
            ),
            Verdict::OutsideRange { allowed, locked } => {
                let locked = locked.join(", ");
                (
                    format!(
                        "runs code when installed; allowed at {allowed} but {locked} is locked: re-read its install script before widening the entry"
                    ),
                    format!(
                        "Re-read {name}'s install script at {locked}; then widen its entry in {INSTALL_SCRIPTS}, or drop the package"
                    ),
                )
            }
            Verdict::UnknownVersion { allowed } => (
                format!("runs code when installed; allowed at {allowed} but the locked version couldn't be read"),
                format!(
                    "Check which {name} the lockfile pins and what its install script does; then fix the lockfile or its entry in {INSTALL_SCRIPTS}"
                ),
            ),
        };
        scan.add(Finding {
            kind: "install-script".into(),
            component: name.clone(),
            location: s.file.to_string_lossy().into_owned(),
            vuln_id: "INSTALL-SCRIPT".into(),
            status: "warn".into(),
            note,
            fix_cmd,
            ..Default::default()
        });
    }
    let npm = found.iter().find(|c| c.name == "npm" && !c.path.is_empty()).map(|c| c.path.clone());
    if let Some(npm) = npm
        && sh(
            &[OsStr::new(&npm), OsStr::new("config"), OsStr::new("get"), OsStr::new("ignore-scripts")],
            Duration::from_secs(15),
        )
        .trim()
        .ends_with("false")
    {
        scan.add(Finding {
            kind: "config".into(),
            component: "npm ignore-scripts".into(),
            location: npm.clone(),
            vuln_id: "NPM-SCRIPTS".into(),
            status: "warn".into(),
            note: "npm runs every dependency's install scripts (how most npm attacks run)".into(),
            fix_cmd: format!("{npm} config set ignore-scripts true  (then allow builds per project)"),
            ..Default::default()
        });
    }
}

#[cfg(test)]
#[path = "install_scripts_tests.rs"]
mod tests;
