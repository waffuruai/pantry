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
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::utils::net::Fake;
    use crate::utils::temp::TempDir;
    use serde_json::json;

    fn allows(lines: &[&str]) -> Vec<Allow> {
        parse_entries(&lines.iter().map(|l| l.to_string()).collect::<Vec<_>>())
    }

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn entries_split_on_the_last_at_sign_so_scopes_survive() {
        assert_eq!(parse_entry("esbuild"), Some(Allow { name: "esbuild".into(), range: None }));
        assert_eq!(parse_entry("@swc/core").unwrap().name, "@swc/core");
        let scoped = parse_entry("@swc/core@^1").unwrap();
        assert_eq!((scoped.name.as_str(), scoped.range.unwrap().shown.as_str()), ("@swc/core", "^1"));
        let exact = parse_entry("  sharp@0.35.5  ").unwrap();
        assert_eq!(exact.range.unwrap().shown, "0.35.5");
    }

    #[test]
    fn garbage_entries_are_skipped_not_panics() {
        for bad in [
            "",
            "  ",
            "esbuild@",
            "esbuild@latest",
            "esbuild@^1.x",
            "esbuild@1.2.3.4",
            "esbuild@^",
            "a b@1",
            "@",
            "esbuild@>=1",
        ] {
            assert_eq!(parse_entry(bad), None, "{bad:?}");
        }
        assert_eq!(allows(&["esbuild@^0.28", "nonsense@^", "sharp"]).len(), 2);
    }

    #[test]
    fn exact_versions_match_only_themselves() {
        let r = Range::parse("1.2.3").unwrap();
        assert!(r.contains("1.2.3") && r.contains("v1.2.3"));
        assert!(!r.contains("1.2.4") && !r.contains("1.2") && !r.contains("1.2.3-beta.1"));
        assert!(Range::parse("=1.2.3").unwrap().contains("1.2.3"));
        assert!(Range::parse("1.2").unwrap().contains("1.2.0"), "a short exact version is padded with zeros");
    }

    #[test]
    fn caret_keeps_the_first_non_zero_part() {
        let one = Range::parse("^1.2.3").unwrap();
        assert!(one.contains("1.2.3") && one.contains("1.9.0") && !one.contains("1.2.2") && !one.contains("2.0.0"));
        let zero = Range::parse("^0.28").unwrap();
        assert!(
            zero.contains("0.28.0") && zero.contains("0.28.9") && !zero.contains("0.29.0") && !zero.contains("0.27.9")
        );
        let tiny = Range::parse("^0.0.3").unwrap();
        assert!(tiny.contains("0.0.3") && !tiny.contains("0.0.4"));
        let all_zero = Range::parse("^0.0").unwrap();
        assert!(all_zero.contains("0.0.9") && !all_zero.contains("0.1.0"));
        let major = Range::parse("^1").unwrap();
        assert!(major.contains("1.0.0") && major.contains("1.99.99") && !major.contains("2.0.0"));
        assert!(!major.contains("1.5.0-rc.1"), "a prerelease is never inside a range");
        assert!(!major.contains("not-a-version"));
    }

    #[test]
    fn tilde_keeps_the_minor() {
        let r = Range::parse("~1.2.3").unwrap();
        assert!(r.contains("1.2.3") && r.contains("1.2.9") && !r.contains("1.3.0") && !r.contains("1.2.2"));
        let short = Range::parse("~1.2").unwrap();
        assert!(short.contains("1.2.0") && !short.contains("1.3.0"));
        let major = Range::parse("~1").unwrap();
        assert!(major.contains("1.9.9") && !major.contains("2.0.0"));
    }

    #[test]
    fn verdicts() {
        let list = allows(&["esbuild@^0.25", "sharp", "@swc/core@^1", "workerd@1.20261019.1", "workerd@^2"]);
        assert_eq!(verdict(&list, "esbuild", &v(&["0.25.9"])), Verdict::Allowed);
        assert_eq!(
            verdict(&list, "esbuild", &v(&["0.28.1"])),
            Verdict::OutsideRange { allowed: "^0.25".into(), locked: v(&["0.28.1"]) }
        );
        assert_eq!(
            verdict(&list, "esbuild", &v(&["0.25.0", "0.28.1"])),
            Verdict::OutsideRange { allowed: "^0.25".into(), locked: v(&["0.28.1"]) },
            "only the versions outside are named"
        );
        assert_eq!(verdict(&list, "esbuild", &[]), Verdict::UnknownVersion { allowed: "^0.25".into() });
        assert_eq!(verdict(&list, "sharp", &v(&["0.1.0"])), Verdict::Allowed, "a bare name allows every version");
        assert_eq!(verdict(&list, "sharp", &[]), Verdict::Allowed, "and needs no version");
        assert_eq!(verdict(&list, "@swc/core", &v(&["1.16.21"])), Verdict::Allowed);
        assert_eq!(verdict(&list, "foo", &v(&["1.0.0"])), Verdict::NotListed);
        assert_eq!(
            verdict(&list, "workerd", &v(&["1.20261019.1", "2.0.0"])),
            Verdict::Allowed,
            "two entries read together"
        );
        assert_eq!(
            verdict(&list, "workerd", &v(&["1.20261031.1"])),
            Verdict::OutsideRange { allowed: "1.20261019.1, ^2".into(), locked: v(&["1.20261031.1"]) }
        );
    }

    #[test]
    fn the_bundled_list_parses_whole_and_is_pinned() {
        let lines = crate::checks::listed(None, crate::defaults::INSTALL_SCRIPTS);
        let parsed = parse_entries(&lines);
        assert_eq!(parsed.len(), lines.len(), "every line of the default file is an entry");
        assert!(parsed.iter().all(|a| a.range.is_some()), "every default entry carries a version range");
        assert_eq!(verdict(&parsed, "esbuild", &v(&["0.28.2"])), Verdict::Allowed);
    }

    /// Install scripts outside the allowlist warn, each verdict with its own
    /// advice; npm running scripts by default is a config warning.
    #[cfg(unix)]
    #[test]
    fn install_scripts_outside_the_allowlist_warn() {
        let d = TempDir::new("install").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d, Options::default());
        let (name, root) = testing::repo(&d, "app");
        testing::write(
            &root,
            "package-lock.json",
            json!({"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/foo": {"version": "1.0.0", "hasInstallScript": true},
            "node_modules/esbuild": {"version": "0.27.0", "hasInstallScript": true},
            "node_modules/fsevents": {"version": "2.3.3", "hasInstallScript": true},
            "node_modules/sharp": {"hasInstallScript": true}}})
            .to_string(),
        );
        let npm = testing::script(d.path(), "npm", "#!/bin/sh\necho false\n");
        let found = [Component::new("manager", "npm", "10.0.0", &npm.to_string_lossy())];
        install_scripts(&mut s, &[(name, root.clone())], &found);
        let script_for = |n: &str| {
            testing::by_id(&s, "INSTALL-SCRIPT")
                .into_iter()
                .find(|f| f.component == n)
                .map(|f| (f.note.clone(), f.fix_cmd.clone()))
        };
        assert!(script_for("fsevents").is_none(), "allowed at that version");
        let (note, fix) = script_for("foo").unwrap();
        assert_eq!(note, "runs code when installed");
        assert!(fix.starts_with("Check what foo's install script does"), "{fix}");
        let (note, fix) = script_for("esbuild").unwrap();
        assert!(note.contains("allowed at ^0.28 but 0.27.0 is locked"), "{note}");
        assert!(fix.starts_with("Re-read esbuild's install script at 0.27.0"), "{fix}");
        let (note, fix) = script_for("sharp").unwrap();
        assert!(note.contains("the locked version couldn't be read"), "{note}");
        assert!(fix.starts_with("Check which sharp the lockfile pins"), "{fix}");
        let f = testing::by_id(&s, "INSTALL-SCRIPT")[0];
        assert_eq!(
            (f.kind.as_str(), f.status.as_str(), f.location.as_str()),
            ("install-script", "warn", root.join("package-lock.json").to_str().unwrap())
        );
        let cfg = testing::by_id(&s, "NPM-SCRIPTS");
        assert_eq!(cfg.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (cfg[0].kind.as_str(), cfg[0].component.as_str(), cfg[0].location.as_str()),
            ("config", "npm ignore-scripts", npm.to_str().unwrap())
        );
        assert_eq!(
            cfg[0].fix_cmd,
            format!("{} config set ignore-scripts true  (then allow builds per project)", npm.display())
        );
        // npm that ignores scripts, or no npm: no config warning.
        let npm = testing::script(d.path(), "npm2", "#!/bin/sh\necho true\n");
        let before = s.findings.len();
        install_scripts(&mut s, &[], &[Component::new("manager", "npm", "10.0.0", &npm.to_string_lossy())]);
        install_scripts(&mut s, &[], &[Component::new("manager", "npm", "10.0.0", "")]);
        assert_eq!(s.findings.len(), before);
    }
}
