//! Supply-chain checks: the scanned repos' dependencies (read by the
//! lockfile extractors, asked of OSV directly), install scripts and
//! committed secrets, the container images they name, the MCP servers they
//! configure, and every package name against the malicious-package index.
//! Licenses (deps.dev), images and the machine-wide parts (editor
//! extensions, harness plugins, the breach check) arrive in phase 2 and are
//! reported unchecked until then.

use crate::check::{Finding, REMOVE, Scan, as_source};
use crate::error::{Error, Result};
use crate::json::str_at;
use crate::lockfiles;
use crate::osv::{self, Item};
use crate::repos::{self, Repo};
use crate::system::{Component, run as sh, short, which};
use crate::{harnesses, leaks, malicious};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GITLEAKS_INSTALL: &str = "https://github.com/gitleaks/gitleaks#installing";
/// How the report names the policy files (their paths vary; the flag doesn't).
pub const INSTALL_SCRIPTS: &str = "the install-scripts allowlist (--install-scripts)";
/// Why an area is unchecked until the Rust port covers it.
pub const PHASE_2: &str =
    "not yet in the Rust implementation (phase 2 of specs/01-rust-port.md); python/bin/wscanner checks it";

/// The repo checks; `found` is what the machine inventory found, for the
/// malicious-package sweep.
pub fn run(scan: &mut Scan, found: &[Component]) -> Result<()> {
    let repos = scan.repos.clone();
    projects(scan, &repos)?;
    let git: Vec<Repo> = repos.iter().filter(|(_, r)| repos::is_git(r)).cloned().collect();
    secrets(scan, &git)?;
    install_scripts(scan, &repos);
    images(scan, &repos);
    let refs = mcp(scan, &repos)?;
    sweep(scan, found, &refs)?;
    Ok(())
}

/// POSIX shell quoting, as Python's `shlex.quote`.
pub fn quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c)) {
        return s.into();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// How to move one locked dependency to `safe` (a step in the repo, never
/// run unattended).
pub fn project_fix(lock: &Path, eco: &str, name: &str, safe: &str) -> String {
    let d = quote(&lock.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
    let file = lock.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match (eco, file) {
        ("crates.io", _) => format!("cd {d} && cargo update -p {name} --precise {safe}"),
        (_, "pnpm-lock.yaml") => format!("cd {d} && pnpm update {name}@{safe}"),
        ("npm", _) => format!("cd {d} && npm install {name}@{safe}"),
        ("PyPI", "uv.lock") => format!("cd {d} && uv lock --upgrade-package {name}=={safe}"),
        ("Go", _) => format!("cd {d} && go get {name}@v{} && go mod tidy", safe.trim_start_matches('v')),
        _ => format!("Update {name} to {safe} in {}", lock.display()),
    }
}

// The scanned repos -----------------------------------------------------------

pub fn projects(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    let files: Vec<PathBuf> = repos
        .iter()
        .flat_map(|(name, r)| {
            scan.status(&format!("Finding lockfiles in {name}"));
            repos::lockfiles(r)
        })
        .collect();
    if files.is_empty() {
        return Ok(());
    }
    let mut read: Vec<(PathBuf, Vec<lockfiles::Package>)> = Vec::new();
    let mut unsupported: BTreeMap<String, usize> = BTreeMap::new();
    for f in &files {
        scan.status(&format!("Reading {}", short(&f.to_string_lossy())));
        match lockfiles::extract(f).map_err(as_source) {
            Ok(Some(pkgs)) => read.push((f.clone(), pkgs)),
            Ok(None) => {
                *unsupported.entry(f.file_name().unwrap_or_default().to_string_lossy().into_owned()).or_default() += 1
            }
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("repo dependencies in {}", short(&f.to_string_lossy())), &e.to_string())
            }
            Err(e) => return Err(e),
        }
    }
    if !unsupported.is_empty() {
        let kinds: Vec<String> = unsupported.iter().map(|(k, n)| format!("{k} ({n})")).collect();
        scan.unchecked(
            "repo dependencies in lockfiles the Rust implementation can't read yet",
            &format!("{}: {PHASE_2}", kinds.join(", ")),
        );
    }
    let total: usize = read.iter().map(|(_, p)| p.len()).sum();
    scan.count("project dependencies", total as i64);
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    let answers = scan.lookup(&items, "repo dependencies against OSV")?;
    for (f, pkgs) in &read {
        for p in pkgs {
            let item = (p.ecosystem.clone(), p.name.clone(), p.version.clone());
            let Some(recs) = answers.get(&item) else { continue };
            if recs.is_empty() {
                continue;
            }
            let mut c = Component::new("project", &p.name, &p.version, &f.to_string_lossy());
            c.fix = project_fix(f, &p.ecosystem, &p.name, "{safe}");
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "fail", Some(osv::group_by_alias(recs)));
        }
    }
    if scan.opts.licenses {
        scan.unchecked("dependency licenses (deps.dev)", PHASE_2);
    }
    Ok(())
}

/// Secrets committed anywhere in the repos' history. A provider-specific
/// rule (AWS, GitHub, OpenAI, …) fails; a generic one asks for review.
pub fn secrets(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    if repos.is_empty() {
        return Ok(());
    }
    let config = scan.opts.policy.gitleaks_config(&scan.cache)?;
    for (name, root) in repos {
        scan.status(&format!("Scanning {name}'s git history for secrets (gitleaks)"));
        let found = match leaks::scan(&scan.cache, root, &config, scan.opts.refresh, scan.opts.offline) {
            Ok(f) => f,
            Err(Error::Missing(_)) => {
                let has_brew = which("brew").is_some();
                scan.add(Finding {
                    kind: "tool".into(),
                    component: "gitleaks".into(),
                    vuln_id: "MISSING".into(),
                    status: "fail".into(),
                    note: "secrets in the repos' history can't be checked".into(),
                    fix_auto: has_brew,
                    fix_cmd: if has_brew {
                        "brew install gitleaks".into()
                    } else {
                        format!("Install gitleaks: {GITLEAKS_INSTALL}")
                    },
                    ..Default::default()
                });
                return Ok(());
            }
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("secrets in {name}'s history (gitleaks)"), &e.to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        scan.count("repos scanned for secrets", 1);
        for f in found {
            let generic = leaks::GENERIC.contains(&f.rule.as_str());
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/{}", f.file),
                location: format!("line {}, commit {}", f.line, f.commit),
                vuln_id: f.rule.clone(),
                status: if generic { "warn" } else { "fail" }.into(),
                note: format!("{}{}", f.description, if generic { " (review: generic rule)" } else { "" }),
                fix_cmd: format!(
                    "If it's real: rotate it, then purge it from history. If not: add {} to {}/.gitleaksignore",
                    f.fingerprint,
                    short(&root.to_string_lossy())
                ),
                ..Default::default()
            });
        }
    }
    Ok(())
}

/// Dependencies that run code at install time, outside the allowlist.
pub fn install_scripts(scan: &mut Scan, repos: &[Repo]) {
    scan.status("Checking which dependencies run install scripts");
    let allowed: HashSet<String> = scan.opts.policy.install_scripts().into_iter().collect();
    let files: Vec<PathBuf> = repos.iter().flat_map(|(_, r)| repos::lockfiles(r)).collect();
    for (where_, name) in repos::install_scripts(&files) {
        if allowed.contains(&name) {
            continue;
        }
        scan.add(Finding {
            kind: "install-script".into(),
            component: name.clone(),
            location: where_.to_string_lossy().into_owned(),
            vuln_id: "INSTALL-SCRIPT".into(),
            status: "warn".into(),
            note: "runs code when installed".into(),
            fix_cmd: format!("Check what {name}'s install script does; then allow it in {INSTALL_SCRIPTS}, or drop it from the build allowlist"),
            ..Default::default()
        });
    }
}

/// The images the repos build from or run, when they exist locally: not
/// scanned yet (phase 2), so each is reported unchecked.
pub fn images(scan: &mut Scan, repos: &[Repo]) {
    let Some(docker) = which("docker") else { return };
    scan.status("Looking for the container images the repos name");
    let mut refs: Vec<String> = repos::repo_images(repos).into_iter().map(|(r, _)| r).collect();
    refs.sort();
    refs.dedup();
    for r in refs {
        let id = sh(
            &[
                docker.as_os_str(),
                OsStr::new("image"),
                OsStr::new("inspect"),
                OsStr::new("--format"),
                OsStr::new("{{.Id}}"),
                OsStr::new(&r),
            ],
            Duration::from_secs(20),
        );
        if id.trim().starts_with("sha256:") {
            scan.unchecked(&format!("image {r}"), &format!("container image scanning is {PHASE_2}"));
        }
    }
}

/// MCP servers the repos start through a package runner. Pinned ones are
/// checked like any package; unpinned ones run whatever is latest on every
/// launch, so they warn (and fail if the name is known malicious).
pub fn mcp(scan: &mut Scan, repos: &[Repo]) -> Result<Vec<Component>> {
    scan.status("Reading the repos' MCP server configs");
    let servers = harnesses::mcp_servers(repos);
    scan.count("MCP servers", servers.len() as i64);
    let mut refs = Vec::new();
    for s in &servers {
        let Some((eco, name, ver)) = harnesses::package_ref(&s.command, &s.args) else { continue };
        let mut c = Component::new(
            "mcp",
            &format!("{name} ({}: {})", s.harness, s.name),
            if ver.is_empty() { "unpinned" } else { &ver },
            &s.file,
        );
        if !ver.is_empty() {
            c.osv = Some((eco.clone(), name.clone(), ver.clone()));
        }
        c.extra.insert("eco".into(), eco.clone());
        c.extra.insert("pkg".into(), name.clone());
        c.extra.insert("ver".into(), ver.clone());
        c.fix = format!(
            "Pin {name} to a reviewed version in {}{}",
            short(&s.file),
            if ver.is_empty() { "" } else { " ({safe} fixes it)" }
        );
        if ver.is_empty() {
            scan.add(Finding {
                vuln_id: "UNPINNED".into(),
                status: "warn".into(),
                fix_cmd: c.fix.clone(),
                note: format!("`{} {name}` runs the latest release on every launch", s.command),
                ..Finding::of(&c)
            });
        }
        refs.push(c);
    }
    let items: Vec<Item> = refs.iter().filter_map(|c| c.osv.clone()).collect();
    let answers = scan.lookup(&items, "MCP server packages against OSV")?;
    for c in &refs {
        if let Some(item) = &c.osv {
            let recs = answers.get(item).cloned().unwrap_or_default();
            scan.advisories(c, &recs, None, "fail", None);
        }
    }
    Ok(refs)
}

/// Every package name we know against the local malicious-package index,
/// which also covers what OSV couldn't be asked about (offline, unpinned).
pub fn sweep(scan: &mut Scan, found: &[Component], refs: &[Component]) -> Result<()> {
    scan.status("Updating the malicious-package index (OpenSSF)");
    let synced = malicious::sync(&scan.cache, scan.opts.offline);
    if scan.guard("malicious-package index (OpenSSF)", synced.map(Some), None)?.is_none() {
        return Ok(());
    }
    let mut flagged: HashSet<(String, String)> =
        scan.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone())).collect();
    let mut items: Vec<(&Component, String, String, String)> =
        found.iter().filter_map(|c| c.osv.as_ref().map(|(e, n, v)| (c, e.clone(), n.clone(), v.clone()))).collect();
    let extra = |c: &Component, k: &str| c.extra.get(k).cloned().unwrap_or_default();
    items.extend(refs.iter().map(|c| (c, extra(c, "eco"), extra(c, "pkg"), extra(c, "ver"))));
    let total = items.len();
    for (n, (c, eco, name, ver)) in items.into_iter().enumerate() {
        scan.status(&format!("Checking {name} against the malicious-package index ({}/{total})", n + 1));
        for rec in malicious::reports(&scan.cache, scan.net, &eco, &name, &ver)? {
            let id = str_at(&rec, "id").to_string();
            if flagged.insert((c.name.clone(), id.clone())) {
                let summary = str_at(&rec, "summary");
                scan.add(Finding {
                    vuln_id: id,
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: if summary.is_empty() { format!("known malicious package {name}") } else { summary.into() },
                    fix_cmd: REMOVE.replace("{}", &name),
                    ..Finding::of(c)
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Python test vectors (python/test_wscanner.py `Plan.test_project_fixes_stay_manual_and_per_ecosystem`).
    #[test]
    fn project_fixes_stay_manual_and_per_ecosystem() {
        assert_eq!(
            project_fix(Path::new("/w/butter/rust/Cargo.lock"), "crates.io", "webpki-roots", "1.0.10"),
            "cd /w/butter/rust && cargo update -p webpki-roots --precise 1.0.10"
        );
        assert_eq!(
            project_fix(Path::new("/w/docs/pnpm-lock.yaml"), "npm", "vite", "8.2.3"),
            "cd /w/docs && pnpm update vite@8.2.3"
        );
        assert_eq!(
            project_fix(Path::new("/w/my app/go.mod"), "Go", "golang.org/x/net", "0.23.0"),
            "cd '/w/my app' && go get golang.org/x/net@v0.23.0 && go mod tidy"
        );
        assert_eq!(quote("it's"), "'it'\"'\"'s'");
    }
}
