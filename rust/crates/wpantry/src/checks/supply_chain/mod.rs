//! Supply-chain checks: the scanned repos' dependencies (read by the
//! lockfile extractors, asked of OSV directly), install scripts and
//! committed secrets, the container images they name, the MCP servers they
//! configure, and every package name against the malicious-package index;
//! dependency licenses (deps.dev) with `--licenses`; on a machine scan also
//! the editor extensions, harness plugins and the breach check.
//!
//! One file per behaviour: `projects` (lockfiles against OSV), `typosquat`,
//! `licenses`, `leaks` (gitleaks), `hooks`, `suspect_code`, `hidden_text`,
//! `documents` (and ClamAV), `install_scripts`, `mptcp`, `images`,
//! `extensions` (and what they bundle), `mcp` and `malicious` (the sweep);
//! `repos` finds the repos. This file is the index: [`run`], in order.

use crate::checks::Scan;
use crate::checks::email::breach;
use crate::component::Component;
use crate::error::Result;
use crate::utils::parallel;
use crate::utils::process::which;
use documents::documents_pass;
use extensions::bundles;
use hooks::repo_hooks;
use images::images_with;
use leaks::{gitleaks_at_once, secret_jobs, secrets};
use malicious::sweep;
use mptcp::mptcp_listeners;
use repos::Repo;
use serde_json::Value;
use std::path::PathBuf;

pub mod documents;
pub mod extensions;
pub mod hidden_text;
pub mod hooks;
pub mod images;
pub mod install_scripts;
pub mod leaks;
pub mod licenses;
pub mod malicious;
pub mod mcp;
pub mod mptcp;
pub mod projects;
pub mod repos;
pub mod suspect_code;
#[cfg(test)]
pub(crate) mod testing;
pub mod typosquat;

pub const GITLEAKS_INSTALL: &str = "https://github.com/gitleaks/gitleaks#installing";
/// How the report names the policy files (their paths vary; the flag doesn't).
pub const LICENSES: &str = "the licenses allowlist (--licenses)";
pub const INSTALL_SCRIPTS: &str = "the install-scripts allowlist (--install-scripts)";

/// The repo checks always; the editor, harness and breach checks only on a
/// machine scan. `found` is what the machine inventory found.
pub fn run(scan: &mut Scan, found: &[Component]) -> Result<()> {
    run_with(scan, found, which("gitleaks"), crate::checks::machine::images::engine())
}

/// As [`run`], with the gitleaks binary and the container engine given
/// (None: not installed).
pub fn run_with(
    scan: &mut Scan,
    found: &[Component],
    gitleaks: Option<PathBuf>,
    engine: Option<PathBuf>,
) -> Result<()> {
    let repos = scan.repos.clone();
    let git: Vec<Repo> = repos.iter().filter(|(_, r)| repos::is_git(r)).cloned().collect();
    // gitleaks is local and CPU-bound: the repos whose cached scan is stale
    // are scanned, a few at once, while `projects` waits on the network.
    let jobs = secret_jobs(scan, &git, gitleaks)?;
    let todo: Vec<(usize, &leaks::Job)> = jobs
        .iter()
        .enumerate()
        .filter_map(|(i, (j, stale))| j.as_ref().ok().filter(|_| *stale).map(|j| (i, j)))
        .collect();
    let ran = std::thread::scope(|s| -> Result<Vec<Option<Result<Value>>>> {
        let at_once = gitleaks_at_once(scan);
        let todo = &todo;
        let running = s.spawn(move || parallel::par_map(todo, at_once, |(_, job)| leaks::run_job(job)));
        projects::projects(scan, &repos)?;
        if !todo.is_empty() {
            scan.status(&format!("Scanning {} repos' git history for secrets (gitleaks)", todo.len()));
        }
        let mut ran: Vec<Option<Result<Value>>> = jobs.iter().map(|_| None).collect();
        let results = running.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        for ((i, _), r) in todo.iter().zip(results) {
            ran[*i] = Some(r);
        }
        Ok(ran)
    })?;
    secrets(scan, &git, jobs, ran)?;
    repo_hooks(scan, &git);
    hidden_text::hidden_text(scan, &git);
    suspect_code::suspect_code(scan, &git);
    mptcp_listeners(scan, &repos);
    documents_pass(scan, &repos);
    install_scripts::install_scripts(scan, &repos, found);
    images_with(scan, &repos, engine)?;
    let exts = if scan.opts.machine { extensions::extensions(scan)? } else { Vec::new() };
    let refs = mcp::mcp(scan, &repos)?;
    if scan.opts.machine {
        bundles(scan, &exts)?;
    }
    let mut known: Vec<Component> = found.to_vec();
    known.extend(exts);
    sweep(scan, &known, &refs)?;
    if scan.opts.machine {
        breach(scan)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::supply_chain::testing;
    use crate::checks::supply_chain::testing::CARGO_LOCK;
    use crate::checks::{Options, REMOVE};
    use crate::utils::temp::TempDir;
    use serde_json::json;

    /// The whole pass over one repo, with gitleaks scanning ahead of the
    /// network: lockfile hits, the secret it found, the sweep against the
    /// malicious index; and once more as a machine scan with nothing
    /// installed under a private home.
    #[cfg(unix)]
    #[test]
    fn run_scans_the_repos_with_gitleaks_ahead() {
        let _home = crate::utils::files::test_home();
        let d = TempDir::new("run").unwrap();
        testing::seed_index(&d, &[("npm", "evil", "MAL-0001")]);
        let net = testing::osv_net(&[("crates.io", "serde")]);
        let mut s = testing::scan(&net, &d, Options { jobs: Some(1), ..Default::default() });
        let (name, root) = testing::repo(&d, "app");
        testing::write(&root, ".git/HEAD", format!("{}\n", "a".repeat(40)));
        testing::write(&root, "Cargo.lock", CARGO_LOCK);
        s.repos = vec![(name, root.clone())];
        let report = json!([{"RuleID": "github-pat", "File": "x.env", "StartLine": 1, "Commit": "0123456789abcdef",
                            "Fingerprint": "fp1", "Description": "GitHub"}]);
        let exe = testing::script(
            d.path(),
            "gitleaks",
            &format!(
                "#!/bin/sh\nif [ \"$1\" = version ]; then echo 8.21.2; exit 0; fi\nprev=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = --report-path ]; then printf '%s' '{report}' > \"$a\"; fi; prev=\"$a\"; done\n"
            ),
        );
        run_with(&mut s, &[], Some(exe), None).unwrap();
        assert_eq!(testing::by_id(&s, "GHSA-serde").len(), 1, "{:?}", s.findings);
        let pat = testing::by_id(&s, "github-pat");
        assert_eq!(pat.len(), 1, "{:?}", s.findings);
        assert_eq!((pat[0].component.as_str(), pat[0].status.as_str()), ("app/x.env", "fail"));
        for what in [
            "repos scanned for secrets",
            "repos checked for hooks",
            "repos checked for suspicious code",
            "repos checked for hidden text",
            "repos checked for documents and images",
        ] {
            assert!(s.counts.contains(&(what.to_string(), 1)), "{what}: {:?}", s.counts);
        }
        assert!(testing::unchecked(&s).is_empty(), "{:?}", s.findings);
        // A machine scan: the editor, bundle and breach steps run over an empty home.
        let net = testing::osv_net(&[]);
        let mut s = testing::scan(&net, &d, Options { machine: true, jobs: Some(1), ..Default::default() });
        s.repos = vec![];
        let mut npm = Component::new("manager", "npm", "10.0.0", "");
        npm.osv = Some(("npm".into(), "evil".into(), "1.0.0".into()));
        run_with(&mut s, &[npm], None, None).unwrap();
        let mal = testing::by_id(&s, "MAL-0001");
        assert_eq!(mal.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (mal[0].status.as_str(), mal[0].severity.as_str(), mal[0].note.as_str()),
            ("fail", "MALICIOUS", "MAL-0001 is malicious")
        );
        assert_eq!(mal[0].fix_cmd, REMOVE.replace("{}", "evil"));
        assert!(mal[0].kev);
    }
}
