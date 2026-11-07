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
use crate::error::{Error, Result};
use crate::utils::parallel;
use documents::documents_pass;
use extensions::bundles;
use hooks::repo_hooks;
use images::images_with;
use leaks::{scans_at_once, secret_jobs, secrets};
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

/// How the report names the policy files (their paths vary; the flag doesn't).
pub const LICENSES: &str = "the licenses allowlist (--licenses)";
pub const INSTALL_SCRIPTS: &str = "the install-scripts allowlist (--install-scripts)";

/// The repo checks always; the editor, harness and breach checks only on a
/// machine scan. `found` is what the machine inventory found.
pub fn run(scan: &mut Scan, found: &[Component]) -> Result<()> {
    run_with(scan, found, crate::checks::machine::images::engine())
}

/// As [`run`], with the container engine given (None: not installed).
pub fn run_with(scan: &mut Scan, found: &[Component], engine: Option<PathBuf>) -> Result<()> {
    let repos = scan.repos.clone();
    let git: Vec<Repo> = repos.iter().filter(|(_, r)| repos::is_git(r)).cloned().collect();
    // The secret scan is local and CPU-bound: the repos whose cached scan is
    // stale are scanned, a few at once, while `projects` waits on the network.
    let rules = leaks::Rules::new(scan.opts.policy.secret_rules()?);
    let jobs = secret_jobs(scan, &git, &rules)?;
    let todo: Vec<(usize, &leaks::Job)> = jobs
        .iter()
        .enumerate()
        .filter_map(|(i, (j, stale))| j.as_ref().ok().filter(|_| *stale).map(|j| (i, j)))
        .collect();
    // The rules compile only when a repo needs scanning.
    let scanner = if todo.is_empty() { None } else { Some(rules.scanner()?) };
    let ran = std::thread::scope(|s| -> Result<Vec<Option<Result<Value>>>> {
        let at_once = scans_at_once(scan);
        let todo = &todo;
        let scanner = scanner.as_ref();
        let running = s.spawn(move || {
            parallel::par_map(todo, at_once, |(_, job)| match scanner {
                Some(sc) => leaks::run_job(job, sc),
                None => Err(Error::Failed("no secret rules".into())),
            })
        });
        projects::projects(scan, &repos)?;
        if !todo.is_empty() {
            scan.status(&format!("Scanning {} repos' git history for secrets", todo.len()));
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
mod tests;
