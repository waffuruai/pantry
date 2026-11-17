//! The machine's own security settings: disk encryption, the firewall,
//! Gatekeeper and SIP, automatic updates, remote access and sharing,
//! guest and automatic login, the screen lock, and the rest of what the
//! CIS benchmarks ask of a workstation. Each check is a read-only probe
//! (a `defaults read`, a `launchctl print-disabled`, a file) and, where
//! one exists, a fix: user-level ones may run unattended, the rest are
//! printed as a `sudo` step. The CIS Apple macOS and Linux benchmarks are
//! the references (README, acknowledgements).
//!
//! A failing Critical or High check fails the scan; Medium and Low warn;
//! a check that can't tell is reported as such, never as a pass.

use std::ffi::OsStr;
use std::time::Duration;

use super::{any, linux, macos};
use crate::checks::Scan;
use crate::finding::Finding;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    /// The check can't be read without rights we don't have, or needs a
    /// human's eyes.
    Manual,
    /// The probe gave no usable answer.
    Unknown,
}

/// What a probe found.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub status: Status,
    /// One line of what was read ("FileVault is Off").
    pub evidence: String,
}

impl Outcome {
    pub fn pass(evidence: impl Into<String>) -> Outcome {
        Outcome { status: Status::Pass, evidence: evidence.into() }
    }
    pub fn fail(evidence: impl Into<String>) -> Outcome {
        Outcome { status: Status::Fail, evidence: evidence.into() }
    }
    pub fn manual(evidence: impl Into<String>) -> Outcome {
        Outcome { status: Status::Manual, evidence: evidence.into() }
    }
    pub fn unknown(evidence: impl Into<String>) -> Outcome {
        Outcome { status: Status::Unknown, evidence: evidence.into() }
    }
    /// Pass or fail by `ok`.
    pub fn of(ok: bool, evidence: impl Into<String>) -> Outcome {
        if ok { Outcome::pass(evidence) } else { Outcome::fail(evidence) }
    }
}

/// How a failing check is put right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fix {
    /// The command, or the setting to change by hand.
    pub cmd: &'static str,
    /// Needs sudo or a system dialog: never unattended.
    pub admin: bool,
}

/// Runs commands for the probes: the real machine, or recorded output in
/// tests. Returns stdout and stderr together, "" when the command can't run.
pub type Runner<'a> = &'a (dyn Fn(&[&str]) -> String + Sync);

pub fn real_runner(argv: &[&str]) -> String {
    let argv: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
    crate::utils::process::run(&argv, Duration::from_secs(15))
}

/// A fix that needs an administrator: printed as a step, never run.
pub(crate) const fn admin(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: true })
}

/// A fix the user's own account can apply.
pub(crate) const fn user(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: false })
}

/// One check.
pub struct Check {
    /// Stable id (the finding's `vuln_id`): `POSTURE-FILEVAULT`.
    pub id: &'static str,
    /// The CIS benchmark item it follows, "" when none.
    pub cis: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub probe: fn(Runner) -> Outcome,
    pub fix: Option<Fix>,
    /// What the fix changes, for the report.
    pub explain: &'static str,
}

/// The checks for this OS, then the developer-tool ones every OS has.
pub fn checks() -> Vec<&'static Check> {
    let os: &'static [Check] = if cfg!(target_os = "macos") {
        macos::CHECKS
    } else if cfg!(target_os = "linux") {
        linux::CHECKS
    } else {
        &[]
    };
    os.iter().chain(any::dev_settings::CHECKS.iter()).collect()
}

/// Run every check not in `skip` (ids, case-insensitive).
pub fn run(skip: &[String], runner: Runner) -> Vec<(&'static Check, Outcome)> {
    let skipped = |id: &str| {
        skip.iter().any(|s| s.eq_ignore_ascii_case(id) || s.eq_ignore_ascii_case(id.trim_start_matches("POSTURE-")))
    };
    let todo: Vec<&'static Check> = checks().into_iter().filter(|c| !skipped(c.id)).collect();
    let outcomes = crate::utils::parallel::par_map(&todo, 4, |c| (c.probe)(runner));
    todo.into_iter().zip(outcomes).collect()
}

/// `defaults read domain key` parsed as a flag: Some(true) for 1/true/YES.
pub fn flag(out: &str) -> Option<bool> {
    let v = out.trim();
    if v.is_empty() || v.contains("does not exist") {
        return None;
    }
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// Whether `launchctl print-disabled` lists `label` as disabled; None
/// when it isn't listed at all.
pub fn launchd_disabled(listing: &str, label: &str) -> Option<bool> {
    let needle = format!("\"{label}\" => ");
    listing.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix(&needle).map(|rest| rest.trim().starts_with("disabled") || rest.trim() == "true")
    })
}

/// The machine's own security settings (`posture`): a failing Critical or
/// High check fails, the rest warn, a check that can't tell says so.
pub fn posture(scan: &mut Scan) {
    posture_with(scan, &crate::checks::machine::settings::real_runner)
}

/// The posture checks over `runner` (the real machine, or a recording).
fn posture_with(scan: &mut Scan, runner: crate::checks::machine::settings::Runner) {
    use crate::checks::machine::settings::{Severity, Status};
    scan.status("Checking the machine's security settings");
    let skip = scan.opts.policy.posture_skip();
    let results = run(&skip, runner);
    scan.count("security settings checked", results.len() as i64);
    for (c, o) in results {
        let (status, note) = match o.status {
            Status::Pass => continue,
            Status::Fail if matches!(c.severity, Severity::Critical | Severity::High) => ("fail", o.evidence),
            Status::Fail => ("warn", o.evidence),
            Status::Manual => ("warn", o.evidence),
            Status::Unknown => ("warn", format!("couldn't tell: {}", o.evidence)),
        };
        let (fix_cmd, fix_auto) = match &c.fix {
            Some(f) => (f.cmd.to_string(), !f.admin && o.status == Status::Fail),
            None => (c.explain.to_string(), false),
        };
        scan.add(Finding {
            kind: "posture".into(),
            component: c.title.into(),
            location: if c.cis.is_empty() { String::new() } else { format!("CIS {}", c.cis) },
            vuln_id: c.id.into(),
            status: status.into(),
            severity: c.severity.as_str().into(),
            note,
            fix_cmd,
            fix_auto,
            ..Default::default()
        });
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
