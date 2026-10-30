//! The machine's own security settings: disk encryption, the firewall,
//! Gatekeeper and SIP, automatic updates, remote access and sharing,
//! guest and automatic login, the screen lock, and the rest of what the
//! CIS benchmarks ask of a workstation. Each check is a read-only probe
//! (a `defaults read`, a `launchctl print-disabled`, a file) and, where
//! one exists, a fix: user-level ones may run unattended, the rest are
//! printed as a `sudo` step. Mergen (sametsazak/mergen, MIT) and the CIS
//! Apple macOS and Linux benchmarks are the references.
//!
//! A failing Critical or High check fails the scan; Medium and Low warn;
//! a check that can't tell is reported as such, never as a pass.

use std::ffi::OsStr;
use std::time::Duration;

pub mod linux;
pub mod macos;
pub mod tools;

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
    crate::system::run(&argv, Duration::from_secs(15))
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
    os.iter().chain(tools::CHECKS.iter()).collect()
}

/// Run every check not in `skip` (ids, case-insensitive).
pub fn run(skip: &[String], runner: Runner) -> Vec<(&'static Check, Outcome)> {
    let skipped = |id: &str| {
        skip.iter().any(|s| s.eq_ignore_ascii_case(id) || s.eq_ignore_ascii_case(id.trim_start_matches("POSTURE-")))
    };
    let todo: Vec<&'static Check> = checks().into_iter().filter(|c| !skipped(c.id)).collect();
    let outcomes = crate::system::par_map(&todo, 4, |c| (c.probe)(runner));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_launchd_listings_parse() {
        assert_eq!(flag("1\n"), Some(true));
        assert_eq!(flag("NO"), Some(false));
        assert_eq!(flag("2026-10-30 07:12:16 +0000: The domain/default pair of (x, y) does not exist"), None);
        assert_eq!(flag(""), None);
        let listing = "disabled services = {\n\t\"com.openssh.sshd\" => disabled\n\t\"com.apple.screensharing\" => enabled\n\t\"com.apple.smbd\" => true\n}\n";
        assert_eq!(launchd_disabled(listing, "com.openssh.sshd"), Some(true));
        assert_eq!(launchd_disabled(listing, "com.apple.screensharing"), Some(false));
        assert_eq!(launchd_disabled(listing, "com.apple.smbd"), Some(true));
        assert_eq!(launchd_disabled(listing, "com.apple.AEServer"), None);
    }

    #[test]
    fn skip_list_matches_ids_with_or_without_the_prefix() {
        let runner = |_: &[&str]| String::new();
        let all = run(&[], &runner).len();
        if all == 0 {
            return; // an OS without checks
        }
        let first = checks()[0].id;
        let _ = &first;
        let without: Vec<String> = vec![first.trim_start_matches("POSTURE-").to_ascii_lowercase()];
        assert_eq!(run(&without, &runner).len(), all - 1);
        let with: Vec<String> = vec![first.to_string()];
        assert_eq!(run(&with, &runner).len(), all - 1);
    }
}
