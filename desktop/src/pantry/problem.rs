//! Scanner failures in plain words: what went wrong, what to do, and the
//! raw text under Show details.

use super::{
    CANCELLED, NEWER_FORMAT, START_FAILED, TIMED_OUT, UNEXPECTED, UNSUPPORTED, UNVERIFIED, clean,
};
use serde::Serialize;
use std::path::Path;

/// What went wrong, in words for people who never open a terminal. The
/// scanner's own text stays in `details`, shown behind "Show details".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// A message Pantry wrote itself, already plain.
    Notice,
    ScannerMissing,
    ScannerBlocked,
    Permission,
    Offline,
    VersionMismatch,
    Cancelled,
    TimedOut,
    /// A fix that was cancelled or ran out of time: it may have partly run.
    FixStopped,
    NeedsPassword,
    StaleFix,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Problem {
    pub kind: ProblemKind,
    pub summary: String,
    pub details: String,
}

impl Problem {
    pub fn notice(text: impl Into<String>) -> Self {
        Self {
            kind: ProblemKind::Notice,
            summary: text.into(),
            details: String::new(),
        }
    }

    pub fn missing(path: &Path) -> Self {
        Self {
            kind: ProblemKind::ScannerMissing,
            summary: "Pantry's scanner is missing. Reinstall Pantry to get it back.".into(),
            details: format!("Pantry looked for its scanner at {}.", path.display()),
        }
    }

    pub fn version_mismatch(scanner: &str) -> Self {
        Self {
            kind: ProblemKind::VersionMismatch,
            summary: format!(
                "This copy of Pantry has parts from two versions (app {}, scanner {scanner}). Reinstall Pantry so they match.",
                env!("CARGO_PKG_VERSION")
            ),
            details: String::new(),
        }
    }

    /// Map scanner output or a start error to a plain summary. Anything
    /// unrecognised becomes a generic summary with the raw text in details.
    pub fn from_scanner(raw: &str) -> Self {
        let lower = raw.to_lowercase();
        let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
        let (kind, summary) = if raw.starts_with(UNVERIFIED) {
            (ProblemKind::Failed, UNVERIFIED)
        } else if raw.starts_with(CANCELLED) {
            (ProblemKind::Cancelled, "Stopped. Nothing else was changed.")
        } else if raw.starts_with(TIMED_OUT) {
            (
                ProblemKind::TimedOut,
                "This took too long, so Pantry stopped it. Try again.",
            )
        } else if raw.starts_with(START_FAILED) && has(&["os error 2", "not found", "cannot find"])
        {
            (
                ProblemKind::ScannerMissing,
                "Pantry's scanner is missing. Reinstall Pantry to get it back.",
            )
        } else if raw.starts_with(START_FAILED) {
            (
                ProblemKind::ScannerBlocked,
                "Pantry's scanner could not start. Reinstall Pantry, or check that your security software allows it.",
            )
        } else if has(&["sudo:", "a password is required", "terminal is required"]) {
            (
                ProblemKind::NeedsPassword,
                "This fix needs your computer password, which Pantry does not ask for. Use the steps below to run it yourself.",
            )
        } else if has(&["newer scan"]) {
            (
                ProblemKind::StaleFix,
                "Pantry has newer results than this fix was checked against. Choose Fix it again to review it.",
            )
        } else if has(&[
            "permission denied",
            "os error 13",
            "access is denied",
            "operation not permitted",
        ]) {
            (
                ProblemKind::Permission,
                "Pantry was not allowed to read or change something. Check that you can open the folder, then try again.",
            )
        } else if has(&[
            "could not resolve",
            "failed to lookup address",
            "dns error",
            "network is unreachable",
            "connection refused",
            "no route to host",
            "error trying to connect",
            "temporary failure in name resolution",
            "nodename nor servname",
            "connection reset",
        ]) {
            (
                ProblemKind::Offline,
                "Pantry could not reach the internet to check for security notices. Check your connection, or scan with saved data.",
            )
        } else if raw.starts_with(UNEXPECTED) {
            (
                ProblemKind::Failed,
                "Pantry's scanner returned something unexpected. Show details to see what it said.",
            )
        } else if raw.starts_with(NEWER_FORMAT)
            || raw.starts_with(UNSUPPORTED)
            || has(&[
                "unexpected argument",
                "unrecognized option",
                "unknown command",
            ])
        {
            (
                ProblemKind::VersionMismatch,
                "Pantry's app and scanner are from different versions. Reinstall Pantry so they match.",
            )
        } else {
            (
                ProblemKind::Failed,
                "Pantry could not finish this task. Show details to see what the scanner said.",
            )
        };
        // Details that only repeat the summary would be a second copy.
        let details = if raw.trim() == summary {
            String::new()
        } else {
            clean(raw.trim())
        };
        Self {
            kind,
            summary: summary.into(),
            details,
        }
    }

    /// A scan's problem: a scan that ran out of time can cover less.
    pub fn for_scan(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        if problem.kind == ProblemKind::TimedOut {
            problem.summary =
                "This scan took too long, so Pantry stopped it. Try again. If it happens again, scan fewer folders at a time."
                    .into();
        }
        problem
    }

    /// A fix's problem: one that was stopped part way may have changed
    /// something, so it says so and offers Scan now.
    pub fn for_fix(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        let stopped = match problem.kind {
            ProblemKind::Cancelled => "You stopped the fix",
            ProblemKind::TimedOut => "The fix took too long, so Pantry stopped it",
            _ => return problem,
        };
        problem.kind = ProblemKind::FixStopped;
        problem.summary = format!(
            "{stopped}. It may have partly run. Choose Scan now to see where things stand."
        );
        problem
    }

    /// An update check's problem, in words about updates, not about
    /// security notices or saved data.
    pub fn for_update(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        problem.summary = match problem.kind {
            ProblemKind::Offline => {
                "Pantry could not reach the internet to check for updates. Check your connection, then try again."
            }
            ProblemKind::Cancelled | ProblemKind::TimedOut => {
                "Pantry stopped checking for updates. Try again later."
            }
            ProblemKind::Notice
            | ProblemKind::ScannerMissing
            | ProblemKind::ScannerBlocked
            | ProblemKind::VersionMismatch => return problem,
            _ => "Pantry could not check for updates. Show details to see what the scanner said.",
        }
        .into();
        // Not an Offline banner: "Scan with saved data" is no answer here.
        if problem.kind == ProblemKind::Offline {
            problem.kind = ProblemKind::Failed;
        }
        problem
    }

    /// True when "Download Pantry" is the way out.
    pub fn needs_reinstall(&self) -> bool {
        matches!(
            self.kind,
            ProblemKind::ScannerMissing
                | ProblemKind::ScannerBlocked
                | ProblemKind::VersionMismatch
        )
    }
}

#[cfg(test)]
#[path = "problem_tests.rs"]
mod tests;
