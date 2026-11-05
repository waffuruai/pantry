//! FileVault.

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

fn filevault(r: Runner) -> Outcome {
    let out = r(&["fdesetup", "status"]);
    let line = out.lines().next().unwrap_or("").trim();
    if line.contains("FileVault is On") {
        Outcome::pass(line)
    } else if line.contains("FileVault is Off") {
        Outcome::fail(line)
    } else {
        Outcome::unknown(if line.is_empty() { "fdesetup gave no answer" } else { line })
    }
}

pub(super) const FILEVAULT: Check = Check {
    id: "POSTURE-FILEVAULT",
    cis: "2.6.1.1",
    title: "FileVault disk encryption",
    severity: Severity::Critical,
    probe: filevault,
    fix: admin("System Settings → Privacy & Security → FileVault → Turn On (or: sudo fdesetup enable)"),
    explain: "A lost or stolen Mac gives up everything on it without encryption",
};
