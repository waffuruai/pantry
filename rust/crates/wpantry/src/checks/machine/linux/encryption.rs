//! Disk encryption (LUKS).

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

fn disk_encryption(r: Runner) -> Outcome {
    let out = r(&["lsblk", "-o", "TYPE,FSTYPE", "--noheadings"]);
    if out.trim().is_empty() {
        return Outcome::unknown("lsblk gave no answer");
    }
    let encrypted = out.lines().any(|l| l.contains("crypt") || l.contains("crypto_LUKS"));
    Outcome::of(
        encrypted,
        if encrypted { "a LUKS (dm-crypt) volume is in use" } else { "no encrypted volume (LUKS) is in use" },
    )
}

pub(super) const DISK_ENCRYPTION: Check = Check {
    id: "POSTURE-DISK-ENCRYPTION",
    cis: "1.4",
    title: "Disk encryption (LUKS)",
    severity: Severity::Critical,
    probe: disk_encryption,
    fix: admin(
        "Encrypt the disk at install time (LUKS); on an installed system, back up and reinstall with encryption",
    ),
    explain: "A lost laptop gives up nothing",
};

#[cfg(test)]
#[path = "encryption_tests.rs"]
mod tests;
