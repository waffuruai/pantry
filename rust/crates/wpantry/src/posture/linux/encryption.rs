//! Disk encryption (LUKS).

use super::super::{Check, Outcome, Runner, Severity, admin};

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
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn luks_volume_or_none() {
        assert_eq!(
            disk_encryption(&machine(&[("lsblk", "disk\npart crypto_LUKS\ncrypt ext4\n")])).status,
            Status::Pass
        );
        assert_eq!(disk_encryption(&machine(&[("lsblk", "disk\npart ext4\n")])).status, Status::Fail);
        assert_eq!(disk_encryption(&machine(&[])).status, Status::Unknown);
    }
}
