//! Who can sit down at the machine or become root: automatic login and
//! passwordless sudo.

use super::super::{Check, Outcome, Runner, Severity, admin};
use super::{ETC, text};
use std::path::Path;

fn auto_login(_: Runner) -> Outcome {
    auto_login_in(Path::new(ETC))
}

fn auto_login_in(etc: &Path) -> Outcome {
    for f in ["gdm3/custom.conf", "gdm/custom.conf"] {
        let t = text(&etc.join(f));
        if t.lines().any(|l| l.replace(' ', "").to_ascii_lowercase().starts_with("automaticloginenable=true")) {
            return Outcome::fail(format!("automatic login is on in {}", etc.join(f).display()));
        }
    }
    let lightdm = text(&etc.join("lightdm/lightdm.conf"));
    if lightdm
        .lines()
        .any(|l| l.trim_start().starts_with("autologin-user=") && l.trim().len() > "autologin-user=".len())
    {
        return Outcome::fail(format!("automatic login is on in {}", etc.join("lightdm/lightdm.conf").display()));
    }
    let sddm = text(&etc.join("sddm.conf"));
    if sddm.contains("[Autologin]") && sddm.lines().any(|l| l.trim_start().starts_with("User=") && l.trim().len() > 5) {
        return Outcome::fail(format!("automatic login is on in {}", etc.join("sddm.conf").display()));
    }
    Outcome::pass("no automatic login")
}

fn sudo_nopasswd(r: Runner) -> Outcome {
    let out = r(&["sudo", "-n", "-l"]);
    if out.contains("NOPASSWD") {
        Outcome::fail("sudo runs without a password for this user")
    } else {
        Outcome::pass("sudo asks for a password")
    }
}

pub(super) const AUTO_LOGIN: Check = Check {
    id: "POSTURE-AUTO-LOGIN",
    cis: "1.8",
    title: "Automatic login off",
    severity: Severity::Critical,
    probe: auto_login,
    fix: admin("Turn off automatic login in the display manager's config (gdm custom.conf, lightdm.conf, sddm.conf)"),
    explain: "Whoever turns the machine on is not logged in as you",
};

pub(super) const SUDO_NOPASSWD: Check = Check {
    id: "POSTURE-SUDO-NOPASSWD",
    cis: "5.3",
    title: "sudo asks for a password",
    severity: Severity::Medium,
    probe: sudo_nopasswd,
    fix: admin("Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/* (visudo)"),
    explain: "A stolen session can't become root silently",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::etc;
    use crate::posture::testing::machine;

    #[test]
    fn sudo_asks_or_not() {
        assert_eq!(
            sudo_nopasswd(&machine(&[(
                "sudo -n -l",
                "User eric may run the following commands:\n    (ALL) NOPASSWD: ALL\n"
            )]))
            .status,
            Status::Fail
        );
        assert_eq!(sudo_nopasswd(&machine(&[("sudo -n -l", "sudo: a password is required\n")])).status, Status::Pass);
    }

    #[test]
    fn automatic_login_in_display_manager_configs() {
        let r = machine(&[]);
        let gdm = etc(&[("gdm3/custom.conf", "[daemon]\nAutomaticLoginEnable = true\nAutomaticLogin = eric\n")]);
        let o = auto_login_in(gdm.path());
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("gdm3/custom.conf"), "{}", o.evidence);
        let gdm_off = etc(&[("gdm/custom.conf", "[daemon]\nAutomaticLoginEnable=false\n")]);
        assert_eq!(auto_login_in(gdm_off.path()).status, Status::Pass);
        let lightdm = etc(&[("lightdm/lightdm.conf", "[Seat:*]\nautologin-user=eric\n")]);
        assert!(auto_login_in(lightdm.path()).evidence.contains("lightdm.conf"));
        let lightdm_empty = etc(&[("lightdm/lightdm.conf", "[Seat:*]\nautologin-user=\n")]);
        assert_eq!(auto_login_in(lightdm_empty.path()).status, Status::Pass);
        let sddm = etc(&[("sddm.conf", "[Autologin]\nUser=eric\nSession=plasma\n")]);
        assert!(auto_login_in(sddm.path()).evidence.contains("sddm.conf"));
        let sddm_empty = etc(&[("sddm.conf", "[Autologin]\nUser=\n")]);
        assert_eq!(auto_login_in(sddm_empty.path()).status, Status::Pass);
        assert_eq!(
            auto_login(&r).status,
            Status::Pass,
            "this machine's /etc (a Mac or CI runner has no display manager autologin)"
        );
    }
}
