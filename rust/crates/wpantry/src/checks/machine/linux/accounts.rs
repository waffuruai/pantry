//! Who can sit down at the machine or become root: automatic login and
//! passwordless sudo.

use super::{ETC, text};
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};
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
#[path = "accounts_tests.rs"]
mod tests;
