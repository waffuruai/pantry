//! Automatic security updates.

use super::{ETC, text};
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};
use std::path::Path;

fn unattended_upgrades(r: Runner) -> Outcome {
    unattended_upgrades_in(r, Path::new(ETC))
}

fn unattended_upgrades_in(r: Runner, etc: &Path) -> Outcome {
    let apt = text(&etc.join("apt/apt.conf.d/20auto-upgrades"));
    if !apt.is_empty() {
        let on = apt.lines().any(|l| l.contains("Unattended-Upgrade") && l.contains("\"1\""));
        return Outcome::of(
            on,
            if on { "unattended-upgrades is on" } else { "unattended-upgrades is off in 20auto-upgrades" },
        );
    }
    for timer in
        ["dnf-automatic.timer", "dnf-automatic-install.timer", "unattended-upgrades.service", "apt-daily-upgrade.timer"]
    {
        let out = r(&["systemctl", "is-enabled", timer]);
        if out.trim() == "enabled" {
            return Outcome::pass(format!("{timer} is enabled"));
        }
    }
    if etc.join("apt").is_dir() || etc.join("dnf").is_dir() {
        return Outcome::fail("no automatic security updates are configured");
    }
    Outcome::manual("automatic updates: not a Debian or Red Hat family system; check your distro's way")
}

pub(super) const AUTO_UPDATES: Check = Check {
    id: "POSTURE-AUTO-UPDATES",
    cis: "1.9",
    title: "Automatic security updates",
    severity: Severity::High,
    probe: unattended_upgrades,
    fix: admin(
        "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades  (dnf: sudo systemctl enable --now dnf-automatic-install.timer)",
    ),
    explain: "Security fixes install on their own",
};

#[cfg(test)]
#[path = "updates_tests.rs"]
mod tests;
