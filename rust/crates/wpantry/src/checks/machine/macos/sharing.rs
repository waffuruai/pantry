//! What the Mac offers the network or people nearby: Remote Login, Screen
//! and File Sharing, Remote Apple Events and Management, Internet,
//! Printer and Bluetooth Sharing, and AirDrop.

use super::{read, read_host};
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin, flag, launchd_disabled, user};

fn sharing(r: Runner, label: &str, what: &str) -> Outcome {
    let listing = r(&["launchctl", "print-disabled", "system"]);
    if listing.trim().is_empty() {
        return Outcome::unknown("launchctl print-disabled gave no answer");
    }
    match launchd_disabled(&listing, label) {
        Some(true) => Outcome::pass(format!("{what} is off")),
        Some(false) => Outcome::fail(format!("{what} is on")),
        // Not listed: never enabled on this system.
        None => Outcome::pass(format!("{what} is off (never enabled)")),
    }
}

fn remote_login(r: Runner) -> Outcome {
    sharing(r, "com.openssh.sshd", "Remote Login (ssh)")
}

fn screen_sharing(r: Runner) -> Outcome {
    sharing(r, "com.apple.screensharing", "Screen Sharing")
}

fn file_sharing(r: Runner) -> Outcome {
    sharing(r, "com.apple.smbd", "File Sharing (smb)")
}

fn remote_events(r: Runner) -> Outcome {
    sharing(r, "com.apple.AEServer", "Remote Apple Events")
}

fn remote_management(r: Runner) -> Outcome {
    let out = r(&["pgrep", "-x", "ARDAgent"]);
    Outcome::of(
        out.trim().is_empty(),
        if out.trim().is_empty() { "Remote Management is off" } else { "Remote Management (ARDAgent) is running" },
    )
}

fn internet_sharing(r: Runner) -> Outcome {
    let out = r(&["defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"]);
    if out.contains("does not exist") || out.trim().is_empty() {
        return Outcome::pass("Internet Sharing is off (never enabled)");
    }
    let on = out.lines().any(|l| l.replace(' ', "").starts_with("Enabled=1"));
    Outcome::of(!on, if on { "Internet Sharing is on" } else { "Internet Sharing is off" })
}

fn printer_sharing(r: Runner) -> Outcome {
    let out = r(&["cupsctl"]);
    if out.trim().is_empty() {
        return Outcome::unknown("cupsctl gave no answer");
    }
    let on = out.lines().any(|l| l.trim() == "_share_printers=1");
    Outcome::of(!on, if on { "Printer Sharing is on" } else { "Printer Sharing is off" })
}

fn bluetooth_sharing(r: Runner) -> Outcome {
    match flag(&read_host(r, "com.apple.Bluetooth", "PrefKeyServicesEnabled")) {
        Some(true) => Outcome::fail("Bluetooth Sharing is on"),
        _ => Outcome::pass("Bluetooth Sharing is off"),
    }
}

/// AirDrop off, or receiving from contacts only: "Everyone" lets anyone
/// nearby push files (and their names) at the Mac.
fn airdrop(r: Runner) -> Outcome {
    if flag(&read(r, "com.apple.NetworkBrowser", "DisableAirDrop")) == Some(true) {
        return Outcome::pass("AirDrop is disabled");
    }
    let out = read(r, "com.apple.sharingd", "DiscoverableMode");
    let mode = out.trim();
    match mode {
        "Everyone" => Outcome::fail("AirDrop receives from everyone"),
        "Off" => Outcome::pass("AirDrop receiving is off"),
        "Contacts Only" => Outcome::pass("AirDrop receives from contacts only"),
        m if m.is_empty() || m.contains("does not exist") => {
            Outcome::pass("AirDrop receives from contacts only (default)")
        }
        m => Outcome::unknown(format!("AirDrop's mode reads {m}")),
    }
}

pub(super) const REMOTE_LOGIN: Check = Check {
    id: "POSTURE-REMOTE-LOGIN",
    cis: "2.3.3.4",
    title: "Remote Login (ssh) off",
    severity: Severity::Critical,
    probe: remote_login,
    fix: admin("sudo systemsetup -setremotelogin off  (System Settings → General → Sharing → Remote Login)"),
    explain: "No ssh server listening on a laptop",
};

pub(super) const SCREEN_SHARING: Check = Check {
    id: "POSTURE-SCREEN-SHARING",
    cis: "2.3.3.1",
    title: "Screen Sharing off",
    severity: Severity::High,
    probe: screen_sharing,
    fix: admin("System Settings → General → Sharing → Screen Sharing: off"),
    explain: "Nobody can take the screen over the network",
};

pub(super) const REMOTE_MANAGEMENT: Check = Check {
    id: "POSTURE-REMOTE-MANAGEMENT",
    cis: "2.3.3.5",
    title: "Remote Management off",
    severity: Severity::High,
    probe: remote_management,
    fix: admin("System Settings → General → Sharing → Remote Management: off"),
    explain: "No Apple Remote Desktop agent",
};

pub(super) const FILE_SHARING: Check = Check {
    id: "POSTURE-FILE-SHARING",
    cis: "2.3.3.2",
    title: "File Sharing off",
    severity: Severity::High,
    probe: file_sharing,
    fix: admin("System Settings → General → Sharing → File Sharing: off"),
    explain: "No smb shares offered to the network",
};

pub(super) const REMOTE_EVENTS: Check = Check {
    id: "POSTURE-REMOTE-EVENTS",
    cis: "2.3.3.6",
    title: "Remote Apple Events off",
    severity: Severity::Medium,
    probe: remote_events,
    fix: admin("sudo systemsetup -setremoteappleevents off"),
    explain: "Other Macs can't script this one",
};

pub(super) const INTERNET_SHARING: Check = Check {
    id: "POSTURE-INTERNET-SHARING",
    cis: "2.3.3.7",
    title: "Internet Sharing off",
    severity: Severity::High,
    probe: internet_sharing,
    fix: admin("System Settings → General → Sharing → Internet Sharing: off"),
    explain: "The Mac isn't a router for whoever joins",
};

pub(super) const PRINTER_SHARING: Check = Check {
    id: "POSTURE-PRINTER-SHARING",
    cis: "2.3.3.3",
    title: "Printer Sharing off",
    severity: Severity::Low,
    probe: printer_sharing,
    fix: admin("sudo cupsctl --no-share-printers"),
    explain: "No printers offered to the network",
};

pub(super) const BLUETOOTH_SHARING: Check = Check {
    id: "POSTURE-BLUETOOTH-SHARING",
    cis: "2.3.3.10",
    title: "Bluetooth Sharing off",
    severity: Severity::Low,
    probe: bluetooth_sharing,
    fix: user("defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"),
    explain: "No file exchange offered over Bluetooth",
};

pub(super) const AIRDROP: Check = Check {
    id: "POSTURE-AIRDROP",
    cis: "2.3.1.1",
    title: "AirDrop off or contacts only",
    severity: Severity::Medium,
    probe: airdrop,
    fix: user(
        "defaults write com.apple.sharingd DiscoverableMode -string \"Contacts Only\"  (Control Center → AirDrop → Contacts Only)",
    ),
    explain: "Strangers nearby can't push files at the Mac",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::machine::settings::Status;
    use crate::checks::machine::testing::machine;

    #[test]
    fn airdrop_disabled_off_or_never_set() {
        // AirDrop: disabled outright, off, or never set.
        assert_eq!(
            airdrop(&machine(&[("DisableAirDrop", "1\n"), ("DiscoverableMode", "Everyone\n")])).status,
            Status::Pass
        );
        assert_eq!(airdrop(&machine(&[("DiscoverableMode", "Off\n")])).status, Status::Pass);
        assert_eq!(airdrop(&machine(&[])).evidence, "AirDrop receives from contacts only (default)");
    }
}
