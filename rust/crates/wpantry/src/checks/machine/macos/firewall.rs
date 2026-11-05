//! The application firewall: on, stealth mode, and logging.

use super::read;
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin, flag};

/// socketfilterfw says "enabled"/"disabled" on older macOS and "is on"/"is
/// off" on newer ones.
fn on_off(line: &str, what: &str) -> Outcome {
    let l = line.to_ascii_lowercase();
    if l.contains("disabled") || l.contains(" off") {
        Outcome::fail(line)
    } else if l.contains("enabled") || l.contains(" on") {
        Outcome::pass(line)
    } else {
        Outcome::unknown(if line.is_empty() { format!("{what} gave no answer") } else { line.to_string() })
    }
}

fn firewall(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]);
    on_off(out.lines().next().unwrap_or("").trim(), "socketfilterfw")
}

fn stealth(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]);
    on_off(out.lines().next().unwrap_or("").trim(), "socketfilterfw")
}

/// The application firewall logs what it blocks. `--getloggingmode` went
/// away in macOS 15; since then only a configuration profile
/// (`com.apple.security.firewall` `EnableLogging`) sets it.
fn firewall_logging(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getloggingmode"]);
    if let Some(line) = out.lines().find(|l| l.contains("Log mode")) {
        return on_off(line.trim(), "socketfilterfw");
    }
    let managed = read(r, "/Library/Managed Preferences/com.apple.security.firewall", "EnableLogging");
    match flag(&managed) {
        Some(true) => Outcome::pass("firewall logging is on (configuration profile)"),
        Some(false) => Outcome::fail("firewall logging is off (configuration profile)"),
        None => Outcome::manual(
            "no configuration profile turns firewall logging on (com.apple.security.firewall EnableLogging); this macOS has no other switch for it",
        ),
    }
}

pub(super) const FIREWALL: Check = Check {
    id: "POSTURE-FIREWALL",
    cis: "2.2.1",
    title: "Application firewall",
    severity: Severity::Critical,
    probe: firewall,
    fix: admin("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
    explain: "Blocks incoming connections to programs that didn't ask for them",
};

pub(super) const STEALTH: Check = Check {
    id: "POSTURE-STEALTH",
    cis: "2.2.2",
    title: "Firewall stealth mode",
    severity: Severity::Medium,
    probe: stealth,
    fix: admin("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"),
    explain: "The Mac stops answering probes (ping, port scans)",
};

pub(super) const FIREWALL_LOGGING: Check = Check {
    id: "POSTURE-FIREWALL-LOGGING",
    cis: "3.6",
    title: "Firewall logging",
    severity: Severity::Low,
    probe: firewall_logging,
    fix: admin(
        "Install a configuration profile with a com.apple.security.firewall payload setting EnableLogging true and LoggingOption detail (or, before macOS 15: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on)",
    ),
    explain: "What the firewall blocks is on record when something tries to get in",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::machine::settings::Status;
    use crate::checks::machine::testing::machine;

    #[test]
    fn firewall_logging_by_socketfilterfw_or_profile() {
        // Firewall logging after macOS 15: a profile, or nothing to read.
        let profile = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n"), ("EnableLogging", "1\n")]);
        assert_eq!(firewall_logging(&profile).status, Status::Pass);
        let none = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n")]);
        assert_eq!(firewall_logging(&none).status, Status::Manual);
    }
}
