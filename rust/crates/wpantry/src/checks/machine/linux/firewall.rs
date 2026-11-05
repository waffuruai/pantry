//! The host firewall: ufw, firewalld, nftables or iptables.

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

fn firewall(r: Runner) -> Outcome {
    let ufw = r(&["ufw", "status"]);
    if ufw.contains("Status: active") {
        return Outcome::pass("ufw is active");
    }
    if ufw.contains("Status: inactive") {
        return Outcome::fail("ufw is installed but inactive");
    }
    let fwd = r(&["firewall-cmd", "--state"]);
    if fwd.trim() == "running" {
        return Outcome::pass("firewalld is running");
    }
    if fwd.contains("not running") {
        return Outcome::fail("firewalld is installed but not running");
    }
    let nft = r(&["nft", "list", "ruleset"]);
    if nft.contains("hook input") {
        return Outcome::pass("nftables has an input chain");
    }
    let ipt = r(&["iptables", "-S", "INPUT"]);
    if ipt.lines().any(|l| l.starts_with("-P INPUT DROP"))
        || ipt.lines().filter(|l| l.starts_with("-A INPUT")).count() > 0
    {
        return Outcome::pass("iptables filters INPUT");
    }
    if ufw.is_empty() && fwd.is_empty() && nft.is_empty() && ipt.is_empty() {
        return Outcome::unknown("no firewall tool answered (ufw, firewalld, nft, iptables)");
    }
    Outcome::fail("no firewall is filtering incoming connections")
}

pub(super) const FIREWALL: Check = Check {
    id: "POSTURE-FIREWALL",
    cis: "3.5",
    title: "Host firewall",
    severity: Severity::High,
    probe: firewall,
    fix: admin("sudo ufw enable  (or: sudo systemctl enable --now firewalld)"),
    explain: "Incoming connections are filtered",
};

#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
