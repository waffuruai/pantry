//! The host firewall: ufw, firewalld, nftables or iptables.

use super::super::{Check, Outcome, Runner, Severity, admin};

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
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn firewall_tools_in_order() {
        assert_eq!(firewall(&machine(&[("ufw status", "Status: active\n")])).status, Status::Pass);
        assert_eq!(firewall(&machine(&[("ufw status", "Status: inactive\n")])).status, Status::Fail);
        assert_eq!(firewall(&machine(&[("firewall-cmd --state", "running\n")])).status, Status::Pass);
        assert_eq!(
            firewall(&machine(&[(
                "nft list ruleset",
                "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0;\n\t}\n}\n"
            )]))
            .status,
            Status::Pass
        );
        assert_eq!(firewall(&machine(&[("iptables -S INPUT", "-P INPUT ACCEPT\n")])).status, Status::Fail);
        assert_eq!(firewall(&machine(&[])).status, Status::Unknown);
    }

    #[test]
    fn firewalld_off_and_iptables_policies() {
        assert_eq!(firewall(&machine(&[("firewall-cmd --state", "not running\n")])).status, Status::Fail);
        assert_eq!(firewall(&machine(&[("iptables -S INPUT", "-P INPUT DROP\n")])).status, Status::Pass);
        assert_eq!(
            firewall(&machine(&[("iptables -S INPUT", "-P INPUT ACCEPT\n-A INPUT -j DROP\n")])).status,
            Status::Pass
        );
    }
}
