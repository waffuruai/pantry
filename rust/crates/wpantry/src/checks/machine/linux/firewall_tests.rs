use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

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
