use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::etc;
use crate::checks::machine::testing::machine;

#[test]
fn automatic_updates_from_apt_config_then_timers() {
    let none = machine(&[]);
    let on = etc(&[(
        "apt/apt.conf.d/20auto-upgrades",
        "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
    )]);
    assert_eq!(unattended_upgrades_in(&none, on.path()).status, Status::Pass);
    let off = etc(&[("apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"0\";\n")]);
    assert_eq!(unattended_upgrades_in(&none, off.path()).status, Status::Fail);
    let dnf = etc(&[("dnf/dnf.conf", "[main]\n")]);
    let timer = machine(&[("dnf-automatic-install.timer", "enabled\n")]);
    let o = unattended_upgrades_in(&timer, dnf.path());
    assert_eq!((o.status, o.evidence.as_str()), (Status::Pass, "dnf-automatic-install.timer is enabled"));
    assert_eq!(unattended_upgrades_in(&none, dnf.path()).status, Status::Fail);
    let other = etc(&[]);
    assert_eq!(unattended_upgrades_in(&none, other.path()).status, Status::Manual);
    // The real /etc: whatever this machine is, it answers.
    assert!(matches!(unattended_upgrades(&none).status, Status::Pass | Status::Fail | Status::Manual));
}
