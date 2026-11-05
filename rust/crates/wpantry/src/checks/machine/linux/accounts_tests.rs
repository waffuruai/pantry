use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::etc;
use crate::checks::machine::testing::machine;

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
