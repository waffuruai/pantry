use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::etc;
use crate::checks::machine::testing::machine;

#[test]
fn ssh_settings_read_the_config_text() {
    let cfg = "# comment\nPort 22\npermitrootlogin prohibit-password\nPasswordAuthentication yes\n";
    assert_eq!(setting(cfg, "PermitRootLogin").as_deref(), Some("prohibit-password"));
    assert_eq!(setting(cfg, "PasswordAuthentication").as_deref(), Some("yes"));
    assert_eq!(setting(cfg, "Missing"), None);
    // No sshd: nothing to harden.
    assert_eq!(ssh_root_login(&machine(&[("is-active", "inactive\n")])).status, Status::Pass);
}

#[test]
fn ssh_settings_from_sshd_config_and_its_drop_ins() {
    let running = machine(&[("is-active ssh", "active\n")]);
    let d = etc(&[
        ("ssh/sshd_config", "# default\nPermitRootLogin yes\nPasswordAuthentication yes\n"),
        ("ssh/sshd_config.d/10-hardening.conf", "PermitRootLogin no\n"),
        ("ssh/sshd_config.d/notes.txt", "PasswordAuthentication no\n"),
    ]);
    assert_eq!(sshd_config(d.path()).matches("PermitRootLogin").count(), 2, "only .conf drop-ins");
    // The main file's setting comes first, as sshd reads it (Include is at its top on Debian).
    let o = ssh_root_login_in(&running, d.path());
    assert_eq!((o.status, o.evidence.as_str()), (Status::Fail, "PermitRootLogin yes"));
    assert_eq!(ssh_passwords_in(&running, d.path()).status, Status::Fail);
    let hardened = etc(&[("ssh/sshd_config", "PermitRootLogin prohibit-password\nPasswordAuthentication no\n")]);
    assert_eq!(ssh_root_login_in(&running, hardened.path()).status, Status::Pass);
    assert_eq!(ssh_passwords_in(&running, hardened.path()).status, Status::Pass);
    let no = etc(&[("ssh/sshd_config", "PermitRootLogin no\n")]);
    assert_eq!(ssh_root_login_in(&running, no.path()).status, Status::Pass);
    let unset = etc(&[("ssh/sshd_config", "Port 22\n")]);
    assert!(ssh_root_login_in(&running, unset.path()).evidence.contains("unset"));
    assert!(ssh_passwords_in(&running, unset.path()).evidence.contains("unset"));
    let unreadable = etc(&[]);
    assert_eq!(ssh_root_login_in(&running, unreadable.path()).status, Status::Manual);
    assert_eq!(ssh_passwords_in(&running, unreadable.path()).status, Status::Manual);
    let stopped = machine(&[("is-active", "inactive\n")]);
    assert_eq!(ssh_passwords(&stopped).status, Status::Pass);
}
