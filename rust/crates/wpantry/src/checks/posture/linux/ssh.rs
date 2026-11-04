//! The ssh server: no root login, keys only.

use super::super::{Check, Outcome, Runner, Severity, admin};
use super::{ETC, text};
use std::path::Path;

fn sshd_config(etc: &Path) -> String {
    let mut all = text(&etc.join("ssh/sshd_config"));
    if let Ok(rd) = std::fs::read_dir(etc.join("ssh/sshd_config.d")) {
        let mut extra: Vec<_> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "conf"))
            .collect();
        extra.sort();
        for p in extra {
            all.push('\n');
            all.push_str(&text(&p));
        }
    }
    all
}

fn setting(config: &str, key: &str) -> Option<String> {
    config
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()?.eq_ignore_ascii_case(key)).then(|| w.next().unwrap_or("").to_ascii_lowercase())
        })
        .next()
}

fn ssh_running(r: Runner) -> bool {
    ["ssh", "sshd"].iter().any(|u| r(&["systemctl", "is-active", u]).trim() == "active")
}

fn ssh_root_login(r: Runner) -> Outcome {
    ssh_root_login_in(r, Path::new(ETC))
}

fn ssh_root_login_in(r: Runner, etc: &Path) -> Outcome {
    if !ssh_running(r) {
        return Outcome::pass("no ssh server is running");
    }
    let cfg = sshd_config(etc);
    if cfg.trim().is_empty() {
        return Outcome::manual("sshd is running and its config can't be read here");
    }
    match setting(&cfg, "PermitRootLogin").as_deref() {
        Some("no") => Outcome::pass("PermitRootLogin no"),
        Some("prohibit-password") | Some("without-password") => Outcome::pass("PermitRootLogin prohibit-password"),
        Some(v) => Outcome::fail(format!("PermitRootLogin {v}")),
        None => Outcome::fail("PermitRootLogin is unset (the default allows root with a key)"),
    }
}

fn ssh_passwords(r: Runner) -> Outcome {
    ssh_passwords_in(r, Path::new(ETC))
}

fn ssh_passwords_in(r: Runner, etc: &Path) -> Outcome {
    if !ssh_running(r) {
        return Outcome::pass("no ssh server is running");
    }
    let cfg = sshd_config(etc);
    if cfg.trim().is_empty() {
        return Outcome::manual("sshd is running and its config can't be read here");
    }
    match setting(&cfg, "PasswordAuthentication").as_deref() {
        Some("no") => Outcome::pass("PasswordAuthentication no"),
        Some(v) => Outcome::fail(format!("PasswordAuthentication {v}")),
        None => Outcome::fail("PasswordAuthentication is unset (the default allows passwords)"),
    }
}

pub(super) const SSH_ROOT: Check = Check {
    id: "POSTURE-SSH-ROOT",
    cis: "5.2.8",
    title: "ssh: no root login",
    severity: Severity::High,
    probe: ssh_root_login,
    fix: admin(
        "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-hardening.conf && sudo systemctl reload ssh",
    ),
    explain: "root can't be brute-forced over ssh",
};

pub(super) const SSH_PASSWORDS: Check = Check {
    id: "POSTURE-SSH-PASSWORDS",
    cis: "5.2.10",
    title: "ssh: keys only, no passwords",
    severity: Severity::High,
    probe: ssh_passwords,
    fix: admin(
        "echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/10-hardening.conf && sudo systemctl reload ssh  (after your key is installed)",
    ),
    explain: "Passwords can't be guessed over ssh",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::posture::Status;
    use crate::checks::posture::testing::etc;
    use crate::checks::posture::testing::machine;

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
}
