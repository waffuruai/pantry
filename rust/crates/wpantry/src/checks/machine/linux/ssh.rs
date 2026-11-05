//! The ssh server: no root login, keys only.

use super::{ETC, text};
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};
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
#[path = "ssh_tests.rs"]
mod tests;
