//! Linux: the CIS Distribution Independent Linux items a user can read.
//! Files are read directly where a command would need root.

use super::{Check, Fix, Outcome, Runner, Severity};
use std::path::Path;

fn text(p: &str) -> String {
    crate::system::read_capped(Path::new(p), 1 << 20).unwrap_or_default()
}

fn disk_encryption(r: Runner) -> Outcome {
    let out = r(&["lsblk", "-o", "TYPE,FSTYPE", "--noheadings"]);
    if out.trim().is_empty() {
        return Outcome::unknown("lsblk gave no answer");
    }
    let encrypted = out.lines().any(|l| l.contains("crypt") || l.contains("crypto_LUKS"));
    Outcome::of(
        encrypted,
        if encrypted { "a LUKS (dm-crypt) volume is in use" } else { "no encrypted volume (LUKS) is in use" },
    )
}

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

fn unattended_upgrades(r: Runner) -> Outcome {
    let apt = text("/etc/apt/apt.conf.d/20auto-upgrades");
    if !apt.is_empty() {
        let on = apt.lines().any(|l| l.contains("Unattended-Upgrade") && l.contains("\"1\""));
        return Outcome::of(
            on,
            if on { "unattended-upgrades is on" } else { "unattended-upgrades is off in 20auto-upgrades" },
        );
    }
    for timer in
        ["dnf-automatic.timer", "dnf-automatic-install.timer", "unattended-upgrades.service", "apt-daily-upgrade.timer"]
    {
        let out = r(&["systemctl", "is-enabled", timer]);
        if out.trim() == "enabled" {
            return Outcome::pass(format!("{timer} is enabled"));
        }
    }
    if Path::new("/etc/apt").is_dir() || Path::new("/etc/dnf").is_dir() {
        return Outcome::fail("no automatic security updates are configured");
    }
    Outcome::manual("automatic updates: not a Debian or Red Hat family system; check your distro's way")
}

fn sshd_config() -> String {
    let mut all = text("/etc/ssh/sshd_config");
    if let Ok(rd) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut extra: Vec<_> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "conf"))
            .collect();
        extra.sort();
        for p in extra {
            all.push('\n');
            all.push_str(&text(&p.to_string_lossy()));
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
    if !ssh_running(r) {
        return Outcome::pass("no ssh server is running");
    }
    let cfg = sshd_config();
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
    if !ssh_running(r) {
        return Outcome::pass("no ssh server is running");
    }
    let cfg = sshd_config();
    if cfg.trim().is_empty() {
        return Outcome::manual("sshd is running and its config can't be read here");
    }
    match setting(&cfg, "PasswordAuthentication").as_deref() {
        Some("no") => Outcome::pass("PasswordAuthentication no"),
        Some(v) => Outcome::fail(format!("PasswordAuthentication {v}")),
        None => Outcome::fail("PasswordAuthentication is unset (the default allows passwords)"),
    }
}

fn auto_login(_: Runner) -> Outcome {
    for f in ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"] {
        let t = text(f);
        if t.lines().any(|l| l.replace(' ', "").to_ascii_lowercase().starts_with("automaticloginenable=true")) {
            return Outcome::fail(format!("automatic login is on in {f}"));
        }
    }
    let lightdm = text("/etc/lightdm/lightdm.conf");
    if lightdm
        .lines()
        .any(|l| l.trim_start().starts_with("autologin-user=") && l.trim().len() > "autologin-user=".len())
    {
        return Outcome::fail("automatic login is on in /etc/lightdm/lightdm.conf");
    }
    let sddm = text("/etc/sddm.conf");
    if sddm.contains("[Autologin]") && sddm.lines().any(|l| l.trim_start().starts_with("User=") && l.trim().len() > 5) {
        return Outcome::fail("automatic login is on in /etc/sddm.conf");
    }
    Outcome::pass("no automatic login")
}

fn mandatory_access_control(r: Runner) -> Outcome {
    let aa = r(&["aa-enabled"]);
    if aa.trim().starts_with("Yes") {
        return Outcome::pass("AppArmor is enabled");
    }
    let se = r(&["getenforce"]);
    match se.trim() {
        "Enforcing" => Outcome::pass("SELinux is enforcing"),
        "Permissive" => Outcome::fail("SELinux is permissive"),
        "Disabled" => Outcome::fail("SELinux is disabled"),
        _ if aa.trim().starts_with("No") => Outcome::fail("AppArmor is installed but not enabled"),
        _ => Outcome::manual("neither AppArmor nor SELinux answered"),
    }
}

fn sudo_nopasswd(r: Runner) -> Outcome {
    let out = r(&["sudo", "-n", "-l"]);
    if out.contains("NOPASSWD") {
        Outcome::fail("sudo runs without a password for this user")
    } else {
        Outcome::pass("sudo asks for a password")
    }
}

fn path_dirs(_: Runner) -> Outcome {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bad: Vec<String> = std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|d| !d.is_empty())
            .filter(|d| std::fs::metadata(d).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o002 != 0))
            .map(str::to_string)
            .collect();
        if bad.is_empty() {
            return Outcome::pass("no directory on PATH is writable by everyone");
        }
        return Outcome::fail(format!("writable by everyone and on PATH: {}", bad.join(", ")));
    }
    #[allow(unreachable_code)]
    Outcome::manual("not checked on this platform")
}

fn time_sync(r: Runner) -> Outcome {
    let out = r(&["timedatectl", "show", "-p", "NTPSynchronized", "--value"]);
    match out.trim() {
        "yes" => Outcome::pass("the clock is synchronised"),
        "no" => Outcome::fail("the clock is not synchronised (NTP off)"),
        _ => Outcome::unknown("timedatectl gave no answer"),
    }
}

const fn admin(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: true })
}

pub static CHECKS: &[Check] = &[
    Check {
        id: "POSTURE-DISK-ENCRYPTION",
        cis: "1.4",
        title: "Disk encryption (LUKS)",
        severity: Severity::Critical,
        probe: disk_encryption,
        fix: admin(
            "Encrypt the disk at install time (LUKS); on an installed system, back up and reinstall with encryption",
        ),
        explain: "A lost laptop gives up nothing",
    },
    Check {
        id: "POSTURE-FIREWALL",
        cis: "3.5",
        title: "Host firewall",
        severity: Severity::High,
        probe: firewall,
        fix: admin("sudo ufw enable  (or: sudo systemctl enable --now firewalld)"),
        explain: "Incoming connections are filtered",
    },
    Check {
        id: "POSTURE-AUTO-UPDATES",
        cis: "1.9",
        title: "Automatic security updates",
        severity: Severity::High,
        probe: unattended_upgrades,
        fix: admin(
            "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades  (dnf: sudo systemctl enable --now dnf-automatic-install.timer)",
        ),
        explain: "Security fixes install on their own",
    },
    Check {
        id: "POSTURE-SSH-ROOT",
        cis: "5.2.8",
        title: "ssh: no root login",
        severity: Severity::High,
        probe: ssh_root_login,
        fix: admin(
            "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-hardening.conf && sudo systemctl reload ssh",
        ),
        explain: "root can't be brute-forced over ssh",
    },
    Check {
        id: "POSTURE-SSH-PASSWORDS",
        cis: "5.2.10",
        title: "ssh: keys only, no passwords",
        severity: Severity::High,
        probe: ssh_passwords,
        fix: admin(
            "echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/10-hardening.conf && sudo systemctl reload ssh  (after your key is installed)",
        ),
        explain: "Passwords can't be guessed over ssh",
    },
    Check {
        id: "POSTURE-AUTO-LOGIN",
        cis: "1.8",
        title: "Automatic login off",
        severity: Severity::Critical,
        probe: auto_login,
        fix: admin(
            "Turn off automatic login in the display manager's config (gdm custom.conf, lightdm.conf, sddm.conf)",
        ),
        explain: "Whoever turns the machine on is not logged in as you",
    },
    Check {
        id: "POSTURE-MAC",
        cis: "1.6",
        title: "AppArmor or SELinux enforcing",
        severity: Severity::Medium,
        probe: mandatory_access_control,
        fix: admin(
            "sudo aa-enforce /etc/apparmor.d/*  (or: sudo setenforce 1 and SELINUX=enforcing in /etc/selinux/config)",
        ),
        explain: "Confined programs can't reach beyond their profile",
    },
    Check {
        id: "POSTURE-SUDO-NOPASSWD",
        cis: "5.3",
        title: "sudo asks for a password",
        severity: Severity::Medium,
        probe: sudo_nopasswd,
        fix: admin("Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/* (visudo)"),
        explain: "A stolen session can't become root silently",
    },
    Check {
        id: "POSTURE-PATH-WRITABLE",
        cis: "6.2",
        title: "No world-writable directory on PATH",
        severity: Severity::Medium,
        probe: path_dirs,
        fix: admin("chmod o-w <dir>  for each directory listed"),
        explain: "Nobody can plant a command you'd run",
    },
    Check {
        id: "POSTURE-TIME-SYNC",
        cis: "2.1.1",
        title: "Clock synchronised",
        severity: Severity::Low,
        probe: time_sync,
        fix: admin("sudo timedatectl set-ntp true"),
        explain: "Certificates and logs line up",
    },
];

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    fn machine(answers: &'static [(&'static str, &'static str)]) -> impl Fn(&[&str]) -> String {
        move |argv: &[&str]| {
            let joined = argv.join(" ");
            answers.iter().find(|(k, _)| joined.contains(k)).map(|(_, v)| v.to_string()).unwrap_or_default()
        }
    }

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
    fn ssh_settings_read_the_config_text() {
        let cfg = "# comment\nPort 22\npermitrootlogin prohibit-password\nPasswordAuthentication yes\n";
        assert_eq!(setting(cfg, "PermitRootLogin").as_deref(), Some("prohibit-password"));
        assert_eq!(setting(cfg, "PasswordAuthentication").as_deref(), Some("yes"));
        assert_eq!(setting(cfg, "Missing"), None);
        // No sshd: nothing to harden.
        assert_eq!(ssh_root_login(&machine(&[("is-active", "inactive\n")])).status, Status::Pass);
    }

    #[test]
    fn the_rest() {
        assert_eq!(mandatory_access_control(&machine(&[("aa-enabled", "Yes\n")])).status, Status::Pass);
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Permissive\n")])).status, Status::Fail);
        assert_eq!(mandatory_access_control(&machine(&[])).status, Status::Manual);
        assert_eq!(
            sudo_nopasswd(&machine(&[(
                "sudo -n -l",
                "User eric may run the following commands:\n    (ALL) NOPASSWD: ALL\n"
            )]))
            .status,
            Status::Fail
        );
        assert_eq!(sudo_nopasswd(&machine(&[("sudo -n -l", "sudo: a password is required\n")])).status, Status::Pass);
        assert_eq!(time_sync(&machine(&[("NTPSynchronized", "yes\n")])).status, Status::Pass);
        assert_eq!(time_sync(&machine(&[("NTPSynchronized", "no\n")])).status, Status::Fail);
        assert_eq!(
            disk_encryption(&machine(&[("lsblk", "disk\npart crypto_LUKS\ncrypt ext4\n")])).status,
            Status::Pass
        );
        assert_eq!(disk_encryption(&machine(&[("lsblk", "disk\npart ext4\n")])).status, Status::Fail);
        assert_eq!(path_dirs(&machine(&[])).status, Status::Pass);
    }
}
