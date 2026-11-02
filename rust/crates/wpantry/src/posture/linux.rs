//! Linux: the CIS Distribution Independent Linux items a user can read.
//! Files are read directly where a command would need root.

use super::{Check, Fix, Outcome, Runner, Severity, dns};
use std::path::Path;

/// The system configuration directory; tests read a copy.
const ETC: &str = "/etc";

fn text(p: &Path) -> String {
    crate::system::read_capped(p, 1 << 20).unwrap_or_default()
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
    unattended_upgrades_in(r, Path::new(ETC))
}

fn unattended_upgrades_in(r: Runner, etc: &Path) -> Outcome {
    let apt = text(&etc.join("apt/apt.conf.d/20auto-upgrades"));
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
    if etc.join("apt").is_dir() || etc.join("dnf").is_dir() {
        return Outcome::fail("no automatic security updates are configured");
    }
    Outcome::manual("automatic updates: not a Debian or Red Hat family system; check your distro's way")
}

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

fn auto_login(_: Runner) -> Outcome {
    auto_login_in(Path::new(ETC))
}

fn auto_login_in(etc: &Path) -> Outcome {
    for f in ["gdm3/custom.conf", "gdm/custom.conf"] {
        let t = text(&etc.join(f));
        if t.lines().any(|l| l.replace(' ', "").to_ascii_lowercase().starts_with("automaticloginenable=true")) {
            return Outcome::fail(format!("automatic login is on in {}", etc.join(f).display()));
        }
    }
    let lightdm = text(&etc.join("lightdm/lightdm.conf"));
    if lightdm
        .lines()
        .any(|l| l.trim_start().starts_with("autologin-user=") && l.trim().len() > "autologin-user=".len())
    {
        return Outcome::fail(format!("automatic login is on in {}", etc.join("lightdm/lightdm.conf").display()));
    }
    let sddm = text(&etc.join("sddm.conf"));
    if sddm.contains("[Autologin]") && sddm.lines().any(|l| l.trim_start().starts_with("User=") && l.trim().len() > 5) {
        return Outcome::fail(format!("automatic login is on in {}", etc.join("sddm.conf").display()));
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
    path_dirs_of(&std::env::var("PATH").unwrap_or_default())
}

/// The world-writable directories among a PATH's entries.
fn path_dirs_of(path: &str) -> Outcome {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bad: Vec<String> = path
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
    {
        let _ = path;
        Outcome::manual("not checked on this platform")
    }
}

fn time_sync(r: Runner) -> Outcome {
    let out = r(&["timedatectl", "show", "-p", "NTPSynchronized", "--value"]);
    match out.trim() {
        "yes" => Outcome::pass("the clock is synchronised"),
        "no" => Outcome::fail("the clock is not synchronised (NTP off)"),
        _ => Outcome::unknown("timedatectl gave no answer"),
    }
}

/// A kernel version as (major, minor, patch).
type Kernel = (u64, u64, u64);

/// `uname -r` as (major, minor, patch); distro suffixes are dropped.
fn kernel_version(r: Runner) -> Option<(u64, u64, u64, String)> {
    let raw = r(&["uname", "-r"]).trim().to_string();
    let core: String = raw.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (a, b, c) = (it.next()??, it.next()??, it.next().flatten().unwrap_or(0));
    Some((a, b, c, raw))
}

/// Whether a kernel version lies in any of the (introduced, fixed) ranges.
fn in_ranges(v: Kernel, ranges: &[(Kernel, Kernel)]) -> bool {
    ranges.iter().any(|(lo, hi)| v >= *lo && v < *hi)
}

/// CVE-2026-98432 (CVSS 9.8): an IPv4 TCP use-after-free since 4.4, fixed
/// in the stable series below (OSV, 2026-10-30). Distro kernels carry
/// backports under their own numbering, so a distro kernel is judged by
/// the mitigation, with a note to check the vendor's advisory.
const CVE_2026_98432_FIXED: &[(Kernel, Kernel)] = &[
    ((4, 4, 0), (5, 10, 272)),
    ((5, 11, 0), (5, 15, 223)),
    ((5, 16, 0), (6, 1, 190)),
    ((6, 2, 0), (6, 6, 159)),
    ((6, 7, 0), (6, 12, 113)),
    ((6, 13, 0), (6, 18, 56)),
    ((6, 19, 0), (7, 2, 10)),
];

/// Whether a rule drops inbound TCP with IP options. `nft list ruleset` and `iptables -S` need root
/// and print nothing without it (so does an empty ruleset), so the read happens as root, or through
/// `sudo -n` (which fails rather than prompts); `None` when neither is available.
pub fn drops_ip_options(r: Runner) -> Option<bool> {
    let root = r(&["id", "-u"]).trim() == "0";
    let (nft, ipt) = if root {
        (r(&["nft", "list", "ruleset"]), r(&["iptables", "-S"]))
    } else if r(&["sudo", "-n", "id", "-u"]).trim() == "0" {
        (r(&["sudo", "-n", "nft", "list", "ruleset"]), r(&["sudo", "-n", "iptables", "-S"]))
    } else {
        return None;
    };
    let nft_rule = nft.contains("hdrlength > 5") && nft.contains("drop");
    let ipt_rule = ipt.contains("ipv4options") && ipt.contains("DROP");
    Some(nft_rule || ipt_rule)
}

/// The running kernel against CVE-2026-98432: its version string, whether
/// an upstream kernel of that version has the fix, and whether it is a
/// distro kernel (a backport under its own numbering: check the vendor's
/// advisory). None when uname gave nothing.
pub fn kernel_cve_2026_98432(r: Runner) -> Option<(String, bool, bool)> {
    let (a, b, c, raw) = kernel_version(r)?;
    let distro = raw.contains('-') && !raw.ends_with("-generic-upstream");
    Some((raw, !in_ranges((a, b, c), CVE_2026_98432_FIXED), distro))
}

fn tcp_ip_options(r: Runner) -> Outcome {
    let Some((raw, fixed, distro)) = kernel_cve_2026_98432(r) else {
        return Outcome::unknown("uname gave no kernel version");
    };
    if fixed {
        return Outcome::pass(format!("kernel {raw} has the fix for CVE-2026-98432"));
    }
    match drops_ip_options(r) {
        Some(true) => {
            return Outcome::pass(format!(
                "kernel {raw}: inbound TCP with IP options is dropped (CVE-2026-98432 stopgap in place); update the kernel when the fix ships"
            ));
        }
        None => {
            return Outcome::manual(format!(
                "kernel {raw} is in CVE-2026-98432's affected range and the ruleset can't be read here (nft needs root): sudo nft list table inet cve_2026_98432, or wpantry mitigate CVE-2026-98432 --dry-run"
            ));
        }
        Some(false) => {}
    }
    if distro {
        Outcome::fail(format!(
            "kernel {raw} (a distro kernel: check the vendor's advisory for a backport) and no stopgap for CVE-2026-98432"
        ))
    } else {
        Outcome::fail(format!("kernel {raw} is in CVE-2026-98432's affected range and no stopgap is in place"))
    }
}

/// A TCP listening socket that is really an MPTCP one.
#[derive(Debug, PartialEq, Eq)]
pub struct MptcpListener {
    /// Local address and port as `ss` prints it (`*:6443`).
    pub local: String,
    /// The processes holding it (name, pid); empty when `ss -p` couldn't see them.
    pub owners: Vec<(String, String)>,
}

/// `(name, pid)` for each `("name",pid=N,fd=M)` in an `ss -p` Process column.
fn owners(line: &str) -> Vec<(String, String)> {
    line.split("(\"")
        .skip(1)
        .filter_map(|rest| {
            let name = rest.split('"').next()?;
            let pid = rest.split("pid=").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?;
            Some((name.to_string(), pid.to_string()))
        })
        .collect()
}

/// The MPTCP listening sockets, two ways. As root (or through `sudo -n`,
/// which fails rather than prompts) `ss -tlnpi` marks every TCP listener
/// whose upper-layer protocol is MPTCP with `tcp-ulp-mptcp`, which needs
/// no extra kernel module; without root the mark isn't shown, so the
/// fallback is `ss -Mlnp`, which lists MPTCP sockets (without their
/// owners) only when the kernel has `mptcp_diag`: an Ubuntu cloud kernel
/// ships without it and `ss -M` then prints an empty list that proves
/// nothing. None when the sockets couldn't be seen.
pub fn mptcp_listeners(r: Runner) -> Option<Vec<MptcpListener>> {
    let sudo: &[&str] = if r(&["id", "-u"]).trim() == "0" {
        &[]
    } else if r(&["sudo", "-n", "id", "-u"]).trim() == "0" {
        &["sudo", "-n"]
    } else {
        if r(&["modprobe", "-n", "mptcp_diag"]).contains("not found") {
            return None;
        }
        let out = r(&["ss", "-Mlnp"]);
        if !out.contains("State") {
            return None;
        }
        return Some(
            out.lines()
                .filter(|l| l.starts_with("LISTEN"))
                .filter_map(|l| {
                    Some(MptcpListener { local: l.split_whitespace().nth(3)?.to_string(), owners: owners(l) })
                })
                .collect(),
        );
    };
    let out = r(&[sudo, &["ss", "-tlnpi"]].concat());
    if !out.contains("State") {
        return None;
    }
    // a LISTEN line, then an indented line of socket info: the mark is on the second
    let mut found = Vec::new();
    let mut listener: Option<&str> = None;
    for l in out.lines() {
        if l.starts_with("LISTEN") {
            listener = Some(l);
        } else if l.starts_with(char::is_whitespace)
            && l.contains("tcp-ulp-mptcp")
            && let Some(hdr) = listener.take()
            && let Some(local) = hdr.split_whitespace().nth(3)
        {
            found.push(MptcpListener { local: local.to_string(), owners: owners(hdr) });
        }
    }
    Some(found)
}

/// The systemd service a pid runs under, from its cgroup
/// (`0::/system.slice/k3s.service`); None for anything else (a container,
/// a user session).
pub fn unit_of(r: Runner, pid: &str) -> Option<String> {
    let cgroup = r(&["cat", &format!("/proc/{pid}/cgroup")]);
    cgroup.lines().filter_map(|l| l.rsplit('/').next()).find(|u| u.ends_with(".service")).map(str::to_string)
}

/// `net.mptcp.enabled` says whether MPTCP sockets can be created; a program
/// that already listens with one keeps it until it is restarted (checked:
/// the listener stays, marked `tcp-ulp-mptcp`, after the sysctl flips to 0).
/// So the listeners are read first and decide.
fn mptcp(r: Runner) -> Outcome {
    let enabled = r(&["cat", "/proc/sys/net/mptcp/enabled"]);
    let enabled = enabled.trim();
    let listeners = mptcp_listeners(r);
    if let Some(l) = listeners.as_deref().filter(|l| !l.is_empty()) {
        // one entry per program (name, pid, unit, ports); unowned sockets together at the end
        let mut programs: Vec<(String, String, Vec<String>)> = Vec::new();
        let mut unowned: Vec<String> = Vec::new();
        for s in l {
            if s.owners.is_empty() {
                unowned.push(s.local.clone());
            }
            for (name, pid) in &s.owners {
                match programs.iter_mut().find(|(_, p, _)| p == pid) {
                    Some((_, _, locals)) => locals.push(s.local.clone()),
                    None => programs.push((name.clone(), pid.clone(), vec![s.local.clone()])),
                }
            }
        }
        let mut units: Vec<String> = Vec::new();
        let mut parts: Vec<String> = Vec::new();
        for (name, pid, locals) in &programs {
            let unit = unit_of(r, pid);
            if let Some(u) = &unit
                && !units.contains(u)
            {
                units.push(u.clone());
            }
            let under = unit.map(|u| format!(" ({u})")).unwrap_or_else(|| " (not a systemd service)".into());
            parts.push(format!("{name} pid {pid}{under} on {}", locals.join(", ")));
        }
        if !unowned.is_empty() {
            parts.push(format!("a process on {} (ss -p needs root: sudo ss -tlnpi)", unowned.join(", ")));
        }
        let restart = if units.is_empty() {
            "restart each".to_string()
        } else {
            format!("sudo systemctl restart {}", units.join(" "))
        };
        let sysctl =
            if enabled == "1" { "; net.mptcp.enabled=1, so they would come back: set it to 0 first" } else { "" };
        let n = programs.len() + usize::from(!unowned.is_empty());
        return Outcome::fail(format!(
            "{} listening with MPTCP (ss): {}. net.mptcp.enabled=0 only stops new MPTCP sockets, a program that already listens keeps its until restarted: {restart}{sysctl}",
            if n == 1 { "a program is".to_string() } else { format!("{n} programs are") },
            parts.join("; ")
        ));
    }
    match (enabled, listeners.is_some()) {
        ("1", true) => Outcome::fail(
            "MPTCP is enabled (net.mptcp.enabled=1), nothing listens with it yet; almost nothing needs it, and CVE-2026-98432's public proof of concept uses it",
        ),
        ("1", false) => Outcome::fail(
            "MPTCP is enabled (net.mptcp.enabled=1) and whether a program listens with it couldn't be seen (sudo ss -tlnpi marks them tcp-ulp-mptcp); almost nothing needs it, and CVE-2026-98432's public proof of concept uses it",
        ),
        ("0", true) => Outcome::pass("MPTCP is off and no program still listens with it (ss)"),
        ("0", false) => Outcome::manual(
            "MPTCP is off (net.mptcp.enabled=0), but whether a program that was listening before it flipped still holds an MPTCP socket can't be seen without root: sudo ss -tlnpi | grep -B1 tcp-ulp-mptcp",
        ),
        _ => Outcome::pass("MPTCP is not built into this kernel"),
    }
}

/// What `resolvectl status` says about DNS over TLS: the best of the global
/// and per-link answers (`+DNSOverTLS` or `DNSOverTLS setting: yes` beats
/// `opportunistic` beats `-DNSOverTLS`), None when it says nothing
/// (systemd-resolved isn't running).
fn resolved_dot(out: &str) -> Option<&'static str> {
    let rank = |v: &str| match v {
        "yes" => 3,
        "opportunistic" => 2,
        "no" => 1,
        _ => 0,
    };
    let mut best: Option<&'static str> = None;
    for l in out.lines() {
        let v = if l.contains("+DNSOverTLS") {
            "yes"
        } else if l.contains("-DNSOverTLS") {
            "no"
        } else if let Some(i) = l.find("DNSOverTLS") {
            let rest = l[i + "DNSOverTLS".len()..].to_ascii_lowercase();
            if rest.contains("opportunistic") {
                "opportunistic"
            } else if rest.contains("yes") {
                "yes"
            } else if rest.split(|c: char| !c.is_alphanumeric()).any(|w| w == "no") {
                "no"
            } else {
                continue;
            }
        } else {
            continue;
        };
        if rank(v) > best.map_or(0, rank) {
            best = Some(v);
        }
    }
    best
}

/// `DNSOverTLS=` in resolved.conf and its drop-ins, when resolvectl can't be asked.
fn resolved_conf_dot(r: Runner) -> Option<String> {
    let mut all = r(&["cat", "/etc/systemd/resolved.conf"]);
    if let Ok(rd) = std::fs::read_dir("/etc/systemd/resolved.conf.d") {
        let mut extra: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        extra.sort();
        for p in extra {
            all.push('\n');
            all.push_str(&text(&p));
        }
    }
    all.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("DNSOverTLS="))
        .next_back()
        .map(|v| v.trim().to_ascii_lowercase())
}

/// Whether DNS leaves the machine encrypted: systemd-resolved's DNS over
/// TLS, NetworkManager's `dns-over-tls`, or a local stub that forwards
/// over TLS or HTTPS as the resolver in /etc/resolv.conf. Plain DNS to a
/// public address fails (Medium: a warning), a stub it can't judge is
/// manual, no answer at all is unknown.
fn dns_encrypted(r: Runner) -> Outcome {
    let resolved = r(&["resolvectl", "status"]);
    let dot = resolved_dot(&resolved).map(str::to_string).or_else(|| resolved_conf_dot(r));
    match dot.as_deref() {
        Some("yes") | Some("true") => return Outcome::pass("systemd-resolved: DNS over TLS is on (DNSOverTLS=yes)"),
        Some("opportunistic") => {
            return Outcome::fail(
                "systemd-resolved: DNSOverTLS=opportunistic falls back to plaintext whenever the server doesn't offer TLS, so an attacker on the path can downgrade it; set DNSOverTLS=yes",
            );
        }
        _ => {}
    }
    let names = r(&["nmcli", "-g", "NAME", "connection", "show", "--active"]);
    for name in names.lines().map(str::trim).filter(|n| !n.is_empty()) {
        let v = r(&["nmcli", "-g", "ipv4.dns-over-tls", "connection", "show", name]);
        match v.trim() {
            "yes" => return Outcome::pass(format!("NetworkManager: ipv4.dns-over-tls yes on {name}")),
            "opportunistic" => {
                return Outcome::fail(format!(
                    "NetworkManager: ipv4.dns-over-tls opportunistic on {name} falls back to plaintext whenever the server doesn't offer TLS; set it to yes"
                ));
            }
            _ => {}
        }
    }
    let resolv = r(&["cat", "/etc/resolv.conf"]);
    let ns = dns::nameservers(&resolv);
    if ns.is_empty() {
        return Outcome::unknown(if resolv.trim().is_empty() {
            "/etc/resolv.conf can't be read"
        } else {
            "/etc/resolv.conf names no resolver"
        });
    }
    if ns.iter().all(|n| dns::is_loopback(n)) {
        if ns.iter().any(|n| n == "127.0.0.53") && (dot.is_some() || !resolved.trim().is_empty()) {
            return Outcome::fail(
                "systemd-resolved's stub (127.0.0.53) forwards in plaintext (DNSOverTLS=no); an internal resolver (Kubernetes, Docker, corporate split DNS) legitimately uses plain DNS, which is why this only warns",
            );
        }
        return dns::local_stub(r, &ns);
    }
    Outcome::fail(dns::plaintext(&ns, "/etc/resolv.conf"))
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
        id: "POSTURE-KERNEL-TCP-IP-OPTIONS",
        cis: "",
        title: "Kernel patched for CVE-2026-98432, or inbound TCP with IP options dropped",
        severity: Severity::Critical,
        probe: tcp_ip_options,
        fix: admin(
            "Update the kernel when your distro ships the fix (upstream 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10); until then drop inbound TCP with IP options: sudo nft add table inet cve_2026_98432 && sudo nft 'add chain inet cve_2026_98432 pre { type filter hook prerouting priority raw - 10; policy accept; }' && sudo nft add rule inet cve_2026_98432 pre ip hdrlength gt 5 meta l4proto tcp counter drop  (wpantry mitigate CVE-2026-98432 persists it, turns MPTCP off and names the services to restart)",
        ),
        explain: "An unauthenticated remote root through a race in TCP's handshake; packets without IP options can't reach it",
    },
    Check {
        id: "POSTURE-MPTCP",
        cis: "",
        title: "MPTCP off, and nothing still listening with it",
        severity: Severity::Medium,
        probe: mptcp,
        fix: admin(
            "sudo sysctl -w net.mptcp.enabled=0 && echo 'net.mptcp.enabled = 0' | sudo tee /etc/sysctl.d/90-no-mptcp.conf; then restart every program the evidence lists (sudo ss -Mlnp shows them; wpantry mitigate CVE-2026-98432 --dry-run names their units): the sysctl only stops new MPTCP sockets",
        ),
        explain: "Multipath TCP is rarely used and widens the kernel's attack surface; Go 1.24+ servers listen with it by default",
    },
    Check {
        id: "POSTURE-DNS-ENCRYPTED",
        cis: "",
        title: "DNS leaves the machine encrypted (DoT or DoH)",
        severity: Severity::Medium,
        probe: dns_encrypted,
        fix: admin(
            "systemd-resolved: DNSOverTLS=yes and DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net in /etc/systemd/resolved.conf, then sudo systemctl restart systemd-resolved; NetworkManager: nmcli connection modify <name> ipv4.dns 1.1.1.1 ipv4.dns-over-tls yes; or a local stub (stubby, dnscrypt-proxy, cloudflared proxy-dns, unbound with forward-tls-upstream: yes) as the nameserver in /etc/resolv.conf",
        ),
        explain: "Whoever carries your packets (the ISP, the hotspot, the network's owner) can't read or rewrite what you look up",
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
    fn kernel_tcp_ip_options_by_version_and_stopgap() {
        let fixed = machine(&[("uname -r", "6.12.113\n")]);
        assert_eq!(tcp_ip_options(&fixed).status, Status::Pass);
        let newer = machine(&[("uname -r", "6.18.60-1-lts\n")]);
        assert_eq!(tcp_ip_options(&newer).status, Status::Pass);
        let old = machine(&[
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            ("nft list ruleset", "table inet filter {\n}\n"),
        ]);
        let o = tcp_ip_options(&old);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("distro kernel"), "{}", o.evidence);
        // not root and no passwordless sudo: the ruleset is unreadable, never a false fail
        let unreadable = machine(&[("uname -r", "6.8.0-45-generic\n"), ("id -u", "1000\n")]);
        let u = tcp_ip_options(&unreadable);
        assert_eq!(u.status, Status::Manual);
        assert!(u.evidence.contains("needs root"), "{}", u.evidence);
        // the rule read through sudo -n (the first match wins: "sudo -n id -u" before "id -u")
        let mitigated = machine(&[
            ("uname -r", "6.8.0-45-generic\n"),
            ("sudo -n id -u", "0\n"),
            ("id -u", "1000\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
        ]);
        assert_eq!(tcp_ip_options(&mitigated).status, Status::Pass);
        let ipt = machine(&[
            ("uname -r", "5.15.0-100-generic\n"),
            ("id -u", "0\n"),
            ("iptables -S", "-A INPUT -p tcp -m ipv4options --any-opt -j DROP\n"),
        ]);
        assert_eq!(tcp_ip_options(&ipt).status, Status::Pass);
        assert_eq!(tcp_ip_options(&machine(&[])).status, Status::Unknown);
        assert_eq!(mptcp(&machine(&[("mptcp/enabled", "1\n")])).status, Status::Fail);
        assert_eq!(mptcp(&machine(&[])).status, Status::Pass, "not built in");
    }

    const SS_T_HEADER: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n";
    // ss -tlnpi as root: two listeners are MPTCP (the mark is on the info line), one is plain TCP
    const SS_T_K3S: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0      4096         *:6443             *:*     users:((\"k3s-server\",pid=392498,fd=17))\n\t cubic cwnd:10 tcp-ulp-mptcp\nLISTEN 0      4096   127.0.0.1:10248            *:*     users:((\"k3s-server\",pid=392498,fd=31))\n\t cubic cwnd:10 tcp-ulp-mptcp\nLISTEN 0      511          *:80               *:*     users:((\"nginx\",pid=700,fd=6),(\"nginx\",pid=699,fd=6))\n\t cubic cwnd:10\nLISTEN 0      4096         *:4317             *:*     users:((\"alloy\",pid=198948,fd=9))\n\t cubic cwnd:10 tcp-ulp-mptcp\nLISTEN 0      4096   127.0.0.1:10010            *:*     users:((\"containerd\",pid=392548,fd=6))\n\t cubic cwnd:10 tcp-ulp-mptcp\n";
    const SS_M_K3S: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0      4096         *:6443             *:*\n";

    #[test]
    fn mptcp_listeners_need_a_restart_whatever_the_sysctl_says() {
        // the sysctl is off, but the services that were listening before it flipped still hold MPTCP sockets
        let stale = machine(&[
            ("mptcp/enabled", "0\n"),
            ("id -u", "0\n"),
            ("ss -tlnpi", SS_T_K3S),
            ("/proc/392498/cgroup", "0::/system.slice/k3s.service\n"),
            ("/proc/198948/cgroup", "0::/system.slice/alloy.service\n"),
            ("/proc/392548/cgroup", "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-abc.scope\n"),
        ]);
        let o = mptcp(&stale);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.starts_with("3 programs are listening with MPTCP (ss): "), "{}", o.evidence);
        assert!(
            o.evidence.contains("k3s-server pid 392498 (k3s.service) on *:6443, 127.0.0.1:10248"),
            "{}",
            o.evidence
        );
        assert!(o.evidence.contains("alloy pid 198948 (alloy.service) on *:4317"), "{}", o.evidence);
        assert!(
            o.evidence.contains("containerd pid 392548 (not a systemd service) on 127.0.0.1:10010"),
            "{}",
            o.evidence
        );
        assert!(!o.evidence.contains("nginx"), "plain TCP listeners are not reported: {}", o.evidence);
        assert!(o.evidence.contains("sudo systemctl restart k3s.service alloy.service"), "{}", o.evidence);
        assert!(!o.evidence.contains("come back"), "{}", o.evidence);
        // still enabled: the restart alone would bring them back
        let on = machine(&[
            ("mptcp/enabled", "1\n"),
            ("id -u", "0\n"),
            ("ss -tlnpi", SS_T_K3S),
            ("/proc/392498/cgroup", "0::/system.slice/k3s.service\n"),
        ]);
        assert!(mptcp(&on).evidence.contains("set it to 0 first"));
        // the mark read through sudo -n when not root (the first match wins: "sudo -n ..." before the bare command)
        let via_sudo = machine(&[
            ("mptcp/enabled", "0\n"),
            ("sudo -n id -u", "0\n"),
            ("id -u", "1000\n"),
            ("sudo -n ss -tlnpi", SS_T_K3S),
            ("/proc/392498/cgroup", "0::/system.slice/k3s.service\n"),
        ]);
        assert!(mptcp(&via_sudo).evidence.contains("k3s.service"));
        // not root and no sudo: ss -M lists the sockets without owners, when the kernel has mptcp_diag
        let unowned = machine(&[("mptcp/enabled", "0\n"), ("id -u", "1000\n"), ("ss -Mlnp", SS_M_K3S)]);
        let o = mptcp(&unowned);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.starts_with("a program is listening"), "{}", o.evidence);
        assert!(o.evidence.contains("a process on *:6443 (ss -p needs root"), "{}", o.evidence);
        assert!(o.evidence.contains("restart each"), "{}", o.evidence);
        // ... and without mptcp_diag an empty ss -M proves nothing: the sysctl alone can't pass
        let blind = machine(&[
            ("mptcp/enabled", "0\n"),
            ("id -u", "1000\n"),
            (
                "modprobe -n mptcp_diag",
                "modprobe: FATAL: Module mptcp_diag not found in directory /lib/modules/6.8.0-117-generic\n",
            ),
            ("ss -Mlnp", SS_T_HEADER),
        ]);
        let o = mptcp(&blind);
        assert_eq!(o.status, Status::Manual);
        assert!(o.evidence.contains("sudo ss -tlnpi"), "{}", o.evidence);
        let blind_on = machine(&[
            ("mptcp/enabled", "1\n"),
            ("id -u", "1000\n"),
            ("modprobe -n mptcp_diag", "modprobe: FATAL: Module mptcp_diag not found\n"),
        ]);
        let o = mptcp(&blind_on);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("couldn't be seen"), "{}", o.evidence);
        // nothing listening: the sysctl decides, and the evidence says the listeners were looked at
        let clean = machine(&[("mptcp/enabled", "0\n"), ("id -u", "0\n"), ("ss -tlnpi", SS_T_HEADER)]);
        let o = mptcp(&clean);
        assert_eq!(o.status, Status::Pass);
        assert!(o.evidence.contains("no program still listens"), "{}", o.evidence);
        let on_idle = machine(&[("mptcp/enabled", "1\n"), ("id -u", "0\n"), ("ss -tlnpi", SS_T_HEADER)]);
        let o = mptcp(&on_idle);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("nothing listens with it yet"), "{}", o.evidence);
        // no ss at all as root: the listeners couldn't be seen
        assert_eq!(mptcp(&machine(&[("mptcp/enabled", "0\n"), ("id -u", "0\n")])).status, Status::Manual);
        assert_eq!(mptcp(&machine(&[("id -u", "0\n")])).status, Status::Pass, "not built in");
        let l = mptcp_listeners(&machine(&[("id -u", "0\n"), ("ss -tlnpi", SS_T_K3S)])).unwrap();
        assert_eq!(l.len(), 4);
        assert_eq!(
            l[0],
            MptcpListener { local: "*:6443".into(), owners: vec![("k3s-server".into(), "392498".into())] }
        );
        assert_eq!(owners("users:((\"nginx\",pid=700,fd=6),(\"nginx\",pid=699,fd=6))").len(), 2);
    }

    #[test]
    fn dns_by_resolved_network_manager_and_resolv_conf() {
        assert_eq!(resolved_dot("Global\n  Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=no/unsupported\n"), Some("yes"));
        assert_eq!(
            resolved_dot(
                "Global\n  Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\nLink 2 (eth0)\n  Protocols: +DefaultRoute -DNSOverTLS\n"
            ),
            Some("no")
        );
        assert_eq!(resolved_dot("Global\n       DNSOverTLS setting: opportunistic\n"), Some("opportunistic"));
        assert_eq!(resolved_dot("Global\n       DNSOverTLS setting: no\n"), Some("no"));
        assert_eq!(
            resolved_dot("Global\n  Protocols: -DNSOverTLS\nLink 2 (wlan0)\n  Protocols: +DNSOverTLS\n"),
            Some("yes"),
            "the best answer"
        );
        assert_eq!(resolved_dot(""), None);
        let on =
            machine(&[("resolvectl status", "Global\n  Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=no/unsupported\n")]);
        assert_eq!(dns_encrypted(&on).status, Status::Pass);
        let opportunistic = machine(&[("resolvectl status", "Global\n  DNSOverTLS setting: opportunistic\n")]);
        let o = dns_encrypted(&opportunistic);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("downgrade"), "{}", o.evidence);
        let stub_off = machine(&[
            ("resolvectl status", "Global\n  Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n"),
            ("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\n"),
        ]);
        let o = dns_encrypted(&stub_off);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.contains("127.0.0.53") && o.evidence.contains("only warns"), "{}", o.evidence);
        let nm = machine(&[
            ("nmcli -g NAME connection show --active", "Wired connection 1\n"),
            ("ipv4.dns-over-tls connection show Wired connection 1", "yes\n"),
        ]);
        assert_eq!(dns_encrypted(&nm).status, Status::Pass);
        let stubby = machine(&[("/etc/resolv.conf", "nameserver 127.0.0.1\n"), ("pgrep -x stubby", "500\n")]);
        let o = dns_encrypted(&stubby);
        assert_eq!(o.status, Status::Pass);
        assert!(o.evidence.starts_with("stubby"), "{}", o.evidence);
        let plain = machine(&[("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n")]);
        let o = dns_encrypted(&plain);
        assert_eq!(o.status, Status::Fail);
        assert!(o.evidence.starts_with("DNS goes to 8.8.8.8, 8.8.4.4 in plaintext"), "{}", o.evidence);
        let lan = machine(&[("/etc/resolv.conf", "nameserver 10.0.0.1\n")]);
        assert!(dns_encrypted(&lan).evidence.contains("LAN or VPN"));
        let unknown_stub = machine(&[("/etc/resolv.conf", "nameserver 127.0.0.1\n")]);
        assert_eq!(dns_encrypted(&unknown_stub).status, Status::Manual);
        assert_eq!(dns_encrypted(&machine(&[])).status, Status::Unknown, "no resolv.conf is not a pass");
        assert_eq!(dns_encrypted(&machine(&[("/etc/resolv.conf", "# empty\nsearch lan\n")])).status, Status::Unknown);
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = crate::system::TempDir::new("path").unwrap();
            let (safe, open) = (d.path().join("safe"), d.path().join("open"));
            std::fs::create_dir(&safe).unwrap();
            std::fs::create_dir(&open).unwrap();
            std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
            let path = |dirs: &[&std::path::Path]| {
                dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join(":")
            };
            assert_eq!(path_dirs_of(&path(&[&safe])).status, Status::Pass);
            let o = path_dirs_of(&path(&[&safe, &open]));
            assert_eq!(o.status, Status::Fail);
            assert!(o.evidence.contains("open"), "{}", o.evidence);
        }
    }

    /// A copy of /etc with the given files.
    fn etc(files: &[(&str, &str)]) -> crate::system::TempDir {
        let d = crate::system::TempDir::new("etc").unwrap();
        for (rel, body) in files {
            let p = d.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        d
    }

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

    #[test]
    fn the_remaining_branches() {
        assert_eq!(disk_encryption(&machine(&[])).status, Status::Unknown);
        assert_eq!(firewall(&machine(&[("firewall-cmd --state", "not running\n")])).status, Status::Fail);
        assert_eq!(firewall(&machine(&[("iptables -S INPUT", "-P INPUT DROP\n")])).status, Status::Pass);
        assert_eq!(
            firewall(&machine(&[("iptables -S INPUT", "-P INPUT ACCEPT\n-A INPUT -j DROP\n")])).status,
            Status::Pass
        );
        assert_eq!(time_sync(&machine(&[])).status, Status::Unknown);
        assert_eq!(
            mandatory_access_control(&machine(&[("aa-enabled", "No - disabled at boot.\n")])).status,
            Status::Fail
        );
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Enforcing\n")])).status, Status::Pass);
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Disabled\n")])).status, Status::Fail);
        // An upstream kernel in the range, root, and no rule: a plain failure.
        let upstream = machine(&[("uname -r", "6.8.0\n"), ("id -u", "0\n")]);
        let o = tcp_ip_options(&upstream);
        assert_eq!(o.status, Status::Fail);
        assert!(!o.evidence.contains("distro"), "{}", o.evidence);
        assert_eq!(kernel_version(&machine(&[("uname -r", "6\n")])), None);
        assert_eq!(kernel_version(&machine(&[("uname -r", "6.1-rc1\n")])), Some((6, 1, 0, "6.1-rc1".into())));
        // This process's PATH, read for real.
        assert!(matches!(path_dirs(&machine(&[])).status, Status::Pass | Status::Fail));
        assert_eq!(admin("x"), Some(Fix { cmd: "x", admin: true }));
        assert!(CHECKS.iter().all(|c| c.id.starts_with("POSTURE-") && !c.title.is_empty()));
    }
}
