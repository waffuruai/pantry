//! Multipath TCP: off, and no program still listening with it.

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

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

pub(super) const MPTCP: Check = Check {
    id: "POSTURE-MPTCP",
    cis: "",
    title: "MPTCP off, and nothing still listening with it",
    severity: Severity::Medium,
    probe: mptcp,
    fix: admin(
        "sudo sysctl -w net.mptcp.enabled=0 && echo 'net.mptcp.enabled = 0' | sudo tee /etc/sysctl.d/90-no-mptcp.conf; then restart every program the evidence lists (sudo ss -Mlnp shows them; wpantry fix CVE-2026-98432 --dry-run names their units): the sysctl only stops new MPTCP sockets",
    ),
    explain: "Multipath TCP is rarely used and widens the kernel's attack surface; Go 1.24+ servers listen with it by default",
};

#[cfg(test)]
#[path = "mptcp_tests.rs"]
mod tests;
