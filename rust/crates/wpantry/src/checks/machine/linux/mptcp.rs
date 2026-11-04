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
        "sudo sysctl -w net.mptcp.enabled=0 && echo 'net.mptcp.enabled = 0' | sudo tee /etc/sysctl.d/90-no-mptcp.conf; then restart every program the evidence lists (sudo ss -Mlnp shows them; wpantry mitigate CVE-2026-98432 --dry-run names their units): the sysctl only stops new MPTCP sockets",
    ),
    explain: "Multipath TCP is rarely used and widens the kernel's attack surface; Go 1.24+ servers listen with it by default",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::machine::settings::Status;
    use crate::checks::machine::testing::machine;

    #[test]
    fn enabled_or_not_built_in() {
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
}
