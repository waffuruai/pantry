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
    assert!(o.evidence.contains("k3s-server pid 392498 (k3s.service) on *:6443, 127.0.0.1:10248"), "{}", o.evidence);
    assert!(o.evidence.contains("alloy pid 198948 (alloy.service) on *:4317"), "{}", o.evidence);
    assert!(o.evidence.contains("containerd pid 392548 (not a systemd service) on 127.0.0.1:10010"), "{}", o.evidence);
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
    assert_eq!(l[0], MptcpListener { local: "*:6443".into(), owners: vec![("k3s-server".into(), "392498".into())] });
    assert_eq!(owners("users:((\"nginx\",pid=700,fd=6),(\"nginx\",pid=699,fd=6))").len(), 2);
}
