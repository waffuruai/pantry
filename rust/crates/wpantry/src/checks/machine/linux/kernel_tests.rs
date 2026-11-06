use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

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
}

#[test]
fn upstream_kernels_and_odd_versions() {
    // An upstream kernel in the range, root, and no rule: a plain failure.
    let upstream = machine(&[("uname -r", "6.8.0\n"), ("id -u", "0\n")]);
    let o = tcp_ip_options(&upstream);
    assert_eq!(o.status, Status::Fail);
    assert!(!o.evidence.contains("distro"), "{}", o.evidence);
    assert_eq!(kernel_version(&machine(&[("uname -r", "6\n")])), None);
    assert_eq!(kernel_version(&machine(&[("uname -r", "6.1-rc1\n")])), Some((6, 1, 0, "6.1-rc1".into())));
}
