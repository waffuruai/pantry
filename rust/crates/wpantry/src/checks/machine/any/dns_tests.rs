use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn resolv_conf_and_address_classes() {
    let resolv = "# generated\n;comment\nnameserver 127.0.0.53\nnameserver\t10.0.0.1 # trailing\noptions edns0\nnameserverx 1.1.1.1\nsearch lan\n";
    assert_eq!(nameservers(resolv), ["127.0.0.53", "10.0.0.1"]);
    assert!(nameservers("").is_empty());
    assert!(is_loopback("127.0.0.53") && is_loopback("::1") && !is_loopback("1.1.1.1"));
    for ip in [
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.1",
        "172.31.255.1",
        "169.254.1.1",
        "100.64.0.1",
        "100.100.100.100",
        "fd00::1",
        "fe80::1",
    ] {
        assert!(is_private(ip), "{ip}");
    }
    for ip in ["172.15.0.1", "172.32.0.1", "100.128.0.1", "8.8.8.8", "2001:4860:4860::8888", "64.59.135.148"] {
        assert!(!is_private(ip), "{ip}");
    }
}

#[test]
fn plaintext_evidence_says_why_it_only_warns() {
    let public = plaintext(&["64.59.135.148".into(), "64.59.128.114".into()], "scutil --dns");
    assert!(
        public.starts_with("DNS goes to 64.59.135.148, 64.59.128.114 in plaintext on UDP 53 (scutil --dns)"),
        "{public}"
    );
    assert!(public.contains("only warns"));
    let lan = plaintext(&["10.0.0.1".into()], "/etc/resolv.conf");
    assert!(lan.contains("(a LAN or VPN address)"), "{lan}");
}

#[test]
fn local_stubs_by_process_and_unbound_by_config() {
    let at = vec!["127.0.0.1".to_string()];
    let stubby = machine(&[("pgrep -x stubby", "412\n")]);
    let o = local_stub(&stubby, &at);
    assert_eq!(o.status, Status::Pass);
    assert!(o.evidence.starts_with("stubby is the local resolver (127.0.0.1)"), "{}", o.evidence);
    let unbound_tls = machine(&[
        ("pgrep -x unbound", "9\n"),
        (
            "/etc/unbound/unbound.conf",
            "server:\n  interface: 127.0.0.1\nforward-zone:\n  name: \".\"\n  forward-tls-upstream: yes\n  forward-addr: 1.1.1.1@853\n",
        ),
    ]);
    assert_eq!(local_stub(&unbound_tls, &at).status, Status::Pass);
    let unbound_plain =
        machine(&[("pgrep -x unbound", "9\n"), ("/etc/unbound/unbound.conf", "server:\n  interface: 127.0.0.1\n")]);
    let o = local_stub(&unbound_plain, &at);
    assert_eq!(o.status, Status::Manual);
    assert!(o.evidence.contains("forward-tls-upstream"), "{}", o.evidence);
    assert_eq!(local_stub(&machine(&[("pgrep -x dnsmasq", "7\n")]), &at).status, Status::Manual);
    let unknown = local_stub(&machine(&[]), &at);
    assert_eq!(unknown.status, Status::Manual);
    assert!(unknown.evidence.contains("doesn't know"), "{}", unknown.evidence);
}
