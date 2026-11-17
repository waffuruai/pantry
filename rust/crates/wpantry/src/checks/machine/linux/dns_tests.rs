use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

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
    let on = machine(&[("resolvectl status", "Global\n  Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=no/unsupported\n")]);
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
