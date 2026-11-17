use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn dns_by_profile_proxy_stub_tunnel_or_plain_resolver() {
    let doh = dns_encrypted(&machine(&[("plutil -p", NE_DOH), ("scutil --dns", SCUTIL_PLAIN)]));
    assert_eq!(doh.status, Status::Pass);
    assert_eq!(doh.evidence, "a DNS over HTTPS configuration is installed (https://dns.nextdns.io/abc123)");
    let dot = dns_encrypted(&machine(&[("plutil -p", "\"$classname\" => \"NEDNSOverTLSSettings\"\n")]));
    assert_eq!(dot.status, Status::Pass);
    let proxy = dns_encrypted(&machine(&[(
        "plutil -p",
        "4 => \"com.nextdns.NextDNS.networkextension\"\n\"$classname\" => \"NEDNSProxyProviderProtocol\"\n",
    )]));
    assert_eq!(proxy.status, Status::Pass);
    assert!(proxy.evidence.starts_with("NextDNS's DNS proxy"), "{}", proxy.evidence);
    let other_proxy = dns_encrypted(&machine(&[("plutil -p", "\"$classname\" => \"NEDNSProxyProviderProtocol\"\n")]));
    assert_eq!(other_proxy.status, Status::Manual);
    // The archive without DNS settings (a VPN only) decides nothing: scutil does.
    const VPN_ONLY: &str =
        "\"DNSSettings\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 0}\n4 => \"com.nordvpn.NordVPN\"\n";
    let plain = dns_encrypted(&machine(&[("plutil -p", VPN_ONLY), ("scutil --dns", SCUTIL_PLAIN)]));
    assert_eq!(plain.status, Status::Fail);
    assert!(
        plain
            .evidence
            .starts_with("DNS goes to 2001:4e8:0:4001::16, 64.59.135.148 in plaintext on UDP 53 (scutil --dns)"),
        "{}",
        plain.evidence
    );
    assert!(plain.evidence.contains("only warns"));
    let stub = dns_encrypted(&machine(&[
        (
            "scutil --dns",
            "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n  flags    : Request A records\n",
        ),
        ("pgrep -x dnscrypt-proxy", "77\n"),
    ]));
    assert_eq!(stub.status, Status::Pass);
    assert!(stub.evidence.starts_with("dnscrypt-proxy is the local resolver (127.0.0.1)"), "{}", stub.evidence);
    let tunnel = dns_encrypted(&machine(&[(
        "scutil --dns",
        "DNS configuration\n\nresolver #1\n  nameserver[0] : 103.86.96.100\n  if_index : 29 (utun4)\n  flags    : Request A records\n",
    )]));
    assert_eq!(tunnel.status, Status::Manual);
    assert!(tunnel.evidence.contains("utun4"), "{}", tunnel.evidence);
    let tailscale = dns_encrypted(&machine(&[(
        "scutil --dns",
        "DNS configuration\n\nresolver #1\n  nameserver[0] : 100.100.100.100\n  if_index : 29 (utun5)\n",
    )]));
    assert_eq!(tailscale.status, Status::Manual);
    assert!(tailscale.evidence.contains("Tailscale"), "{}", tailscale.evidence);
    // The default resolver is the first unscoped block without a domain, whatever its number.
    assert_eq!(
        default_resolver(
            "resolver #1\n  domain   : corp.example\n  nameserver[0] : 10.1.1.1\n\nresolver #2\n  nameserver[0] : 1.1.1.1\n  if_index : 14 (en0)\n"
        ),
        Some((vec!["1.1.1.1".into()], "en0".into()))
    );
    assert_eq!(default_resolver("DNS configuration\n"), None);
    assert_eq!(dns_encrypted(&machine(&[("scutil --dns", "DNS configuration\n")])).status, Status::Unknown);
    assert_eq!(dns_encrypted(&machine(&[])).status, Status::Unknown);
}
