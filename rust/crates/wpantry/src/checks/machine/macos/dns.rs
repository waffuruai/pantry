//! Whether DNS leaves the Mac encrypted.

use super::super::any::dns;
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

/// Where macOS keeps the network-extension configurations: a DNS over
/// HTTPS or TLS profile and the DNS proxy extensions (NextDNS, AdGuard,
/// Cloudflare) are recorded here, and nowhere `scutil --dns` shows.
const NE_PLIST: &str = "/Library/Preferences/com.apple.networkextension.plist";

/// DNS proxy extensions known to forward over TLS or HTTPS, by bundle id prefix.
const ENCRYPTING_PROXIES: &[(&str, &str)] = &[
    ("com.nextdns", "NextDNS"),
    ("com.adguard", "AdGuard"),
    ("com.cloudflare", "Cloudflare"),
    ("controld", "Control D"),
];

/// The encrypted-DNS configuration the network-extension archive records,
/// read through `plutil -p`: the DoH or DoT settings class, with the DoH
/// server URL when it has one, or a DNS proxy extension and whose it is.
fn encrypted_configuration(archive: &str) -> Option<Outcome> {
    if archive.contains("NEDNSOverHTTPSSettings") {
        let url = archive.split("\"https://").nth(1).and_then(|r| r.split('"').next()).map(|u| format!("https://{u}"));
        return Some(Outcome::pass(match url {
            Some(u) => format!("a DNS over HTTPS configuration is installed ({u})"),
            None => "a DNS over HTTPS configuration is installed".into(),
        }));
    }
    if archive.contains("NEDNSOverTLSSettings") {
        return Some(Outcome::pass("a DNS over TLS configuration is installed"));
    }
    if archive.contains("NEDNSProxyProviderProtocol") {
        return Some(match ENCRYPTING_PROXIES.iter().find(|(id, _)| archive.contains(id)) {
            Some((_, app)) => Outcome::pass(format!(
                "{app}'s DNS proxy extension handles queries and forwards them over TLS or HTTPS"
            )),
            None => Outcome::manual(
                "a DNS proxy extension handles queries (network extension settings); check that it forwards over TLS or HTTPS",
            ),
        });
    }
    None
}

/// The resolver macOS uses for names no other resolver claims: the first
/// block of `scutil --dns` (before the scoped section) without a `domain`.
/// Its addresses and the interface it is bound to (`en0`, `utun4`).
fn default_resolver(out: &str) -> Option<(Vec<String>, String)> {
    let unscoped = out.split("(for scoped queries)").next().unwrap_or("");
    let mut blocks: Vec<(Vec<String>, String, bool)> = Vec::new();
    for raw in unscoped.lines() {
        let l = raw.trim();
        if l.starts_with("resolver #") {
            blocks.push((Vec::new(), String::new(), false));
            continue;
        }
        let Some((k, v)) = l.split_once(':') else { continue };
        let Some(b) = blocks.last_mut() else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.starts_with("nameserver[") {
            b.0.push(v.to_string());
        } else if k == "domain" {
            b.2 = true;
        } else if k == "if_index" {
            b.1 = v.split('(').nth(1).unwrap_or("").trim_end_matches(')').to_string();
        }
    }
    blocks.into_iter().find(|b| !b.2).map(|b| (b.0, b.1))
}

/// Whether DNS leaves the Mac encrypted: a DoH or DoT profile or a DNS
/// proxy extension in the network-extension settings, else a local stub
/// that forwards encrypted, else what `scutil --dns` sends the queries to.
/// Plain addresses on UDP 53 fail (Medium: a warning); a VPN tunnel or
/// Tailscale's resolver is manual, since what happens past it can't be
/// read here; no answer is unknown.
fn dns_encrypted(r: Runner) -> Outcome {
    if let Some(o) = encrypted_configuration(&r(&["plutil", "-p", NE_PLIST])) {
        return o;
    }
    let out = r(&["scutil", "--dns"]);
    if out.trim().is_empty() {
        return Outcome::unknown("scutil --dns gave no answer");
    }
    let Some((ns, iface)) = default_resolver(&out) else {
        return Outcome::unknown("scutil --dns names no default resolver");
    };
    if ns.is_empty() {
        return Outcome::unknown("the default resolver has no nameserver (scutil --dns)");
    }
    if ns.iter().all(|n| dns::is_loopback(n)) {
        return dns::local_stub(r, &ns);
    }
    if ns.iter().any(|n| n == "100.100.100.100") {
        return Outcome::manual(
            "Tailscale's resolver (100.100.100.100) answers inside the tunnel; whether its upstream is encrypted is the tailnet's DNS setting, which can't be read here",
        );
    }
    if iface.starts_with("utun") {
        return Outcome::manual(format!(
            "DNS goes through the VPN tunnel ({iface}) to {}: encrypted as far as the VPN's resolver, plaintext beyond it for all that can be read here",
            ns.join(", ")
        ));
    }
    Outcome::fail(dns::plaintext(&ns, "scutil --dns"))
}

pub(super) const DNS_ENCRYPTED: Check = Check {
    id: "POSTURE-DNS-ENCRYPTED",
    cis: "",
    title: "DNS leaves the Mac encrypted (DoH or DoT)",
    severity: Severity::Medium,
    probe: dns_encrypted,
    fix: admin(
        "Install a DNS over HTTPS or TLS configuration profile (a .mobileconfig with a DNSSettings payload; NextDNS, Cloudflare, Quad9, AdGuard and Control D publish them: open it, then System Settings → General → Device Management) or the provider's app (NextDNS, Cloudflare WARP, AdGuard), or run a local stub (dnscrypt-proxy, stubby) on 127.0.0.1 and set it as the DNS server in System Settings → Network",
    ),
    explain: "Whoever carries your packets (the ISP, the hotspot, the network's owner) can't read or rewrite what you look up",
};

/// `scutil --dns` on a Mac on an ISP's resolvers, cut to what the probe reads.
#[cfg(test)]
pub(super) const SCUTIL_PLAIN: &str = "DNS configuration\n\nresolver #1\n  nameserver[0] : 2001:4e8:0:4001::16\n  nameserver[1] : 64.59.135.148\n  if_index : 14 (en0)\n  flags    : Request A records, Request AAAA records\n  reach    : 0x00000002 (Reachable)\n\nresolver #2\n  domain   : local\n  options  : mdns\n  timeout  : 5\n  order    : 300000\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 2001:4e8:0:4001::16\n  nameserver[1] : 64.59.135.148\n  if_index : 14 (en0)\n  flags    : Scoped, Request A records, Request AAAA records\n";
/// The network-extension archive with a DoH profile, as `plutil -p` prints it.
#[cfg(test)]
pub(super) const NE_DOH: &str = "{\n  \"$objects\" => [\n    0 => \"$null\"\n    1 => {\n      \"DNSSettings\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 7}\n    }\n    7 => {\n      \"$class\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 9}\n      \"ServerURL\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 8}\n    }\n    8 => \"https://dns.nextdns.io/abc123\"\n    9 => {\n      \"$classes\" => [\n        0 => \"NEDNSOverHTTPSSettings\"\n        1 => \"NEDNSSettings\"\n        2 => \"NSObject\"\n      ]\n      \"$classname\" => \"NEDNSOverHTTPSSettings\"\n    }\n  ]\n}\n";

#[cfg(test)]
mod tests {
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
        let other_proxy =
            dns_encrypted(&machine(&[("plutil -p", "\"$classname\" => \"NEDNSProxyProviderProtocol\"\n")]));
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
}
