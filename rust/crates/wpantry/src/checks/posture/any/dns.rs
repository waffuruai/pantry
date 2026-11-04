//! What the encrypted-DNS check on each OS shares: reading a resolver
//! list, telling a loopback or LAN address from a public one, naming the
//! local stubs that forward over TLS or HTTPS, and the one sentence a
//! plaintext resolver gets. Plain DNS to an internal resolver (Kubernetes,
//! Docker, corporate split DNS) is legitimate, which is why the check is
//! Medium: it warns, never fails.

use crate::checks::posture::{Outcome, Runner};

/// Local resolvers that forward over TLS or HTTPS, by process name.
pub const ENCRYPTING_STUBS: &[&str] =
    &["stubby", "dnscrypt-proxy", "cloudflared", "nextdns", "AdGuardHome", "ctrld", "dnsproxy"];

/// Where unbound keeps its config: the distro path, then Homebrew's.
const UNBOUND_CONF: &[&str] =
    &["/etc/unbound/unbound.conf", "/opt/homebrew/etc/unbound/unbound.conf", "/usr/local/etc/unbound/unbound.conf"];

/// The `nameserver` lines of a resolv.conf.
pub fn nameservers(resolv: &str) -> Vec<String> {
    resolv
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter(|r| r.starts_with(char::is_whitespace))
        .map(|r| r.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn is_loopback(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "::1"
}

/// RFC 1918, link-local, CGNAT and ULA ranges: a LAN or VPN resolver.
pub fn is_private(ip: &str) -> bool {
    let l = ip.to_ascii_lowercase();
    if l.starts_with("10.") || l.starts_with("192.168.") || l.starts_with("169.254.") {
        return true;
    }
    let second = |rest: &str| rest.split('.').next().and_then(|p| p.parse::<u8>().ok());
    if let Some(n) = l.strip_prefix("172.").and_then(second) {
        return (16..=31).contains(&n);
    }
    if let Some(n) = l.strip_prefix("100.").and_then(second) {
        return (64..=127).contains(&n);
    }
    l.starts_with("fc") || l.starts_with("fd") || l.starts_with("fe80:")
}

/// Whether a process by that exact name is running.
pub fn running(r: Runner, name: &str) -> bool {
    !r(&["pgrep", "-x", name]).trim().is_empty()
}

/// The evidence for resolvers reached in the clear, with why it only warns.
pub fn plaintext(resolvers: &[String], source: &str) -> String {
    let kind = if resolvers.iter().all(|n| is_private(n)) { " (a LAN or VPN address)" } else { "" };
    format!(
        "DNS goes to {}{kind} in plaintext on UDP 53 ({source}); an internal resolver (Kubernetes, Docker, corporate split DNS) legitimately uses plain DNS, which is why this only warns",
        resolvers.join(", ")
    )
}

/// A loopback resolver: which stub answers there, and whether it is one
/// that forwards encrypted. unbound is judged by its config; anything
/// else needs a person's eyes.
pub fn local_stub(r: Runner, resolvers: &[String]) -> Outcome {
    let at = resolvers.join(", ");
    if let Some(stub) = ENCRYPTING_STUBS.iter().find(|s| running(r, s)) {
        return Outcome::pass(format!("{stub} is the local resolver ({at}) and forwards over TLS or HTTPS"));
    }
    if running(r, "unbound") {
        let conf: String = UNBOUND_CONF.iter().map(|p| r(&["cat", p])).collect::<Vec<_>>().join("\n");
        let tls = conf.lines().map(str::trim).any(|l| l.starts_with("forward-tls-upstream:") && l.ends_with("yes"));
        return if tls {
            Outcome::pass(format!(
                "unbound is the local resolver ({at}) and forwards over TLS (forward-tls-upstream: yes)"
            ))
        } else {
            Outcome::manual(format!(
                "unbound is the local resolver ({at}) without forward-tls-upstream: a recursive resolver asks the authoritative servers in the clear, a forwarder asks its upstream in the clear; couldn't tell which it is"
            ))
        };
    }
    if running(r, "dnsmasq") {
        return Outcome::manual(format!(
            "dnsmasq is the local resolver ({at}): it forwards in plaintext unless its servers are an encrypting stub; couldn't tell"
        ));
    }
    Outcome::manual(format!(
        "a local resolver on {at} that wpantry doesn't know; check that it forwards over TLS or HTTPS"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::posture::Status;
    use crate::checks::posture::testing::machine;

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
}
