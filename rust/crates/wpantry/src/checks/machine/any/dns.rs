//! What the encrypted-DNS check on each OS shares: reading a resolver
//! list, telling a loopback or LAN address from a public one, naming the
//! local stubs that forward over TLS or HTTPS, and the one sentence a
//! plaintext resolver gets. Plain DNS to an internal resolver (Kubernetes,
//! Docker, corporate split DNS) is legitimate, which is why the check is
//! Medium: it warns, never fails.

use crate::checks::machine::settings::{Outcome, Runner};

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
#[path = "dns_tests.rs"]
mod tests;
