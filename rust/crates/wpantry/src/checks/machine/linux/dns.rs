//! Whether DNS leaves the machine encrypted.

use super::super::any::dns;
use super::text;
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

/// What `resolvectl status` says about DNS over TLS: the best of the global
/// and per-link answers (`+DNSOverTLS` or `DNSOverTLS setting: yes` beats
/// `opportunistic` beats `-DNSOverTLS`), None when it says nothing
/// (systemd-resolved isn't running).
fn resolved_dot(out: &str) -> Option<&'static str> {
    let rank = |v: &str| match v {
        "yes" => 3,
        "opportunistic" => 2,
        "no" => 1,
        _ => 0,
    };
    let mut best: Option<&'static str> = None;
    for l in out.lines() {
        let v = if l.contains("+DNSOverTLS") {
            "yes"
        } else if l.contains("-DNSOverTLS") {
            "no"
        } else if let Some(i) = l.find("DNSOverTLS") {
            let rest = l[i + "DNSOverTLS".len()..].to_ascii_lowercase();
            if rest.contains("opportunistic") {
                "opportunistic"
            } else if rest.contains("yes") {
                "yes"
            } else if rest.split(|c: char| !c.is_alphanumeric()).any(|w| w == "no") {
                "no"
            } else {
                continue;
            }
        } else {
            continue;
        };
        if rank(v) > best.map_or(0, rank) {
            best = Some(v);
        }
    }
    best
}

/// `DNSOverTLS=` in resolved.conf and its drop-ins, when resolvectl can't be asked.
fn resolved_conf_dot(r: Runner) -> Option<String> {
    let mut all = r(&["cat", "/etc/systemd/resolved.conf"]);
    if let Ok(rd) = std::fs::read_dir("/etc/systemd/resolved.conf.d") {
        let mut extra: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        extra.sort();
        for p in extra {
            all.push('\n');
            all.push_str(&text(&p));
        }
    }
    all.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("DNSOverTLS="))
        .next_back()
        .map(|v| v.trim().to_ascii_lowercase())
}

/// Whether DNS leaves the machine encrypted: systemd-resolved's DNS over
/// TLS, NetworkManager's `dns-over-tls`, or a local stub that forwards
/// over TLS or HTTPS as the resolver in /etc/resolv.conf. Plain DNS to a
/// public address fails (Medium: a warning), a stub it can't judge is
/// manual, no answer at all is unknown.
fn dns_encrypted(r: Runner) -> Outcome {
    let resolved = r(&["resolvectl", "status"]);
    let dot = resolved_dot(&resolved).map(str::to_string).or_else(|| resolved_conf_dot(r));
    match dot.as_deref() {
        Some("yes") | Some("true") => return Outcome::pass("systemd-resolved: DNS over TLS is on (DNSOverTLS=yes)"),
        Some("opportunistic") => {
            return Outcome::fail(
                "systemd-resolved: DNSOverTLS=opportunistic falls back to plaintext whenever the server doesn't offer TLS, so an attacker on the path can downgrade it; set DNSOverTLS=yes",
            );
        }
        _ => {}
    }
    let names = r(&["nmcli", "-g", "NAME", "connection", "show", "--active"]);
    for name in names.lines().map(str::trim).filter(|n| !n.is_empty()) {
        let v = r(&["nmcli", "-g", "ipv4.dns-over-tls", "connection", "show", name]);
        match v.trim() {
            "yes" => return Outcome::pass(format!("NetworkManager: ipv4.dns-over-tls yes on {name}")),
            "opportunistic" => {
                return Outcome::fail(format!(
                    "NetworkManager: ipv4.dns-over-tls opportunistic on {name} falls back to plaintext whenever the server doesn't offer TLS; set it to yes"
                ));
            }
            _ => {}
        }
    }
    let resolv = r(&["cat", "/etc/resolv.conf"]);
    let ns = dns::nameservers(&resolv);
    if ns.is_empty() {
        return Outcome::unknown(if resolv.trim().is_empty() {
            "/etc/resolv.conf can't be read"
        } else {
            "/etc/resolv.conf names no resolver"
        });
    }
    if ns.iter().all(|n| dns::is_loopback(n)) {
        if ns.iter().any(|n| n == "127.0.0.53") && (dot.is_some() || !resolved.trim().is_empty()) {
            return Outcome::fail(
                "systemd-resolved's stub (127.0.0.53) forwards in plaintext (DNSOverTLS=no); an internal resolver (Kubernetes, Docker, corporate split DNS) legitimately uses plain DNS, which is why this only warns",
            );
        }
        return dns::local_stub(r, &ns);
    }
    Outcome::fail(dns::plaintext(&ns, "/etc/resolv.conf"))
}

pub(super) const DNS_ENCRYPTED: Check = Check {
    id: "POSTURE-DNS-ENCRYPTED",
    cis: "",
    title: "DNS leaves the machine encrypted (DoT or DoH)",
    severity: Severity::Medium,
    probe: dns_encrypted,
    fix: admin(
        "systemd-resolved: DNSOverTLS=yes and DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net in /etc/systemd/resolved.conf, then sudo systemctl restart systemd-resolved; NetworkManager: nmcli connection modify <name> ipv4.dns 1.1.1.1 ipv4.dns-over-tls yes; or a local stub (stubby, dnscrypt-proxy, cloudflared proxy-dns, unbound with forward-tls-upstream: yes) as the nameserver in /etc/resolv.conf",
    ),
    explain: "Whoever carries your packets (the ISP, the hotspot, the network's owner) can't read or rewrite what you look up",
};

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
