//! Traffic to a bare IP address instead of a name: nothing to look up,
//! nothing to block by name, and no certificate that fits. Loopback and
//! the unspecified address are what a dev server binds. It warns alone and
//! fails beside a hard finding from the rules before it.

use super::{Context, Suspect, line_at, push};

const SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];
/// Addresses that stay on the machine.
const LOOPBACK: &str = "127.";
const UNSPECIFIED: &str = "0.0.0.0";
/// Dotted quads have this many parts, each at most this large.
const QUAD_PARTS: usize = 4;
const MAX_OCTET: u16 = 255;

pub(super) fn scan(file: &str, text: &str, ctx: Context, out: &mut Vec<Suspect>) {
    if !matches!(ctx, Context::Web | Context::Markup | Context::Python | Context::Shell) {
        return;
    }
    let Some((ip, line)) = raw_ip_url(text) else { return };
    let obfuscated = out.iter().any(|o| o.hard);
    push(out, file, "SUSPECT-RAW-IP", line, format!("talks to a bare IP address ({ip}) instead of a name"), obfuscated);
}

/// `http://1.2.3.4` or `ws://1.2.3.4` in the text: the address and its line.
fn raw_ip_url(text: &str) -> Option<(String, usize)> {
    for scheme in SCHEMES {
        let mut rest = text;
        while let Some(i) = rest.find(scheme) {
            let host: String =
                rest[i + scheme.len()..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() == QUAD_PARTS
                && parts.iter().all(|p| !p.is_empty() && p.parse::<u16>().is_ok_and(|n| n <= MAX_OCTET))
                && !host.starts_with(LOOPBACK)
                && host != UNSPECIFIED
            {
                let at = text.len() - rest.len() + i;
                return Some((host, line_at(text, at)));
            }
            rest = &rest[i + scheme.len()..];
        }
    }
    None
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
