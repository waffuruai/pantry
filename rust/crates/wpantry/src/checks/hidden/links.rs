//! Links that leak or mislead: exfiltration parameters, dangerous URI
//! schemes and look-alike domains.

use crate::checks::hidden::instructions::unquoted;
use crate::checks::hidden::unicode::mixed_script;

// --- Links ---------------------------------------------------------------

const EXFIL_KEYS: &[&str] = &[
    "data",
    "q",
    "c",
    "ctx",
    "context",
    "prompt",
    "secret",
    "secrets",
    "key",
    "token",
    "conversation",
    "conv",
    "history",
    "content",
    "text",
    "msg",
    "message",
    "payload",
    "exfil",
    "leak",
    "env",
    "creds",
    "credentials",
    "password",
    "pw",
    "summary",
];

fn host_of(url: &str) -> String {
    let rest = url.trim_start_matches("https://").trim_start_matches("http://").trim_start_matches("//");
    rest.split(['/', '?', '#']).next().unwrap_or("").to_string()
}

/// A markdown or HTML link or image whose query string is built to carry
/// something: a template placeholder, an empty or oversized value under a
/// telling key, or a very long query. (line, host, why).
pub(crate) fn exfil_link(text: &str) -> Option<(usize, String, &'static str)> {
    for (n, line) in text.lines().enumerate() {
        for marker in ["](http", "](//", "src=\"http", "src='http", "href=\"http", "href='http"] {
            let mut rest = line;
            while let Some(i) = rest.find(marker) {
                let url_start = i + marker.len() - if marker == "](//" { 2 } else { 4 };
                let url = rest[url_start..].split([')', '"', '\'', ' ', '>', '<']).next().unwrap_or("");
                if let Some(q) = url.find('?') {
                    let query = &url[q + 1..];
                    let lq = query.to_ascii_lowercase();
                    let templated =
                        ["{{", "${", "%7b", "%24%7b", "<", "%3c", "[", "%5b"].iter().any(|t| lq.contains(t));
                    let keyed = query.split('&').filter_map(|kv| kv.split_once('=')).any(|(k, v)| {
                        EXFIL_KEYS.contains(&k.to_ascii_lowercase().as_str()) && (v.is_empty() || v.len() > 100)
                    });
                    if templated {
                        return Some((n + 1, host_of(url), "with a placeholder in its query string"));
                    }
                    if keyed {
                        return Some((
                            n + 1,
                            host_of(url),
                            "with an empty or oversized value under a telling query key",
                        ));
                    }
                    if query.len() > 400 {
                        return Some((n + 1, host_of(url), "with a very long query string"));
                    }
                }
                rest = &rest[i + marker.len()..];
            }
        }
    }
    None
}

/// `javascript:`, `vbscript:` and executable `data:` URIs: (line, what,
/// whether it is a link target rather than a mention).
pub(crate) fn dangerous_uri(text: &str) -> Option<(usize, &'static str, bool)> {
    let schemes: &[(&str, &str)] = &[
        ("javascript:", "a javascript: URI"),
        ("vbscript:", "a vbscript: URI"),
        ("data:text/html", "an HTML document as a data: URI"),
        ("data:application/javascript", "script as a data: URI"),
        ("data:application/x-javascript", "script as a data: URI"),
        ("data:text/javascript", "script as a data: URI"),
        ("data:application/octet-stream", "a binary download as a data: URI"),
    ];
    for (n, line) in text.lines().enumerate() {
        let l = line.to_ascii_lowercase();
        for (needle, what) in schemes {
            let mut from = 0;
            while let Some(i) = l[from..].find(needle) {
                let at = from + i;
                let after = &l[at + needle.len()..];
                from = at + needle.len();
                if *needle == "javascript:"
                    && (after.starts_with("void(0)") || after.starts_with("void 0") || after.starts_with(';'))
                {
                    continue;
                }
                let before = &l[..at];
                let linked =
                    ["](", "href=\"", "href='", "href=", "src=\"", "src='", "src=", "url(", "action=\"", "action='"]
                        .iter()
                        .any(|m| before.ends_with(m));
                if !linked && !unquoted(&l).contains(needle) {
                    continue; // quoted: a mention, not a link
                }
                return Some((n + 1, what, linked));
            }
        }
    }
    None
}

/// A host in a URL made of look-alike letters (fail) or punycode (warn):
/// (line, host, hard).
pub(crate) fn confusable_domain(text: &str) -> Option<(usize, String, bool)> {
    for (n, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(i) = rest.find("://") {
            let host: String = rest[i + 3..]
                .chars()
                .take_while(|c| {
                    !matches!(c, '/' | ':' | '?' | '#' | ')' | '"' | '\'' | '<' | '>' | ']' | ',' | '`')
                        && !c.is_whitespace()
                })
                .collect();
            rest = &rest[i + 3..];
            if host.is_empty() {
                continue;
            }
            if host.is_ascii() {
                if host.split('.').any(|label| label.starts_with("xn--")) {
                    return Some((n + 1, host, false));
                }
                continue;
            }
            if host.split('.').any(mixed_script) {
                return Some((n + 1, host, true));
            }
        }
    }
    None
}
