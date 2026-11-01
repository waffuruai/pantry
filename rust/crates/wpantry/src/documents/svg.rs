//! SVG is XML that browsers run: scripts, event handlers, `javascript:`
//! URIs and entity declarations fail; HTML inside the image and content
//! from another host warn. Read lowercased, up to the member cap.

use super::{Doc, MAX_MEMBER, find, push};

/// ` onload`, ` onclick`: at least this many letters after `on` before the `=`.
const MIN_HANDLER_LETTERS: usize = 3;

pub(super) fn scan(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let lower: Vec<u8> = bytes.iter().take(MAX_MEMBER).map(|b| b.to_ascii_lowercase()).collect();
    let has = |s: &[u8]| find(&lower, s).is_some();
    if has(b"<script") {
        push(out, file, "IMG-SVG-SCRIPT", "a <script> element: the image runs code where it is rendered", true);
    } else if has_handler(&lower) {
        push(out, file, "IMG-SVG-SCRIPT", "an on* event handler: the image runs code where it is rendered", true);
    } else if has(b"javascript:") {
        push(out, file, "IMG-SVG-SCRIPT", "a javascript: URI: the image runs code where it is rendered", true);
    }
    if has(b"<!entity") {
        push(
            out,
            file,
            "IMG-SVG-SCRIPT",
            "an XML entity declaration: the parser can be made to read local files (XXE)",
            true,
        );
    }
    if has(b"<foreignobject") || has(b"<iframe") || has(b"<embed") || has(b"<object") {
        push(
            out,
            file,
            "IMG-SVG-EXTERNAL",
            "foreignObject, iframe, embed or object: HTML or another document inside the image",
            false,
        );
    } else if has(b"href=\"http") || has(b"href='http") || has(b"href=\"//") {
        push(out, file, "IMG-SVG-EXTERNAL", "content loaded from another host when the image renders", false);
    }
}

/// ` onload=`, ` onclick=`, …: an attribute starting with `on` followed by
/// letters and `=`.
fn has_handler(lower: &[u8]) -> bool {
    let mut from = 0;
    while let Some(i) = find(&lower[from..], b" on") {
        let at = from + i + 3;
        let letters = lower[at..].iter().take_while(|c| c.is_ascii_lowercase()).count();
        if letters >= MIN_HANDLER_LETTERS && lower.get(at + letters) == Some(&b'=') {
            return true;
        }
        from = at;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::{ids, scan_bytes};

    #[test]
    fn a_plain_drawing_is_nothing() {
        assert!(
            scan_bytes("logo.svg", b"<svg viewBox=\"0 0 1 1\"><path d=\"M0 0h1v1z\" fill=\"none\"/></svg>").is_empty()
        );
        assert!(
            scan_bytes("x.svg", b"<svg><g id=\"onion\" font=\"x\"/></svg>").is_empty(),
            "words starting with on are not handlers"
        );
        assert!(
            scan_bytes("x.svg", b"<svg><use href=\"#shape\"/><a href=\"/local\"/></svg>").is_empty(),
            "local references are not external content"
        );
    }

    #[test]
    fn scripts_handlers_and_uris_fail() {
        let script = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>fetch('https://x.y')</script></svg>";
        let got = scan_bytes("logo.svg", script);
        assert_eq!(ids(&got), [("IMG-SVG-SCRIPT", true)]);
        assert!(got[0].note.contains("<script>"), "{}", got[0].note);
        let handler = b"<svg onload=\"alert(1)\"><circle r=\"1\"/></svg>";
        let got = scan_bytes("logo.svg", handler);
        assert_eq!(ids(&got), [("IMG-SVG-SCRIPT", true)]);
        assert!(got[0].note.contains("event handler"), "{}", got[0].note);
        let shouting = b"<SVG ONLOAD=\"alert(1)\"></SVG>";
        assert_eq!(ids(&scan_bytes("logo.svg", shouting)), [("IMG-SVG-SCRIPT", true)], "case doesn't hide it");
        let uri = b"<svg><a href=\"javascript:alert(1)\"><text>hi</text></a></svg>";
        let got = scan_bytes("logo.svg", uri);
        assert_eq!(ids(&got), [("IMG-SVG-SCRIPT", true)]);
        assert!(got[0].note.contains("javascript: URI"), "{}", got[0].note);
        let xxe = b"<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><svg>&x;</svg>";
        let got = scan_bytes("logo.svg", xxe);
        assert_eq!(ids(&got), [("IMG-SVG-SCRIPT", true)]);
        assert!(got[0].note.contains("XXE"), "{}", got[0].note);
    }

    #[test]
    fn external_content_warns() {
        let image = b"<svg><image href=\"https://x.y/a.png\"/></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", image)), [("IMG-SVG-EXTERNAL", false)]);
        let protocol_relative = b"<svg><image href=\"//x.y/a.png\"/></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", protocol_relative)), [("IMG-SVG-EXTERNAL", false)]);
        let foreign =
            b"<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><p>hi</p></body></foreignObject></svg>";
        let got = scan_bytes("logo.svg", foreign);
        assert_eq!(ids(&got), [("IMG-SVG-EXTERNAL", false)]);
        assert!(got[0].note.contains("foreignObject"), "{}", got[0].note);
        let both = b"<svg onclick=\"x()\"><iframe src=\"https://x.y\"/></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", both)), [("IMG-SVG-SCRIPT", true), ("IMG-SVG-EXTERNAL", false)]);
    }

    #[test]
    fn handlers_need_letters_and_an_equals_sign() {
        assert!(has_handler(b"<svg onload=\"x\">"));
        assert!(has_handler(b"<a onmouseover='x'>"));
        assert!(!has_handler(b"<g id=\"onion\">"), "no equals after the letters");
        assert!(!has_handler(b"<g on=\"x\">"), "too short to be an event");
        assert!(!has_handler(b"<g onload >"), "no equals at all");
        assert!(!has_handler(b"ongoing=\"x\""), "not an attribute: no space before it");
    }
}
