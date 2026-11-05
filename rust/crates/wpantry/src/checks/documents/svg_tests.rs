use super::*;
use crate::checks::documents::{ids, scan_bytes};

#[test]
fn a_plain_drawing_is_nothing() {
    assert!(scan_bytes("logo.svg", b"<svg viewBox=\"0 0 1 1\"><path d=\"M0 0h1v1z\" fill=\"none\"/></svg>").is_empty());
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
