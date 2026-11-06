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
#[path = "svg_tests.rs"]
mod tests;
