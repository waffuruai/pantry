use super::*;
use crate::checks::secrets::tests::scanner;

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A GitHub token, built here so this file holds none.
fn token() -> String {
    let tail: String = (0..36).map(|i| ALNUM[(i * 7 + 3) % ALNUM.len()] as char).collect();
    format!("{}{}_{tail}", "gh", "p")
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = c.iter().fold(0u32, |a, &b| a << 8 | b as u32) << (8 * (3 - c.len()));
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// What the scanner reports for `text`: (rule, line, columns, tags).
fn report(text: &str) -> Vec<(String, usize, usize, usize, String)> {
    scanner()
        .scan(text.as_bytes(), "", None)
        .into_iter()
        .map(|f| (f.rule, f.start_line, f.start_col, f.end_col, f.tags.join(",")))
        .collect()
}

// Each expectation is what betterleaks v1.10.0 reports for the same text.
#[test]
fn encoded_secrets_are_found_where_their_encoding_is() {
    let inner = format!("token = \"{}\"", token());
    let pct: String = inner.bytes().map(|b| format!("%{b:02X}")).collect();
    let hex: String = inner.bytes().map(|b| format!("{b:02x}")).collect();
    let uni: String = inner.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
    let gh = || "github-pat".to_string();
    assert_eq!(
        report(&format!("first line\ndata: {}\n", b64(inner.as_bytes()))),
        vec![(gh(), 2, 7, 74, "decoded:base64,decode-depth:1".into())]
    );
    assert_eq!(
        report(&format!("x: {}\n", b64(b64(inner.as_bytes()).as_bytes()))),
        vec![(gh(), 1, 4, 95, "decoded:base64,decode-depth:2".into())]
    );
    assert_eq!(report(&format!("blob {hex} end\n")), vec![(gh(), 1, 6, 105, "decoded:hex,decode-depth:1".into())]);
    assert_eq!(
        report(&format!("url = https://example.com/?q={pct}\n")),
        vec![(gh(), 1, 30, 179, "decoded:percent,decode-depth:1".into())]
    );
    assert_eq!(report(&format!("s = \"{uni}\"\n")), vec![(gh(), 1, 6, 305, "decoded:unicode,decode-depth:1".into())]);
}

#[test]
fn the_raw_secret_is_found_without_tags() {
    assert_eq!(report(&format!("token = \"{}\"\n", token())), vec![("github-pat".into(), 1, 10, 49, String::new())]);
}

#[test]
fn decoders_follow_go() {
    assert_eq!(percent(b"a%41b%zz"), b"aAb%zz");
    assert!(percent(b"%00").is_empty(), "unprintable");
    assert_eq!(hex_decode(b"41424344"), b"ABCD");
    assert!(hex_decode(b"abcdef").is_empty(), "no digit");
    assert!(hex_decode(b"414").is_empty(), "odd length");
    assert_eq!(base64(b"aGVsbG8gd29ybGQ="), b"hello world");
    assert_eq!(base64(b"aGVsbG8gd29ybGQ"), b"hello world", "raw URL alphabet, unpadded");
    assert!(base64(b"aGVsbG8gd29ybGQ==").is_empty(), "bad padding");
    assert!(base64(b"abcdefghijklmnop").is_empty(), "no digit or symbol");
    assert_eq!(unicode(b"U+0041 U+0042"), "AB".as_bytes());
    assert_eq!(unicode(b"\\u0041\\\\u0042"), b"AB");
    assert_eq!(unicode(b"\\ud800"), "\u{FFFD}".as_bytes());
}

#[test]
fn runs_are_found_by_kind_and_touching_neighbours_yield_to_the_stronger() {
    let kinds = |d: &[u8]| matches(d).into_iter().map(|(k, s)| (k, s.start, s.end)).collect::<Vec<_>>();
    assert_eq!(kinds(b"x %41%42 y"), vec![(PERCENT, 2, 8)]);
    assert_eq!(kinds(&[b"0123456789abcdef".repeat(2), b" ".to_vec()].concat()), vec![(HEX, 0, 32)]);
    assert_eq!(kinds(b"short abc123"), vec![]);
    assert_eq!(kinds(b"YWJjZGVmZ2hpamtsbW5v=="), vec![(BASE64, 0, 22)]);
    // A base64 run touching a percent run gives way to it.
    assert_eq!(kinds(b"%41YWJjZGVmZ2hpamtsbW5v"), vec![(PERCENT, 0, 3)]);
}
