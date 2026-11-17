use super::*;
use crate::pattern::{Syntax, parse_hex, parse_regex};

fn re(src: &str) -> Node {
    parse_regex(src.as_bytes(), false, false, Syntax::Relaxed, 1).unwrap()
}

fn first(node: &Node, data: &[u8], start: usize) -> Option<usize> {
    Matcher::new(data, start, true, data.len()).first(node, start)
}

#[test]
fn greedy_and_lazy_repeats() {
    assert_eq!(first(&re("a+"), b"aaab", 0), Some(3));
    assert_eq!(first(&re("a+?"), b"aaab", 0), Some(1));
    assert_eq!(first(&re("a*b"), b"aaab", 0), Some(4));
    assert_eq!(first(&re("a{2}"), b"aaab", 0), Some(2));
    assert_eq!(first(&re("a{5}"), b"aaab", 0), None);
    assert_eq!(first(&re("(ab)+c"), b"ababc", 0), Some(5));
    assert_eq!(first(&re("(ab)+?"), b"ababc", 0), Some(2));
    assert_eq!(first(&re("(a|)*b"), b"aab", 0), Some(3));
}

#[test]
fn alternation_and_assertions() {
    assert_eq!(first(&re("ab|a"), b"ac", 0), Some(1));
    assert_eq!(first(&re("^a"), b"ba", 1), None);
    assert_eq!(first(&re("^b"), b"ba", 0), Some(1));
    assert_eq!(first(&re("a$"), b"ba", 1), Some(2));
    assert_eq!(first(&re(r"\bfoo\b"), b"a foo b", 2), Some(5));
    assert_eq!(first(&re(r"foo\b"), b"foobar", 0), None);
    assert_eq!(first(&re(r"foo\B"), b"foobar", 0), Some(3));
}

#[test]
fn hex_jumps_match_every_distance() {
    let node = parse_hex("01 [1-3] 02", 1).unwrap();
    assert_eq!(first(&node, b"\x01xx\x02", 0), Some(4));
    assert_eq!(first(&node, b"\x01\x02", 0), None);
    assert_eq!(first(&node, b"\x01xxxx\x02", 0), None);
    let alt = parse_hex("01 ( 02 | 03 04 ) 05", 1).unwrap();
    assert_eq!(first(&alt, b"\x01\x03\x04\x05", 0), Some(4));
}

#[test]
fn backwards_finds_every_start() {
    // The prefix `a+` read backwards from position 3 of "aaab" can start at 0, 1 or 2.
    let prefix = re("a+").reversed();
    let mut starts = Matcher::new(b"aaab", 3, false, 10).all(&prefix, 3);
    starts.sort();
    assert_eq!(starts, vec![0, 1, 2]);
}

#[test]
fn limits_and_budget() {
    // The window stops a match from reading past it.
    assert_eq!(Matcher::new(b"aaaa", 0, true, 2).first(&re("a+"), 0), Some(2));
    // A pathological pattern gives up instead of hanging.
    let evil = re("(a*)*b");
    let data = vec![b'a'; 64];
    assert_eq!(first(&evil, &data, 0), None);
}

#[test]
fn search_finds_anywhere() {
    assert!(search(&re("b+c"), b"aaabbc"));
    assert!(!search(&re("x"), b"aaabbc"));
    assert!(search(&re("$"), b""));
}
