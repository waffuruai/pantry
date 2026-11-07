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

fn caps(src: &str, data: &[u8]) -> Option<Captures> {
    let (node, groups) = crate::pattern::parse_regex_groups(src.as_bytes(), false, false, Syntax::Relaxed).unwrap();
    search_captures(&node, data, groups)
}

#[test]
fn captures_record_where_each_group_matched() {
    assert_eq!(caps(r"key=(\w+)", b"a key=abc;"), Some(vec![Some((2, 9)), Some((6, 9))]));
    // Non-capturing groups aren't numbered; nested groups count in `(` order.
    assert_eq!(caps(r"(?:x)((a)(b))", b"xab"), Some(vec![Some((0, 3)), Some((1, 3)), Some((1, 2)), Some((2, 3))]));
}

#[test]
fn a_group_that_took_no_part_is_none_and_a_repeat_keeps_its_last_iteration() {
    assert_eq!(caps(r"(a)|(b)", b"b"), Some(vec![Some((0, 1)), None, Some((0, 1))]));
    assert_eq!(caps(r"(\d)+", b"123"), Some(vec![Some((0, 3)), Some((2, 3))]));
}

#[test]
fn a_backtracked_group_forgets_its_failed_attempt() {
    // `(a+)` first takes "aaa", the `ab` after it fails, and it gives one back.
    assert_eq!(caps(r"(a+)ab", b"aaab"), Some(vec![Some((0, 4)), Some((0, 2))]));
    assert_eq!(caps(r"(x)?y", b"y"), Some(vec![Some((0, 1)), None]));
}

#[test]
fn search_finds_the_leftmost_match_first_in_priority_order() {
    assert_eq!(caps(r"b+|ab", b"cabb"), Some(vec![Some((1, 3))]));
    assert_eq!(caps(r"z", b"abc"), None);
}
