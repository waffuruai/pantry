use super::*;

fn set(bytes: &[u8]) -> Node {
    let mut s = ByteSet::default();
    for b in bytes {
        s.insert(*b);
    }
    Node::Set(s)
}

#[test]
fn byteset_basics() {
    let s = ByteSet::range(b'a', b'c');
    assert_eq!(s.len(), 3);
    assert!(s.contains(b'b') && !s.contains(b'd'));
    assert_eq!(s.case_fold().len(), 6);
    assert_eq!(s.complement().len(), 253);
    assert!(ByteSet::default().is_empty());
    assert_eq!(ByteSet::masked(0x4A, 0x0F).len(), 16);
    assert!(ByteSet::masked(0x4A, 0x0F).contains(0x7A));
}

#[test]
fn hex_strings_parse_to_sets_jumps_and_alternatives() {
    let n = parse_hex("4D 5A ?? ?F [2-4] ( 01 | 02 03 ) ~00 [3] [5-]", 1).unwrap_err();
    assert!(n.to_string().contains("end with a jump"));
    let n = parse_hex("4D ?? [2-4] ( 01 | 02 03 ) ~00", 1).unwrap();
    let Node::Seq(items) = n else { panic!() };
    assert_eq!(items[0], set(&[0x4D]));
    assert_eq!(items[1], Node::Set(ByteSet::FULL));
    assert_eq!(
        items[2],
        Node::Repeat { node: Box::new(Node::Set(ByteSet::FULL)), min: 2, max: Some(4), greedy: false }
    );
    assert!(matches!(&items[3], Node::Alt(b) if b.len() == 2));
    let Node::Set(not0) = items[4] else { panic!() };
    assert_eq!(not0.len(), 255);
}

#[test]
fn hex_jump_forms() {
    assert_eq!(hex_jump("4"), Some((4, Some(4))));
    assert_eq!(hex_jump("2-"), Some((2, None)));
    assert_eq!(hex_jump("-"), Some((0, None)));
    assert_eq!(hex_jump("0x10-0o20"), Some((16, Some(16))));
    assert_eq!(hex_jump("5-2"), None);
    assert_eq!(hex_jump("x"), None);
}

#[test]
fn hex_errors() {
    for bad in ["4", "4G", "( 01", "01 | 02", "( )", "[2-4] 01", "01 [2", "01 )"] {
        assert!(parse_hex(bad, 1).is_err(), "{bad}");
    }
}

#[test]
fn regexes_parse_classes_repeats_and_escapes() {
    let n = parse_regex(br"ab+[c-e\d]{2,3}?\x41.\b", false, false, Syntax::Strict, 1).unwrap();
    let Node::Seq(items) = n else { panic!() };
    assert_eq!(items[0], set(b"a"));
    assert!(matches!(&items[1], Node::Repeat { min: 1, max: None, greedy: true, .. }));
    assert!(matches!(&items[2], Node::Repeat { min: 2, max: Some(3), greedy: false, .. }));
    assert_eq!(items[3], set(b"A"));
    let Node::Set(dot) = items[4] else { panic!() };
    assert!(!dot.contains(b'\n'));
    assert_eq!(items[5], Node::Assert(Assert::WordBoundary));
}

#[test]
fn regex_flags() {
    assert_eq!(parse_regex(b"a", true, false, Syntax::Strict, 1).unwrap(), set(b"aA"));
    let Node::Set(dot) = parse_regex(b".", false, true, Syntax::Strict, 1).unwrap() else { panic!() };
    assert_eq!(dot, ByteSet::FULL);
    assert!(matches!(parse_regex(b"a|b", false, false, Syntax::Strict, 1).unwrap(), Node::Alt(_)));
    assert!(matches!(parse_regex(b"(?:a)", false, false, Syntax::Strict, 1).unwrap(), Node::Set(_)));
}

#[test]
fn strict_and_relaxed_differ_on_braces_and_escapes() {
    assert!(parse_regex(b"a{x", false, false, Syntax::Strict, 1).is_err());
    assert!(parse_regex(b"a{x", false, false, Syntax::Relaxed, 1).is_ok());
    assert!(parse_regex(br"\g", false, false, Syntax::Strict, 1).is_err());
    assert_eq!(parse_regex(br"\g", false, false, Syntax::Relaxed, 1).unwrap(), set(b"g"));
    // A brace that is a repeat is fine in both.
    assert!(parse_regex(b"a{2}", false, false, Syntax::Strict, 1).is_ok());
}

#[test]
fn classes() {
    assert_eq!(
        parse_regex(b"[^a]", false, false, Syntax::Strict, 1).unwrap(),
        Node::Set(ByteSet::one(b'a').complement())
    );
    assert_eq!(parse_regex(b"[]a]", false, false, Syntax::Strict, 1).unwrap(), set(b"]a"));
    assert_eq!(parse_regex(b"[a-]", false, false, Syntax::Strict, 1).unwrap(), set(b"a-"));
    let Node::Set(w) = parse_regex(br"[\w.]", false, false, Syntax::Strict, 1).unwrap() else { panic!() };
    assert_eq!(w.len(), 64);
    assert_eq!(parse_regex(br"[\b]", false, false, Syntax::Strict, 1).unwrap(), set(&[8]));
    for bad in ["[a", "[z-a]", r"[\B]", "a)", "(a", "*a", r"\", r"\xZ", "^*"] {
        assert!(parse_regex(bad.as_bytes(), false, false, Syntax::Strict, 1).is_err(), "{bad}");
    }
}

#[test]
fn reversed_widened_and_folded() {
    let n = parse_regex(b"ab", false, false, Syntax::Strict, 1).unwrap();
    assert_eq!(n.reversed(), Node::Seq(vec![set(b"b"), set(b"a")]));
    assert_eq!(n.widened().flatten(), Node::Seq(vec![set(b"a"), set(&[0]), set(b"b"), set(&[0])]));
    assert_eq!(n.case_folded(), Node::Seq(vec![set(b"aA"), set(b"bB")]));
}
