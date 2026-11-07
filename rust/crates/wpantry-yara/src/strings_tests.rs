use super::*;

/// The compiled string at YARA's regex reach.
fn compile(def: &StringDef) -> CompiledString {
    super::compile(def, REGEX_REACH)
}
use crate::parser::BASE64_STANDARD;
use crate::pattern::{Syntax, parse_hex, parse_regex};

fn def(kind: StringKind, mods: Modifiers) -> StringDef {
    StringDef { id: "a".into(), kind, mods, line: 1 }
}

fn find(s: &CompiledString, data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for v in &s.variants {
        if v.atoms.is_empty() {
            v.scan_all(data, &mut out);
            continue;
        }
        for pos in 0..data.len() {
            for (atom, off) in &v.atoms {
                if data[pos..].starts_with(atom) {
                    v.verify(data, pos, *off, &mut out);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn text_ascii_wide_and_nocase() {
    let mods = Modifiers { wide: true, ascii: true, nocase: true, ..Default::default() };
    let s = compile(&def(StringKind::Text(b"Hi".to_vec()), mods));
    assert_eq!(s.variants.len(), 2);
    assert_eq!(find(&s, b"xhI H\0i\0"), vec![(1, 2), (4, 4)]);
    let plain = compile(&def(StringKind::Text(b"Hi".to_vec()), Modifiers::default()));
    assert_eq!(find(&plain, b"hi Hi"), vec![(3, 2)]);
}

#[test]
fn xor_finds_every_key_and_fullword_decodes_neighbours() {
    let mods = Modifiers { xor: Some((0, 255)), fullword: true, ..Default::default() };
    let s = compile(&def(StringKind::Text(b"evil".to_vec()), mods));
    assert_eq!(s.variants.len(), 256);
    let key = 0x41;
    let mut data: Vec<u8> = b" evil ".iter().map(|b| b ^ key).collect();
    assert_eq!(find(&s, &data), vec![(1, 4)]);
    // "xevil" under the same key isn't a whole word.
    data = b"xevil ".iter().map(|b| b ^ key).collect();
    assert!(find(&s, &data).is_empty());
}

#[test]
fn base64_alignments() {
    let forms = base64_forms(b"This program cannot", BASE64_STANDARD);
    assert_eq!(forms.len(), 3);
    assert_eq!(forms[0], b"VGhpcyBwcm9ncmFtIGNhbm5vd");
    assert_eq!(forms[1], b"RoaXMgcHJvZ3JhbSBjYW5ub3");
    assert_eq!(forms[2], b"UaGlzIHByb2dyYW0gY2Fubm90");
    let mods = Modifiers { base64: Some(BASE64_STANDARD.to_vec()), ..Default::default() };
    let s = compile(&def(StringKind::Text(b"This program cannot".to_vec()), mods));
    assert_eq!(find(&s, b"xxVGhpcyBwcm9ncmFtIGNhbm5vdA==").len(), 1);
    let wide = Modifiers { base64wide: Some(BASE64_STANDARD.to_vec()), ..Default::default() };
    let s = compile(&def(StringKind::Text(b"abc".to_vec()), wide));
    assert_eq!(find(&s, &widen(b"YWJj")).len(), 1);
}

#[test]
fn wide_fullword() {
    let mods = Modifiers { wide: true, fullword: true, ..Default::default() };
    let s = compile(&def(StringKind::Text(b"ab".to_vec()), mods));
    assert_eq!(find(&s, &widen(b" ab ")), vec![(2, 4)]);
    assert!(find(&s, &widen(b"xab")).is_empty());
}

#[test]
fn hex_strings_with_prefixes_find_every_start() {
    let s = compile(&def(StringKind::Hex(parse_hex("?? [0-2] 41 42 43 44", 1).unwrap()), Modifiers::default()));
    // The atom is ABCD; the prefix (one byte, then 0-2 more) can start at 1, 2 or 3.
    assert_eq!(find(&s, b"xxxxABCD"), vec![(1, 7), (2, 6), (3, 5)]);
    let masked = compile(&def(StringKind::Hex(parse_hex("4? 5A", 1).unwrap()), Modifiers::default()));
    assert_eq!(find(&masked, b"\x4dZ\x5dZ"), vec![(0, 2)]);
}

#[test]
fn regexes_with_and_without_atoms() {
    let re = |s: &str| parse_regex(s.as_bytes(), false, false, Syntax::Relaxed, 1).unwrap();
    let s = compile(&def(StringKind::Regex(re("[0-9]+abc")), Modifiers::default()));
    assert_eq!(find(&s, b"x12abc"), vec![(1, 5), (2, 4)]);
    let wide = compile(&def(StringKind::Regex(re("ab")), Modifiers { wide: true, ..Default::default() }));
    assert_eq!(find(&wide, b"a\0b\0"), vec![(0, 4)]);
    let nocase =
        compile(&def(StringKind::Regex(re("ab")), Modifiers { nocase: true, fullword: true, ..Default::default() }));
    assert_eq!(find(&nocase, b"AB xAB"), vec![(0, 2)]);
    // No position is a good atom: tried everywhere its first byte allows.
    let none = compile(&def(StringKind::Regex(re("[a-z][0-9][a-z][0-9][a-z]")), Modifiers::default()));
    assert!(none.variants[0].atoms.is_empty());
    assert_eq!(find(&none, b"..a1b2c.."), vec![(2, 5)]);
}

#[test]
fn alternations_and_repeats_give_atoms() {
    let re = |s: &str| parse_regex(s.as_bytes(), false, false, Syntax::Relaxed, 1).unwrap();
    let s = compile(&def(StringKind::Regex(re(r"(e|\\x65)(\\x76|\\118)al")), Modifiers::default()));
    assert!(!s.variants[0].atoms.is_empty());
    assert_eq!(find(&s, br"x\x65\118al"), vec![(1, 10)]);
    let stack = compile(&def(StringKind::Regex(re(r"(\xC6\x45.{2}){3}")), Modifiers::default()));
    assert_eq!(stack.variants[0].atoms.len(), 1);
    assert_eq!(find(&stack, b"\xC6\x45ab\xC6\x45cd\xC6\x45ef"), vec![(0, 12)]);
    assert!(leading(&Node::Assert(crate::pattern::Assert::Start)).is_none());
    let bounded = compile(&def(StringKind::Regex(re(r"(\beval\(|\bassert\()")), Modifiers::default()));
    assert!(!bounded.variants[0].atoms.is_empty());
    assert_eq!(find(&bounded, b"x eval( xeval("), vec![(2, 5)]);
}

#[test]
fn atoms_avoid_filler() {
    let s = compile(&def(StringKind::Text(b"\0\0\0\0\0evil".to_vec()), Modifiers::default()));
    assert_eq!(s.variants[0].atoms, vec![(b"evil".to_vec(), 5)]);
    assert_eq!(expand(&[ByteSet::one(b'a').case_fold(), ByteSet::one(b'b')]).len(), 2);
    assert_eq!(first_set(&Node::Assert(crate::pattern::Assert::Start)), None);
}
