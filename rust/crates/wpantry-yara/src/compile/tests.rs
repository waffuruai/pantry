//! Conditions end to end: compile a rule, scan some bytes, see whether it hit.

use crate::{Compiler, ScanOptions, Syntax};

fn hits(src: &str, data: &[u8]) -> Vec<String> {
    hits_with(src, data, &ScanOptions::default())
}

fn hits_with(src: &str, data: &[u8], opts: &ScanOptions) -> Vec<String> {
    let mut c = Compiler::new();
    c.add_source("t", src, Syntax::Relaxed);
    let rules = c.build();
    assert!(rules.rejected.is_empty(), "{:?}", rules.rejected);
    rules.scan(data, opts).matches.into_iter().map(|h| h.rule).collect()
}

/// Whether a one-rule condition is true on `data`, with strings $a = "abc", $b = "xyz".
fn holds(cond: &str, data: &[u8]) -> bool {
    let src = format!("import \"math\" rule r {{ strings: $a = \"abc\" $b = \"xyz\" condition: {cond} }}");
    !hits(&src, data).is_empty()
}

fn rejected(src: &str) -> String {
    let mut c = Compiler::new();
    assert_eq!(c.add_source("t", src, Syntax::Strict), 0, "{src}");
    let rules = c.build();
    rules.rejected[0].error.to_string()
}

#[test]
fn strings_counts_offsets_and_lengths() {
    let data = b"abc..abc..xyz";
    assert!(holds("$a and $b", data));
    assert!(holds("#a == 2 and #b == 1", data));
    assert!(holds("@a[1] == 0 and @a[2] == 5 and @a == 0 and !a[1] == 3", data));
    assert!(holds("@a[3] == 0 or true", data));
    assert!(!holds("@a[3] == 0", data));
    assert!(holds("$a at 5 and not $a at 4", data));
    assert!(holds("$b in (8..12) and not $b in (0..5)", data));
    assert!(holds("#a in (1..10) == 1", data));
    assert!(!holds("$a", b"ab"));
}

#[test]
fn quantifiers() {
    let data = b"abc";
    assert!(holds("any of them", data));
    assert!(!holds("all of them", data));
    assert!(holds("1 of them", data));
    assert!(!holds("2 of them", data));
    assert!(holds("50% of them", data));
    assert!(!holds("none of them", data));
    assert!(holds("none of ($b)", data));
    assert!(holds("any of ($a*)", data));
    assert!(holds("any of them at 0", data));
    assert!(holds("any of them in (0..1)", data));
    assert!(holds("for any of ($a, $b) : ($ at 0)", data));
    assert!(holds("for all of ($a) : (# == 1 and @ == 0 and ! == 3)", data));
    assert!(holds("for 1 of them : (#a == 1)", data));
    assert!(holds("2 of (true, $a, false)", data));
    assert!(!holds("3 of (true, $a, false)", data));
}

#[test]
fn loops_and_with() {
    assert!(holds("for any i in (1..3) : (i == 2)", b""));
    assert!(holds("for all i in (1..3) : (i > 0)", b""));
    assert!(!holds("for all i in (1..3) : (i > 1)", b""));
    assert!(holds("for none i in (1, 2) : (i == 3)", b""));
    assert!(holds("for 2 i in (1, 2, 3) : (i >= 2)", b""));
    assert!(holds("for any i in (1..#a) : (@a[i] == 5)", b"abc..abc"));
    assert!(!holds("for all i in (1..0) : (false)", b""), "an empty range is undefined, as in YARA");
    assert!(!holds("for any i in (1..0) : (true)", b""));
    assert!(holds("with x = 2, y = x * 3 : (y == 6)", b""));
    assert!(holds("for any i in (\"a\", \"b\") : (i == \"b\")", b""));
}

#[test]
fn arithmetic_and_undefined() {
    assert!(holds("1 + 2 * 3 == 7 and 7 \\ 2 == 3 and 7 % 3 == 1", b""));
    assert!(holds("0xF0 | 0x0F == 0xFF and 6 & 3 == 2 and 6 ^ 3 == 5 and 1 << 4 == 16 and 16 >> 2 == 4", b""));
    assert!(holds("1 << 64 == 0 and -3 < 0 and ~0 == -1", b""));
    assert!(holds("1.5 + 1 == 2.5 and 3 \\ 2.0 == 1.5 and 2.0 * 2 - 1 == 3.0 and -1.5 < 0", b""));
    assert!(!holds("1 \\ 0 == 0", b""), "division by zero is undefined");
    assert!(!holds("not (1 \\ 0 == 0)", b""), "not undefined is undefined");
    assert!(holds("not defined (1 \\ 0)", b""));
    assert!(holds("defined 1", b""));
    assert!(holds("filesize == 3 and uint8(0) == 0x61 and uint16(0) == 0x6261 and uint16be(0) == 0x6162", b"abc"));
    assert!(holds(
        "int8(0) == -1 and uint32(0) == 0xFFFFFFFF and int32be(0) == -1 and int16(0) == -1",
        b"\xff\xff\xff\xff"
    ));
    assert!(!holds("uint32(2) == 0", b"abc"));
    assert!(holds("1 < 2 and 2 <= 2 and 3 > 2 and 3 >= 3 and 1 != 2", b""));
}

#[test]
fn string_operators() {
    assert!(holds(r#""hello" contains "ell" and "Hello" icontains "ELL""#, b""));
    assert!(holds(r#""hello" startswith "he" and "Hello" istartswith "HE""#, b""));
    assert!(holds(r#""hello" endswith "lo" and "Hello" iendswith "LO" and "AbC" iequals "aBc""#, b""));
    assert!(holds(r#""hello" matches /l+o$/ and not ("hello" matches /^x/)"#, b""));
    assert!(holds(r#""b" > "a""#, b""));
    assert!(holds(r#""abc".len() == 3"#, b""));
}

#[test]
fn modules_and_functions() {
    assert!(holds("math.entropy(0, filesize) == 0.0", b"aaaa"));
    assert!(holds("math.MEAN_BYTES == 127.5", b""));
    assert!(holds("math.in_range(math.mean(0, 2), 97, 98)", b"ab"));
    assert!(!holds("math.entropy(0, 100) >= 0", b"a"), "an out-of-range window is undefined");
    assert!(holds("math.deviation(0, 2, 1) == 1.0", b"\x00\x02"));
}

#[test]
fn externals() {
    let opts = ScanOptions { filename: Some("evil.exe".into()), extension: Some(".exe".into()), ..Default::default() };
    let src = r#"rule r { condition: filename == "evil.exe" and extension == ".exe" and filepath == "" }"#;
    assert_eq!(hits_with(src, b"", &opts), ["r"]);
}

#[test]
fn rule_references_private_and_global() {
    let src = r#"
        private rule p { strings: $a = "abc" condition: $a }
        rule uses_p { condition: p }
        rule wild_1 { condition: true }
        rule wild_2 { condition: false }
        rule any_wild { condition: any of (wild_*) }
        rule all_wild { condition: all of (wild_*) }
    "#;
    assert_eq!(hits(src, b"abc"), ["uses_p", "wild_1", "any_wild"]);
    let global = r#"
        global rule g { condition: filesize > 2 }
        rule r { condition: true }
    "#;
    assert_eq!(hits(global, b"abc"), ["g", "r"]);
    assert!(hits(global, b"ab").is_empty());
}

#[test]
fn file_type_gating() {
    let src = r#"rule pe { strings: $a = "abc" condition: uint16(0) == 0x5A4D and $a }
                 rule other { strings: $a = "abc" condition: $a }"#;
    assert_eq!(hits(src, b"MZabc"), ["pe", "other"]);
    assert_eq!(hits(src, b"..abc"), ["other"]);
}

#[test]
fn hit_details() {
    let mut c = Compiler::new();
    c.add_source(
        "ns",
        r#"rule r : tag { meta: a = 1 strings: $x = "abc" $y = "zz" private condition: $x and $y }"#,
        Syntax::Strict,
    );
    let rules = c.build();
    let res = rules.scan(b"..abc..zz", &ScanOptions::default());
    assert_eq!(res.matches.len(), 1);
    let h = &res.matches[0];
    assert_eq!((h.namespace.as_str(), h.rule.as_str()), ("ns", "r"));
    assert_eq!(h.strings, vec![("x".to_string(), 2)], "private strings aren't reported");
    assert_eq!(rules.rules()[h.index].tags, ["tag"]);
    assert!(!res.truncated);
}

#[test]
fn semantic_errors_are_reported_per_rule() {
    assert!(rejected("rule r { condition: nope }").contains("unknown identifier"));
    assert!(rejected("rule r { condition: pe.is_pe }").contains("missing import"));
    assert!(rejected("rule r { condition: $a }").contains("undefined string"));
    assert!(rejected("rule r { condition: $ }").contains("outside"));
    assert!(rejected("rule r { condition: any of them }").contains("no strings"));
    assert!(rejected(r#"rule r { strings: $a = "x" condition: any of ($b*) }"#).contains("no string matches"));
    assert!(rejected(r#"rule r { condition: 1 == "a" }"#).contains("compare"));
    assert!(rejected(r#"rule r { condition: "a" contains 1 }"#).contains("two strings"));
    assert!(rejected(r#"rule r { condition: "a" + 1 }"#).contains("numbers"));
    assert!(rejected(r#"rule r { condition: 1.5 % 2 == 0 }"#).contains("integers"));
    assert!(rejected(r#"rule r { condition: "a" matches "b" }"#).contains("regular expression"));
    assert!(rejected(r#"rule r { condition: 1 matches /b/ }"#).contains("left"));
    assert!(rejected(r#"rule r { condition: /a/ }"#).contains("regular expression"));
    assert!(rejected(r#"import "math" rule r { condition: math.nope }"#).contains("unknown field"));
    assert!(rejected(r#"import "math" rule r { condition: math.entropy }"#).contains("call it"));
    assert!(rejected(r#"import "math" rule r { condition: math.entropy("a", "b") }"#).contains("no `entropy`"));
    assert!(rejected(r#"import "math" rule r { condition: math.nope(1) }"#).contains("unknown function"));
    assert!(rejected(r#"rule r { condition: (1).x }"#).contains("no fields"));
    assert!(rejected(r#"rule r { condition: 1[0] }"#).contains("indexed"));
    assert!(rejected(r#"rule r { condition: uint8(1, 2) }"#).contains("one offset"));
    assert!(rejected(r#"rule r { condition: x(1) }"#).contains("only functions"));
    assert!(rejected(r#"rule r { condition: for any i in (1..2) : (j) }"#).contains("unknown identifier"));
    assert!(rejected(r#"rule r { condition: for any a, b in (1..2) : (a) }"#).contains("variable"));
    assert!(rejected(r#"rule r { condition: -"a" }"#).contains("negate"));
    assert!(rejected(r#"rule r { condition: ~1.5 }"#).contains("integer"));
    assert!(rejected(r#"rule r { condition: with a = nope : (a) }"#).contains("unknown"));
}

#[test]
fn duplicate_rules_and_bad_syntax_are_rejected_without_losing_the_rest() {
    let mut c = Compiler::new();
    let added = c.add_source(
        "t",
        "rule a { condition: true } rule a { condition: true } rule b { condition: (} rule c { condition: true }",
        Syntax::Strict,
    );
    assert_eq!(added, 2);
    let rules = c.build();
    assert_eq!(rules.rejected.len(), 2);
    assert!(rules.rejected.iter().any(|r| r.rule == "a" && r.error.to_string().contains("duplicate")));
    assert!(rules.rejected.iter().any(|r| r.rule == "b"));
}
