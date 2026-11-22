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

#[test]
fn a_files_imports_dont_classify_rules_that_dont_use_them() {
    let src = r#"import "pe" import "elf"
        rule Plain { strings: $a = "abc" condition: $a }
        rule Uses_Pe { condition: pe.is_pe and for any s in pe.sections : (s.name == "x") }
        rule Uses_Elf_In_Loop { condition: for any i in (0..elf.number_of_sections) : (true) }
        rule Uses_Pe_In_Of { strings: $a = "abc" condition: 1 of ($a) at pe.entry_point }
        rule Uses_Elf_In_With { condition: with n = elf.type : (n == 2) }
    "#;
    let mut c = Compiler::new();
    c.add_source("t", src, Syntax::Relaxed);
    let rules = c.build();
    let os: Vec<_> = rules.rules().iter().map(|r| r.os).collect();
    use crate::Os::*;
    assert_eq!(os, [Any, Windows, Linux, Windows, Linux]);
}

#[test]
fn rules_are_classified_and_filtered() {
    let src = r#"
        rule MAL_Win_Thing { strings: $a = "abc" condition: uint16(0) == 0x5A4D and $a }
        rule HKTL_Lnx_Tool { strings: $a = "abc" condition: $a }
        rule Generic_Script { meta: score = 50 strings: $a = "abc" condition: $a }
    "#;
    let mut c = Compiler::new();
    c.add_source("t", src, Syntax::Relaxed);
    let rules = c.build();
    let got: Vec<_> = rules.rules().iter().map(|r| (r.name.as_str(), r.os, r.category, r.score)).collect();
    assert_eq!(
        got,
        [
            ("MAL_Win_Thing", crate::Os::Windows, "malware", 75),
            ("HKTL_Lnx_Tool", crate::Os::Linux, "hacktool", 75),
            ("Generic_Script", crate::Os::Any, "suspicious", 50),
        ]
    );
    let mut c = Compiler::new();
    c.set_filter(|os, _| matches!(os, crate::Os::Linux | crate::Os::Any));
    c.add_source("t", src, Syntax::Relaxed);
    let rules = c.build();
    assert_eq!(rules.rules().iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["HKTL_Lnx_Tool", "Generic_Script"]);
    assert_eq!(rules.stats().skipped, 1);
}

/// What a compile kept, rejected and finds, to compare two compiles by.
fn compiled(src: &str, os: crate::Os, data: &[&[u8]]) -> (Vec<String>, Vec<String>, Vec<Vec<String>>) {
    let mut c = Compiler::new();
    c.set_filter(move |o, _| o == os || o == crate::Os::Any);
    c.add_source("t", src, Syntax::Relaxed);
    let rules = c.build();
    let kept = rules.rules().iter().map(|r| format!("{}:{}:{:?}", r.namespace, r.name, r.os)).collect();
    let rejected = rules.rejected.iter().map(|r| format!("{}:{}", r.rule, r.error)).collect();
    let hits = data
        .iter()
        .map(|d| {
            rules
                .scan(d, &ScanOptions::default())
                .matches
                .into_iter()
                .map(|h| format!("{} {:?}", h.rule, h.strings))
                .collect()
        })
        .collect();
    (kept, rejected, hits)
}

#[test]
fn a_split_file_compiles_as_the_whole_file_does_on_its_system() {
    let src = "import \"pe\"\n\
        // Windows only\n\
        rule Win_A { strings: $ = \"evil\" condition: uint16(0) == 0x5A4D and all of them }\n\
        rule Linux_Miner { strings: $ = \"xmrig\" condition: uint32(0) == 0x464C457F and any of them }\n\
        /* every system */\n\
        rule Script_B { strings: $ = \"evil\" $ = \"curl\" condition: any of them }\n\
        rule Broken { condition: nope( }\n\
        rule MacOS_C { strings: $ = \"osascript\" condition: $ and not Linux_Miner }\n\
        rule Uses_B { condition: Script_B and Win_A }  rule PE_D { condition: pe.is_pe }\n\
        private rule Any_E { strings: $a = \"curl\" condition: $a }\n\
        rule Line_F { condition: Any_E and @Any_E_missing }\n";
    let data: [&[u8]; 3] = [b"MZ..evil..curl", b"\x7fELF xmrig evil", b"osascript curl"];
    for (os, part) in crate::compile::split_by_os(src, Syntax::Relaxed) {
        assert_eq!(part.lines().count(), src.lines().count(), "{os:?}: lines kept");
        assert_eq!(Compiler::new().add_source_split("t", src, Syntax::Relaxed, os).1, part, "{os:?}");
        assert_eq!(compiled(&part, os, &data), compiled(src, os, &data), "{os:?}");
        let other = match os {
            crate::Os::Linux => "Win_A",
            _ => "Linux_Miner",
        };
        assert!(!part.contains(&format!("rule {other}")), "{os:?} keeps {other}");
        assert!(part.contains("rule Broken") && part.contains("rule Script_B"), "{os:?}");
    }
}

#[test]
fn a_file_with_no_rules_or_with_stray_characters_splits_to_itself() {
    for src in [
        "",
        "// nothing\n",
        "import \"pe\"\n/* x */",
        "rule a { condition: true } é ü rule Win_b { condition: uint16(0) == 0x5A4D } ✓",
    ] {
        for (_, part) in crate::compile::split_by_os(src, Syntax::Relaxed) {
            assert_eq!(part, src);
        }
    }
}

/// On real rules (`RULES_DIR`): each system's split compiles to what the
/// whole files do under its filter, and how long each takes.
/// `cargo test --release -p wpantry-yara real_rules_split -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_rules_split() {
    let dir = std::env::var("RULES_DIR").expect("RULES_DIR");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yar"))
        .collect();
    files.sort();
    let srcs: Vec<(String, String)> = files
        .iter()
        .map(|f| (f.file_stem().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(f).unwrap()))
        .collect();
    let t = std::time::Instant::now();
    let splits: Vec<_> = srcs.iter().map(|(_, s)| crate::compile::split_by_os(s, Syntax::Relaxed)).collect();
    println!("split: {:?}", t.elapsed());
    for (k, os) in [crate::Os::Windows, crate::Os::Linux, crate::Os::MacOS].into_iter().enumerate() {
        let compile = |texts: &mut dyn Iterator<Item = (&str, &str)>| {
            let mut c = Compiler::new();
            c.set_filter(move |o, _| o == os || o == crate::Os::Any);
            for (ns, src) in texts {
                c.add_source(ns, src, Syntax::Relaxed);
            }
            c.build()
        };
        let t = std::time::Instant::now();
        let whole = compile(&mut srcs.iter().map(|(n, s)| (n.as_str(), s.as_str())));
        let tw = t.elapsed();
        let t = std::time::Instant::now();
        let part = compile(&mut srcs.iter().zip(&splits).map(|((n, _), sp)| (n.as_str(), sp[k].1.as_str())));
        println!("{os:?}: whole {tw:?}, split {:?}, {} rules", t.elapsed(), part.rules().len());
        let names =
            |r: &crate::Rules| r.rules().iter().map(|r| (r.namespace.clone(), r.name.clone())).collect::<Vec<_>>();
        assert_eq!(names(&part), names(&whole));
        assert_eq!(
            crate::compile::Stats { skipped: 0, ..part.stats() },
            crate::compile::Stats { skipped: 0, ..whole.stats() }
        );
        let rej = |r: &crate::Rules| r.rejected.iter().map(|r| format!("{} {}", r.rule, r.error)).collect::<Vec<_>>();
        assert_eq!(rej(&part), rej(&whole));
    }
}

/// The code a rule's system depends on, pinned with
/// [`SPLIT_VERSION`](crate::compile::SPLIT_VERSION): when this fails, the
/// classing or parsing changed, so bump `SPLIT_VERSION` (kept splits are
/// then made again) and put the new hash here.
#[test]
fn the_split_rules_are_versioned() {
    let compile = include_str!("compile.rs");
    let from = compile.find("/// A rule's system, category and score.").unwrap();
    let uses = compile.find("\nfn uses(").unwrap();
    let to = uses + compile[uses..].find("\n}\n").unwrap();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for text in [include_str!("classify.rs"), include_str!("parser.rs"), include_str!("lexer.rs"), &compile[from..to]] {
        for b in text.bytes() {
            h = (h ^ b as u64).wrapping_mul(0x0100_0000_01b3);
        }
    }
    assert_eq!((crate::compile::SPLIT_VERSION, format!("{h:016x}")), (1, "ca4ab6dec8d41c25".to_string()));
}
