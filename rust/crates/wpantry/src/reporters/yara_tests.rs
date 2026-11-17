use super::*;
use std::collections::HashMap;
use wpantry_yara::generate::{Describe, generate};
use wpantry_yara::{Compiler, ScanOptions, Syntax};

fn describe(hashes: &[String]) -> Describe<'_> {
    Describe {
        name: "Gen_Test_Kit",
        category: "miner",
        family: "TestKit",
        author: "test",
        reference: "r",
        date: "2026-11-04",
        hashes,
    }
}

fn compiled(text: &str) -> wpantry_yara::Rules {
    let mut c = Compiler::new();
    assert_eq!(c.add_source("t", text, Syntax::Strict), 1, "{text}");
    c.build()
}

#[test]
fn a_generated_rule_writes_out_compiles_and_matches_its_samples_only() {
    let a = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho \"common line\"\n";
    let b = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho other\n";
    let mut good = HashMap::new();
    good.insert(b"echo \"common line\"".to_vec(), 9u64);
    let hashes = vec!["ab".repeat(32)];
    let text = rule(&generate(&[a, b], &good, &describe(&hashes)).unwrap());
    assert!(text.starts_with(
        "rule Gen_Test_Kit\n{\n    meta:\n        description = \"Generated from 2 sample(s) of TestKit; unreviewed\"\n"
    ));
    assert!(text.contains("        category = \"suspicious\"\n        score = 60\n        hash1 = \""), "{text}");
    assert!(!text.contains("common line"), "goodware strings are dropped");
    let rules = compiled(&text);
    assert_eq!(rules.scan(a, &ScanOptions::default()).matches.len(), 1);
    assert_eq!(rules.scan(b, &ScanOptions::default()).matches.len(), 1);
    assert!(rules.scan(b"#!/bin/sh\necho hello there\n", &ScanOptions::default()).matches.is_empty());
}

#[test]
fn code_snippets_write_as_hex_and_literals_escape() {
    let d = Draft {
        name: "Gen_Elf".into(),
        meta: vec![("os".into(), MetaValue::Text("linux".into())), ("score".into(), MetaValue::Int(60))],
        strings: vec![(b"wide one".to_vec(), true)],
        opcodes: vec![(1..=16u8).collect()],
        condition: "uint32(0) == 0x464C457F and filesize < 1KB and (1 of ($s*) or all of ($op*))".into(),
    };
    let text = rule(&d);
    assert!(text.contains("$op1 = { 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 }"), "{text}");
    assert!(text.contains("$s1 = \"wide one\" wide") && text.contains("score = 60"), "{text}");
    let mut elf = b"\x7fELF".to_vec();
    elf.extend([0u8; 60]);
    elf.extend(1..=16u8);
    assert_eq!(compiled(&text).scan(&elf, &ScanOptions::default()).matches.len(), 1);
    assert_eq!(literal(b"a\"b\\c\td\x01"), r#""a\"b\\c\td\x01""#);
}
