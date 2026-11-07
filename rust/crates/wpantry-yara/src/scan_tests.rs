use super::*;

#[test]
fn detects_file_types() {
    assert_eq!(FileType::detect(b"MZ\x90\x00"), FileType::Mz);
    assert_eq!(FileType::detect(b"\x7fELF\x02"), FileType::Elf);
    assert_eq!(FileType::detect(b"\xcf\xfa\xed\xfe"), FileType::MachO);
    assert_eq!(FileType::detect(b"\xca\xfe\xba\xbe"), FileType::MachO);
    assert_eq!(FileType::detect(b"#!/bin/sh"), FileType::Other);
    assert_eq!(FileType::detect(b""), FileType::Other);
}

fn build(src: &str, reach: Option<usize>) -> Rules {
    let mut c = crate::Compiler::new();
    if let Some(r) = reach {
        c.set_regex_reach(r);
    }
    assert_eq!(c.add_source("t", src, crate::Syntax::Strict), 1);
    c.build()
}

#[test]
fn spans_keep_every_match_of_every_string() {
    let rules = build(r#"rule r { strings: $a = "ab" $b = /c+/ condition: $a }"#, None);
    let (res, spans) = rules.scan_spans(b"ab ab ccc", &ScanOptions::default());
    assert_eq!(res.matches.len(), 1);
    assert_eq!(spans.by_string[0], vec![(0, 2), (3, 2)]);
    assert_eq!(spans.by_string[1].first(), Some(&(6, 3)));
    assert_eq!(rules.string_rule(1), 0);
    assert_eq!(rules.scan(b"ab ab ccc", &ScanOptions::default()), res);
}

#[test]
fn a_longer_regex_reach_finds_matches_past_yaras_limit() {
    let src = r#"rule r { strings: $a = /BEGIN[\s\S]+?END/ condition: $a }"#;
    let data = [b"BEGIN".as_slice(), &vec![b'x'; 5000], b"END"].concat();
    assert!(build(src, None).scan(&data, &ScanOptions::default()).matches.is_empty());
    let (res, spans) = build(src, Some(1 << 16)).scan_spans(&data, &ScanOptions::default());
    assert_eq!(res.matches.len(), 1);
    assert_eq!(spans.by_string[0], vec![(0, data.len())]);
}
