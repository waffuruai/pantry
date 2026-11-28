use super::*;
use crate::checks::models::testing::{Gguf, Val, check_bytes, fake_pe, filler, ids};

fn cursor(b: &[u8]) -> Parsed {
    check(std::io::Cursor::new(b.to_vec()), b.len() as u64)
}

/// Oracle: the writer lays the tensors out end to end, so a file that ends
/// where they end has nothing to say. Benign twin of every tail rule.
#[test]
fn a_clean_model_has_nothing_to_say() {
    let b = Gguf::default().bytes();
    assert_eq!(cursor(&b), Parsed::default());
    let mut padded = b.clone();
    padded.extend([0u8; 100]);
    assert!(cursor(&padded).issues.is_empty(), "a short zero pad is padding");
    let mut v1 = Gguf { version: 1, ..Gguf::default() };
    v1.kvs.push(("tokenizer.ggml.tokens".into(), Val::Strs(vec!["a".into(), "b".into()])));
    assert!(cursor(&v1.bytes()).issues.is_empty(), "v1 counts and lengths are u32");
    let mut g = Gguf { align: 64, ..Gguf::default() };
    g.kvs.push(("general.alignment".into(), Val::U32(64)));
    g.kvs.push(("tokenizer.ggml.scores".into(), Val::Bytes(vec![1; 300])));
    g.kvs.push(("tokenizer.ggml.merges".into(), Val::Nested(vec![vec!["a b".into()], vec![]])));
    assert!(cursor(&g.bytes()).issues.is_empty(), "general.alignment is honoured: {:?}", cursor(&g.bytes()));
    let none = Gguf { tensors: vec![], ..Gguf::default() };
    assert!(cursor(&none.bytes()).issues.is_empty(), "a vocabulary-only file");
}

/// Known bad: a program (inert stand-in) or archive after the last tensor
/// fails, named by its magic, reported in hex only.
#[test]
fn a_program_after_the_last_tensor_fails() {
    let base = Gguf::default().bytes();
    let tails: Vec<(Vec<u8>, &str)> = vec![
        (fake_pe(200), "MZ"),
        ([b"\x7fELF".as_slice(), &filler(60)].concat(), "ELF"),
        ([b"\xcf\xfa\xed\xfe".as_slice(), &filler(60)].concat(), "Mach-O"),
        ([b"\xca\xfe\xba\xbe".as_slice(), &filler(60)].concat(), "Mach-O universal"),
        ([b"PK\x03\x04".as_slice(), &filler(60)].concat(), "ZIP"),
        ([b"\x1f\x8b\x08".as_slice(), &filler(60)].concat(), "gzip"),
        ([b"#!/bin/sh\n".as_slice(), &filler(60)].concat(), "shebang"),
        ([b"\x80\x04\x95".as_slice(), &filler(60)].concat(), "pickle"),
    ];
    for (tail, what) in tails {
        let got = cursor(&[base.clone(), tail.clone()].concat()).issues;
        assert_eq!(ids(&got), [(ids::APPENDED_PROGRAM, Level::Fail)], "{what}");
        assert!(got[0].note.contains(what), "{what}: {}", got[0].note);
        assert!(got[0].note.contains(&format!("{} bytes", tail.len())), "{}", got[0].note);
        assert!(got[0].note.contains(&hex(&tail[..16])), "the first bytes in hex: {}", got[0].note);
    }
}

/// Known bad: a program hidden behind filler near the end of the file,
/// and raw Deflate with no magic at all: size alone fails it.
#[test]
fn hidden_or_magicless_tails_fail_by_size() {
    let base = Gguf::default().bytes();
    let behind = [base.clone(), filler(300 << 10), fake_pe(4096)].concat();
    let got = cursor(&behind).issues;
    assert_eq!(ids(&got), [(ids::APPENDED_PROGRAM, Level::Fail)]);
    assert!(got[0].note.contains("inside"), "{}", got[0].note);
    let raw = cursor(&[base.clone(), filler(SHORT_TAIL as usize)].concat()).issues;
    assert_eq!(ids(&raw), [(ids::TRAILING_DATA, Level::Fail)]);
    let small = cursor(&[base.clone(), filler(100)].concat()).issues;
    assert_eq!(ids(&small), [(ids::TRAILING_DATA, Level::Warn)], "under 4 KiB and not zero: a warning");
    let zeros = cursor(&[base, vec![0u8; SHORT_TAIL as usize]].concat()).issues;
    assert_eq!(ids(&zeros), [(ids::TRAILING_DATA, Level::Fail)], "a long tail fails even when zero");
}

/// The default tensors with a 4 KiB hole after the first, and where the
/// hole sits in the file.
fn holed() -> (Vec<u8>, usize) {
    let g = Gguf { offsets: Some(vec![0, 1024 + 4096, 1024 + 4096 + 96]), ..Gguf::default() };
    let b = g.bytes();
    // The data ends at 5216 + 102 = 5318, padded to 5344.
    let data = b.len() - 5344;
    (b, data + 1024)
}

/// Known bad: a program (inert stand-in) in a hole between two tensors
/// fails; the hole's benign twin (filler, no magic) warns; the normal
/// padded layout says nothing (`a_clean_model_has_nothing_to_say`).
#[test]
fn a_hole_in_the_tensor_data_is_a_finding() {
    let (b, at) = holed();
    let got = cursor(&b).issues;
    assert_eq!(ids(&got), [(ids::DATA_GAP, Level::Warn)], "{got:?}");
    assert!(got[0].note.contains("1 hole(s)") && got[0].note.contains("4096 bytes"), "{}", got[0].note);
    let mut bad = b.clone();
    bad[at..at + 4096].copy_from_slice(&fake_pe(4096));
    let got = cursor(&bad).issues;
    assert_eq!(ids(&got), [(ids::DATA_GAP, Level::Fail)], "{got:?}");
    assert!(got[0].note.contains("MZ") && got[0].note.contains(&hex(b"MZ")), "{}", got[0].note);
    // Behind filler, found by the PE header inside the window.
    let mut hidden = b.clone();
    hidden[at + 512..at + 4096].copy_from_slice(&fake_pe(3584));
    assert_eq!(ids(&cursor(&hidden).issues), [(ids::DATA_GAP, Level::Fail)]);
    // The first tensor not at offset 0.
    let late = Gguf { offsets: Some(vec![64, 1088, 1184]), ..Gguf::default() };
    let got = cursor(&late.bytes()).issues;
    assert_eq!(ids(&got), [(ids::DATA_GAP, Level::Warn)]);
    assert!(got[0].note.contains("first at data offset 0"), "{}", got[0].note);
    // A gap under the alignment is a writer's padding.
    assert!(holes(&[(0, 1000), (1024, 1100)], 32).is_empty());
    assert_eq!(holes(&[(0, 1000), (1056, 1100)], 32), [(1000, 1056)]);
}

/// More holes than are read is said, and still a finding.
#[test]
fn many_holes_are_capped_and_said() {
    let n = MAX_GAPS as u64 + 3;
    let g = Gguf {
        tensors: (0..n).map(|i| (format!("t{i}"), vec![8], 0)).collect(),
        offsets: Some((0..n).map(|i| i * 64).collect()),
        ..Gguf::default()
    };
    let got = cursor(&g.bytes()).issues;
    assert_eq!(ids(&got), [(ids::DATA_GAP, Level::Warn)]);
    assert!(got[0].note.contains(&format!("{} holes, only the first {MAX_GAPS} read", n - 1)), "{}", got[0].note);
}

/// What can't be judged is not checked, with the reason, never clean.
#[test]
fn what_cant_be_judged_is_not_checked() {
    let mut custom = Gguf::default();
    custom.tensors.push(("blk.1.ffn.weight".into(), vec![256], 200));
    let got = cursor(&custom.bytes()).issues;
    assert_eq!(ids(&got), [(ids::NOT_CHECKED, Level::Unchecked)]);
    assert!(got[0].note.contains("200"), "{}", got[0].note);

    let b = Gguf::default().bytes();
    let cut = cursor(&b[..b.len() - 50]).issues;
    assert_eq!(ids(&cut), [(ids::NOT_CHECKED, Level::Unchecked)], "truncated data");
    assert!(cut[0].note.contains("cut short"), "{}", cut[0].note);

    let mut odd = Gguf::default();
    odd.kvs.push(("general.alignment".into(), Val::U32(48)));
    assert!(cursor(&odd.bytes()).issues[0].note.contains("power of two"));
    let mut wrong_type = Gguf::default();
    wrong_type.kvs.push(("general.alignment".into(), Val::Str("32".into())));
    assert_eq!(ids(&cursor(&wrong_type.bytes()).issues), [(ids::NOT_CHECKED, Level::Unchecked)]);

    let mut too_many = b"GGUF\x03\0\0\0".to_vec();
    too_many.extend((MAX_TENSORS + 1).to_le_bytes());
    too_many.extend(0u64.to_le_bytes());
    assert!(cursor(&too_many).issues[0].note.contains("tensor count"));
    let mut big_string = b"GGUF\x03\0\0\0".to_vec();
    big_string.extend(0u64.to_le_bytes());
    big_string.extend(1u64.to_le_bytes());
    big_string.extend((MAX_KEY + 1).to_le_bytes());
    big_string.extend(filler(64));
    assert_eq!(ids(&cursor(&big_string).issues), [(ids::NOT_CHECKED, Level::Unchecked)]);

    let mut long = Gguf::default();
    long.kvs.push(("tokenizer.chat_template".into(), Val::Str("x".repeat(MAX_TEMPLATE as usize + 1))));
    let got = cursor(&long.bytes()).issues;
    assert_eq!(ids(&got), [(ids::NOT_CHECKED, Level::Unchecked)]);
    assert!(got[0].note.contains("template cap"), "{}", got[0].note);
}

/// Odd headers warn: a version this reader doesn't know, big-endian,
/// byte-swapped magic, duplicate keys, overlapping tensors.
#[test]
fn odd_headers_warn() {
    let b = Gguf::default().bytes();
    let mut v4 = b.clone();
    v4[4] = 4;
    assert_eq!(ids(&cursor(&v4).issues), [(ids::HEADER, Level::Warn), (ids::NOT_CHECKED, Level::Unchecked)]);
    let mut be = b.clone();
    be[4..8].copy_from_slice(&3u32.to_be_bytes());
    assert!(cursor(&be).issues[0].note.contains("big-endian"));
    let mut swapped = b.clone();
    swapped[..4].copy_from_slice(b"FUGG");
    assert_eq!(cursor(&swapped).issues[0].id, ids::HEADER);
    let mut dup = Gguf::default();
    dup.kvs.push(("general.architecture".into(), Val::Str("llama".into())));
    assert_eq!(ids(&cursor(&dup.bytes()).issues), [(ids::HEADER, Level::Warn)]);
    let overlap = Gguf { offsets: Some(vec![0, 512, 1024]), ..Gguf::default() };
    assert_eq!(ids(&cursor(&overlap.bytes()).issues), [(ids::HEADER, Level::Warn)]);
}

/// The split count and the templates are kept; the templates run through
/// the template rules in `check_path`.
#[test]
fn split_count_and_templates_are_read() {
    let mut g = Gguf::with_template("{% for m in messages %}{{ m['content'] }}{% endfor %}");
    g.kvs.push(("split.count".into(), Val::U16(3)));
    g.kvs.push(("tokenizer.chat_template.tool_use".into(), Val::Str("{{ '[SYSTEM DIRECTIVE] x' }}".into())));
    let p = cursor(&g.bytes());
    assert_eq!(p.split, 3);
    assert_eq!(p.templates.len(), 2);
    let got = check_bytes(&g.bytes());
    assert_eq!(ids(&got), [(ids::INJECTION, Level::Fail)]);
    assert!(got[0].note.starts_with("tokenizer.chat_template.tool_use:"), "{}", got[0].note);
    let d = crate::utils::temp::TempDir::new("gguf-dir").unwrap();
    assert_eq!(check_path(d.path()).issues[0].level, Level::Unchecked, "a folder is not a file");
    assert_eq!(check_path(&d.path().join("gone")).issues[0].level, Level::Unchecked);
}

/// Every fixture cut short at many points, and with bytes mangled, reads
/// as a result: never a panic.
#[test]
fn truncated_and_mangled_files_never_panic() {
    let mut g = Gguf::with_template("{{ messages }}");
    g.kvs.push(("tokenizer.ggml.tokens".into(), Val::Strs(vec!["a".into(); 20])));
    g.kvs.push(("tokenizer.ggml.merges".into(), Val::Nested(vec![vec!["a b".into()]])));
    let fixtures = [
        Gguf::default().bytes(),
        g.bytes(),
        Gguf { version: 1, ..Gguf::default() }.bytes(),
        [Gguf::default().bytes(), fake_pe(300)].concat(),
        holed().0,
    ];
    for b in fixtures {
        for cut in 0..b.len() {
            let _ = cursor(&b[..cut]);
        }
        for i in 0..b.len() {
            for x in [0xffu8, 0x80, 0x01] {
                let mut m = b.clone();
                m[i] ^= x;
                let _ = cursor(&m);
            }
        }
    }
}

#[test]
fn the_block_table_matches_ggml() {
    // Spot checks from ggml's type traits: block bytes are scale plus quants.
    assert_eq!(block(12), Some((256, 144)), "Q4_K: 2+2+12+128");
    assert_eq!(block(14), Some((256, 210)), "Q6_K: 128+64+16+2");
    assert_eq!(block(23), Some((256, 136)), "IQ4_XS: 2+2+4+128");
    assert_eq!(block(30), Some((1, 2)), "BF16");
    for removed in [4, 5, 31, 32, 33, 36, 37, 38] {
        assert_eq!(block(removed), None, "type {removed} was removed from ggml");
    }
    assert_eq!(program_or_archive(b"\x80\x01"), None, "pickle protocol 1 has no PROTO opcode");
    assert!(program_inside(b"MZ").is_none(), "too short to carry e_lfanew");
}
