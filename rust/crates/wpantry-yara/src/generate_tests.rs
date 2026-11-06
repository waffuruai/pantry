use super::*;

#[test]
fn extracts_ascii_and_wide_strings() {
    let mut data = b"\x01\x02hello world\x00ab\x00\x01".to_vec();
    data.extend(b"w\0i\0d\0e\0s\0t\0r\0\0\0");
    let s = strings(&data);
    assert!(s.contains(&Extracted { bytes: b"hello world".to_vec(), wide: false }));
    assert!(s.contains(&Extracted { bytes: b"widestr".to_vec(), wide: true }));
    assert!(!s.iter().any(|x| x.bytes == b"ab"), "too short");
    assert!(strings(b"").is_empty());
}

#[test]
fn scores_reward_telling_strings_and_punish_goodware() {
    let none: HashMap<Vec<u8>, u64> = HashMap::new();
    let s = |t: &str| Extracted { bytes: t.as_bytes().to_vec(), wide: false };
    assert!(score(&s("stratum+tcp://pool.example:3333"), &none) > score(&s("Copyright Microsoft Corp"), &none));
    assert!(score(&s("connect 89.36.231.178"), &none) >= 5);
    assert!(score(&s("aaaaaaaaaaaa"), &none) < 0);
    let mut good = HashMap::new();
    good.insert(b"stratum+tcp://pool.example:3333".to_vec(), 4);
    assert!(score(&s("stratum+tcp://pool.example:3333"), &good) < score(&s("stratum+tcp://pool.example:3333"), &none));
}

fn describe<'a>(hashes: &'a [String]) -> Describe<'a> {
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

#[test]
fn drafts_a_rule_from_what_the_samples_share_and_goodware_lacks() {
    let a = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho \"common line\"\n";
    let b = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho other\n";
    let mut good = HashMap::new();
    good.insert(b"echo \"common line\"".to_vec(), 9u64);
    let hashes = vec!["ab".repeat(32)];
    let g = generate(&[a, b], &good, &describe(&hashes)).unwrap();
    assert!(g.strings.len() >= 2 && g.opcodes.is_empty());
    let meta = |k: &str| g.meta.iter().find(|(m, _)| m == k).map(|(_, v)| v.clone());
    assert_eq!(meta("category"), Some(MetaValue::Text("suspicious".into())));
    assert_eq!(meta("proposed_category"), Some(MetaValue::Text("miner".into())));
    assert_eq!((meta("score"), meta("os")), (Some(MetaValue::Int(60)), Some(MetaValue::Text("any".into()))));
    assert!(g.strings.iter().all(|(s, _)| !s.windows(11).any(|w| w == b"common line")), "goodware strings are dropped");
    assert!(g.condition.ends_with("of ($s*)"), "{}", g.condition);
}

#[test]
fn executables_get_their_magic_and_code_snippets() {
    let mut elf = crate::modules::elf_sample_for_tests();
    let code: Vec<u8> = (1..=40u8).collect();
    elf[0x100..0x100 + code.len()].copy_from_slice(&code);
    let ops = opcodes(&elf);
    assert_eq!(ops, vec![code[..16].to_vec()]);
    let hashes = vec![];
    let g = generate(&[&elf], &HashMap::new(), &describe(&hashes)).unwrap();
    assert!(g.condition.starts_with("uint32(0) == 0x464C457F"), "{}", g.condition);
    assert_eq!(g.opcodes, [code[..16].to_vec()]);
    assert!(g.meta.contains(&("os".into(), MetaValue::Text("linux".into()))));
}

#[test]
fn nothing_usable_is_none() {
    let hashes = vec![];
    assert!(generate(&[], &HashMap::new(), &describe(&hashes)).is_none());
    assert!(generate(&[b"\x00\x01\x02"], &HashMap::new(), &describe(&hashes)).is_none());
}
