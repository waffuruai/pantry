//! YARA rules generated from samples, after yarGen's approach (ideas only):
//! pull the strings and code snippets out of the samples, drop the ones
//! known-good software also has, score the rest, and write the best into a
//! rule that the compiler must accept in strict mode.
//!
//! The goodware knowledge comes from the caller ([`Goodware`]): pantry builds
//! it from this machine's own system binaries and keeps it in SQLite, so it
//! never leaves the machine. A generated rule is a proposal: it is marked
//! `suspicious` with a score of 60 and the category a person proposed, until
//! someone reviews it.

use crate::scan::FileType;
use crate::{Compiler, Syntax};
use std::collections::HashMap;

/// Shortest string worth keeping, and longest kept.
pub const MIN_STRING: usize = 6;
const MAX_STRING: usize = 128;
/// Strings and code snippets in one rule.
const MAX_STRINGS: usize = 20;
const MAX_OPCODES: usize = 3;
/// A code snippet's length, and the zero run that separates functions.
const OPCODE_LEN: usize = 16;
/// The score a generated rule carries until someone reviews it.
pub const UNREVIEWED_SCORE: i64 = 60;

/// A string pulled from a sample.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Extracted {
    pub bytes: Vec<u8>,
    /// Found as UTF-16LE (and stored narrowed).
    pub wide: bool,
}

/// Printable ASCII runs and UTF-16LE runs of printable ASCII, at least
/// [`MIN_STRING`] characters, each once.
pub fn strings(data: &[u8]) -> Vec<Extracted> {
    let printable = |b: u8| (0x20..0x7F).contains(&b) || b == b'\t';
    let mut out = Vec::new();
    let mut run = Vec::new();
    for &b in data.iter().chain(std::iter::once(&0)) {
        if printable(b) && run.len() < MAX_STRING {
            run.push(b);
        } else {
            if run.len() >= MIN_STRING {
                out.push(Extracted { bytes: std::mem::take(&mut run), wide: false });
            }
            run.clear();
            if printable(b) {
                run.push(b);
            }
        }
    }
    for start in 0..2 {
        let mut run = Vec::new();
        let mut i = start;
        while i + 1 < data.len() + 2 {
            let (lo, hi) = (data.get(i).copied().unwrap_or(0), data.get(i + 1).copied().unwrap_or(1));
            if hi == 0 && printable(lo) && run.len() < MAX_STRING {
                run.push(lo);
            } else {
                if run.len() >= MIN_STRING {
                    out.push(Extracted { bytes: std::mem::take(&mut run), wide: true });
                }
                run.clear();
            }
            i += 2;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The code section of a PE or ELF file, when it has one.
fn code_section(data: &[u8]) -> Option<&[u8]> {
    use crate::modules::{u16le, u32le, u64le};
    match FileType::detect(data) {
        FileType::Mz => {
            let pe = u32le(data, 0x3C)? as usize;
            let sections = pe + 24 + u16le(data, pe + 20)? as usize;
            for i in 0..u16le(data, pe + 6)?.min(96) as usize {
                let at = sections + 40 * i;
                let characteristics = u32le(data, at + 36)?;
                if characteristics & 0x20 != 0 {
                    let (size, off) = (u32le(data, at + 16)? as usize, u32le(data, at + 20)? as usize);
                    return data.get(off..off.checked_add(size)?.min(data.len()));
                }
            }
            None
        }
        FileType::Elf if data.get(4) == Some(&2) && data.get(5) == Some(&1) => {
            // 64-bit little-endian: the first SHF_EXECINSTR section.
            let shoff = u64le(data, 40)? as usize;
            let (entsize, count) = (u16le(data, 58)? as usize, u16le(data, 60)? as usize);
            for i in 0..count.min(4096) {
                let at = shoff + i * entsize;
                if u64le(data, at + 8)? & 0x4 != 0 {
                    let (off, size) = (u64le(data, at + 24)? as usize, u64le(data, at + 32)? as usize);
                    return data.get(off..off.checked_add(size)?.min(data.len()));
                }
            }
            None
        }
        _ => None,
    }
}

/// Code snippets: the start of each function-sized chunk of the code section
/// (chunks are split on three zero bytes, as yarGen does).
pub fn opcodes(data: &[u8]) -> Vec<Vec<u8>> {
    let Some(code) = code_section(data) else { return Vec::new() };
    let mut out: Vec<Vec<u8>> = code
        .split(|b| *b == 0)
        .filter(|chunk| chunk.len() >= OPCODE_LEN)
        .map(|chunk| chunk[..OPCODE_LEN].to_vec())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// What known-good software contains: how many goodware files have a string
/// or code snippet (0 when none).
pub trait Goodware {
    fn count(&self, item: &[u8]) -> u64;
}

impl Goodware for HashMap<Vec<u8>, u64> {
    fn count(&self, item: &[u8]) -> u64 {
        self.get(item).copied().unwrap_or(0)
    }
}

/// Words that make a string more telling (`stratum`, `cmd.exe`) or less
/// (`Copyright`, `Microsoft`): `(substring, score)`, case-insensitive.
const SCORES: &[(&str, i64)] = &[
    ("stratum+", 8),
    ("wallet", 5),
    ("miner", 5),
    ("xmrig", 6),
    ("pool", 3),
    ("mining", 4),
    ("cmd.exe", 4),
    ("powershell", 4),
    ("/bin/sh", 4),
    ("/bin/bash", 4),
    ("/dev/tcp", 6),
    ("crontab", 4),
    ("launchctl", 4),
    ("loginitems", 4),
    ("keychain", 5),
    ("password", 3),
    ("passwd", 3),
    ("token", 2),
    ("cookie", 3),
    ("login data", 5),
    ("safe storage", 6),
    ("http://", 3),
    ("https://", 2),
    (".onion", 7),
    ("base64", 3),
    ("eval(", 4),
    ("exec(", 3),
    ("chmod +x", 4),
    ("nohup", 3),
    ("pkill", 3),
    ("killall", 3),
    ("/tmp/", 3),
    ("\\temp\\", 3),
    ("appdata", 3),
    ("schtasks", 4),
    ("reg add", 4),
    ("vssadmin", 6),
    ("bcdedit", 5),
    ("shadowcopy", 6),
    (".bit", 2),
    ("tor ", 2),
    ("copyright", -5),
    ("microsoft", -4),
    ("version", -2),
    ("windows", -1),
    ("kernel32", -3),
    ("ntdll", -3),
    ("msvcrt", -3),
    ("libc", -3),
    ("glibc", -3),
    ("gcc", -3),
    ("clang", -3),
    ("rust", -2),
    ("go.buildid", -4),
];

/// A string's score: its words, its length, how unusual its characters
/// are, and minus how common it is in goodware.
pub fn score(s: &Extracted, goodware: &dyn Goodware) -> i64 {
    let text = String::from_utf8_lossy(&s.bytes).to_ascii_lowercase();
    let mut score: i64 = SCORES.iter().filter(|(w, _)| text.contains(w)).map(|(_, v)| v).sum();
    score += (s.bytes.len() as i64 / 8).min(4);
    // An IP address or a long run of one character.
    let ipv4 = |tok: &str| tok.split('.').count() == 4 && tok.split('.').all(|p| p.parse::<u8>().is_ok());
    if text.split(|c: char| !c.is_ascii_digit() && c != '.').any(ipv4) {
        score += 5;
    }
    let distinct = s.bytes.iter().collect::<std::collections::HashSet<_>>().len();
    if distinct < 4 {
        score -= 6;
    }
    let seen = goodware.count(&s.bytes);
    score - (seen.min(10) as i64) * 3
}

/// One generated rule: its text and how many strings and snippets it has.
#[derive(Debug)]
pub struct Generated {
    pub text: String,
    pub strings: usize,
    pub opcodes: usize,
}

/// What the generated rule should say about itself.
pub struct Describe<'a> {
    /// The rule's name (letters, digits and `_`).
    pub name: &'a str,
    /// The category a person proposes (`miner`, `infostealer`, …).
    pub category: &'a str,
    pub family: &'a str,
    pub author: &'a str,
    pub reference: &'a str,
    pub date: &'a str,
    /// The samples' SHA-256s, for the rule's meta and its test file.
    pub hashes: &'a [String],
}

/// A rule matching what `samples` share that goodware lacks, or `None` when
/// they share nothing usable. It compiles in strict mode (checked here).
pub fn generate(samples: &[&[u8]], goodware: &dyn Goodware, d: &Describe) -> Option<Generated> {
    if samples.is_empty() {
        return None;
    }
    // Strings every sample has (one sample: all of its strings), scored.
    let mut common: Vec<Extracted> = strings(samples[0]);
    for s in &samples[1..] {
        let theirs: std::collections::HashSet<Extracted> = strings(s).into_iter().collect();
        common.retain(|x| theirs.contains(x));
    }
    let mut scored: Vec<(i64, Extracted)> = common
        .into_iter()
        .filter(|s| goodware.count(&s.bytes) == 0)
        .map(|s| (score(&s, goodware), s))
        .filter(|(sc, _)| *sc > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.truncate(MAX_STRINGS);
    let mut ops: Vec<Vec<u8>> = opcodes(samples[0]);
    for s in &samples[1..] {
        let theirs: std::collections::HashSet<Vec<u8>> = opcodes(s).into_iter().collect();
        ops.retain(|o| theirs.contains(o));
    }
    ops.retain(|o| goodware.count(o) == 0);
    ops.truncate(MAX_OPCODES);
    if scored.is_empty() && ops.is_empty() {
        return None;
    }
    let text = emit(samples, &scored, &ops, d);
    // Never hand back a rule that doesn't compile.
    let mut c = Compiler::new();
    if c.add_source("generated", &text, Syntax::Strict) != 1 {
        return None;
    }
    Some(Generated { text, strings: scored.len(), opcodes: ops.len() })
}

/// A YARA text string literal for these bytes.
fn literal(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02X}")),
        }
    }
    out.push('"');
    out
}

fn emit(samples: &[&[u8]], strings: &[(i64, Extracted)], ops: &[Vec<u8>], d: &Describe) -> String {
    let largest = samples.iter().map(|s| s.len()).max().unwrap_or(0);
    // The size bound: twice the largest sample, rounded up to a kilobyte.
    let limit_kb = (largest * 2).div_ceil(1024).max(1);
    let ft = FileType::detect(samples[0]);
    let same_type = samples.iter().all(|s| FileType::detect(s) == ft);
    let (os, magic) = match ft {
        FileType::Mz if same_type => ("windows", Some("uint16(0) == 0x5A4D")),
        FileType::Elf if same_type => ("linux", Some("uint32(0) == 0x464C457F")),
        FileType::MachO if same_type => ("macos", Some("(uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE)")),
        _ => ("any", None),
    };
    let mut t = String::new();
    t.push_str(&format!("rule {}\n{{\n    meta:\n", d.name));
    t.push_str(&format!(
        "        description = {}\n",
        literal(format!("Generated from {} sample(s) of {}; unreviewed", samples.len(), d.family).as_bytes())
    ));
    for (k, v) in [
        ("author", d.author),
        ("reference", d.reference),
        ("date", d.date),
        ("os", os),
        ("family", d.family),
        ("proposed_category", d.category),
    ] {
        t.push_str(&format!("        {k} = {}\n", literal(v.as_bytes())));
    }
    t.push_str("        category = \"suspicious\"\n");
    t.push_str(&format!("        score = {UNREVIEWED_SCORE}\n"));
    for (i, h) in d.hashes.iter().enumerate() {
        t.push_str(&format!("        hash{} = {}\n", i + 1, literal(h.as_bytes())));
    }
    t.push_str("\n    strings:\n");
    for (i, (_, s)) in strings.iter().enumerate() {
        let modifier = if s.wide { " wide" } else { "" };
        t.push_str(&format!("        $s{} = {}{modifier}\n", i + 1, literal(&s.bytes)));
    }
    for (i, o) in ops.iter().enumerate() {
        let hex: Vec<String> = o.iter().map(|b| format!("{b:02X}")).collect();
        t.push_str(&format!("        $op{} = {{ {} }}\n", i + 1, hex.join(" ")));
    }
    // Most of the strings, or all of a few; any one code snippet helps.
    let need = strings.len().div_ceil(2).max(1).min(strings.len());
    let mut terms = Vec::new();
    if let Some(m) = magic {
        terms.push(m.to_string());
    }
    terms.push(format!("filesize < {limit_kb}KB"));
    let body = match (strings.is_empty(), ops.is_empty()) {
        (false, true) => format!("{need} of ($s*)"),
        (true, false) => "all of ($op*)".to_string(),
        _ => format!("({need} of ($s*) or all of ($op*))"),
    };
    terms.push(body);
    t.push_str(&format!("\n    condition:\n        {}\n}}\n", terms.join(" and ")));
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanOptions;

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
        assert!(
            score(&s("stratum+tcp://pool.example:3333"), &good) < score(&s("stratum+tcp://pool.example:3333"), &none)
        );
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
    fn generates_a_rule_that_matches_its_samples_and_not_goodware() {
        let a = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho \"common line\"\n";
        let b = b"#!/bin/sh\npkill -f xmrig\nPOOL=stratum+tcp://evil.example:3333\nWALLET=TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx\necho other\n";
        let mut good = HashMap::new();
        good.insert(b"echo \"common line\"".to_vec(), 9u64);
        let hashes = vec!["ab".repeat(32)];
        let g = generate(&[a, b], &good, &describe(&hashes)).unwrap();
        assert!(g.strings >= 2 && g.opcodes == 0);
        assert!(g.text.contains("category = \"suspicious\"") && g.text.contains("proposed_category = \"miner\""));
        assert!(g.text.contains("score = 60") && g.text.contains("os = \"any\""));
        assert!(!g.text.contains("common line"), "goodware strings are dropped");
        let mut c = Compiler::new();
        assert_eq!(c.add_source("t", &g.text, Syntax::Strict), 1);
        let rules = c.build();
        assert_eq!(rules.scan(a, &ScanOptions::default()).matches.len(), 1);
        assert_eq!(rules.scan(b, &ScanOptions::default()).matches.len(), 1);
        assert!(rules.scan(b"#!/bin/sh\necho hello there\n", &ScanOptions::default()).matches.is_empty());
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
        assert!(g.text.contains("uint32(0) == 0x464C457F") && g.text.contains("$op1 = { 01 02 03"));
        assert!(g.text.contains("os = \"linux\""));
        let mut c = Compiler::new();
        c.add_source("t", &g.text, Syntax::Strict);
        assert_eq!(c.build().scan(&elf, &ScanOptions::default()).matches.len(), 1);
    }

    #[test]
    fn nothing_usable_is_none() {
        let hashes = vec![];
        assert!(generate(&[], &HashMap::new(), &describe(&hashes)).is_none());
        assert!(generate(&[b"\x00\x01\x02"], &HashMap::new(), &describe(&hashes)).is_none());
        assert_eq!(literal(b"a\"b\\c\td\x01"), r#""a\"b\\c\td\x01""#);
    }
}
