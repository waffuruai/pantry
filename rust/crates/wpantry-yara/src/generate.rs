//! YARA rules generated from samples, after yarGen's approach (ideas only):
//! pull the strings and code snippets out of the samples, drop the ones
//! known-good software also has, score the rest, and put the best into a
//! rule draft ([`Draft`]). wpantry writes the draft's text (its YARA
//! reporter) and checks that the compiler accepts it in strict mode.
//!
//! The goodware knowledge comes from the caller ([`Goodware`]): pantry builds
//! it from this machine's own system binaries and keeps it in SQLite, so it
//! never leaves the machine. A generated rule is a proposal: it is marked
//! `suspicious` with a score of 60 and the category a person proposed, until
//! someone reviews it.

use crate::scan::FileType;
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

/// A meta value of a generated rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaValue {
    Text(String),
    Int(i64),
}

/// A generated rule, before it is written out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    pub name: String,
    pub meta: Vec<(String, MetaValue)>,
    /// The text strings (`$s1`, `$s2`, …): their bytes, and whether they
    /// are matched as UTF-16 too.
    pub strings: Vec<(Vec<u8>, bool)>,
    /// The code snippets (`$op1`, …).
    pub opcodes: Vec<Vec<u8>>,
    /// The condition, over `$s*` and `$op*`.
    pub condition: String,
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
/// they share nothing usable.
pub fn generate(samples: &[&[u8]], goodware: &dyn Goodware, d: &Describe) -> Option<Draft> {
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
    Some(draft(samples, &scored, ops, d))
}

fn draft(samples: &[&[u8]], strings: &[(i64, Extracted)], ops: Vec<Vec<u8>>, d: &Describe) -> Draft {
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
    let text = |s: &str| MetaValue::Text(s.to_string());
    let mut meta = vec![(
        "description".to_string(),
        text(&format!("Generated from {} sample(s) of {}; unreviewed", samples.len(), d.family)),
    )];
    for (k, v) in [
        ("author", d.author),
        ("reference", d.reference),
        ("date", d.date),
        ("os", os),
        ("family", d.family),
        ("proposed_category", d.category),
        ("category", "suspicious"),
    ] {
        meta.push((k.to_string(), text(v)));
    }
    meta.push(("score".to_string(), MetaValue::Int(UNREVIEWED_SCORE)));
    for (i, h) in d.hashes.iter().enumerate() {
        meta.push((format!("hash{}", i + 1), text(h)));
    }
    // Most of the strings, or all of a few; any one code snippet helps.
    let need = strings.len().div_ceil(2).max(1).min(strings.len());
    let mut terms = Vec::new();
    if let Some(m) = magic {
        terms.push(m.to_string());
    }
    terms.push(format!("filesize < {limit_kb}KB"));
    terms.push(match (strings.is_empty(), ops.is_empty()) {
        (false, true) => format!("{need} of ($s*)"),
        (true, false) => "all of ($op*)".to_string(),
        _ => format!("({need} of ($s*) or all of ($op*))"),
    });
    Draft {
        name: d.name.to_string(),
        meta,
        strings: strings.iter().map(|(_, s)| (s.bytes.clone(), s.wide)).collect(),
        opcodes: ops,
        condition: terms.join(" and "),
    }
}

#[cfg(test)]
#[path = "generate_tests.rs"]
mod tests;
