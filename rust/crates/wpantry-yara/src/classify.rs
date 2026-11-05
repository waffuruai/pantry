//! What a rule is for: the operating system its targets run on and the kind
//! of threat it names, so a scan can use only this machine's rules by
//! default and a report can weigh a hit.
//!
//! Our rules say so in `meta` (`os`, `category`). Published ones mostly don't,
//! so it is read from what they do carry: the words in their name and tags
//! (`MAL_`, `HKTL_`, `Win32`, `Lnx`, `Ransomware`), the modules they import,
//! the magic bytes they require, and Forge's `score` when the name is just a
//! family (`ESET_Kobalos`).

use crate::ast::Meta;
use crate::scan::FileType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    Linux,
    MacOS,
    /// Scripts, documents, configs: anything that isn't one platform's binary.
    Any,
}

impl Os {
    pub fn name(self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Linux => "linux",
            Os::MacOS => "macos",
            Os::Any => "any",
        }
    }

    /// The system this build runs on.
    pub fn host() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOS
        } else if cfg!(target_os = "windows") {
            Os::Windows
        } else {
            Os::Linux
        }
    }

    fn from_word(w: &str) -> Option<Os> {
        Some(match w {
            "win" | "win32" | "win64" | "windows" | "pe" | "exe" | "dll" | "msi" | "dotnet" | "net" | "ps1"
            | "powershell" => Os::Windows,
            "lnx" | "linux" | "lin" | "elf" | "unix" => Os::Linux,
            "osx" | "macos" | "mac" | "darwin" | "macho" | "apple" => Os::MacOS,
            _ => return None,
        })
    }
}

/// The categories, most specific first: when a rule's words name several,
/// the earliest wins (`MAL_XMR_Miner` is a miner, not just malware).
pub const CATEGORIES: &[&str] = &[
    "ransomware",
    "miner",
    "clipper",
    "infostealer",
    "backdoor",
    "rootkit",
    "dropper",
    "downloader",
    "trojan",
    "virus",
    "webshell",
    "exploit",
    "credential-access",
    "persistence",
    "execution",
    "malware",
    "certificate",
    "hacktool",
    "pua",
    "suspicious",
];

/// The categories that are malware outright: a hit is a critical failure.
pub const MALWARE: &[&str] = &[
    "ransomware",
    "miner",
    "clipper",
    "infostealer",
    "backdoor",
    "rootkit",
    "dropper",
    "downloader",
    "trojan",
    "virus",
    "webshell",
    "exploit",
    "credential-access",
    "malware",
    "certificate",
];

/// The score at or above which a rule whose words name no category is
/// taken for malware: Forge gives family rules 75 and heuristics less.
const MALWARE_SCORE: i64 = 75;

fn category_of_word(w: &str) -> Option<&'static str> {
    Some(match w {
        "ransom" | "ransomware" | "locker" | "cryptolocker" => "ransomware",
        "miner" | "coinminer" | "cryptominer" | "xmrig" | "monero" | "xmr" | "cryptojacking" => "miner",
        "clipper" | "clipboard" => "clipper",
        "stealer" | "infostealer" | "grabber" | "keylogger" | "spyware" | "credstealer" => "infostealer",
        "backdoor" | "rat" | "implant" | "beacon" | "cobaltstrike" | "c2" | "bot" | "botnet" => "backdoor",
        "rootkit" | "bootkit" => "rootkit",
        "dropper" => "dropper",
        "loader" | "downloader" | "stager" => "downloader",
        "trojan" => "trojan",
        "virus" | "worm" | "infector" => "virus",
        "webshell" | "webshells" => "webshell",
        "exploit" | "expl" | "cve" => "exploit",
        "mal" | "malware" | "apt" | "crime" | "crimeware" | "malicious" => "malware",
        "cert" | "certificate" => "certificate",
        "hktl" | "hacktool" | "tool" | "pentest" | "offensive" | "mimikatz" => "hacktool",
        "pua" | "pup" | "adware" | "riskware" | "vuln" => "pua",
        "susp" | "suspicious" | "gen" | "generic" | "indicator" | "anomaly" | "obfusc" | "obfuscated" | "packer"
        | "packed" | "hunting" | "hunt" => "suspicious",
        _ => return None,
    })
}

fn meta_str<'a>(meta: &'a [(String, Meta)], key: &str) -> Option<&'a [u8]> {
    meta.iter().find_map(|(k, v)| match v {
        Meta::Str(s) if k == key => Some(s.as_slice()),
        _ => None,
    })
}

fn meta_int(meta: &[(String, Meta)], key: &str) -> Option<i64> {
    meta.iter().find_map(|(k, v)| match v {
        Meta::Int(i) if k == key => Some(*i),
        _ => None,
    })
}

/// The words of a rule name or tag: split on `_`, `-`, `.` and case changes.
fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(['_', '-', '.', ' ']) {
        let mut word = String::new();
        let mut prev_lower = false;
        for c in part.chars() {
            if c.is_ascii_uppercase() && prev_lower && !word.is_empty() {
                out.push(std::mem::take(&mut word).to_ascii_lowercase());
            }
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            word.push(c);
        }
        if !word.is_empty() {
            out.push(word.to_ascii_lowercase());
        }
    }
    // Whole parts count too: `Win32` and `CobaltStrike` as written; and a
    // word without its trailing digits (`Coinminer02`).
    out.extend(s.split(['_', '-', '.', ' ']).filter(|p| !p.is_empty()).map(str::to_ascii_lowercase));
    let stems: Vec<String> = out
        .iter()
        .map(|w| w.trim_end_matches(|c: char| c.is_ascii_digit()).to_string())
        .filter(|w| !w.is_empty())
        .collect();
    out.extend(stems);
    out
}

/// A rule's operating system, category and score.
pub fn classify(
    name: &str,
    tags: &[String],
    meta: &[(String, Meta)],
    imports: &[String],
    needs: Option<FileType>,
) -> (Os, &'static str, i64) {
    let score = meta_int(meta, "score").unwrap_or(MALWARE_SCORE);
    let mut text_words = words(name);
    for t in tags {
        text_words.extend(words(t));
    }
    let os = meta_str(meta, "os")
        .and_then(|o| Os::from_word(&String::from_utf8_lossy(o).to_ascii_lowercase()).or(Some(Os::Any)))
        .or(match needs {
            Some(FileType::Mz) => Some(Os::Windows),
            Some(FileType::Elf) => Some(Os::Linux),
            Some(FileType::MachO) => Some(Os::MacOS),
            _ => None,
        })
        .or_else(|| text_words.iter().find_map(|w| Os::from_word(w)))
        .or_else(|| imports.iter().find_map(|m| Os::from_word(m)))
        .unwrap_or(Os::Any);
    let explicit = meta_str(meta, "category")
        .map(|c| String::from_utf8_lossy(c).to_ascii_lowercase())
        .and_then(|c| CATEGORIES.iter().find(|k| **k == c).copied());
    let category = explicit.unwrap_or_else(|| {
        let found: Vec<&'static str> = text_words.iter().filter_map(|w| category_of_word(w)).collect();
        CATEGORIES.iter().find(|c| found.contains(c)).copied().unwrap_or(if score >= MALWARE_SCORE {
            "malware"
        } else {
            "suspicious"
        })
    });
    (os, category, score)
}

/// Whether a category is malware outright.
pub fn is_malware(category: &str) -> bool {
    MALWARE.contains(&category)
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
