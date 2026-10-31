//! Text in a repo that reads one way to a person and another to a parser
//! or a model: Unicode bidirectional overrides that reorder what the eye
//! sees (Trojan Source, CVE-2021-42574), tag characters and zero-width
//! characters that hide instructions in a comment or a string (the way
//! prompts are smuggled into text an AI assistant will read), homoglyphs
//! that make two identifiers look like one, and identifiers packed with
//! weapon and poison vocabulary so that an AI reviewer refuses to read the
//! code at all. None of it is proof of harm; all of it is a reason to read
//! the file yourself before trusting what a tool says about it.

use crate::repos;
use std::path::Path;

/// One file's hidden-text finding.
#[derive(Clone, Debug, PartialEq)]
pub struct Hidden {
    /// Relative to the repo.
    pub file: String,
    /// `HIDDEN-BIDI` (fail), `HIDDEN-TAGS` (fail), `HIDDEN-ZERO-WIDTH`
    /// (warn), `HIDDEN-HOMOGLYPH` (warn), `AI-BAIT` (warn).
    pub id: &'static str,
    pub note: String,
    /// The first line it was seen on.
    pub line: usize,
}

impl Hidden {
    pub fn fails(&self) -> bool {
        matches!(self.id, "HIDDEN-BIDI" | "HIDDEN-TAGS")
    }
}

/// Files worth reading: source, scripts, config and prose a person or an
/// agent reads. Binary and generated formats are left alone.
const EXTENSIONS: &[&str] = &[
    "rs",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "py",
    "rb",
    "go",
    "java",
    "kt",
    "swift",
    "c",
    "h",
    "cc",
    "cpp",
    "hpp",
    "cs",
    "php",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "lua",
    "pl",
    "r",
    "scala",
    "dart",
    "ex",
    "exs",
    "erl",
    "hs",
    "ml",
    "sql",
    "yml",
    "yaml",
    "toml",
    "json",
    "jsonc",
    "md",
    "mdx",
    "mdc",
    "txt",
    "env",
    "ini",
    "cfg",
    "conf",
    "html",
    "htm",
    "xml",
    "svg",
    "css",
    "scss",
    "vue",
    "svelte",
    "astro",
    "tf",
    "gradle",
    "cmake",
    "make",
    "mk",
    "dockerfile",
    "proto",
];

/// The most of a file read, and of a repo.
const MAX_FILE: u64 = 1 << 20;
const MAX_REPO: u64 = 64 << 20;

/// Every hidden-text finding in the repo, one per (file, id).
pub fn scan_repo(root: &Path) -> Vec<Hidden> {
    let mut out = Vec::new();
    let mut budget = MAX_REPO;
    for (dir, files) in repos::walk(root, 6) {
        for name in files {
            if !wanted(&name) {
                continue;
            }
            let path = dir.join(&name);
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if !meta.is_file() || meta.len() > MAX_FILE || meta.len() > budget {
                continue;
            }
            budget -= meta.len();
            let Ok(text) = crate::system::read_capped(&path, MAX_FILE) else { continue };
            if looks_minified(&text) {
                continue; // a bundle: not something a person reads, and full of escapes
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            out.extend(scan_text(&rel, &text));
        }
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out
}

fn wanted(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if ["dockerfile", "makefile", "containerfile", "justfile"].contains(&lower.as_str()) {
        return true;
    }
    if lower.ends_with(".min.js") || lower.ends_with(".min.css") || lower.ends_with(".map") || lower.ends_with(".lock")
    {
        return false;
    }
    lower.rsplit_once('.').is_some_and(|(_, ext)| EXTENSIONS.contains(&ext))
}

/// Built output: a line over 2000 characters in the first few.
pub fn looks_minified(text: &str) -> bool {
    text.lines().take(5).any(|l| l.len() > 2000)
}

fn is_code(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.rsplit_once('.').is_some_and(|(_, ext)| {
        [
            "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "go", "java", "kt", "swift", "c", "h", "cc",
            "cpp", "cs", "php", "lua", "scala", "dart",
        ]
        .contains(&ext)
    })
}

/// The findings for one file's text.
pub fn scan_text(file: &str, text: &str) -> Vec<Hidden> {
    let mut out = Vec::new();
    let (mut bidi, mut tags, mut zero, mut bidi_line, mut tags_line, mut zero_line) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut line = 1usize;
    let mut prev = '\0';
    for (i, c) in text.char_indices() {
        if c == '\n' {
            line += 1;
            prev = c;
            continue;
        }
        match c {
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
                bidi += 1;
                if bidi_line == 0 {
                    bidi_line = line;
                }
            }
            '\u{E0000}'..='\u{E007F}' => {
                tags += 1;
                if tags_line == 0 {
                    tags_line = line;
                }
            }
            '\u{200B}' | '\u{200C}' | '\u{2060}' | '\u{00AD}' | '\u{034F}' | '\u{180E}' | '\u{2061}'..='\u{2064}' => {
                zero += 1;
                if zero_line == 0 {
                    zero_line = line;
                }
            }
            // A joiner between two non-ASCII characters is an emoji or a script
            // that needs it; between ASCII it hides.
            '\u{200D}' => {
                let next = text[i + c.len_utf8()..].chars().next().unwrap_or('\0');
                if prev.is_ascii() || next.is_ascii() {
                    zero += 1;
                    if zero_line == 0 {
                        zero_line = line;
                    }
                }
            }
            // A byte-order mark is fine at the very start, hidden anywhere else.
            '\u{FEFF}' if i > 0 => {
                zero += 1;
                if zero_line == 0 {
                    zero_line = line;
                }
            }
            _ => {}
        }
        prev = c;
    }
    if bidi > 0 {
        out.push(Hidden { file: file.into(), id: "HIDDEN-BIDI", line: bidi_line, note: format!("{bidi} bidirectional override character(s): the text can read differently from how it runs (Trojan Source)") });
    }
    if tags > 0 {
        out.push(Hidden {
            file: file.into(),
            id: "HIDDEN-TAGS",
            line: tags_line,
            note: format!(
                "{tags} invisible Unicode tag character(s): hidden text an AI assistant would read and you wouldn't"
            ),
        });
    }
    if zero >= 3 {
        out.push(Hidden {
            file: file.into(),
            id: "HIDDEN-ZERO-WIDTH",
            line: zero_line,
            note: format!("{zero} zero-width or invisible character(s) inside ordinary text"),
        });
    }
    if let Some((word, l)) = if is_code(file) { first_mixed_script_word(text) } else { None } {
        out.push(Hidden {
            file: file.into(),
            id: "HIDDEN-HOMOGLYPH",
            line: l,
            note: format!("`{word}` mixes Latin with Cyrillic or Greek letters: two names can look like one"),
        });
    }
    if is_code(file) {
        let baited = bait_identifiers(text);
        if baited.len() >= 3 {
            let shown: Vec<&str> = baited.iter().take(3).map(String::as_str).collect();
            out.push(Hidden { file: file.into(), id: "AI-BAIT", line: 0, note: format!("{} identifiers named after weapons, poisons or lethal doses ({}, …): wording meant to make an AI reviewer refuse to read the code", baited.len(), shown.join(", ")) });
        }
    }
    out
}

/// Letters that print like a Latin letter but aren't one: Cyrillic а е о р
/// с у х і ј ѕ һ ԁ ԛ ԝ ӏ (and capitals), Greek α ο ν ρ κ τ υ ι (and capitals
/// Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ). Σ, Δ, θ, π and the rest are maths, not
/// disguises.
fn is_confusable(c: char) -> bool {
    "аеорсухіјѕһԁԛԝӏёАВЕКМНОРСТХІЈЅҮαονρκτυιΑΒΕΖΗΙΚΜΝΟΡΤΥΧ".contains(c)
}

/// A mostly Latin identifier with a look-alike letter from another script
/// in it, and the line it is on. Code only: prose has its own alphabets.
fn first_mixed_script_word(text: &str) -> Option<(String, usize)> {
    for (n, line) in text.lines().enumerate() {
        for word in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            let latin = word.chars().filter(|c| c.is_ascii_alphabetic()).count();
            let fakes = word.chars().filter(|c| is_confusable(*c)).count();
            let other = word.chars().filter(|c| !c.is_ascii() && !is_confusable(*c)).count();
            if word.chars().count() >= 3 && latin >= 2 && fakes >= 1 && other == 0 {
                return Some((word.to_string(), n + 1));
            }
        }
    }
    None
}

/// Words that have no business in a fingerprinting script's identifiers.
const BAIT: &[&str] = &[
    "lethal",
    "poison",
    "ricin",
    "sarin",
    "anthrax",
    "cyanide",
    "toxin",
    "bioweapon",
    "nerveagent",
    "overdose",
    "suicide",
    "kill",
    "murder",
    "bomb",
    "explosive",
    "detonat",
    "weapon",
    "warhead",
    "uranium",
    "plutonium",
    "pathogen",
    "chemicalweapon",
    "massdestruction",
    "genocide",
    "assassinat",
    "torture",
    "fentanyl",
    "deadly",
    "dosage",
    "dose",
];

/// Identifiers (camelCase or snake_case words) carrying two or more bait
/// terms, or one of the unmistakable ones.
pub fn bait_identifiers(text: &str) -> Vec<String> {
    let strong = [
        "ricin",
        "sarin",
        "anthrax",
        "bioweapon",
        "nerveagent",
        "chemicalweapon",
        "massdestruction",
        "warhead",
        "plutonium",
    ];
    let mut out: Vec<String> = Vec::new();
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.len() < 12 || !word.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let lower = word.to_ascii_lowercase().replace('_', "");
        let hits = BAIT.iter().filter(|b| lower.contains(*b)).count();
        if (hits >= 2 || strong.iter().any(|s| lower.contains(s))) && !out.contains(&word.to_string()) {
            out.push(word.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(h: &[Hidden]) -> Vec<&str> {
        h.iter().map(|x| x.id).collect()
    }

    #[test]
    fn trojan_source_and_tag_characters_fail() {
        let bidi =
            "fn main() {\n    let access = false; /*\u{202E} } \u{2066}if (access)\u{2069} \u{2066}*/ ... */\n}\n";
        let h = scan_text("a.rs", bidi);
        assert_eq!(ids(&h), ["HIDDEN-BIDI"]);
        assert_eq!(h[0].line, 2);
        assert!(h[0].fails());
        let tags = format!("# README\n\nInstall with npm.{}{}{}\n", '\u{E0001}', '\u{E0069}', '\u{E007F}');
        let h = scan_text("README.md", &tags);
        assert_eq!(ids(&h), ["HIDDEN-TAGS"]);
        assert_eq!(h[0].line, 3);
    }

    #[test]
    fn zero_width_needs_a_few_and_joiners_in_emoji_are_fine() {
        assert!(scan_text("x.md", "a\u{200B}b").is_empty(), "one is noise");
        assert_eq!(ids(&scan_text("x.md", "a\u{200B}b\u{200C}c\u{2060}d")), ["HIDDEN-ZERO-WIDTH"]);
        assert!(scan_text("x.md", "👨\u{200D}👩\u{200D}👧\u{200D}👦 family").is_empty());
        assert_eq!(ids(&scan_text("x.py", "x = 'a\u{200D}b\u{200D}c\u{200D}d'")), ["HIDDEN-ZERO-WIDTH"]);
        assert!(scan_text("x.py", "\u{FEFF}print(1)").is_empty(), "a leading BOM");
    }

    #[test]
    fn homoglyphs_and_bait() {
        let h = scan_text("auth.js", "const admin = 1;\nconst аdmin = 2;\n");
        assert_eq!(ids(&h), ["HIDDEN-HOMOGLYPH"]);
        assert_eq!(h[0].line, 2);
        assert!(
            scan_text("ops.swift", "// y = Σ_k x_k, Δlogit, θ_i, 2πk, β_t\nlet Σ_k = 1\n").is_empty(),
            "maths is not a disguise"
        );
        assert!(scan_text("notes.md", "const аdmin = 2;\n").is_empty(), "prose is not checked");
        assert!(scan_text("x.py", "привет = 1\n").is_empty(), "a whole-script word is fine");
        let bait = "function computeRicinLethalDosageForWaterSupply(){}\nfunction calculateDeadlyLethalSuicideAspirinDosage(){}\nfunction getSarinNerveAgentDispersalRate(){}\nfunction getUserAgent(){}\n";
        let h = scan_text("fp.js", bait);
        assert_eq!(ids(&h), ["AI-BAIT"]);
        assert!(h[0].note.contains("3 identifiers"), "{}", h[0].note);
        assert!(scan_text("fp.md", bait).is_empty(), "prose isn't code");
        assert!(scan_text("ok.js", "function getLethalCompanyScore(){}\nfunction dosage(){}\n").is_empty());
    }

    #[test]
    fn walks_a_repo_and_skips_what_it_should() {
        let d = crate::system::TempDir::new("hidden").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/x")).unwrap();
        std::fs::write(d.path().join("node_modules/x/i.js"), "\u{202E}").unwrap();
        std::fs::write(d.path().join("a.min.js"), "\u{202E}").unwrap();
        std::fs::write(d.path().join("b.png"), "\u{202E}").unwrap();
        std::fs::write(d.path().join("c.ts"), "let x = 1; // \u{202E}\n").unwrap();
        std::fs::write(d.path().join("bundle.js"), format!("{}\u{202E}", "x".repeat(3000))).unwrap();
        let h = scan_repo(d.path());
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!((h[0].file.as_str(), h[0].id), ("c.ts", "HIDDEN-BIDI"));
    }
}
