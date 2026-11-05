//! Text in a repo that reads one way to a person and another to a parser
//! or a model: Unicode bidirectional overrides that reorder what the eye
//! sees (Trojan Source, CVE-2021-42574), tag characters and zero-width
//! characters that hide instructions in a comment or a string (the way
//! prompts are smuggled into text an AI assistant will read), homoglyphs
//! that make two identifiers look like one, and identifiers packed with
//! weapon and poison vocabulary so that an AI reviewer refuses to read the
//! code at all.
//!
//! And, since an agent now reads READMEs, comments, package descriptions
//! and commit messages as it works: text in those places that addresses
//! the agent instead of the reader ("ignore previous instructions"), text
//! the reader never sees because HTML hides it (a `display:none` block,
//! white on white, a zero-size font, an HTML comment) and that carries such
//! instructions, links built to carry the agent's context away in a query
//! string when they are rendered, `javascript:` and `data:` URIs where a
//! link should be, and look-alike characters in file names and domains.
//!
//! None of it is proof of harm; all of it is a reason to read the file
//! yourself before trusting what a tool says about it.
//!
//! One file per behaviour: `unicode` (bidi, tags, flags, mixed scripts),
//! `instructions` (text addressed to an agent), `html` (hidden markup),
//! `links` (exfiltration and dangerous links), `bait`, `names` (file
//! names) and `commits` (commit messages). This file is the index: which
//! files are read, and `scan_text`, which runs each over one file.

mod bait;
mod commits;
mod html;
mod instructions;
mod links;
mod names;
mod unicode;

use crate::checks::files::{Contents, Read, Stats, When};
use bait::bait_identifiers;
use commits::commit_messages;
use html::{hidden_elements, html_comments};
use instructions::{addresses_agents, agent_instruction, first_agent_instruction, instructable};
use links::{confusable_domain, dangerous_uri, exfil_link};
use names::name_findings;
use std::path::{Path, PathBuf};
use unicode::{BLACK_FLAG, excerpt, first_mixed_script_word, is_rtl, without_subdivision_flags};

/// One file's hidden-text finding.
#[derive(Clone, Debug, PartialEq)]
pub struct Hidden {
    /// Relative to the repo.
    pub file: String,
    /// `HIDDEN-PROMPT`, `HIDDEN-FILENAME`, `CONFUSABLE-DOMAIN` (fail);
    /// `HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`,
    /// `AGENT-INSTRUCTIONS`, `HIDDEN-HTML`, `CONFUSABLE-NAME` (warn);
    /// `HIDDEN-BIDI` (fail on a line with no right-to-left text, warn beside
    /// Arabic or Hebrew); `HIDDEN-TAGS` (fail when the tag characters spell
    /// an instruction to an agent or sit in a file written for agents, warn
    /// otherwise); `EXFIL-LINK` (fail in a file that also addresses the
    /// agent, warn otherwise); `DANGEROUS-URI` (fail as a link in prose,
    /// warn in page source). What was found is quoted in the note so a
    /// person can judge: context decides, not the character alone.
    pub id: &'static str,
    pub note: String,
    /// The first line it was seen on.
    pub line: usize,
    /// Fails the scan.
    pub hard: bool,
}

impl Hidden {
    /// A finding graded by its id alone; the ids whose grade depends on
    /// context set `hard` after.
    fn new(file: &str, id: &'static str, line: usize, note: String) -> Hidden {
        let hard = matches!(id, "HIDDEN-PROMPT" | "HIDDEN-FILENAME" | "CONFUSABLE-DOMAIN");
        Hidden { file: file.into(), id, note, line, hard }
    }

    pub fn fails(&self) -> bool {
        self.hard
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
    "markdown",
    "rst",
    "adoc",
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

/// How deep a repo is walked.
pub const DEPTH: usize = 6;

/// Every hidden-text finding in the repo, one per (file, id): the files'
/// text, their names, and the commit messages. One job of the files pass
/// ([`crate::checks::files::pass`]).
pub fn scan_repo(root: &Path) -> Vec<Hidden> {
    crate::checks::files::Results::default().hidden(root)
}

/// One step of a repo's findings, in walk order: a name's finding, or a
/// file's (by its read).
#[derive(Debug)]
enum Step {
    Name(Hidden),
    Read(usize),
}

/// The text files a repo's check reads (at most [`MAX_FILE`] each and
/// [`MAX_REPO`] in all, in walk order), and its names' findings.
#[derive(Debug)]
pub struct Plan {
    pub reads: Vec<Read>,
    steps: Vec<Step>,
}

pub fn plan(root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    let mut plan = Plan { reads: Vec::new(), steps: Vec::new() };
    let mut budget = MAX_REPO;
    for (dir, files) in walk {
        if let Some(h) = dir
            .strip_prefix(root)
            .ok()
            .filter(|r| !r.as_os_str().is_empty())
            .and_then(|r| name_findings(&r.to_string_lossy()))
        {
            plan.steps.push(Step::Name(h));
        }
        for name in files {
            let path = dir.join(name);
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            if let Some(h) = name_findings(&rel) {
                plan.steps.push(Step::Name(h));
            }
            if !wanted(name) {
                continue;
            }
            let Some(s) = stat(&path) else { continue };
            if !s.file || s.size > MAX_FILE || s.size > budget {
                continue;
            }
            budget -= s.size;
            plan.steps.push(Step::Read(plan.reads.len()));
            plan.reads.push(Read { path, rel, cap: MAX_FILE, role: 0, when: When::Always });
        }
    }
    plan
}

/// One file's findings.
pub fn file(read: &Read, c: &Contents) -> Vec<Hidden> {
    let Some(text) = c.text() else { return Vec::new() };
    if looks_minified(&text) {
        return Vec::new(); // a bundle: not something a person reads, and full of escapes
    }
    scan_text(&read.rel, &text)
}

/// The repo's findings: its names' and files', in walk order, and its
/// commit messages', one per (file, id).
pub fn finish(root: &Path, plan: &Plan, files: &[Option<&Vec<Hidden>>]) -> Vec<Hidden> {
    let mut out = Vec::new();
    for step in &plan.steps {
        match step {
            Step::Name(h) => out.push(h.clone()),
            Step::Read(i) => out.extend(files[*i].into_iter().flatten().cloned()),
        }
    }
    out.extend(commit_messages(root));
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out.dedup_by(|a, b| a.file == b.file && a.id == b.id);
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

pub(crate) fn ext_of(file: &str) -> String {
    let lower = file.to_ascii_lowercase();
    lower.rsplit_once('.').map(|(_, e)| e.to_string()).unwrap_or_default()
}

pub(crate) fn is_code(file: &str) -> bool {
    [
        "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "go", "java", "kt", "swift", "c", "h", "cc", "cpp",
        "cs", "php", "lua", "scala", "dart", "sh", "bash", "zsh", "fish", "ps1", "pl", "r", "ex", "exs", "erl", "hs",
        "ml", "sql", "css", "scss", "vue", "svelte", "astro", "tf", "gradle", "cmake", "make", "mk", "proto",
    ]
    .contains(&ext_of(file).as_str())
}

/// Prose a person (or an agent) reads rendered: READMEs, docs, plain text.
pub(crate) fn is_prose(file: &str) -> bool {
    ["md", "mdx", "mdc", "markdown", "rst", "adoc", "txt"].contains(&ext_of(file).as_str())
}

/// Formats that carry HTML: pages, components and the markdown that embeds it.
fn is_markup(file: &str) -> bool {
    ["html", "htm", "xhtml", "md", "mdx", "mdc", "markdown", "svg", "vue", "jsx", "tsx", "astro", "svelte", "xml"]
        .contains(&ext_of(file).as_str())
}

/// The findings for one file's text.
pub fn scan_text(file: &str, text: &str) -> Vec<Hidden> {
    let flags_removed;
    let text = if text.contains(BLACK_FLAG) {
        flags_removed = without_subdivision_flags(text);
        flags_removed.as_str()
    } else {
        text
    };
    let mut out = Vec::new();
    let (mut bidi, mut tags, mut zero, mut bidi_line, mut tags_line, mut zero_line) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    // Bidi controls on a line with no right-to-left text, and the first such line.
    let (mut bidi_bare, mut bidi_bare_line) = (0usize, 0usize);
    let mut smuggled = String::new();
    let mut line = 1usize;
    let mut line_start = 0usize;
    let mut line_rtl: Option<bool> = None;
    let mut prev = '\0';
    for (i, c) in text.char_indices() {
        if c == '\n' {
            line += 1;
            line_start = i + 1;
            line_rtl = None;
            prev = c;
            continue;
        }
        match c {
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
                bidi += 1;
                if bidi_line == 0 {
                    bidi_line = line;
                }
                // Beside Arabic or Hebrew the control is doing its job;
                // alone it reorders what the eye sees.
                let rtl = *line_rtl
                    .get_or_insert_with(|| text[line_start..].split('\n').next().unwrap_or("").chars().any(is_rtl));
                if !rtl {
                    bidi_bare += 1;
                    if bidi_bare_line == 0 {
                        bidi_bare_line = line;
                    }
                }
            }
            '\u{E0000}'..='\u{E007F}' => {
                tags += 1;
                if tags_line == 0 {
                    tags_line = line;
                }
                // Tag characters are ASCII moved up by 0xE0000: the text they hide.
                let n = c as u32 - 0xE0000;
                if (0x20..0x7F).contains(&n) && smuggled.len() < 400 {
                    smuggled.push(char::from(n as u8));
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
    if bidi_bare > 0 {
        let beside = bidi - bidi_bare;
        let rest = if beside > 0 {
            format!(" ({beside} more sit beside right-to-left text, where they belong)")
        } else {
            String::new()
        };
        let mut h = Hidden::new(
            file,
            "HIDDEN-BIDI",
            bidi_bare_line,
            format!(
                "{bidi_bare} bidirectional override character(s) on a line with no right-to-left text: the text can read differently from how it runs (Trojan Source){rest}"
            ),
        );
        h.hard = true;
        out.push(h);
    } else if bidi > 0 {
        out.push(Hidden::new(file, "HIDDEN-BIDI", bidi_line, format!("{bidi} bidirectional control character(s), each on a line with Arabic, Hebrew or another right-to-left script: formatting that script needs, not an override of what you see")));
    }
    if tags > 0 {
        let spelled: String = smuggled.chars().take(80).collect();
        let instruction = agent_instruction(&smuggled);
        let for_agents = addresses_agents(file);
        let decoded = match instruction {
            Some(what) => format!("; they spell out {what}: `{spelled}`"),
            None if !smuggled.is_empty() => format!("; they spell `{spelled}`"),
            None => String::new(),
        };
        let where_ = if for_agents { ", in a file written for agents" } else { "" };
        let mut h = Hidden::new(
            file,
            "HIDDEN-TAGS",
            tags_line,
            format!(
                "{tags} invisible Unicode tag character(s): hidden text an AI assistant would read and you wouldn't{decoded}{where_}"
            ),
        );
        h.hard = instruction.is_some() || for_agents;
        out.push(h);
    }
    if zero >= 3 {
        out.push(Hidden::new(
            file,
            "HIDDEN-ZERO-WIDTH",
            zero_line,
            format!("{zero} zero-width or invisible character(s) inside ordinary text"),
        ));
    }
    let code = is_code(file);
    if let Some((word, l)) = if code { first_mixed_script_word(text) } else { None } {
        out.push(Hidden::new(
            file,
            "HIDDEN-HOMOGLYPH",
            l,
            format!("`{word}` mixes Latin with Cyrillic or Greek letters: two names can look like one"),
        ));
    }
    if code {
        let baited = bait_identifiers(text);
        if baited.len() >= 3 {
            let shown: Vec<&str> = baited.iter().take(3).map(String::as_str).collect();
            out.push(Hidden::new(file, "AI-BAIT", 0, format!("{} identifiers named after weapons, poisons or lethal doses ({}, …): wording meant to make an AI reviewer refuse to read the code", baited.len(), shown.join(", "))));
        }
    }

    // Text that addresses an agent where a person is addressed: any line of
    // prose and config, comment lines of code; never in the files whose job
    // it is (CLAUDE.md, .cursor/rules, prompts).
    let instructs = instructable(file).and_then(|mode| first_agent_instruction(text, mode));
    if let Some((l, what, line_text)) = &instructs {
        out.push(Hidden::new(
            file,
            "AGENT-INSTRUCTIONS",
            *l,
            format!("addresses an AI agent rather than the reader ({what}): `{}`", excerpt(line_text)),
        ));
    }

    let markup = is_markup(file);
    let prose = is_prose(file);
    if markup || prose {
        // Text the reader never sees: hidden elements and HTML comments.
        let mut prompt: Option<(usize, String, &'static str)> = None;
        let mut hidden_block: Option<(usize, String, &'static str)> = None;
        for (l, body, how) in hidden_elements(text) {
            if agent_instruction(&body).is_some() {
                prompt.get_or_insert((l, body, how));
            } else {
                hidden_block.get_or_insert((l, body, how));
            }
        }
        for (l, body) in html_comments(text) {
            if agent_instruction(&body).is_some() {
                prompt.get_or_insert((l, body, "an HTML comment"));
            }
        }
        if let Some((l, body, how)) = prompt {
            out.push(Hidden::new(
                file,
                "HIDDEN-PROMPT",
                l,
                format!("instructions to an AI agent hidden from the reader ({how}): `{}`", excerpt(&body)),
            ));
        } else if let Some((l, body, how)) = hidden_block
            && prose
        {
            out.push(Hidden::new(
                file,
                "HIDDEN-HTML",
                l,
                format!("text hidden when rendered ({how}): `{}`", excerpt(&body)),
            ));
        }

        // Links that carry data away when rendered or followed.
        if let Some((l, host, why)) = exfil_link(text) {
            let mut h = Hidden::new(
                file,
                "EXFIL-LINK",
                l,
                format!("a link to {host} {why}: rendered or followed by an agent, it sends what it was given"),
            );
            if instructs.is_some() {
                h.hard = true;
                h.note.push_str(", in a file that also addresses the agent");
            }
            out.push(h);
        }

        // A script where a link should be.
        if let Some((l, what, linked)) = dangerous_uri(text)
            && (linked || prose)
        {
            let mut h = Hidden::new(
                file,
                "DANGEROUS-URI",
                l,
                format!("{what}{}", if linked { " as a link target" } else { "" }),
            );
            h.hard = linked && prose;
            out.push(h);
        }
    }

    // A domain that only looks like the one you know.
    if let Some((l, host, hard)) = confusable_domain(text) {
        let mut h = Hidden::new(
            file,
            "CONFUSABLE-DOMAIN",
            l,
            if hard {
                format!("`{host}` mixes Latin with look-alike letters from another script: not the domain it resembles")
            } else {
                format!(
                    "`{host}` is an internationalized domain (punycode): check what it renders as before trusting it"
                )
            },
        );
        h.hard = hard;
        out.push(h);
    }
    out
}

#[cfg(test)]
mod tests;
