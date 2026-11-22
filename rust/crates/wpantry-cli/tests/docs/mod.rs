//! Check that every `wpantry` command and flag the user docs mention exists
//! (docs/public/*.md and desktop/README.md), against the binary's own help.
//!
//! For each `wpantry ...` command in inline code or a code block, the
//! subcommand path (such as `schedule status`) must be a real command, and
//! each `--flag` after it must appear in that command's `--help`, or in the
//! help of a command above it (`wpantry --help` lists the global options). A
//! flag in inline code on its own, such as `--no-personal-files`, on a line
//! that also names a `wpantry` command in code, must appear in some wpantry
//! help text, or belong to Pantry Setup or the desktop app. Commands of other
//! programs (cargo, rustup, wpantry-setup, ...) and bare flags on lines about
//! them are skipped.
//!
//! The matching follows the patterns the original checker used (Python
//! `re`), written out by hand because they need lookbehind:
//!
//! ```text
//! CODE_SPAN = `([^`\n]+)`
//! FLAG      = (?<![\w-])--[a-z][a-z0-9-]*
//! COMMAND   = (?<![\w./-])wpantry(?:\.exe)?(?![\w-])((?:\s+[^\s|;&]+)*)
//! WORD      = [a-z][a-z-]*$
//! LEAD      = (?:.*(?:&&|\|\||[|;(]))?\s*(?:\$\s*)?(?:sudo\s+)?(?:[A-Z_][A-Z0-9_]*=\S*\s+)*
//! ```
//!
//! Usage (tests/docs_flags.rs):
//!
//! ```text
//! let mut cli = Cli::new(|path| run_help(path));
//! let problems = check(&mut cli, &[("docs/public/usage.md".into(), text)]);
//! ```

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

/// Flags of the other Pantry programs that docs mention on their own:
/// Pantry Setup (desktop/src/bin/wpantry-setup.rs), the desktop app
/// (`wpantry-desktop --help`) and the install scripts.
pub const OTHER_PROGRAM_FLAGS: &[&str] = &[
    "--install-only",
    "--uninstall", // Pantry Setup
    "--automation",
    "--scanner",
    "--scheduled-run", // wpantry-desktop
    "--open",
    "--no-install", // desktop/release/install-local.sh
    "--dir",        // rust/release/install.sh (its --version is also wpantry's)
];

/// Python's `\w` for str patterns.
fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Inline code spans of one line: the text between backticks, never empty.
fn code_spans(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        match after.find('`') {
            Some(0) => rest = after,
            Some(close) => {
                out.push(&after[..close]);
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    out
}

/// (line number, code, in a fenced block) for inline code spans and code
/// block lines.
pub fn snippets(text: &str) -> Vec<(usize, &str, bool)> {
    let mut out = Vec::new();
    let mut fenced = false;
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            out.push((i + 1, line, true));
        } else {
            out.extend(code_spans(line).into_iter().map(|span| (i + 1, span, false)));
        }
    }
    out
}

/// Every `--flag` in `text`: not preceded by a word character or `-`.
pub fn flags(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < chars.len() {
        let free = i == 0 || !(word_char(chars[i - 1]) || chars[i - 1] == '-');
        if free && chars[i] == '-' && chars[i + 1] == '-' && chars[i + 2].is_ascii_lowercase() {
            let mut end = i + 3;
            while end < chars.len()
                && (chars[end].is_ascii_lowercase() || chars[end].is_ascii_digit() || chars[end] == '-')
            {
                end += 1;
            }
            out.push(chars[i..end].iter().collect());
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// A `wpantry` command in code: where it starts (in chars) and its
/// argument text (COMMAND's group 1).
struct CommandMatch {
    start: usize,
    args: String,
}

fn commands_in(code: &str) -> Vec<CommandMatch> {
    let chars: Vec<char> = code.chars().collect();
    let name: Vec<char> = "wpantry".chars().collect();
    let exe: Vec<char> = ".exe".chars().collect();
    let at = |i: usize, s: &[char]| chars.get(i..i + s.len()) == Some(s);
    let free_after = |i: usize| chars.get(i).is_none_or(|&c| !(word_char(c) || c == '-'));
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let free_before = i == 0 || !(word_char(chars[i - 1]) || ".-/".contains(chars[i - 1]));
        if !(free_before && at(i, &name)) {
            i += 1;
            continue;
        }
        // (?:\.exe)? then (?![\w-]): with .exe first, then without.
        let mut end = i + name.len();
        if at(end, &exe) && free_after(end + exe.len()) {
            end += exe.len();
        } else if !free_after(end) {
            i += 1;
            continue;
        }
        // ((?:\s+[^\s|;&]+)*): whitespace, then a word without | ; &.
        let args_start = end;
        loop {
            let mut j = end;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let word_start = j;
            while j < chars.len() && !chars[j].is_whitespace() && !"|;&".contains(chars[j]) {
                j += 1;
            }
            if word_start == end || j == word_start {
                break;
            }
            end = j;
        }
        out.push(CommandMatch { start: i, args: chars[args_start..end].iter().collect() });
        i = end;
    }
    out
}

/// LEAD.fullmatch: what comes before `wpantry` makes it a command (nothing,
/// a prompt, a shell separator, `sudo`, or VAR=value pairs).
fn is_lead(prefix: &str) -> bool {
    fn tail(s: &str) -> bool {
        let mut s = s.trim_start();
        if let Some(rest) = s.strip_prefix('$') {
            s = rest.trim_start();
        }
        if let Some(rest) = s.strip_prefix("sudo")
            && rest.starts_with(char::is_whitespace)
        {
            s = rest.trim_start();
        }
        // ([A-Z_][A-Z0-9_]*=\S*\s+)*
        while !s.is_empty() {
            let mut chars = s.char_indices();
            match chars.next() {
                Some((_, c)) if c.is_ascii_uppercase() || c == '_' => {}
                _ => return false,
            }
            let name_end = s
                .char_indices()
                .skip(1)
                .find(|&(_, c)| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                .map_or(s.len(), |(i, _)| i);
            let Some(value) = s[name_end..].strip_prefix('=') else {
                return false;
            };
            let value_end = value.find(char::is_whitespace).unwrap_or(value.len());
            let after = &value[value_end..];
            if after.is_empty() {
                return false;
            }
            s = after.trim_start();
        }
        true
    }
    if tail(prefix) {
        return true;
    }
    // (?:.*(?:&&|\|\||[|;(]))?: any separator, anywhere before.
    prefix.char_indices().any(|(i, c)| {
        let after = i + c.len_utf8();
        let separator = "|;(".contains(c) || (c == '&' && prefix[after..].starts_with('&'));
        let end = if c == '&' { after + 1 } else { after };
        separator && tail(&prefix[end..])
    })
}

/// WORD.match: a lowercase word, hyphens allowed after the first letter.
fn is_word(w: &str) -> bool {
    let mut chars = w.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase()) && chars.all(|c| c.is_ascii_lowercase() || c == '-')
}

/// One mention in a doc.
#[derive(Clone, Debug, PartialEq)]
pub struct Mention {
    pub file: String,
    pub line: usize,
    /// Subcommand path, empty for wpantry itself.
    pub path: Vec<String>,
    pub flags: Vec<String>,
    /// A bare `--flag` in inline code.
    pub standalone: bool,
    /// A first word that looks like a command but is not one.
    pub unknown: String,
}

fn prefix_chars(code: &str, n: usize) -> &str {
    code.char_indices().nth(n).map_or(code, |(i, _)| &code[..i])
}

/// Commands and bare flags in one Markdown file. `commands` is the set of
/// top-level subcommands, used to tell a subcommand from an argument
/// (`wpantry scan ~/code` has none).
pub fn mentions(text: &str, name: &str, commands: &BTreeSet<String>) -> Vec<Mention> {
    let snippets = snippets(text);
    let lines_with_commands: BTreeSet<usize> = snippets
        .iter()
        .filter(|(_, code, _)| commands_in(code).iter().any(|m| is_lead(prefix_chars(code, m.start))))
        .map(|(n, _, _)| *n)
        .collect();
    let mut found = Vec::new();
    for (number, code, block) in snippets {
        let mut matched = false;
        for m in commands_in(code) {
            if !is_lead(prefix_chars(code, m.start)) {
                continue;
            }
            matched = true;
            let words: Vec<&str> = m.args.split_whitespace().collect();
            let mut unknown = String::new();
            if let Some(first) = words.first()
                && is_word(first)
                && !commands.contains(*first)
            {
                unknown = first.to_string();
            }
            let mut path: Vec<String> = Vec::new();
            for word in &words {
                if word.starts_with('-') {
                    break;
                }
                if path.is_empty() && commands.contains(*word) {
                    path.push(word.to_string());
                } else if path.len() == 1 && is_word(word) {
                    // A second word is a nested command only if help knows
                    // it; check_mention resolves that against the real CLI.
                    path.push(word.to_string());
                } else {
                    break;
                }
            }
            found.push(Mention {
                file: name.to_string(),
                line: number,
                path,
                flags: flags(&m.args),
                standalone: false,
                unknown,
            });
        }
        if !matched && !block && lines_with_commands.contains(&number) {
            let bare = flags(code);
            // Only inline code that is just a flag (and maybe its value).
            if !bare.is_empty() && code.trim().starts_with("--") && code.split_whitespace().count() <= 2 {
                found.push(Mention {
                    file: name.to_string(),
                    line: number,
                    path: Vec::new(),
                    flags: vec![bare[0].clone()],
                    standalone: true,
                    unknown: String::new(),
                });
            }
        }
    }
    found
}

/// Help text from the scanner, cached per subcommand path. `help` returns
/// the stdout of `wpantry <path> --help`, or None when it exits non-zero.
pub struct Cli<F: FnMut(&[String]) -> Option<String>> {
    help: F,
    cache: BTreeMap<Vec<String>, Option<String>>,
}

/// `^  ([a-z][a-z-]*)\b` with re.M: the command names a help section lists.
fn listed(section: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in section.split('\n') {
        let Some(rest) = line.strip_prefix("  ") else { continue };
        let chars: Vec<char> = rest.chars().collect();
        if !chars.first().is_some_and(|c| c.is_ascii_lowercase()) {
            continue;
        }
        let mut run = 1;
        while run < chars.len() && (chars[run].is_ascii_lowercase() || chars[run] == '-') {
            run += 1;
        }
        // \b after a greedy run: back off until the boundary holds.
        let boundary = |n: usize| {
            let before = word_char(chars[n - 1]);
            let after = chars.get(n).is_some_and(|&c| word_char(c));
            before != after
        };
        if let Some(n) = (1..=run).rev().find(|&n| boundary(n)) {
            out.push(chars[..n].iter().collect());
        }
    }
    out
}

impl<F: FnMut(&[String]) -> Option<String>> Cli<F> {
    pub fn new(help: F) -> Self {
        Cli { help, cache: BTreeMap::new() }
    }

    pub fn help(&mut self, path: &[String]) -> Option<String> {
        if !self.cache.contains_key(path) {
            let text = (self.help)(path);
            self.cache.insert(path.to_vec(), text);
        }
        self.cache[path].clone()
    }

    pub fn commands(&mut self) -> BTreeSet<String> {
        let text = self.help(&[]).unwrap_or_default();
        let section = text.split_once("Commands:").map_or(text.as_str(), |(_, s)| s);
        listed(section).into_iter().collect()
    }

    pub fn all_flags(&mut self) -> BTreeSet<String> {
        let mut all: BTreeSet<String> = flags(&self.help(&[]).unwrap_or_default()).into_iter().collect();
        for command in self.commands() {
            let text = self.help(std::slice::from_ref(&command)).unwrap_or_default();
            all.extend(flags(&text));
            let nested = text.split_once("Commands:").map_or("", |(_, s)| s);
            for sub in listed(nested) {
                all.extend(flags(&self.help(&[command.clone(), sub]).unwrap_or_default()));
            }
        }
        all
    }
}

pub fn check_mention<F: FnMut(&[String]) -> Option<String>>(
    mention: &Mention,
    cli: &mut Cli<F>,
    every_flag: &BTreeSet<String>,
) -> Vec<String> {
    let at = format!("{}:{}", mention.file, mention.line);
    if mention.standalone {
        let flag = &mention.flags[0];
        if every_flag.contains(flag) || OTHER_PROGRAM_FLAGS.contains(&flag.as_str()) {
            return Vec::new();
        }
        return vec![format!("{at}: {flag} is not a wpantry, Pantry Setup or Pantry Desktop flag")];
    }
    if !mention.unknown.is_empty() {
        return vec![format!("{at}: `wpantry {}` is not a command", mention.unknown)];
    }
    let mut path = mention.path.clone();
    // Drop a trailing word that is an argument, not a nested command.
    if path.len() == 2 && cli.help(&path).is_none() {
        path.truncate(1);
    }
    if !path.is_empty() && cli.help(&path).is_none() {
        return vec![format!("{at}: `wpantry {}` is not a command", path.join(" "))];
    }
    let mut known = BTreeSet::new();
    for depth in 0..=path.len() {
        known.extend(flags(&cli.help(&path[..depth]).unwrap_or_default()));
    }
    let command = std::iter::once("wpantry".to_string()).chain(path.iter().cloned()).collect::<Vec<_>>().join(" ");
    mention.flags.iter().filter(|f| !known.contains(*f)).map(|f| format!("{at}: `{command}` has no {f}")).collect()
}

/// Every problem in `docs`, each (display name, Markdown text).
pub fn check<F: FnMut(&[String]) -> Option<String>>(cli: &mut Cli<F>, docs: &[(String, String)]) -> Vec<String> {
    let commands = cli.commands();
    if commands.is_empty() {
        return vec!["wpantry --help listed no commands".to_string()];
    }
    let every_flag = cli.all_flags();
    let mut problems = Vec::new();
    for (name, text) in docs {
        for mention in mentions(text, name, &commands) {
            problems.extend(check_mention(&mention, cli, &every_flag));
        }
    }
    problems
}
