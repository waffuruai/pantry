//! Colour on a terminal: failures red, warnings yellow, what's fine green,
//! headings bold. Only when the stream is a terminal, `NO_COLOR` is unset or
//! empty (no-color.org) and `TERM` isn't "dumb"; pipes, files, CI logs and
//! `--json` get plain text. The report is written plain and coloured line
//! by line here, from the marks it already carries (`✗`, `⚠`, `✓`), so the
//! words are the same with or without colour.

use std::io::IsTerminal;

const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const CYAN: &str = "36";
const BOLD: &str = "1";
const DIM: &str = "2";

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Style {
    on: bool,
}

/// Whether the environment allows colour at all.
fn allowed(var: &dyn Fn(&str) -> Option<String>) -> bool {
    var("NO_COLOR").is_none_or(|v| v.is_empty()) && var("TERM").is_none_or(|t| t != "dumb")
}

/// `s` without terminal control characters and escape sequences (C0 except
/// tab, DEL, C1, and whole CSI/OSC sequences): a package, file or server
/// name from a repo is data, never an escape that redraws or hides a line.
pub fn clean(s: &str) -> String {
    if !s.chars().any(is_control) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' | '\u{9b}' | '\u{9d}' => {
                // ESC [ … final byte (CSI), ESC ] … BEL or ESC \ (OSC), else ESC + one char.
                let kind = if c == '\u{9b}' {
                    '['
                } else if c == '\u{9d}' {
                    ']'
                } else {
                    chars.next().unwrap_or(' ')
                };
                match kind {
                    '[' => {
                        for n in chars.by_ref() {
                            if ('\x40'..='\x7e').contains(&n) {
                                break;
                            }
                        }
                    }
                    ']' => {
                        while let Some(n) = chars.next() {
                            if n == '\x07' || (n == '\x1b' && chars.peek() == Some(&'\\')) {
                                chars.next_if_eq(&'\\');
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            c if is_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

fn is_control(c: char) -> bool {
    (c.is_control() && c != '\t') || ('\u{80}'..='\u{9f}').contains(&c)
}

impl Style {
    pub fn new(on: bool) -> Style {
        Style { on }
    }

    /// For stdout: colour when it's a terminal and the environment allows.
    pub fn stdout() -> Style {
        Style::new(std::io::stdout().is_terminal() && allowed(&|k| std::env::var(k).ok()))
    }

    /// For stderr (errors, the progress line, prompts).
    pub fn stderr() -> Style {
        Style::new(std::io::stderr().is_terminal() && allowed(&|k| std::env::var(k).ok()))
    }

    fn paint(self, codes: &[&str], s: &str) -> String {
        if !self.on || s.is_empty() {
            return s.to_string();
        }
        format!("\x1b[{}m{s}\x1b[0m", codes.join(";"))
    }

    pub fn red(self, s: &str) -> String {
        self.paint(&[BOLD, RED], s)
    }

    pub fn yellow(self, s: &str) -> String {
        self.paint(&[YELLOW], s)
    }

    pub fn green(self, s: &str) -> String {
        self.paint(&[GREEN], s)
    }

    pub fn cyan(self, s: &str) -> String {
        self.paint(&[BOLD, CYAN], s)
    }

    pub fn bold(self, s: &str) -> String {
        self.paint(&[BOLD], s)
    }

    pub fn dim(self, s: &str) -> String {
        self.paint(&[DIM], s)
    }

    /// One line of the report (or `tools`, `export`, `breach`), coloured by
    /// its leading mark; unchanged when colour is off.
    pub fn line(self, l: &str) -> String {
        if !self.on {
            return l.to_string();
        }
        if let Some(rest) = l.strip_prefix("==> ") {
            return format!("{} {}", self.cyan("==>"), self.bold(rest));
        }
        let indent = l.len() - l.trim_start().len();
        let (pad, body) = l.split_at(indent);
        let mut chars = body.chars();
        let Some(mark) = chars.next() else { return l.to_string() };
        let rest = chars.as_str();
        // A summary line (no indent) is coloured whole; an entry's mark only.
        let whole = indent == 0;
        match mark {
            '✗' if whole => self.red(l),
            '⚠' if whole => self.yellow(l),
            '✓' if whole => self.green(l),
            '✗' => format!("{pad}{}{}", self.red("✗"), self.details(rest)),
            '⚠' => format!("{pad}{}{}", self.yellow("⚠"), self.details(rest)),
            '✓' => format!("{pad}{}{rest}", self.green("✓")),
            '→' => format!("{pad}{}{rest}", self.cyan("→")),
            '·' => self.dim(l),
            _ if whole && l == "not checked" => self.paint(&[BOLD, YELLOW], l),
            _ if whole => self.bold(l),
            _ => l.to_string(),
        }
    }

    /// An entry's tags `(ID KEV SEVERITY)` and its `Fix:`.
    fn details(self, rest: &str) -> String {
        let (head, tail) = match rest.find(" - (").and_then(|i| rest[i..].find(')').map(|j| (i + 4, i + j))) {
            Some((open, close)) => {
                let tags: Vec<String> = rest[open..close]
                    .split(' ')
                    .map(|t| match t.trim_end_matches(',') {
                        "KEV" | "CRITICAL" | "HIGH" | "MALICIOUS" => self.red(t),
                        "MEDIUM" => self.yellow(t),
                        _ => t.to_string(),
                    })
                    .collect();
                (format!("{}{}", &rest[..open], tags.join(" ")), &rest[close..])
            }
            None => (String::new(), rest),
        };
        match tail.find(" Fix: ") {
            Some(i) => format!("{head}{} {}{}", &tail[..i], self.bold("Fix:"), &tail[i + 5..]),
            None => format!("{head}{tail}"),
        }
    }
}

#[cfg(test)]
#[path = "style_tests.rs"]
mod tests;
