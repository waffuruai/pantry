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
                        "MODERATE" | "MEDIUM" => self.yellow(t),
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
mod tests {
    use super::*;

    const LINES: &[&str] = &[
        "==> Security scan (~/.cache/wpantry/wpantry.db)",
        "project",
        "  ✗ vite 8.2.1 (~/w/web/pnpm-lock.yaml) - (GHSA-1 KEV HIGH) Path traversal. Fix: pnpm update vite@8.2.3",
        "  ⚠ node 22.1.0 (~/.nvm) - (OUTDATED) behind 22.23.4. Fix: nvm install 22.23.4",
        "not checked",
        "  ⚠ OSV - unreachable",
        "  · 3 applicable advisories have no released fix yet",
        "✗ 1 thing(s) to update (1 advisories), 1 warning(s).",
        "✓ nothing with a released fix applies to what was scanned",
        "  ✓ git          2.47.0     required  repo HEADs",
        "",
    ];

    #[test]
    fn off_is_the_plain_text() {
        for l in LINES {
            assert_eq!(Style::new(false).line(l), *l);
        }
    }

    /// With colour on, the words are the same once the escapes are gone.
    #[test]
    fn on_only_adds_escapes() {
        let strip = |s: &str| {
            let mut out = String::new();
            let mut it = s.chars();
            while let Some(c) = it.next() {
                if c == '\x1b' {
                    for c in it.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        for l in LINES {
            assert_eq!(strip(&Style::new(true).line(l)), *l);
        }
        let s = Style::new(true);
        assert!(s.line(LINES[2]).starts_with("  \x1b[1;31m✗\x1b[0m vite"));
        assert!(s.line(LINES[2]).contains("\x1b[1;31mKEV\x1b[0m \x1b[1;31mHIGH\x1b[0m"));
        assert!(s.line(LINES[2]).contains("\x1b[1mFix:\x1b[0m pnpm update"));
        assert!(s.line(LINES[3]).starts_with("  \x1b[33m⚠\x1b[0m node"));
        assert_eq!(s.line(LINES[8]), format!("\x1b[32m{}\x1b[0m", LINES[8]));
        assert!(s.line(LINES[9]).starts_with("  \x1b[32m✓\x1b[0m git"));
    }

    #[test]
    fn no_color_and_dumb_terminals_turn_it_off() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
        };
        assert!(allowed(&env(&[("TERM", "xterm-256color")])));
        assert!(allowed(&env(&[("NO_COLOR", "")])), "an empty NO_COLOR doesn't count");
        assert!(!allowed(&env(&[("NO_COLOR", "1")])));
        assert!(!allowed(&env(&[("TERM", "dumb")])));
    }
}
