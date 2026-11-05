use super::*;

#[test]
fn control_characters_are_dropped() {
    assert_eq!(clean("plain\tkept"), "plain\tkept");
    assert_eq!(clean("a\x1b[2K\x1b[1Ab\u{9b}2Kc\x07\x7f"), "abc");
    assert_eq!(clean("x\x1b]52;c;aGVsbG8=\x07y\x1b]8;;http://e\x1b\\z"), "xyz");
    assert_eq!(clean("plain \x1b"), "plain ");
}

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
