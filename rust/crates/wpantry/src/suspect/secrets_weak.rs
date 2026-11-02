//! Hardcoded passwords in source and config: a `password`, `passwd`, `pwd`
//! or `secret` assignment whose value is a known-weak password fails; any
//! other non-empty password literal warns, since a committed default is
//! still a credential to rotate. This is the source-level, non-git part of
//! password hygiene; full secret scanning (provider tokens, entropy) lives
//! in the gitleaks pass, so this rule stays on human-chosen passwords and
//! leaves API keys to it.
//!
//! Placeholders (`changeme` is weak and fails, but `${VAR}`, `<your pass>`,
//! `xxx`, an env lookup) and tests and fixtures are skipped.

use super::{Context, Suspect, line_at, push, test_path};

pub(super) const ID: &str = "SUSPECT-WEAK-PASSWORD";

/// The bundled known-weak list.
const WEAK: &str = include_str!("../../assets/defaults/weak-passwords.txt");
/// Identifier tails that name a password.
const KEYS: &[&str] = &["password", "passwd", "passphrase", "pwd", "secret"];

fn reads(ctx: Context) -> bool {
    matches!(ctx, Context::Data | Context::Web | Context::Python | Context::Shell | Context::Manifest)
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, out: &mut Vec<Suspect>) {
    if !reads(ctx) || test_path(file) {
        return;
    }
    let mut offset = 0;
    for line in text.lines() {
        let line_start = offset;
        offset += line.len() + 1;
        let Some((key, value, quoted)) = assignment(line) else { continue };
        if value.is_empty() {
            continue;
        }
        if is_weak(&value) {
            push(out, file, ID, line_at(text, line_start), format!("`{key}` is assigned a known-weak password"), true);
            return;
        }
        if quoted && !placeholder(&value) {
            push(
                out,
                file,
                ID,
                line_at(text, line_start),
                format!("`{key}` holds a hardcoded password literal in source"),
                false,
            );
            return;
        }
    }
}

fn is_weak(value: &str) -> bool {
    WEAK.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).any(|w| w.eq_ignore_ascii_case(value))
}

/// A value that stands in for a real password rather than being one.
fn placeholder(value: &str) -> bool {
    let v = value.trim();
    let lower = v.to_ascii_lowercase();
    v.starts_with("${")
        || v.starts_with("$(")
        || v.starts_with('<')
        || v.ends_with('>')
        || v.contains("{{")
        || lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv")
        || lower.contains("secrets.")
        || [
            "xxx",
            "xxxx",
            "yourpassword",
            "your_password",
            "example",
            "placeholder",
            "todo",
            "redacted",
            "none",
            "null",
        ]
        .contains(&lower.as_str())
        || v.len() > 64
}

/// A `key = value` or `key: value` on one line: the key as written, the
/// value, and whether it was a quoted literal.
fn assignment(line: &str) -> Option<(String, String, bool)> {
    let lower = line.to_ascii_lowercase();
    for key in KEYS {
        let mut from = 0;
        while let Some(i) = lower[from..].find(key) {
            let at = from + i;
            let before_ok = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphabetic();
            let after = line[at + key.len()..].trim_start();
            if before_ok && let Some(rest) = split_operator(after) {
                let ident: String = line[..at + key.len()]
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let (value, quoted) = read_value(rest);
                if !value.is_empty() {
                    return Some((ident, value, quoted));
                }
            }
            from = at + key.len();
        }
    }
    None
}

/// The text after an assignment operator (`=`, `:`, `:=`, `=>`), or `None`
/// when what follows isn't one (a comparison `==`, no operator).
fn split_operator(after: &str) -> Option<&str> {
    let a = after.trim_start();
    if let Some(r) = a.strip_prefix(":=").or_else(|| a.strip_prefix("=>")) {
        return Some(r);
    }
    if let Some(r) = a.strip_prefix('=') {
        return if r.starts_with('=') { None } else { Some(r) };
    }
    a.strip_prefix(':')
}

/// The value: a quoted literal's contents, or the first bare token.
fn read_value(rest: &str) -> (String, bool) {
    let r = rest.trim_start();
    let mut chars = r.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => {
            let body: String = chars.take_while(|&c| c != q).collect();
            (body, true)
        }
        _ => {
            let token: String = r.chars().take_while(|c| !c.is_whitespace() && !matches!(c, ';' | ',' | '#')).collect();
            (token, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Kind, ids, scan_text};
    use super::*;

    #[test]
    fn a_known_weak_password_fails() {
        let got = scan_text("config/app.env", "DB_PASSWORD=letmein\n", Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", true)], "{got:?}");
        assert!(got[0].note.contains("known-weak password"), "{}", got[0].note);
        assert_eq!(
            ids(&scan_text("conf/db.yaml", "password: changeme\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", true)],
            "an unquoted weak value in yaml fails"
        );
        assert_eq!(
            ids(&scan_text("src/db.py", "admin_password = \"123456\"\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", true)]
        );
    }

    #[test]
    fn a_hardcoded_literal_warns_and_placeholders_are_skipped() {
        let got = scan_text("src/config.js", "const pwd = \"s3rvice-Acct!\";\n", Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", false)], "a non-weak literal warns: {got:?}");
        assert!(got[0].note.contains("hardcoded password literal"), "{}", got[0].note);
        assert!(scan_text("src/a.py", "password = os.environ['PW']\n", Kind::Repo).is_empty(), "an env lookup");
        assert!(scan_text("app.yaml", "password: ${DB_PASS}\n", Kind::Repo).is_empty(), "a variable");
        assert!(scan_text("tpl.yaml", "password: \"<your password>\"\n", Kind::Repo).is_empty(), "a placeholder");
        assert!(scan_text("ci.yml", "password: ${{ secrets.DEPLOY }}\n", Kind::Repo).is_empty(), "a CI secret ref");
        assert!(
            scan_text("src/config.js", "const dbPassword = process.env.DB_PASS;\n", Kind::Repo).is_empty(),
            "an unquoted env read does not warn"
        );
    }

    #[test]
    fn tests_native_and_comparisons_are_left_alone() {
        assert!(
            scan_text("tests/data/seed.env", "PASSWORD=letmein\n", Kind::Repo).is_empty(),
            "a test path is skipped"
        );
        assert!(scan_text("src/main.rs", "let password = \"letmein\";\n", Kind::Repo).is_empty(), "native is not read");
        assert!(
            scan_text("src/check.py", "if password == user_input:\n", Kind::Repo).is_empty(),
            "a comparison is not an assignment"
        );
        assert_eq!(assignment("PASSWORD=hunter2").map(|(_, v, q)| (v, q)), Some(("hunter2".into(), false)));
        assert_eq!(assignment("  secret: \"abc\"").map(|(_, v, q)| (v, q)), Some(("abc".into(), true)));
        assert_eq!(assignment("keyboard = 3"), None, "the key must be a password word");
        assert!(placeholder("${X}") && placeholder("xxx") && !placeholder("hunter2"));
    }
}
