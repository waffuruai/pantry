//! Hardcoded passwords in source and config: a `password`, `passwd`, `pwd`
//! or `secret` assignment whose value is a known-weak password. The bundled
//! list is in two tiers. A shipped default or committed throwaway
//! (`changeme`, `admin`, `password`) fails, since it is almost never a real
//! secret. A common dictionary or pop-culture password (`monkey`, `dragon`,
//! `sunshine`) only warns: it is weak, but more likely a real bad password
//! than a default. Any other non-empty password literal also warns, since a
//! committed default is still a credential to rotate. This is the
//! source-level, non-git part of password hygiene; full secret scanning
//! (provider tokens, entropy) lives in the gitleaks pass, so this rule
//! stays on human-chosen passwords and leaves API keys to it.
//!
//! Before matching, the value is normalized — trailing digits and symbols
//! dropped, common leet substitutions undone — so `Admin1` and `p@ssw0rd`
//! match too. Placeholders (`changeme` is a default and fails, but `${VAR}`,
//! `<your pass>`, `xxx`, an env lookup) and tests and fixtures are skipped.

use super::{Context, Suspect, line_at, push, test_path};

pub(super) const ID: &str = "SUSPECT-WEAK-PASSWORD";

/// The bundled known-weak list, in two tiers (see the file).
const LIST: &str = include_str!("../../../assets/defaults/weak-passwords.txt");
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
        match classify(&value) {
            Some(Tier::Fail) => {
                push(
                    out,
                    file,
                    ID,
                    line_at(text, line_start),
                    format!("`{key}` is assigned a known default or weak password"),
                    true,
                );
                return;
            }
            Some(Tier::Warn) => {
                push(
                    out,
                    file,
                    ID,
                    line_at(text, line_start),
                    format!("`{key}` is assigned a common, easily-guessed password"),
                    false,
                );
                return;
            }
            None => {
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
    }
}

/// Which tier a known-weak password falls in.
enum Tier {
    Fail,
    Warn,
}

/// Classify a value against the bundled list, matching it as written and in
/// a normalized form so simple mutations are caught. `# tier: warn` in the
/// list marks where the warn tier begins; entries before it fail.
fn classify(value: &str) -> Option<Tier> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    let norm = normalize(&raw);
    let mut warn = false;
    for line in LIST.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix('#') {
            if rest.trim().eq_ignore_ascii_case("tier: warn") {
                warn = true;
            }
            continue;
        }
        let entry = l.to_ascii_lowercase();
        if entry == raw || (!norm.is_empty() && entry == norm) {
            return Some(if warn { Tier::Warn } else { Tier::Fail });
        }
    }
    None
}

/// Fold a value toward its dictionary form: drop trailing digits and symbols
/// (an appended number or `!`), then undo common leet substitutions.
/// Interior digits read as letters (`adm1n` -> `admin`) while trailing ones
/// are suffixes (`monkey1` -> `monkey`), so the strip comes first.
fn normalize(v: &str) -> String {
    let stem = v.trim_end_matches(|c: char| !c.is_ascii_alphabetic());
    stem.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            '$' => 's',
            other => other,
        })
        .collect()
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
        assert!(got[0].note.contains("known default or weak"), "{}", got[0].note);
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

    #[test]
    fn dictionary_words_warn_and_defaults_fail() {
        // monkey/sunshine are common but not shipped defaults: warn, not fail.
        assert_eq!(
            ids(&scan_text("conf/app.yaml", "password: monkey\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", false)],
            "a common dictionary password warns, it does not fail"
        );
        let got = scan_text("conf/app.yaml", "password: sunshine\n", Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", false)]);
        assert!(got[0].note.contains("common, easily-guessed"), "{}", got[0].note);
        // changeme stays a hard fail: a shipped default, not a real secret.
        assert_eq!(
            ids(&scan_text("conf/app.yaml", "password: changeme\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", true)]
        );
    }

    #[test]
    fn normalization_catches_simple_mutations() {
        assert_eq!(
            ids(&scan_text("a.env", "ADMIN_PASSWORD=Admin1\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", true)],
            "a trailing digit does not hide a default"
        );
        assert_eq!(
            ids(&scan_text("a.env", "PASSWORD=p@ssw0rd\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", true)],
            "leet substitutions are undone"
        );
        assert_eq!(
            ids(&scan_text("a.yaml", "password: Monkey99!\n", Kind::Repo)),
            [("SUSPECT-WEAK-PASSWORD", false)],
            "a mutated dictionary word still warns"
        );
        assert_eq!(normalize("p@ssw0rd"), "password");
        assert_eq!(normalize("admin1"), "admin");
        assert_eq!(normalize("monkey99!"), "monkey");
        assert!(classify("Tr0ub4dour&3xplr").is_none(), "a strong password is not matched");
    }
}
