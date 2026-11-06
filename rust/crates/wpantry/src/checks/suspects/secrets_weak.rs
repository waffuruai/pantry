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

/// The bundled known-weak lists, `fail` and `warn` (see the file), lowercase.
static LISTS: std::sync::LazyLock<(Vec<String>, Vec<String>)> = std::sync::LazyLock::new(|| {
    let list = |k: &str| {
        crate::utils::toml::list(crate::defaults::WEAK_PASSWORDS, "", k)
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.trim().to_ascii_lowercase())
            .filter(|p| !p.is_empty())
            .collect()
    };
    (list("fail"), list("warn"))
});
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
/// a normalized form so simple mutations are caught: a `fail` entry
/// fails, a `warn` entry warns.
fn classify(value: &str) -> Option<Tier> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    let norm = normalize(&raw);
    let hit = |list: &[String]| list.iter().any(|e| *e == raw || (!norm.is_empty() && *e == norm));
    if hit(&LISTS.0) {
        Some(Tier::Fail)
    } else if hit(&LISTS.1) {
        Some(Tier::Warn)
    } else {
        None
    }
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
#[path = "secrets_weak_tests.rs"]
mod tests;
