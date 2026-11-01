//! Developer-tool guardrails, the same on every OS: the editors' extension
//! update cooldown (a compromised extension version is pulled from the
//! marketplace within hours; a cooldown means it is never installed here)
//! and git hooks that run at commit time.

use super::{Check, Fix, Outcome, Runner, Severity};
use std::path::PathBuf;

/// The VS Code family: (name, settings dir under the per-OS user config
/// root). All of them read `extensions.installCooldownHours`.
pub const EDITORS: &[(&str, &str)] = &[
    ("VS Code", "Code"),
    ("VS Code Insiders", "Code - Insiders"),
    ("Cursor", "Cursor"),
    ("Windsurf", "Windsurf"),
    ("VSCodium", "VSCodium"),
    ("Positron", "Positron"),
];

/// The settings.json of every editor of the family installed here.
pub fn editor_settings() -> Vec<(&'static str, PathBuf)> {
    let home = crate::system::home();
    let roots: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![home.join("Library/Application Support")]
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from).into_iter().collect()
    } else {
        vec![
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config")),
        ]
    };
    let mut out = Vec::new();
    for (name, dir) in EDITORS {
        for root in &roots {
            let user = root.join(dir).join("User");
            if user.is_dir() {
                out.push((*name, user.join("settings.json")));
            }
        }
    }
    out
}

/// What a settings.json says about extension updates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExtensionPolicy {
    /// `extensions.installCooldownHours`, when set.
    pub cooldown_hours: Option<f64>,
    /// `extensions.autoUpdate`, when set (true, false, or a mode string).
    pub auto_update: Option<String>,
}

/// Read the two keys from a settings.json (JSON with comments and trailing
/// commas allowed), without a JSON parser: a missing file is a default policy.
pub fn extension_policy(text: &str) -> ExtensionPolicy {
    let mut out = ExtensionPolicy::default();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("//") {
            continue;
        }
        if let Some(v) = value_of(l, "extensions.installCooldownHours") {
            out.cooldown_hours = v.trim_matches('"').parse::<f64>().ok();
        }
        if let Some(v) = value_of(l, "extensions.autoUpdate") {
            out.auto_update = Some(v.trim_matches('"').to_string());
        }
    }
    out
}

/// `"key": value,` on one line → the value text.
fn value_of<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!("\"{key}\""))?;
    let rest = line[at + key.len() + 2..].trim_start().strip_prefix(':')?;
    let v = rest.split("//").next().unwrap_or(rest).trim();
    Some(v.trim_end_matches('}').trim().trim_end_matches(',').trim())
}

/// The cooldown this check wants, in hours (three days: a pulled version is
/// long gone by then).
pub const WANTED_COOLDOWN_HOURS: f64 = 72.0;

fn extension_cooldown(_: Runner) -> Outcome {
    let editors = editor_settings();
    if editors.is_empty() {
        return Outcome::pass("no VS Code-family editor installed");
    }
    let mut bad = Vec::new();
    let mut manual = Vec::new();
    let mut good = Vec::new();
    for (name, file) in &editors {
        let text = crate::system::read_capped(file, 1 << 20).unwrap_or_default();
        let p = extension_policy(&text);
        match p.cooldown_hours {
            Some(h) if h >= 24.0 => good.push(format!("{name} {h}h")),
            _ if p.auto_update.as_deref() == Some("false") => {
                manual.push(format!("{name} (updates by hand, no cooldown)"))
            }
            Some(h) => bad.push(format!("{name} {h}h")),
            None => bad.push(format!("{name} (no cooldown: new versions install at once)")),
        }
    }
    if bad.is_empty() && manual.is_empty() {
        Outcome::pass(format!("extension updates wait before installing: {}", good.join(", ")))
    } else if bad.is_empty() {
        // Manual updates already keep a compromised version from arriving on
        // its own; the cooldown still stops it being installed by hand.
        Outcome::manual(format!("{}; set a cooldown too", manual.join(", ")))
    } else {
        Outcome::fail(format!(
            "{}{}",
            bad.join(", "),
            if manual.is_empty() { String::new() } else { format!("; {}", manual.join(", ")) }
        ))
    }
}

/// Set `extensions.installCooldownHours` in every editor's settings.json
/// (the fix for [`extension_cooldown`]); returns what was changed. The key
/// is replaced where present and inserted after the opening brace
/// otherwise, so comments and formatting stay.
pub fn set_extension_cooldown(hours: u32) -> crate::error::Result<Vec<String>> {
    let mut changed = Vec::new();
    for (name, file) in editor_settings() {
        let text = if file.is_file() { crate::system::read_capped(&file, 1 << 20)? } else { String::new() };
        let new = with_cooldown(&text, hours);
        if new != text {
            if let Some(dir) = file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = file.with_extension("json.wpantry-tmp");
            std::fs::write(&tmp, &new)?;
            std::fs::rename(&tmp, &file)?;
            changed.push(format!("{name}: {} ({})", hours, file.display()));
        }
    }
    Ok(changed)
}

/// `text` with the cooldown set to `hours`.
pub fn with_cooldown(text: &str, hours: u32) -> String {
    let key = "\"extensions.installCooldownHours\"";
    if text.trim().is_empty() {
        return format!("{{\n    {key}: {hours}\n}}\n");
    }
    if let Some(at) = text.find(key) {
        // Replace the value on that line.
        let line_start = text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = text[at..].find('\n').map(|i| at + i).unwrap_or(text.len());
        let line = &text[line_start..line_end];
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let comma = if line.trim_end().ends_with(',') { "," } else { "" };
        return format!("{}{indent}{key}: {hours}{comma}{}", &text[..line_start], &text[line_end..]);
    }
    let Some(brace) = text.find('{') else { return format!("{{\n    {key}: {hours}\n}}\n") };
    let after = &text[brace + 1..];
    let empty = after.trim_start().starts_with('}');
    let indent = after
        .lines()
        .nth(1)
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "    ".into());
    format!(
        "{}{{\n{indent}{key}: {hours}{}{}",
        &text[..brace],
        if empty { "\n" } else { ",\n" },
        after.strip_prefix('\n').unwrap_or(after)
    )
}

fn git_hooks(r: Runner) -> Outcome {
    let path = r(&["git", "config", "--global", "core.hooksPath"]);
    let path = path.trim();
    if !path.is_empty() {
        let dir = if let Some(rest) = path.strip_prefix("~/") {
            crate::system::home().join(rest)
        } else {
            PathBuf::from(path)
        };
        let pre_commit = dir.join("pre-commit");
        return Outcome::of(
            pre_commit.is_file(),
            if pre_commit.is_file() {
                format!("global hooks in {path} (pre-commit present)")
            } else {
                format!("core.hooksPath is {path} but it has no pre-commit hook")
            },
        );
    }
    let template = r(&["git", "config", "--global", "init.templateDir"]);
    if !template.trim().is_empty() {
        return Outcome::manual(format!("hooks come from init.templateDir {} (new clones only)", template.trim()));
    }
    Outcome::fail("no global git hooks: nothing checks a commit for secrets before it leaves")
}

const fn user(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: false })
}

pub static CHECKS: &[Check] = &[
    Check {
        id: "POSTURE-EXTENSION-COOLDOWN",
        cis: "",
        title: "Editor extensions wait before installing new versions",
        severity: Severity::High,
        probe: extension_cooldown,
        fix: user("wpantry harden extension-cooldown --hours 72"),
        explain: "A compromised extension version is pulled from the marketplace within hours; a 72-hour cooldown (extensions.installCooldownHours) means it never lands here",
    },
    Check {
        id: "POSTURE-GIT-HOOKS",
        cis: "",
        title: "Git hooks check commits before they leave",
        severity: Severity::Low,
        probe: git_hooks,
        fix: None,
        explain: "A global core.hooksPath with a pre-commit hook (gitleaks on the staged changes) stops a secret at the commit, not after the push",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_policy_reads_jsonc() {
        let p = extension_policy(
            "{\n  // comment\n  \"editor.fontSize\": 14,\n  \"extensions.autoUpdate\": false,\n  \"extensions.installCooldownHours\": 72, // three days\n}\n",
        );
        assert_eq!(p, ExtensionPolicy { cooldown_hours: Some(72.0), auto_update: Some("false".into()) });
        assert_eq!(extension_policy("{}"), ExtensionPolicy::default());
        assert_eq!(
            extension_policy("{\"extensions.autoUpdate\": \"onlyEnabledExtensions\"}").auto_update.as_deref(),
            Some("onlyEnabledExtensions")
        );
    }

    #[test]
    fn cooldown_is_inserted_or_replaced_keeping_the_rest() {
        assert_eq!(with_cooldown("", 72), "{\n    \"extensions.installCooldownHours\": 72\n}\n");
        assert_eq!(with_cooldown("{}\n", 72), "{\n    \"extensions.installCooldownHours\": 72\n}\n");
        let before = "{\n  // mine\n  \"editor.fontSize\": 14,\n  \"extensions.autoUpdate\": false\n}\n";
        let after = with_cooldown(before, 72);
        assert_eq!(
            after,
            "{\n  \"extensions.installCooldownHours\": 72,\n  // mine\n  \"editor.fontSize\": 14,\n  \"extensions.autoUpdate\": false\n}\n"
        );
        assert_eq!(extension_policy(&after).cooldown_hours, Some(72.0));
        let zero = "{\n  \"extensions.installCooldownHours\": 0,\n  \"a\": 1\n}\n";
        assert_eq!(with_cooldown(zero, 336), "{\n  \"extensions.installCooldownHours\": 336,\n  \"a\": 1\n}\n");
        let last = "{\n  \"a\": 1,\n  \"extensions.installCooldownHours\": 0\n}\n";
        assert_eq!(with_cooldown(last, 72), "{\n  \"a\": 1,\n  \"extensions.installCooldownHours\": 72\n}\n");
    }

    #[test]
    fn git_hooks_outcomes() {
        let d = crate::system::TempDir::new("hooks").unwrap();
        std::fs::write(d.path().join("pre-commit"), "#!/bin/sh\n").unwrap();
        let dir = d.path().to_string_lossy().into_owned();
        let with =
            move |argv: &[&str]| if argv.contains(&"core.hooksPath") { format!("{dir}\n") } else { String::new() };
        assert_eq!(git_hooks(&with).status, super::super::Status::Pass);
        let none = |_: &[&str]| String::new();
        assert_eq!(git_hooks(&none).status, super::super::Status::Fail);
        let tmpl = |argv: &[&str]| {
            if argv.contains(&"init.templateDir") { "~/.git-template\n".to_string() } else { String::new() }
        };
        assert_eq!(git_hooks(&tmpl).status, super::super::Status::Manual);
    }
}
