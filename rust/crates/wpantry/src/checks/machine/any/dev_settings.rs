//! Developer-tool guardrails, the same on every OS: the editors' extension
//! update cooldown (a compromised extension version is pulled from the
//! marketplace within hours; a cooldown means it is never installed here)
//! and git hooks that run at commit time.

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, user};
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
    let home = crate::utils::files::home();
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
        let text = crate::utils::files::read_capped(file, 1 << 20).unwrap_or_default();
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

fn git_hooks(r: Runner) -> Outcome {
    let path = r(&["git", "config", "--global", "core.hooksPath"]);
    let path = path.trim();
    if !path.is_empty() {
        let dir = if let Some(rest) = path.strip_prefix("~/") {
            crate::utils::files::home().join(rest)
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

pub static CHECKS: &[Check] = &[
    Check {
        id: "POSTURE-EXTENSION-COOLDOWN",
        cis: "",
        title: "Editor extensions wait before installing new versions",
        severity: Severity::High,
        probe: extension_cooldown,
        fix: user("wpantry fix extension-cooldown"),
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
#[path = "dev_settings_tests.rs"]
mod tests;
