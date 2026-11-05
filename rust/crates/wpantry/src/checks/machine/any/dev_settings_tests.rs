use super::*;
use crate::remediation::editors::set_extension_cooldown;

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
fn git_hooks_outcomes() {
    let d = crate::utils::temp::TempDir::new("hooks").unwrap();
    std::fs::write(d.path().join("pre-commit"), "#!/bin/sh\n").unwrap();
    let dir = d.path().to_string_lossy().into_owned();
    let with = move |argv: &[&str]| if argv.contains(&"core.hooksPath") { format!("{dir}\n") } else { String::new() };
    assert_eq!(git_hooks(&with).status, crate::checks::machine::settings::Status::Pass);
    let none = |_: &[&str]| String::new();
    assert_eq!(git_hooks(&none).status, crate::checks::machine::settings::Status::Fail);
    let tmpl = |argv: &[&str]| {
        if argv.contains(&"init.templateDir") { "~/.git-template\n".to_string() } else { String::new() }
    };
    assert_eq!(git_hooks(&tmpl).status, crate::checks::machine::settings::Status::Manual);
}

/// Where an editor's `User` directory sits under a test home, on this
/// OS; None where the test can't place one (Windows, or a Linux with
/// XDG_CONFIG_HOME pointing elsewhere).
fn user_dir(dir: &str) -> Option<PathBuf> {
    let home = crate::utils::files::home();
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support").join(dir).join("User"))
    } else if cfg!(target_os = "windows") || std::env::var_os("XDG_CONFIG_HOME").is_some_and(|v| !v.is_empty()) {
        None
    } else {
        Some(home.join(".config").join(dir).join("User"))
    }
}

#[test]
fn extension_cooldown_across_the_installed_editors() {
    let home = crate::utils::files::test_home();
    assert!(editor_settings().is_empty());
    let o = extension_cooldown(&|_: &[&str]| String::new());
    assert_eq!(
        (o.status, o.evidence.as_str()),
        (crate::checks::machine::settings::Status::Pass, "no VS Code-family editor installed")
    );
    let Some(code) = user_dir("Code") else { return };
    let settings = |dir: &str, text: Option<&str>| {
        let user = user_dir(dir).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        if let Some(t) = text {
            std::fs::write(user.join("settings.json"), t).unwrap();
        }
    };
    settings("Code", Some("{\n  \"extensions.installCooldownHours\": 72\n}\n"));
    let found = editor_settings();
    assert_eq!(found, vec![("VS Code", code.join("settings.json"))]);
    let probe = |_: &[&str]| String::new();
    let o = extension_cooldown(&probe);
    assert_eq!(
        (o.status.clone(), o.evidence.as_str()),
        (crate::checks::machine::settings::Status::Pass, "extension updates wait before installing: VS Code 72h")
    );
    settings("Cursor", Some("{\"extensions.autoUpdate\": false}"));
    let o = extension_cooldown(&probe);
    assert_eq!(o.status, crate::checks::machine::settings::Status::Manual);
    assert!(o.evidence.starts_with("Cursor (updates by hand, no cooldown); set a cooldown too"), "{}", o.evidence);
    settings("Windsurf", Some("{\"extensions.installCooldownHours\": 1}"));
    settings("VSCodium", None);
    let o = extension_cooldown(&probe);
    assert_eq!(o.status, crate::checks::machine::settings::Status::Fail);
    assert_eq!(
        o.evidence,
        "Windsurf 1h, VSCodium (no cooldown: new versions install at once); Cursor (updates by hand, no cooldown)"
    );
    // The fix: every editor gets the cooldown, the rest of its settings kept.
    let changed = set_extension_cooldown(72).unwrap();
    assert_eq!(changed.len(), 3, "{changed:?}");
    assert!(changed.iter().all(|c| c.contains(": 72 (")), "{changed:?}");
    assert!(changed.iter().any(|c| c.starts_with("Cursor: ")), "{changed:?}");
    let cursor = std::fs::read_to_string(user_dir("Cursor").unwrap().join("settings.json")).unwrap();
    assert!(cursor.contains("\"extensions.autoUpdate\": false"), "{cursor}");
    assert_eq!(extension_policy(&cursor).cooldown_hours, Some(72.0));
    let codium = std::fs::read_to_string(user_dir("VSCodium").unwrap().join("settings.json")).unwrap();
    assert_eq!(codium, "{\n    \"extensions.installCooldownHours\": 72\n}\n");
    assert!(set_extension_cooldown(72).unwrap().is_empty(), "nothing left to change");
    assert_eq!(
        extension_cooldown(&probe).status,
        crate::checks::machine::settings::Status::Pass,
        "a cooldown is what counts"
    );
    drop(home);
}

#[test]
fn git_hooks_under_home_and_without_a_pre_commit() {
    let home = crate::utils::files::test_home();
    let hooks = crate::utils::files::home().join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let tilde = |argv: &[&str]| if argv.contains(&"core.hooksPath") { "~/hooks\n".to_string() } else { String::new() };
    let o = git_hooks(&tilde);
    assert_eq!(o.status, crate::checks::machine::settings::Status::Fail);
    assert_eq!(o.evidence, "core.hooksPath is ~/hooks but it has no pre-commit hook");
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\n").unwrap();
    let o = git_hooks(&tilde);
    assert_eq!(
        (o.status, o.evidence.as_str()),
        (crate::checks::machine::settings::Status::Pass, "global hooks in ~/hooks (pre-commit present)")
    );
    assert!(CHECKS.iter().all(|c| c.id.starts_with("POSTURE-")));
    drop(home);
}
