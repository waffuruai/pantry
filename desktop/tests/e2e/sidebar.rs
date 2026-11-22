//! The main suite, part four: the update notice, the fullest sidebar at the
//! minimum window, every remaining dispatcher action, and the scanner's own
//! schedule plan.

use crate::db;
use crate::first_run::Main;
use crate::oracles::{audit, sidebar_reachable};
use serde_json::{Value, json};
use std::process::Command;

/// The release target this machine's download is built for.
fn target() -> String {
    if cfg!(target_os = "macos") {
        "universal-apple-darwin".into()
    } else if cfg!(windows) {
        "x86_64-pc-windows-msvc".into()
    } else {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        format!("{arch}-unknown-linux-gnu")
    }
}

fn set_latest(db_path: &std::path::Path, assets: &[&str]) {
    let result = json!({"version": "99.1.2", "assets": assets}).to_string();
    db::with_db(db_path, |tx| {
        tx.execute(
            "INSERT OR REPLACE INTO runs VALUES ('github-latest:waffuruai/pantry', '', ?, ?)",
            rusqlite::params![db::now(), result],
        )
    });
}

pub fn updates(m: &mut Main) {
    let db_path = m.env.path("WPANTRY_DB");
    let d = &mut m.driver;
    // An update must use the matching package and signer's workflow at the tag.
    let target = target();
    let asset = format!("wpantry-desktop-{target}.zip");
    set_latest(&db_path, &[&asset]);
    assert_eq!(d.state()["state"]["details"], json!(true));
    d.click("updates.check");
    assert_eq!(d.settled()["update"]["latest"], "99.1.2");
    let copied = d.click("updates.copy")["clipboard"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        copied.contains(&asset)
            && copied.contains("refs/tags/v99.1.2")
            && copied.contains(".github/workflows/release.yml"),
        "{copied}"
    );
    let browser = d.click("updates.open")["browser"].clone();
    assert!(
        browser
            .as_str()
            .is_some_and(|b| b.ends_with(&format!("/v99.1.2/{asset}"))),
        "{browser}"
    );

    let installer_ext = if cfg!(target_os = "macos") {
        "zip"
    } else if cfg!(windows) {
        "exe"
    } else {
        "tar.gz"
    };
    let installer = format!("wpantry-setup-{target}.{installer_ext}");
    set_latest(&db_path, &[&asset, &installer]);
    d.click("updates.check");
    d.settled();
    let browser = d.click("updates.open")["browser"].clone();
    assert!(
        browser
            .as_str()
            .is_some_and(|b| b.ends_with(&format!("/v99.1.2/{installer}"))),
        "{browser}"
    );

    // Nonmatching assets must never result in a generic download link.
    set_latest(&db_path, &[]);
    d.click("updates.check");
    d.settled();
    d.click_refused("updates.open");
    audit(d, "updates");
}

pub fn minimum_sidebar(m: &mut Main) {
    let d = &mut m.driver;
    // The fullest sidebar (schedule form, update notice, technical details)
    // at the 820 x 480 minimum: every control can be scrolled into view and
    // the help links stay pinned below it.
    d.action("edit_schedule", json!({"open": true}));
    d.resize(820, 480);
    let controls = sidebar_reachable(d, "minimum window sidebar");
    assert!(
        controls.iter().any(|c| c == "scan.refresh")
            && controls.iter().any(|c| c == "schedule.save"),
        "{controls:?}"
    );
    d.resize(1080, 740);
    d.action("edit_schedule", json!({"open": false}));
}

pub fn dispatcher(m: &mut Main) {
    let d = &mut m.driver;
    // Every remaining action through the typed dispatcher.
    assert_eq!(
        d.action("show", json!({"page": "results"}))["state"]["page"],
        "results"
    );
    assert_eq!(
        d.action("search", json!({"text": "zzz"}))["state"]["search"],
        "zzz"
    );
    assert_eq!(
        d.action("set_filter", json!({"filter": "fixable"}))["state"]["filter"],
        "fixable"
    );
    d.action("set_filter", json!({"filter": "all"}));
    d.action("show", json!({"page": "attention"}));
    assert_eq!(
        d.action("show_lower_priority", json!({"open": true}))["state"]["show_lower"],
        json!(true)
    );
    assert_eq!(
        d.action("set_details", json!({"on": false}))["state"]["details"],
        json!(false)
    );
    assert_eq!(
        d.action("set_light", json!({"light": true}))["palette"],
        "light"
    );
    assert_eq!(
        d.action("open_download", Value::Null)["browser"],
        "https://github.com/waffuruai/pantry/releases/latest"
    );
    assert_eq!(
        d.action("open_github", Value::Null)["browser"],
        "https://github.com/waffuruai/pantry"
    );
    assert_eq!(
        d.action("open_support", Value::Null)["browser"],
        "mailto:support@waffuru.ai"
    );
    let access = d.action("open_scan_access", Value::Null)["browser"].clone();
    assert!(
        access
            .as_str()
            .is_some_and(|b| b.starts_with("x-apple.systempreferences:")),
        "{access}"
    );
    assert_eq!(
        d.action("set_personal_files", json!({"include": true}))["state"]["include_personal_files"],
        json!(true)
    );
    d.action("set_personal_files", json!({"include": false}));
    d.action("edit_schedule", json!({"open": true}));
    assert_eq!(
        d.action("set_period", json!({"every": "month"}))["state"]["period"],
        "month"
    );
    d.action("edit_schedule", json!({"open": false}));
    for refused in ["cancel", "confirm_fix", "confirm_fix_all", "fix_it"] {
        d.action_refused(refused, Value::Null);
    }
    for action in [
        "cancel_fix",
        "cancel_fix_all",
        "dismiss_fix_all",
        "dismiss_error",
        "dismiss_fix_result",
        "toggle_error_details",
        "toggle_fix_details",
        "close_finding",
        "refresh",
    ] {
        d.action(action, Value::Null);
        d.settled();
    }
    let watch = d.action("copy_watch_command", Value::Null)["clipboard"].clone();
    assert!(
        watch.as_str().is_some_and(|c| c.ends_with(" watch")),
        "{watch}"
    );
}

pub fn schedule_plan(m: &mut Main) {
    let mut command = Command::new(&m.scanner);
    command.args([
        "schedule",
        "install",
        "--every",
        "quarter",
        "--at",
        "08:25",
        "--dry-run",
    ]);
    m.env.apply(&mut command);
    let output = command.output().expect("run the scanner");
    assert!(output.status.success(), "{output:?}");
    let plan = String::from_utf8_lossy(&output.stdout);
    assert!(
        plan.contains("08:25") || plan.contains("<integer>25</integer>") || plan.contains("25 8 "),
        "{plan}"
    );
}
