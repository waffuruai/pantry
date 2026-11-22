//! The main suite, part one: the first-run screen, the schedule form, both
//! palettes, technical details and the first real scan.

use crate::harness::{Driver, Env};
use crate::oracles::{audit, audit_rejects_known_bad, shown_once_rejects_known_bad};
use serde_json::{Value, json};
use std::path::PathBuf;

/// What the main suite's parts share: the driver on the real scanner, its
/// environment, and the ids and paths later checks look up.
pub struct Main {
    pub driver: Driver,
    pub scanner: PathBuf,
    pub temp: PathBuf,
    pub env: Env,
    /// The stand-in launchctl's folder (macOS and Linux).
    pub tools: Option<PathBuf>,
    pub project: PathBuf,
    pub applied: PathBuf,
    pub patch: String,
    pub scan: i64,
    pub auto: Value,
    pub manual: Value,
    pub earlier: Value,
}

pub fn first_run(m: &mut Main) {
    audit_rejects_known_bad();
    shown_once_rejects_known_bad();
    let d = &mut m.driver;
    // First run: the welcome card and its one big button.
    let state = d.settled();
    assert!(
        state["report"].is_null() && state["report_error"].is_null(),
        "{state}"
    );
    assert_eq!(d.state()["mode"], "first_run");
    assert!(d.has_label("Welcome to Pantry"));
    assert_eq!(d.widget("scan.first")["role"], "Button");
    assert_eq!(d.widget("scan.run")["role"], "Button");
    if cfg!(target_os = "macos") {
        assert_eq!(d.widget("scan.personal")["role"], "CheckBox");
        assert_eq!(
            d.click("scan.personal")["state"]["include_personal_files"],
            json!(true)
        );
        let browser = d.click("scan.access")["browser"].clone();
        assert!(
            browser
                .as_str()
                .is_some_and(|b| b.starts_with("x-apple.systempreferences:")),
            "{browser}"
        );
        assert_eq!(
            d.click("scan.personal")["state"]["include_personal_files"],
            json!(false)
        );
    }
    audit(d, "first run");
    assert_eq!(d.widget("help.github")["role"], "Link");
    assert_eq!(d.label("help.support"), "support@waffuru.ai");
    assert_eq!(
        d.click("help.github")["browser"],
        "https://github.com/waffuruai/pantry"
    );
    assert_eq!(
        d.click("help.support")["browser"],
        "mailto:support@waffuru.ai"
    );
}

fn pick_week_at_0705(d: &mut Driver) -> Value {
    d.click("schedule.every");
    d.click("schedule.every.week");
    d.click("schedule.hour");
    d.click("schedule.hour.07");
    d.click("schedule.minute");
    d.click("schedule.minute.05")
}

pub fn schedule(m: &mut Main) {
    let d = &mut m.driver;
    // Schedule form with hour and minute dropdowns, without a real OS job.
    d.click("schedule.edit");
    audit(d, "schedule form");
    d.action("set_time", json!({"at": "25:90"}));
    let summary = d.click("schedule.save")["state"]["error"]["summary"].clone();
    assert!(
        summary
            .as_str()
            .is_some_and(|s| s.starts_with("Enter a time")),
        "{summary}"
    );
    let state = pick_week_at_0705(d)["state"].clone();
    assert!(
        state["period"] == "week" && state["at"] == "07:05",
        "{state}"
    );
    d.click("schedule.cancel");
    if !cfg!(windows) {
        d.click("schedule.edit");
        pick_week_at_0705(d);
        d.click("schedule.save");
        let configured = d.settled()["schedule"].clone();
        assert!(
            configured["installed"] == true
                && configured["enabled"] == true
                && configured["every"] == "week",
            "{configured}"
        );
        assert!(
            configured["at"] == "07:05"
                && configured["interval"]
                    .as_str()
                    .is_some_and(|i| i.contains("Mondays")),
            "{configured}"
        );
        d.click("schedule.edit");
        d.click("schedule.remove");
        assert_eq!(d.settled()["schedule"]["installed"], json!(false));
    }
    if cfg!(target_os = "macos") {
        // A removal whose bootout fails: the plist is gone but launchd still
        // holds the job. The sidebar must not say scans are off, and Remove
        // it tries again. Known-bad: "Scheduled scans are off".
        let bootout_fails = m
            .tools
            .as_ref()
            .expect("the stand-in launchctl")
            .join(".bootout-fails");
        d.click("schedule.edit");
        d.click("schedule.save");
        assert_eq!(d.settled()["schedule"]["installed"], json!(true));
        std::fs::write(&bootout_fails, "").expect("arm the failing bootout");
        d.click("schedule.edit");
        d.click("schedule.remove");
        let state = d.settled();
        assert!(!state["error"].is_null(), "a failed removal is reported");
        assert!(
            state["schedule"]["installed"] == false && state["schedule"]["loaded"] == true,
            "{}",
            state["schedule"]
        );
        d.action("dismiss_error", Value::Null);
        assert_eq!(
            d.label("schedule.state"),
            "A scheduled scan is still registered"
        );
        std::fs::remove_file(&bootout_fails).expect("disarm the failing bootout");
        d.click("schedule.remove_stray");
        let state = d.settled();
        assert!(
            state["schedule"]["loaded"] == false && state["error"].is_null(),
            "{} {}",
            state["schedule"],
            state["error"]
        );
        assert_eq!(d.label("schedule.state"), "Scheduled scans are off");
        assert!(!d.has_widget("schedule.remove_stray"));
    }
}

pub fn palettes_and_details(m: &mut Main) {
    let d = &mut m.driver;
    // Both palettes, through the real toggle and through set_theme.
    let reply = d.click("theme.toggle");
    assert!(
        reply["palette"] == "light" && reply["state"]["settings"]["light"] == true,
        "{reply}"
    );
    audit(d, "light palette");
    assert_eq!(d.click("theme.toggle")["palette"], "dark");
    assert!(
        d.action("set_theme", json!({"theme": "system"}))["state"]["settings"]["light"].is_null()
    );
    assert_eq!(
        d.action("set_theme", json!({"theme": "light"}))["palette"],
        "light"
    );
    assert_eq!(
        d.action("set_theme", json!({"theme": "dark"}))["palette"],
        "dark"
    );

    // Technical details on: Reload results lives there.
    assert_eq!(d.click("view.details")["state"]["details"], json!(true));
    assert_eq!(d.label("scan.refresh"), "Reload results");
}

pub fn first_scan(m: &mut Main) {
    m.project = m.temp.join("test project");
    std::fs::create_dir(&m.project).expect("create the project");
    let project = m.project.display().to_string();
    let d = &mut m.driver;
    let state = d.action("scan", json!({"path": project, "offline": true}));
    assert_eq!(state["busy"], "Scanning…");
    let state = d.settled();
    let scope = &state["report"]["scan"]["scope"];
    assert!(
        scope.as_str().is_some_and(|s| s.ends_with(&project)),
        "{}",
        state["report"]["scan"]
    );
    assert_eq!(d.state()["mode"], "has_report");
}
