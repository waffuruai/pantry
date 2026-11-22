//! What a fix and Fix all report when the `outcome` stand-in misbehaves
//! (macOS and Linux). Part one: scanner text, the earlier scans group, the
//! busy guard, cancelled reloads, and still-open, failed and unconfirmed
//! fixes. Part two is outcomes_more.rs.
//!
//! Oracle for each check: the stand-in's own state. A finding it still lists
//! after the fix is "still open"; a fix that failed keeps what the scanner
//! said; a reload that failed after a fix can't confirm anything; a
//! cancelled job leaves the results usable; earlier scopes never count in
//! the headline.

use crate::fixes::statuses;
use crate::harness::{Ctx, Driver, Env, pid_alive, read_json, read_pid, standin, wait_until};
use crate::oracles::{audit, shown_once};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub struct Outcome {
    pub d: Driver,
    pub env: Env,
    pub main: PathBuf,
    pub other: PathBuf,
    pub gone: PathBuf,
    pub profile: PathBuf,
    knobs_file: PathBuf,
    state_file: PathBuf,
}

impl Outcome {
    pub fn new(app: &Path, ctx: &Ctx) -> Outcome {
        let base = ctx.temp.join("outcomes");
        let (main, other, gone) = (base.join("main"), base.join("other"), base.join("gone"));
        std::fs::create_dir_all(&main).expect("create the main folder");
        std::fs::create_dir(&other).expect("create the other folder");
        let (knobs_file, state_file, profile) = (
            base.join("knobs.json"),
            base.join("state.json"),
            base.join("profile"),
        );
        let env = ctx.env.with(&[
            ("PANTRY_FAKE_MODE", "outcome".as_ref()),
            ("PANTRY_FAKE_STATE", state_file.as_os_str()),
            ("PANTRY_FAKE_KNOBS", knobs_file.as_os_str()),
            ("PANTRY_FAKE_MAIN", main.as_os_str()),
            ("PANTRY_FAKE_OTHER", other.as_os_str()),
            ("PANTRY_FAKE_GONE", gone.as_os_str()),
            ("PANTRY_FAKE_VERSION", env!("CARGO_PKG_VERSION").as_ref()),
            ("WPANTRY_DESKTOP_HOME", profile.as_os_str()),
        ]);
        let outcome = Outcome {
            d: Driver::start(app, Some(&standin()), &env),
            env,
            main,
            other,
            gone,
            profile,
            knobs_file,
            state_file,
        };
        outcome.knobs(json!({}));
        outcome
    }

    /// Close this app (it must exit 0), set `knobs`, and start the app
    /// again on the same stand-in, profile and cache.
    pub fn reopen(self, app: &Path, knobs: Value) -> Outcome {
        let Outcome {
            d,
            env,
            main,
            other,
            gone,
            profile,
            knobs_file,
            state_file,
        } = self;
        d.close();
        std::fs::write(&knobs_file, knobs.to_string()).expect("write the knobs");
        let d = Driver::start(app, Some(&standin()), &env);
        Outcome {
            d,
            env,
            main,
            other,
            gone,
            profile,
            knobs_file,
            state_file,
        }
    }

    pub fn knobs(&self, values: Value) {
        std::fs::write(&self.knobs_file, values.to_string()).expect("write the knobs");
    }

    pub fn log(&self) -> Vec<Value> {
        read_json(&self.state_file)["log"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// How many calls of the scanner subcommand `name` the stand-in saw.
    pub fn calls(&self, name: &str) -> usize {
        self.log().iter().filter(|a| a[0] == name).count()
    }

    /// The pid of the stand-in that is sleeping now.
    pub fn wait_pid(&self) -> u32 {
        let pid_file = PathBuf::from(format!("{}.pid", self.state_file.display()));
        wait_until("the stand-in never started", || pid_file.exists());
        let pid = read_pid(&pid_file);
        std::fs::remove_file(&pid_file).expect("clear the pid file");
        pid
    }

    pub fn scan_main(&mut self) -> Value {
        self.d.action(
            "scan",
            json!({"path": self.main.display().to_string(), "offline": true}),
        );
        self.d.settled()
    }

    /// Select `id`, preview its fix, confirm, and return the state after.
    pub fn fix(&mut self, id: &str) -> Value {
        self.d.action("select", json!({"id": id}));
        self.d.click("fix.preview");
        self.d.settled();
        self.d.click("fix.confirm");
        self.d.settled()
    }

    /// Open Fix all, confirm, and return the batch after.
    pub fn fix_all(&mut self) -> Value {
        self.d.click("fix.all");
        self.d.settled();
        self.d.click("fix.all.confirm");
        self.d.settled()["batch"].clone()
    }
}

pub fn scanner_text_and_earlier(o: &mut Outcome) {
    o.d.settled();
    let state = o.scan_main();
    let d = &mut o.d;
    // Scanner text is shown without control or bidi characters.
    let names: Vec<&Value> = state["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| &f["component"])
        .collect();
    assert_eq!(names, [&json!("alpha"), &json!("bravognp.exe[31m")]);
    assert!(
        !d.labels()
            .iter()
            .any(|l| l.contains('\u{202e}') || l.contains('\u{1b}'))
    );

    // The headline counts only the latest scan.
    assert_eq!(d.state()["headline_count"], json!(2));
    assert!(
        d.has_label("2 things need your attention"),
        "{:?}",
        d.labels()
    );
    let earlier = d.state()["earlier"].clone();
    let ids: Vec<&Value> = earlier
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert!(
        ids.len() == 2 && ids.contains(&&json!("e1")) && ids.contains(&&json!("e2")),
        "{earlier}"
    );
    let e2 = earlier
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "e2")
        .unwrap();
    assert_eq!(
        e2["missing_folders"],
        json!([o.gone.display().to_string()]),
        "{earlier}"
    );
    // A folder that is gone says so and offers only Dismiss.
    assert!(
        d.label("earlier.e2.missing")
            .starts_with("That folder is no longer there.")
    );
    assert!(!d.has_widget("earlier.e2.rescan"));
    let refused = d.action_refused("rescan_earlier", json!({"id": "e2"}));
    assert!(
        refused
            .as_str()
            .is_some_and(|r| r.contains("no longer there")),
        "{refused}"
    );
    audit(d, "from earlier scans");
    // Dismiss hides it, is saved, and Latest scan shows it again.
    d.click("earlier.e2.dismiss");
    assert!(!d.has_widget("earlier.e2"));
    let settings = read_json(&o.profile.join("state").join("settings.json"));
    assert_eq!(settings["dismissed"], json!(["e2"]), "{settings}");
    let exposures = d.state()["state"]["report"]["history"]["exposures"].clone();
    assert!(
        exposures
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == "e2")
    );
    d.click("nav.results");
    assert_eq!(
        d.label("earlier.dismissed"),
        "Dismissed from earlier scans (1)"
    );
    d.click("earlier.e2.restore");
    d.click("nav.attention");
    assert!(d.label("earlier.e2").starts_with("gone-tool"));
    // Scan that folder again: a scan of exactly that path.
    d.click("earlier.e1.rescan");
    d.settled();
    let log = o.log();
    let other = o.other.display().to_string();
    assert_eq!(
        log[log.len() - 2],
        json!([
            "scan",
            "--json",
            "--no-input",
            "--no-machine",
            "--path",
            other,
            "--offline"
        ])
    );
    assert!(
        !o.d.state()["earlier"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == "e1")
    );
    o.scan_main();
}

pub fn busy_guard_and_cancelled_reload(o: &mut Outcome) {
    // Busy guard: one job at a time, and a row's Fix it is disabled (not
    // just unclickable) while a scan runs.
    o.knobs(json!({"scan_sleep": true}));
    let main = o.main.display().to_string();
    o.d.action("scan", json!({"path": main, "offline": true}));
    let pid = o.wait_pid();
    let refused =
        o.d.action_refused("scan", json!({"path": main, "offline": true}));
    assert_eq!(refused, "Wait for Pantry to finish the current task.");
    assert_eq!(o.d.widget("finding.f1.fix")["enabled"], json!(false));
    // Cancel keeps the results usable.
    o.d.click("task.cancel");
    let state = o.d.settled();
    assert!(!pid_alive(pid));
    assert!(
        state["error"]["kind"] == "cancelled" && state["report_error"].is_null(),
        "{state}"
    );
    assert!(!state["report"].is_null());
    o.d.click("error.dismiss");
    assert!(o.d.state()["banner"].is_null());
    // A reload that is itself cancelled keeps the results it had.
    o.knobs(json!({"report_sleep": true}));
    o.d.action("refresh", Value::Null);
    o.wait_pid();
    o.d.action("cancel", Value::Null);
    let state = o.d.settled();
    assert!(
        state["report_error"].is_null() && !state["report"].is_null(),
        "{}",
        state["report_error"]
    );
    o.knobs(json!({}));
    o.d.action("select", json!({"id": "f1"}));
    o.d.click("fix.preview");
    assert_eq!(o.d.settled()["pending_fix"]["id"], "f1");

    // A newer scan clears a pending fix and a Fix all confirm.
    assert!(o.scan_main()["pending_fix"].is_null());
    o.d.click("fix.all");
    assert_eq!(o.d.settled()["batch"]["stage"], "confirm");
    assert!(o.scan_main()["batch"].is_null());
    // Esc closes the Fix all confirm.
    o.d.click("fix.all");
    o.d.settled();
    assert!(o.d.key("Escape", false)["state"]["batch"].is_null());
    // The exact commands are one click away in the confirm.
    o.d.click("fix.all");
    o.d.settled();
    o.d.click("fix.all.commands");
    assert_eq!(
        o.d.label("fix.all.item.f1.command"),
        "npm install alpha@2.0"
    );
    o.d.click("fix.all.cancel");
    o.d.action("toggle_fix_details", Value::Null);
}

pub fn still_open_gap_and_failed(o: &mut Outcome) {
    // Still open: the fix exits 0 but the scanner still lists it.
    o.knobs(json!({"sticky": true}));
    let state = o.fix("f1");
    assert_eq!(
        state["fix_result"]["outcome"], "still_open",
        "{}",
        state["fix_result"]
    );
    assert!(o.d.label("fix.result").starts_with("Still open."));
    shown_once(&mut o.d, state["fix_result"]["message"].as_str().unwrap());
    o.d.click("fix.result.dismiss");
    o.d.action("close_finding", Value::Null);
    let batch = o.fix_all();
    assert_eq!(statuses(&batch), ["still_open", "still_open"], "{batch}");
    assert_eq!(batch["message"], "0 of 2 fixed and checked.", "{batch}");
    assert_eq!(o.d.label("fix.all.item.f1"), "Still open");
    o.d.click("fix.all.dismiss");

    // A real gap: nothing may read as Fixed.
    o.knobs(json!({"gap": true}));
    o.scan_main();
    let batch = o.fix_all();
    assert!(
        statuses(&batch).iter().all(|s| s == "unconfirmed"),
        "{batch}"
    );
    for item in batch["items"].as_array().unwrap() {
        let id = item["id"].as_str().unwrap();
        assert_ne!(o.d.label(&format!("fix.all.item.{id}")), "Fixed");
    }
    o.d.click("fix.all.dismiss");

    // A failed item keeps what the scanner said.
    o.knobs(json!({"sticky": true, "fix_fail": ["f2"], "fresh": true}));
    o.scan_main();
    let batch = o.fix_all();
    let failed = batch["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "f2")
        .unwrap();
    assert!(
        failed["status"] == "failed"
            && failed["details"]
                .as_str()
                .is_some_and(|d| d.contains("E404")),
        "{failed}"
    );
    o.d.click("fix.all.item.f2.details");
    assert!(
        o.d.label("fix.all.item.f2.raw")
            .contains("npm ERR! code E404")
    );
    o.d.click("fix.all.dismiss");

    // The reload after a fix fails: never "Still open".
    o.knobs(json!({"sticky": true, "report_fails": true}));
    let state = o.fix("f1");
    assert_eq!(
        state["fix_result"]["outcome"], "unconfirmed",
        "{}",
        state["fix_result"]
    );
    assert_eq!(
        state["fix_result"]["message"], "Could not confirm. Scan again.",
        "{}",
        state["fix_result"]
    );
    o.d.click("fix.result.dismiss");
    o.d.action("close_finding", Value::Null);
    o.d.action("dismiss_error", Value::Null);
    assert!(o.d.state()["state"]["report_error"].is_null());
    let batch = o.fix_all();
    let messages: Vec<&Value> = batch["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["message"])
        .collect();
    assert_eq!(
        messages,
        [&json!("Could not confirm. Scan again."); 2],
        "{batch}"
    );
    assert!(
        !statuses(&batch).iter().any(|s| s == "still_open"),
        "{batch}"
    );
    o.d.click("fix.all.dismiss");
    o.d.action("dismiss_error", Value::Null);
}

pub fn cancelled_fix(o: &mut Outcome) {
    // A cancelled fix may have partly run, and offers Scan now.
    o.knobs(json!({"fix_sleep": ["f1"], "fresh": true}));
    o.scan_main();
    o.d.action("select", json!({"id": "f1"}));
    o.d.click("fix.preview");
    o.d.settled();
    o.d.click("fix.confirm");
    let pid = o.wait_pid();
    o.d.click("task.cancel");
    let state = o.d.settled();
    assert!(!pid_alive(pid));
    assert_eq!(state["error"]["kind"], "fix_stopped", "{}", state["error"]);
    // The results are read again after the cancelled fix.
    assert_eq!(o.log().last().unwrap(), &json!(["report", "all", "--json"]));
    let summary = state["error"]["summary"].as_str().unwrap_or("").to_string();
    assert!(
        summary.contains("may have partly run"),
        "{}",
        state["error"]
    );
    shown_once(&mut o.d, &summary);
    assert!(state["report_error"].is_null());
    o.knobs(json!({}));
    let before = o.calls("scan");
    o.d.click("error.scan");
    o.d.settled();
    assert_eq!(o.calls("scan"), before + 1);
}
