//! Outcome checks, part two (part one and the stand-in's oracle are in
//! outcomes.rs): garbage output, an old update answer, refused fix previews,
//! Cancel during Fix all, offline scans, background reloads, refused fixes,
//! the attack list, Dismiss saved to settings.json, rows below the fold and
//! a scan the app's exit stops.

use crate::fixes::statuses;
use crate::harness::{pid_alive, read_json};
use crate::oracles::{bounds, inside};
use crate::outcomes::Outcome;
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

pub fn garbage_and_updates(o: &mut Outcome) {
    // Garbage from the scanner is "unexpected", never "Reinstall".
    o.knobs(json!({"scan_garbage": true}));
    o.scan_main();
    let banner = o.d.state()["banner"].clone();
    assert!(
        banner["summary"]
            .as_str()
            .is_some_and(|s| s.starts_with("Pantry's scanner returned something unexpected.")),
        "{banner}"
    );
    assert!(
        banner["details"]
            .as_str()
            .is_some_and(|s| s.contains("proxy error")),
        "{banner}"
    );
    assert!(!o.d.has_widget("error.download"));
    o.d.click("error.dismiss");

    // An old update answer says when Pantry last checked.
    o.knobs(json!({"update_stale": true}));
    o.d.click("updates.check");
    o.d.settled();
    assert!(
        o.d.label("updates.stale")
            .starts_with("Could not check for updates. Last checked ")
    );
    assert!(!o.d.has_label("You're up to date."));
    o.knobs(json!({}));
    o.d.click("updates.check");
    o.d.settled();
    assert!(o.d.has_label("You're up to date."));
    assert!(!o.d.has_widget("updates.stale"));
}

pub fn refused_previews(o: &mut Outcome) {
    let unverified = "Pantry could not verify the command for this fix.";
    let items = |batch: &Value, id: &str| {
        batch["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == id)
            .unwrap()
            .clone()
    };
    // A fix preview with a hidden character is refused as it was sent, not
    // cleaned and shown: one fix, and the same item in Fix all.
    o.knobs(json!({"dry_run_hidden": ["f2"], "fresh": true}));
    o.scan_main();
    o.d.action("select", json!({"id": "f2"}));
    o.d.click("fix.preview");
    let state = o.d.settled();
    assert!(state["pending_fix"].is_null(), "{}", state["pending_fix"]);
    let banner = o.d.state()["banner"].clone();
    assert_eq!(banner["summary"], unverified, "{banner}");
    o.d.action("dismiss_error", Value::Null);
    o.d.action("close_finding", Value::Null);
    o.d.click("fix.all");
    let batch = o.d.settled()["batch"].clone();
    let f2 = items(&batch, "f2");
    assert!(
        f2["status"] == "not_ready" && f2["message"] == unverified,
        "{batch}"
    );
    assert_eq!(f2["command"], "", "{f2}");
    assert_eq!(items(&batch, "f1")["status"], "waiting", "{batch}");
    assert!(!o.d.labels().iter().any(|l| l.contains('\u{202e}')));
    o.d.click("fix.all.cancel");
    // An answer for a different scan is refused the same way.
    o.knobs(json!({"dry_run_other_scan": ["f1"]}));
    o.d.click("fix.all");
    let batch = o.d.settled()["batch"].clone();
    let f1 = items(&batch, "f1");
    assert!(
        f1["status"] == "not_ready" && f1["message"] == unverified,
        "{batch}"
    );
    o.d.click("fix.all.cancel");
    // A preview with words beyond the known npm shape does not get the
    // specific "install the fixed version" sentence, and the whole command
    // shows without a click.
    let extra = "npm install alpha@2.0; touch marker";
    o.knobs(json!({"dry_run_suffix": {"f1": "; touch marker"}}));
    o.d.action("select", json!({"id": "f1"}));
    o.d.click("fix.preview");
    assert_eq!(o.d.settled()["pending_fix"]["command"], extra);
    let labels = o.d.labels();
    assert!(
        labels
            .iter()
            .any(|l| l.starts_with("Pantry will run one command. Then")),
        "{labels:?}"
    );
    assert!(
        !labels
            .iter()
            .any(|l| l.contains("install the fixed version")),
        "{labels:?}"
    );
    assert!(labels.iter().any(|l| l == extra), "{labels:?}");
    assert!(!o.d.has_widget("fix.details"));
    o.d.action("cancel_fix", Value::Null);
    // The plain command keeps the specific sentence behind Show the command.
    o.knobs(json!({}));
    o.d.click("fix.preview");
    o.d.settled();
    let labels = o.d.labels();
    assert!(
        labels
            .iter()
            .any(|l| l.starts_with("Pantry will update alpha from version 1.0 to 2.0.")),
        "{labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l == "npm install alpha@2.0"),
        "{labels:?}"
    );
    o.d.widget("fix.details");
    o.d.action("cancel_fix", Value::Null);
    o.d.action("close_finding", Value::Null);
}

pub fn cancel_during_fix_all(o: &mut Outcome) {
    // Cancel during Fix all: the running item is Stopped, the later one
    // Skipped, no check scan runs, and Scan now is offered in the card.
    o.knobs(json!({"fix_sleep": ["f1"], "fresh": true}));
    o.scan_main();
    o.d.click("fix.all");
    o.d.settled();
    let scans_before = o.calls("scan");
    let f2_runs = |o: &Outcome| {
        o.log()
            .iter()
            .filter(|a| {
                a[0] == "fix" && a[1] == "f2" && a.as_array().unwrap().iter().any(|w| w == "--yes")
            })
            .count()
    };
    let f2_before = f2_runs(o);
    o.d.click("fix.all.confirm");
    let pid = o.wait_pid();
    o.d.click("task.cancel");
    let batch = o.d.settled()["batch"].clone();
    assert!(!pid_alive(pid));
    assert_eq!(statuses(&batch), ["stopped", "skipped"], "{batch}");
    assert_eq!(o.calls("scan"), scans_before, "a check scan ran");
    assert_eq!(f2_runs(o), f2_before, "the later fix ran");
    assert_eq!(o.d.widget("fix.all.scan")["enabled"], json!(true));
    // The summary line shows once, in the card, not again as the status.
    assert_eq!(json!(o.d.label("fix.all.result")), batch["message"]);
    assert!(!o.d.has_widget("status.message"), "shown twice");
    o.d.click("fix.all.scan");
    o.d.settled();
    assert_eq!(o.calls("scan"), scans_before + 1);
    o.d.click("fix.all.dismiss");
    o.knobs(json!({}));
}

pub fn offline_and_background_reload(o: &mut Outcome) {
    let main = o.main.display().to_string();
    // Offline: "Scan with saved data" repeats the scan that failed.
    o.knobs(json!({"scan_offline": true}));
    o.d.action("scan", json!({"path": main}));
    o.d.settled();
    let banner = o.d.state()["banner"].clone();
    assert_eq!(banner["kind"], "offline", "{banner}");
    o.d.click("error.offline");
    o.d.settled();
    let log = o.log();
    assert_eq!(
        log[log.len() - 2],
        json!([
            "scan",
            "--json",
            "--no-input",
            "--no-machine",
            "--path",
            main,
            "--offline"
        ])
    );
    o.knobs(json!({}));

    // A background reload keeps a banner being read.
    o.knobs(json!({"scan_garbage": true}));
    o.scan_main();
    let banner = o.d.state()["banner"].clone();
    assert!(!banner.is_null());
    let reports = o.calls("report");
    let cache = o.env.path("WPANTRY_DB");
    std::fs::write(&cache, crate::db::now().to_string()).expect("touch the cache");
    o.d.action("check_cache", Value::Null);
    o.d.settled();
    assert_eq!(
        o.calls("report"),
        reports + 1,
        "{:?}",
        &o.log()[o.log().len() - 2..]
    );
    assert_eq!(o.d.state()["banner"], banner);
    o.d.action("dismiss_error", Value::Null);
    o.knobs(json!({}));

    // Fix it is refused while the results could not be read.
    o.scan_main();
    o.knobs(json!({"report_fails": true, "sticky": true}));
    assert!(!o.fix("f1")["report_error"].is_null());
    o.d.action("select", json!({"id": "f1"}));
    let refused = o.d.action_refused("fix_it", Value::Null);
    assert_eq!(refused, "Reload results before running a fix.");
    o.knobs(json!({}));
    o.d.action("refresh", Value::Null);
    assert!(o.d.settled()["report_error"].is_null());

    // Not checked against the attack list: the line says so, and a finding
    // with no notice summary has no quoted summary.
    o.knobs(json!({"gap": true}));
    o.scan_main();
    o.d.action("select", json!({"id": "f1"}));
    let unchecked = "Pantry could not check whether attackers are using this.";
    assert_eq!(o.d.label("finding.attacks"), unchecked);
    assert_eq!(o.d.state()["finding"]["attacks"], unchecked);
    assert!(!o.d.has_widget("finding.summary"));
    o.d.action("close_finding", Value::Null);
    o.knobs(json!({}));
}

pub fn dismiss_saved_and_rows_below_fold(o: &mut Outcome) {
    // settings.json is right straight after Show again, and an unknown id is
    // refused without touching it.
    let settings_file = o.profile.join("state").join("settings.json");
    o.scan_main();
    o.d.click("earlier.e2.dismiss");
    assert_eq!(
        o.d.label("status.message"),
        "Dismissed. Show it again from Latest scan."
    );
    o.d.click("nav.results");
    assert!(
        !o.d.has_widget("status.message"),
        "the status outlived navigation"
    );
    o.d.click("earlier.e2.restore");
    assert_eq!(read_json(&settings_file)["dismissed"], json!([]));
    let before = std::fs::read(&settings_file).unwrap();
    let refused = o.d.action_refused("dismiss_earlier", json!({"id": "nope"}));
    assert_eq!(refused, "This problem is no longer in the results.");
    assert_eq!(std::fs::read(&settings_file).unwrap(), before);

    // At the smallest window, every Latest scan row is in the accessibility
    // tree, even one far below the fold, and can be scrolled to. Known-bad:
    // a list that lays out only visible rows leaves the last row out of the
    // tree.
    o.knobs(json!({"many": true}));
    o.scan_main();
    o.d.action("show", json!({"page": "results"}));
    o.d.resize(820, 480);
    let last = o.d.widget("finding.f14");
    assert!(bounds(&last)[1] >= 480.0, "not below the fold: {last}");
    o.d.scroll_into_view("finding.f14");
    let last = o.d.widget("finding.f14");
    assert!(inside(bounds(&last), [0.0, 0.0, 820.0, 480.0]), "{last}");
    o.d.resize(1080, 740);
    o.knobs(json!({}));
}

/// Closing the driver's stdin while a scan runs stops that scan too: the
/// app is started again on the same stand-in, which then sleeps in `scan`.
pub fn exit_stops_scan(o: Outcome, app: &Path) {
    let mut o = o.reopen(app, json!({"scan_sleep": true}));
    o.d.settled();
    o.d.action(
        "scan",
        json!({"path": o.main.display().to_string(), "offline": true}),
    );
    let pid = o.wait_pid();
    o.d.close_stdin();
    let deadline = Instant::now() + Duration::from_secs(10);
    while pid_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!pid_alive(pid), "scanner {pid} outlived the app");
    o.knobs(json!({}));
}
