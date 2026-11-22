//! A machine-scope fix with skipped personal folders, in a fake HOME, on the
//! `machine` stand-in (macOS and Linux).
//!
//! With only skipped areas left unchecked the fix must read as fixed and
//! checked. The known-bad twin adds one real gap: then it must not.

use crate::harness::{Ctx, Driver, read_json, standin};
use crate::oracles::{audit, shown_once};
use serde_json::{Value, json};
use std::path::Path;

fn scans(state_file: &Path) -> Vec<Value> {
    read_json(state_file)["log"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a[0] == "scan")
        .cloned()
        .collect()
}

pub fn machine_scope(app: &Path, ctx: &Ctx, gap: bool) {
    let name = if gap { "machine gap" } else { "machine" };
    let home = ctx.temp.join(format!("{name} home"));
    std::fs::create_dir_all(home.join("project")).expect("create the fake home");
    let state_file = ctx.temp.join(format!("{name} state.json"));
    let profile = ctx.temp.join(format!("{name} profile"));
    let mut env = ctx.env.with(&[
        ("PANTRY_FAKE_MODE", "machine".as_ref()),
        ("HOME", home.as_os_str()),
        ("PANTRY_FAKE_STATE", state_file.as_os_str()),
        ("PANTRY_FAKE_GAP", if gap { "1" } else { "0" }.as_ref()),
        ("WPANTRY_DESKTOP_HOME", profile.as_os_str()),
    ]);
    // Only macOS passes --no-personal-files; elsewhere the stand-in skips
    // the same areas on its own so the exclusion path is still exercised.
    if !cfg!(target_os = "macos") {
        env.set("PANTRY_FAKE_SKIP", "1");
    }
    let mut d = Driver::start(app, Some(&standin()), &env);
    assert!(d.settled()["report"].is_null());
    d.action("set_personal_files", json!({"include": false}));
    d.action("scan", json!({"offline": true}));
    let state = d.settled();
    let report = &state["report"];
    assert_eq!(
        report["scan"]["scope"], "machine:~;no-personal-files",
        "{}",
        report["scan"]
    );
    let excluded = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["excluded"] == true)
        .count();
    assert_eq!(excluded, 2, "{}", report["findings"]);
    let first = scans(&state_file);
    if cfg!(target_os = "macos") {
        assert!(
            first
                .last()
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "--no-personal-files"),
            "{first:?}"
        );
    }

    // Skipped areas are not problems and not unfinished checks.
    let incomplete = d
        .labels()
        .into_iter()
        .filter(|l| l.contains("did not finish"))
        .count();
    assert_eq!(incomplete > 0, gap, "{incomplete} 'did not finish' labels");
    d.action("show", json!({"page": "results"}));
    let labels = d.labels();
    let skipped: Vec<Value> = d
        .tree()
        .into_iter()
        .filter(|n| n["id"] == "scan.skipped")
        .collect();
    assert!(
        skipped.len() == 1 && skipped[0]["label"] == "Skipped by your choice: personal folders",
        "{skipped:?}"
    );
    // Two skipped areas, one real problem, and no warnings from the skips.
    let counts = if gap {
        "1 problem · 1 warning"
    } else {
        "1 problem · 0 warnings"
    };
    assert!(
        labels.iter().any(|l| l == counts),
        "{counts} not in {labels:?}"
    );
    assert!(
        !labels
            .iter()
            .any(|l| l.contains("Safari settings") || l.contains("Personal documents")),
        "{labels:?}"
    );
    assert_eq!(d.widget("scan.skipped.include")["role"], "CheckBox");
    audit(&mut d, &format!("{name} results"));
    if gap {
        assert!(
            d.has_label("1 check did not finish in the latest scan"),
            "{labels:?}"
        );
        assert_eq!(
            d.action("select", json!({"id": "g1"}))["state"]["selected"],
            "g1"
        );
        assert!(d.has_label("CISA KEV list unreachable and not cached"));
        audit(&mut d, &format!("{name} could not be checked"));
        d.click("finding.retry");
        let state = d.settled();
        let again = scans(&state_file);
        assert!(
            again.len() == first.len() + 1 && again.last() == first.last(),
            "{again:?}"
        );
        assert_eq!(
            state["report"]["scan"]["scope"],
            "machine:~;no-personal-files"
        );
        d.action("close_finding", Value::Null);
    } else {
        assert!(
            !labels.iter().any(|l| l.contains("did not finish")),
            "{labels:?}"
        );
    }

    // Fix it, confirm, and the automatic rescan of the same scope.
    d.action("show", json!({"page": "attention"}));
    assert_eq!(
        d.action("select", json!({"id": "f1"}))["can_fix_selected"],
        json!(true)
    );
    d.click("fix.preview");
    d.settled();
    d.click("fix.confirm");
    let state = d.settled();
    assert!(state["error"].is_null(), "{}", state["error"]);
    let rescan = scans(&state_file).last().cloned();
    assert_eq!(rescan.as_ref(), first.last(), "the rescan changed scope");
    let result = &state["fix_result"];
    let message = d.label("fix.result");
    let fixes = state["report"]["history"]["fixes"].as_array().unwrap();
    if gap {
        assert_eq!(result["outcome"], "unconfirmed", "{result}");
        assert!(!message.contains("Fixed"), "{message}");
        assert!(
            fixes.last().unwrap()["verified_scan"].is_null(),
            "{fixes:?}"
        );
    } else {
        assert_eq!(result["outcome"], "fixed", "{result}");
        assert!(message.starts_with("Fixed and checked."), "{message}");
        assert_eq!(
            fixes.last().unwrap()["verified_scan"],
            state["report"]["scan"]["id"],
            "{fixes:?}"
        );
        assert!(
            !state["report"]["history"]["exposures"][0]["resolved"].is_null(),
            "{}",
            state["report"]["history"]
        );
    }
    shown_once(&mut d, &message);
    d.click("fix.result.dismiss");

    // The checkbox puts personal folders back in the next scan.
    d.action("show", json!({"page": "results"}));
    d.click("scan.skipped.include");
    assert_eq!(d.state()["state"]["include_personal_files"], json!(true));
    d.close();
}
