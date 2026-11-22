//! The main suite, part three: Fix it through the real scanner (confirm,
//! cancel, a stale confirm, the check scan, a verified fix) and Fix all.

use crate::db;
use crate::first_run::Main;
use crate::home::name;
use crate::oracles::{audit, shown_once};
use serde_json::{Value, json};

pub fn fix_it(m: &mut Main) {
    let (scan, patch, applied) = (m.scan, m.patch.clone(), m.applied.clone());
    let d = &mut m.driver;
    // The row's own Fix it opens the finding with the confirm step.
    d.click(&format!("finding.{}.fix", name(&m.auto)));
    let state = d.settled();
    assert_eq!(
        state["pending_fix"]["command"],
        json!(patch),
        "{}",
        state["pending_fix"]
    );
    assert!(d.labels().iter().any(|l| l == "Ready to fix"));
    assert!(!applied.exists());
    audit(d, "confirm step");
    assert_eq!(d.click("fix.copy")["clipboard"], json!(patch));
    d.click("fix.cancel");
    assert!(d.settled()["pending_fix"].is_null());
    d.click("fix.preview");
    assert_eq!(d.settled()["pending_fix"]["scan"], json!(scan));
    assert!(d.key("Escape", false)["state"]["pending_fix"].is_null());
    // Without details, a command Pantry can't describe (this stand-in)
    // still shows, with no toggle to hide it. The npm case in the outcome
    // checks covers a described command behind its toggle.
    d.click("view.details");
    assert!(!d.has_widget("fix.details"));
    assert_eq!(d.click("fix.copy")["clipboard"], json!(patch));
    d.click("view.details");
}

pub fn stale_then_confirmed(m: &mut Main) {
    let (scan, patch, applied) = (m.scan, m.patch.clone(), m.applied.clone());
    let db_path = m.env.path("WPANTRY_DB");
    let scope = format!("repos:{}", m.project.display());
    let d = &mut m.driver;
    // A scan arriving between Fix it and the confirm blocks the update.
    d.click("fix.preview");
    assert_eq!(d.settled()["pending_fix"]["scan"], json!(scan));
    let counts = db::Counts {
        fails: 2,
        warns: 1,
        unchecked: 1,
        ..db::Counts::default()
    };
    let newer = db::with_db(&db_path, |tx| {
        db::insert_scan(tx, db::now(), &scope, counts)
    });
    d.click("fix.confirm");
    let state = d.settled();
    let error = &state["error"];
    assert_eq!(error["kind"], "stale_fix", "{error}");
    assert!(
        error["details"]
            .as_str()
            .is_some_and(|s| s.contains("newer scan")),
        "{error}"
    );
    assert!(
        !error["summary"]
            .as_str()
            .unwrap_or("")
            .contains("newer scan"),
        "{error}"
    );
    assert_eq!(
        d.click("error.details")["state"]["show_error_details"],
        json!(true)
    );
    assert!(d.has_label("newer scan"));
    audit(d, "error banner");
    assert!(d.click("error.dismiss")["state"]["error"].is_null());
    assert!(!applied.exists());

    // Fix it, confirm, then the automatic check scan of the same scope.
    d.click("fix.preview");
    assert_eq!(d.settled()["pending_fix"]["scan"], json!(newer));
    let busy = d.click("fix.confirm")["busy"].clone();
    assert!(busy == "Fixing…" || busy == "Checking the fix…", "{busy}");
    let state = d.settled();
    assert!(applied.is_file());
    assert!(state["error"].is_null(), "{}", state["error"]);
    let rescan = state["report"]["scan"]["id"].as_i64().unwrap();
    assert!(rescan > newer, "the fix was not followed by a check scan");
    let result = &state["fix_result"];
    // The offline check has unfinished feeds, so it can't confirm the fix.
    assert_eq!(result["outcome"], "unconfirmed", "{result}");
    assert_eq!(json!(d.label("fix.result")), result["message"]);
    shown_once(d, result["message"].as_str().unwrap());
    assert!(d.click("fix.result.dismiss")["state"]["fix_result"].is_null());

    d.click("nav.history");
    assert!(d.labels().iter().any(|l| l == "Fix ran, not checked yet"));
    let fixes = d.settled()["report"]["history"]["fixes"].clone();
    let last = fixes.as_array().unwrap().last().unwrap();
    assert!(
        last["command"] == json!(patch) && last["verified_scan"].is_null(),
        "{last}"
    );
}

pub fn verified_fix(m: &mut Main) {
    let db_path = m.env.path("WPANTRY_DB");
    let project = m.project.display().to_string();
    let d = &mut m.driver;
    // Supply offline answers for the three feeds the scanner reads even for
    // an empty project. The real scanner must then be able to verify the fix.
    db::with_db(&db_path, |tx| {
        tx.execute(
            "INSERT INTO kev (cve, added) VALUES ('CVE-2000-0000', '2000-01-01')",
            [],
        )?;
        tx.execute("INSERT INTO epss VALUES ('CVE-2000-0000', 0.01, 0.01)", [])?;
        tx.execute(
            "INSERT INTO malicious VALUES ('npm', 'pantry-test-fixture', 'MAL-TEST')",
            [],
        )
    });
    d.action("scan", json!({"path": project, "offline": true}));
    let state = d.settled();
    assert_eq!(
        state["report"]["scan"]["unchecked"],
        json!(0),
        "{}",
        state["report"]["findings"]
    );
    let recheck = state["report"]["scan"]["id"].clone();
    d.click("nav.history");
    let expected = format!("Fixed and checked · scan #{recheck}");
    assert!(
        d.labels().contains(&expected),
        "{expected} not in {:?}",
        d.labels()
    );
    let fixes = d.settled()["report"]["history"]["fixes"].clone();
    assert_eq!(
        fixes.as_array().unwrap().last().unwrap()["verified_scan"],
        recheck
    );
    d.click("nav.attention");
    // The latest scan is clean; the earlier finding from another scope is
    // still open, apart from the headline.
    assert!(
        d.has_label("Everything checked is up to date"),
        "{:?}",
        d.labels()
    );
    let earlier = d.label(&format!("earlier.{}", name(&m.earlier)));
    assert!(earlier.starts_with("older-open"), "{earlier}");
}

pub fn fix_all(m: &mut Main) {
    let db_path = m.env.path("WPANTRY_DB");
    let made = [m.temp.join("batch one"), m.temp.join("batch two")];
    let project = m.project.clone();
    let d = &mut m.driver;
    // Fix all: one confirm, one at a time, per-item results, one check scan.
    db::with_db(&db_path, |tx| {
        db::seed_fixable(tx, &project, &[&made[0], &made[1]])
    });
    d.action("check_cache", Value::Null);
    d.settled();
    assert_eq!(d.label("fix.all"), "Fix all 2 that Pantry can fix");
    d.click("fix.all");
    let batch = d.settled()["batch"].clone();
    assert!(
        batch["stage"] == "confirm" && statuses(&batch) == ["waiting", "waiting"],
        "{batch}"
    );
    assert!(
        batch["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["command"].as_str().is_some_and(|c| !c.is_empty()))
    );
    assert!(!made.iter().any(|p| p.exists()));
    audit(d, "fix all confirm");
    assert!(d.click("fix.all.cancel")["state"]["batch"].is_null());
    d.click("fix.all");
    d.settled();
    d.click("fix.all.confirm");
    let batch = d.settled()["batch"].clone();
    assert!(made.iter().all(|p| p.is_file()));
    assert_eq!(batch["stage"], "done", "{batch}");
    assert_eq!(statuses(&batch), ["fixed", "fixed"], "{batch}");
    assert_eq!(d.label("fix.all.result"), "2 of 2 fixed and checked.");
    assert!(d.click("fix.all.dismiss")["state"]["batch"].is_null());
}

/// Each Fix all item's status, in order.
pub fn statuses(batch: &Value) -> Vec<String> {
    batch["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["status"].as_str().unwrap_or("").to_string())
        .collect()
}
