use super::*;
use crate::data::Scan;

fn unchecked(component: &str, excluded: Option<bool>) -> serde_json::Value {
    let mut value = serde_json::json!({
        "kind": "unchecked", "component": component, "version": "", "location": "",
        "vuln_id": "", "status": "warn", "note": "", "fixed": "", "severity": "",
        "kev": false, "fix_cmd": "",
    });
    if let Some(excluded) = excluded {
        value["excluded"] = excluded.into();
    }
    value
}

/// Oracle: the scanner contract. Exposures another scope left open
/// are not the latest scan's: they are never in `open` (the headline),
/// show in `earlier` until dismissed, and a key the latest scan lists
/// shows once.
#[test]
fn earlier_scopes_stay_out_of_the_headline() {
    let finding = |component: &str| {
        serde_json::json!({
            "id": format!("F-{component}"), "kind": "osv", "component": component, "version": "1",
            "location": "/p", "vuln_id": "X-1", "status": "fail", "note": "", "fixed": "2",
            "severity": "high", "kev": false, "fix_cmd": "",
        })
    };
    let exposure = |component: &str, resolved: Option<&str>| {
        let mut value = finding(component);
        value["resolved"] = resolved.into();
        value["scope"] = "repos:/other".into();
        value
    };
    let report: Report = serde_json::from_value(serde_json::json!({
        "schema": 1,
        "scan": {"id": 2, "when": "", "scope": "repos:/p", "fails": 1, "warns": 0, "unchecked": 0},
        "findings": [finding("latest")],
        "fix_plan": [], "checked": {}, "unfixed": 0,
        "history": {"scans": [], "exposures": [
            exposure("latest", None), exposure("other", None), exposure("done", Some("2026-01-01 00:00 UTC")),
        ]},
    }))
    .unwrap();
    let open: Vec<_> = report
        .open()
        .into_iter()
        .map(|(f, _)| f.component.as_str())
        .collect();
    assert_eq!(open, ["latest"]);
    let earlier: Vec<_> = report
        .earlier(&[])
        .iter()
        .map(|e| e.finding.component.as_str())
        .collect();
    assert_eq!(earlier, ["other"]);
    assert_eq!(report.earlier(&[]).first().unwrap().scope, "repos:/other");
    assert!(report.earlier(&["F-other".into()]).is_empty());
    assert_eq!(report.earlier_all().len(), 1, "dismissing only hides it");
}

fn earlier_report(exposures: serde_json::Value, findings: serde_json::Value) -> Report {
    serde_json::from_value(serde_json::json!({
        "schema": 1,
        "scan": {"id": 3, "when": "", "scope": "repos:/p", "fails": 0, "warns": 0, "unchecked": 0},
        "findings": findings,
        // Known-bad: a plan even answers to the earlier row's id.
        "fix_plan": [
            {"id": "F-auto", "how": "wpantry", "run": "", "fix_cmd": "npm i auto@2"},
            {"id": "earlier-F-auto", "how": "wpantry", "run": "", "fix_cmd": "npm i auto@2"},
        ],
        "checked": {}, "unfixed": 0,
        "history": {"scans": [], "exposures": exposures},
    }))
    .unwrap()
}

/// Oracle: an area an earlier scan could not check is not a problem
/// anyone has to clear, so it is never listed under earlier scans.
#[test]
fn unchecked_exposures_are_never_earlier_problems() {
    let mut gap = unchecked("OSV", Some(false));
    gap["id"] = "F-gap".into();
    gap["scope"] = "repos:/other".into();
    gap["resolved"] = serde_json::Value::Null;
    let report = earlier_report(serde_json::json!([gap]), serde_json::json!([]));
    assert!(report.earlier_all().is_empty());
    assert!(report.earlier(&[]).is_empty());
}

/// Oracle: an earlier problem is from another scan, which Pantry cannot
/// fix from here, even when its fix is automatic and a plan with the
/// same id exists; the same finding in the latest scan can be fixed.
#[test]
fn earlier_problems_cannot_be_auto_fixed() {
    let auto = serde_json::json!({
        "id": "F-auto", "kind": "project", "component": "auto", "version": "1",
        "location": "/other", "vuln_id": "GHSA-aaaa-bbbb-cccc", "status": "fail", "note": "",
        "fixed": "2", "severity": "high", "kev": false, "fix_cmd": "npm i auto@2",
        "fix_auto": true, "scope": "repos:/other", "resolved": null,
    });
    let report = earlier_report(serde_json::json!([auto.clone()]), serde_json::json!([]));
    let earlier = report.earlier_all();
    assert_eq!(earlier.len(), 1);
    let finding = &earlier[0].finding;
    assert!(finding.fix_auto);
    assert!(!report.can_fix(finding, "earlier-F-auto"));
    let latest = earlier_report(serde_json::json!([]), serde_json::json!([auto]));
    assert!(latest.can_fix(&latest.findings[0], "F-auto"));
}

/// Oracle: the scanner contract. A skipped area is not a gap, and a
/// scanner too old to send `excluded` has every unchecked source count.
#[test]
fn skipped_areas_are_not_gaps() {
    let findings: Vec<Finding> = serde_json::from_value(serde_json::json!([
        unchecked("Documents", Some(true)),
        unchecked("Feed", Some(false)),
        unchecked("Old feed", None),
    ]))
    .unwrap();
    let report = Report {
        findings,
        ..Default::default()
    };
    assert_eq!(report.gaps(), 2);
    let report = Report {
        scan: Scan {
            warns: 3,
            ..Default::default()
        },
        ..report
    };
    assert_eq!(report.warnings(), 2);
    let skipped: Vec<_> = report.skipped().iter().map(|f| &f.component).collect();
    assert_eq!(skipped, ["Documents"]);
    assert!(report.open().is_empty());
}
