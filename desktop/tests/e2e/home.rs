//! The main suite, part two: seeded results on the home page, the earlier
//! scans group, search, a manual finding's page and an advisory's page.

use crate::db;
use crate::first_run::Main;
use crate::oracles::audit;
use serde_json::{Value, json};

/// The `id` of the item in `list` whose `field` is `value`.
fn id_of(list: &Value, field: &str, value: &str) -> Value {
    let item = list
        .as_array()
        .and_then(|items| items.iter().find(|i| i[field] == value));
    item.unwrap_or_else(|| panic!("no {field} = {value} in {list}"))["id"].clone()
}

/// An id as widget names spell it (`finding.<id>`).
pub fn name(id: &Value) -> String {
    id.as_str().map_or_else(|| id.to_string(), str::to_string)
}

pub fn seeded_home(m: &mut Main) {
    let db_path = m.env.path("WPANTRY_DB");
    m.applied = m.temp.join("patch ran");
    let (project, applied) = (m.project.clone(), m.applied.clone());
    let (scan, patch) = db::with_db(&db_path, |tx| {
        db::clear(tx)?;
        db::seed(tx, &project, &applied)
    });
    (m.scan, m.patch) = (scan, patch);
    let d = &mut m.driver;

    // A change to the cache (like a scheduled scan) reloads by itself.
    d.action("check_cache", Value::Null);
    let state = d.settled();
    assert_eq!(state["report"]["scan"]["id"], json!(scan));
    // The headline counts the latest scan only; an earlier scan of another
    // scope shows apart, under "From earlier scans".
    assert!(
        d.has_label("2 things need your attention"),
        "{:?}",
        d.labels()
    );
    assert_eq!(d.state()["headline_count"], json!(2));
    assert_eq!(d.label("earlier.heading"), "From earlier scans");
    m.manual = id_of(&state["report"]["findings"], "vuln_id", "TEST-2026-MANUAL");
    m.auto = id_of(&state["report"]["findings"], "vuln_id", "TEST-2026-AUTO");
    let (auto, manual) = (name(&m.auto), name(&m.manual));
    let current = d.state();
    assert_eq!(
        current["fixable"],
        json!([m.auto]),
        "{}",
        current["fixable"]
    );
    assert_eq!(d.label("fix.all"), "Fix the 1 that Pantry can fix");
    assert_eq!(d.label(&format!("finding.{auto}.fix")), "Fix it");
    // Lower priority rows start folded away.
    assert_eq!(d.label("findings.lower"), "Show lower priority (1)");
    d.click_refused(&format!("finding.{manual}"));
    d.click("findings.lower");
    assert_eq!(d.label(&format!("finding.{manual}.how")), "Show me how");
    audit(d, "home");
    assert!(d.labels().iter().any(|l| l == "Can fix (1)"));
    assert_eq!(
        d.click("findings.filter.fixable")["state"]["filter"],
        "fixable"
    );
    d.click_refused(&format!("finding.{manual}"));
    d.click("findings.filter.all");
    assert!(!d.has_label("older-resolved"));

    m.earlier = id_of(
        &state["report"]["history"]["exposures"],
        "component",
        "older-open",
    );
    d.click(&format!("earlier.{}.how", name(&m.earlier)));
    assert_eq!(
        d.click("fix.copy")["clipboard"],
        "Update the installed tool."
    );
    d.click_refused("fix.preview");
    d.click("finding.back");
    d.click("nav.results");
    assert!(d.has_label("Feed unavailable"));
    assert!(d.has_label("no fix released yet"));
    audit(d, "latest scan");
    d.click("nav.history");
    assert!(d.has_label("older-resolved"));
    d.click("nav.attention");
}

pub fn manual_finding(m: &mut Main) {
    let (auto, manual) = (name(&m.auto), name(&m.manual));
    let project_name = m.project.file_name().unwrap().to_string_lossy().to_string();
    let d = &mut m.driver;
    d.set_value("findings.search", "manual-fixture");
    d.click_refused(&format!("finding.{auto}"));
    // Only lower-priority rows match, so they show without the toggle.
    d.click_refused("findings.lower");
    d.click(&format!("finding.{manual}"));
    let labels = d.labels();
    for expected in [
        "What Pantry found",
        "Installed version 1.0",
        "How to fix it",
    ] {
        assert!(
            labels.iter().any(|l| l == expected),
            "{expected} not in {labels:?}"
        );
    }
    // A plain sentence leads; the scanner's note shows only with details.
    let sentence = d.label("finding.sentence");
    assert!(
        sentence.starts_with("manual-fixture has a security flaw with no fix yet."),
        "{sentence}"
    );
    assert!(!d.labels().iter().any(|l| l == "Manual update."));
    // The path reads as ~/... or is elided in the middle, never a long raw path.
    let found = d.label("finding.location");
    assert!(
        found.starts_with("Found in ") && found.chars().count() <= "Found in ".len() + 56,
        "{found}"
    );
    assert!(found.ends_with(&project_name), "{found} {project_name}");
    assert_eq!(
        d.click("fix.copy")["clipboard"],
        "Install the vendor update."
    );
    d.click_refused("fix.preview");
    audit(d, "manual detail");
    // No weakness or summary: the neutral sentence, with no ids to link.
    let finding = d.state()["finding"].clone();
    assert_eq!(finding["explanation_source"], "generic", "{finding}");
    assert_eq!(
        finding["identifiers"],
        json!([{"id": "TEST-2026-MANUAL", "url": null}]),
        "{finding}"
    );
    d.key("Escape", false);
    d.set_value("findings.search", "");
}

pub fn advisory_finding(m: &mut Main) {
    let d = &mut m.driver;
    // A finding with a weakness type, ids and a summary: what could happen,
    // each id a link to its notice, the notice's own words, Copy ID.
    d.action("select", json!({"id": m.auto}));
    let finding = d.state()["finding"].clone();
    assert_eq!(finding["explanation_source"], "cwe", "{finding}");
    assert!(
        finding["explanation"]
            .as_str()
            .is_some_and(|e| e.contains("run their own programs")),
        "{finding}"
    );
    assert_eq!(
        finding["summary"], "Out-of-bounds write in the test decoder",
        "{finding}"
    );
    let ids: Vec<Value> = finding["identifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].clone())
        .collect();
    assert_eq!(
        ids,
        [
            json!("CVE-2099-0001"),
            json!("TEST-2026-AUTO"),
            json!("GHSA-test-aaaa-bbbb")
        ]
    );
    assert!(
        finding["identifiers"][1]["url"].is_null(),
        "a test id links nowhere"
    );
    assert_eq!(d.widget("finding.advisory.CVE-2099-0001")["role"], "Link");
    assert!(
        d.label("finding.summary")
            .starts_with("From the security notice:")
    );
    assert!(
        d.label("finding.attacks")
            .starts_with("It is not on the public list")
    );
    assert_eq!(
        d.click("finding.advisory.CVE-2099-0001")["browser"],
        "https://www.cve.org/CVERecord?id=CVE-2099-0001"
    );
    assert_eq!(
        d.click("finding.advisory.GHSA-test-aaaa-bbbb")["browser"],
        "https://github.com/advisories/GHSA-test-aaaa-bbbb"
    );
    assert_eq!(d.click("finding.copy_id")["clipboard"], "CVE-2099-0001");
    // Only an id the finding lists can be opened.
    let refused = d.action_refused("open_advisory", json!({"id": "RUSTSEC-0000-0000"}));
    assert!(refused.as_str().is_some_and(|e| !e.is_empty()), "{refused}");
    d.action("copy_id", Value::Null);
    // The home row's sentence names the consequence, not the generic hole.
    let sentence = d.state()["finding"]["sentence"].clone();
    assert!(
        !sentence
            .as_str()
            .unwrap_or("")
            .ends_with("has a security flaw."),
        "{sentence}"
    );
    audit(d, "advisory detail");
    let was = d.state()["state"]["details"].clone();
    d.action("set_details", json!({"on": true}));
    assert_eq!(
        d.label("finding.tech.weakness_type"),
        "Weakness type: CWE-787 (Out-of-bounds write)"
    );
    audit(d, "advisory technical details");
    d.action("set_details", json!({"on": was}));
    d.key("Escape", false);
    d.action("select", json!({"id": m.manual}));
    // Esc goes back.
    assert!(d.key("Escape", false)["state"]["selected"].is_null());
    d.set_value("findings.search", "");
    // Cmd/Ctrl+F focuses search.
    assert_eq!(d.key("F", true)["search_focused"], json!(true));
}
