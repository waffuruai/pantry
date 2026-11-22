//! The suite's oracles over the accessibility tree, each with a known-bad
//! self-check: every interactive widget tagged, a message shown once, a
//! control inside a region, and the sidebar reachable at the minimum window.
//!
//! ```text
//! let tree = audit(&mut driver, "home");
//! shown_once(&mut driver, "Fixed and checked.");
//! ```

use crate::harness::Driver;
use serde_json::{Value, json};

pub const INTERACTIVE_ROLES: &[&str] = &[
    "Button",
    "CheckBox",
    "ComboBox",
    "TextInput",
    "MultilineTextInput",
    "Link",
    "Slider",
    "RadioButton",
    "Switch",
    "Tab",
    "ListBoxOption",
    "MenuItem",
];

/// Interactive widgets that lack an automation id (should be none).
pub fn untagged(tree: &[Value]) -> Vec<Value> {
    tree.iter()
        .filter(|n| {
            let interactive = n["interactive"] == true
                || n["role"]
                    .as_str()
                    .is_some_and(|r| INTERACTIVE_ROLES.contains(&r));
            interactive && n["id"].as_str().is_none_or(str::is_empty)
        })
        .cloned()
        .collect()
}

/// Every interactive widget has an id, no two share one, and each tagged
/// widget has bounds and a role. Returns the tree.
pub fn audit(driver: &mut Driver, place: &str) -> Vec<Value> {
    let tree = driver.tree();
    let missing = untagged(&tree);
    assert!(missing.is_empty(), "{place}: untagged {missing:?}");
    let ids: Vec<&str> = tree
        .iter()
        .filter_map(|n| n["id"].as_str())
        .filter(|i| !i.is_empty())
        .collect();
    let mut duplicates: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|i| ids.iter().filter(|j| *j == i).count() > 1)
        .collect();
    duplicates.dedup();
    assert!(
        duplicates.is_empty(),
        "{place}: duplicate ids {duplicates:?}"
    );
    for node in &tree {
        if node["id"].as_str().is_some_and(|i| !i.is_empty()) {
            assert!(
                !node["bounds"].is_null() && on(&node["role"]),
                "{place}: {node}"
            );
        }
    }
    tree
}

fn on(value: &Value) -> bool {
    !(value.is_null() || value == "" || value == false)
}

pub fn audit_rejects_known_bad() {
    // Known-bad case: the audit must flag a button with no id.
    let bad = vec![
        json!({"id": null, "label": "Mystery", "role": "Button", "interactive": true, "bounds": [0, 0, 1, 1]}),
    ];
    assert_eq!(untagged(&bad), bad);
    let good = [json!({"id": "ok", "label": "x", "role": "Button", "interactive": true})];
    assert!(untagged(&good).is_empty());
}

/// A fix outcome is told once on screen: in the banner card, not again as
/// the status line under it. A label's own text runs are part of it, not a
/// second copy.
pub fn shown_once_in(tree: &[Value], text: &str) -> Result<(), String> {
    let nodes: Vec<&Value> = tree
        .iter()
        .filter(|n| {
            n["label"]
                .as_str()
                .is_some_and(|l| !l.is_empty() && l.contains(text))
                && !n["bounds"].is_null()
                && n["role"] != "TextRun"
        })
        .collect();
    if nodes.len() == 1 {
        Ok(())
    } else {
        Err(format!("{text:?} shown {} times: {nodes:?}", nodes.len()))
    }
}

pub fn shown_once(driver: &mut Driver, text: &str) {
    let tree = driver.tree();
    if let Err(message) = shown_once_in(&tree, text) {
        panic!("{message}");
    }
}

pub fn shown_once_rejects_known_bad() {
    // Known-bad case: the same message as both banner and status line.
    let node = |id| json!({"id": id, "label": "Fixed and checked.", "bounds": [0, 0, 1, 1]});
    let twice = [node("fix.result"), node("status.message")];
    assert!(
        shown_once_in(&twice, "Fixed and checked.").is_err(),
        "shown_once accepted a message shown twice"
    );
}

/// The four numbers of a `bounds` value ([x0, y0, x1, y1]).
pub fn bounds(node: &Value) -> [f64; 4] {
    let b = node["bounds"]
        .as_array()
        .unwrap_or_else(|| panic!("no bounds: {node}"));
    [0, 1, 2, 3].map(|i| b[i].as_f64().expect("bounds are numbers"))
}

/// True when `b` lies within `region`.
pub fn inside(b: [f64; 4], region: [f64; 4]) -> bool {
    let slack = 0.5;
    b[0] >= region[0] - slack
        && b[1] >= region[1] - slack
        && b[2] <= region[2] + slack
        && b[3] <= region[3] + slack
}

pub fn inside_rejects_known_bad() {
    // Known-bad case: a control half under the footer is not inside.
    let region = [0.0, 100.0, 236.0, 440.0];
    assert!(inside([18.0, 200.0, 200.0, 230.0], region));
    assert!(!inside([18.0, 430.0, 200.0, 460.0], region));
    assert!(!inside([18.0, 600.0, 200.0, 630.0], region));
}

/// Oracle for the sidebar at the minimum window: the scroll area and the
/// pinned help links fit the window, and every sidebar control either sits
/// inside the scroll area or comes inside it when scrolled into view.
pub fn sidebar_reachable(driver: &mut Driver, place: &str) -> Vec<String> {
    let window = [0.0, 0.0, 820.0, 480.0];
    inside_rejects_known_bad();
    let tree = audit(driver, place);
    let regions: Vec<&Value> = tree
        .iter()
        .filter(|n| n["id"] == "sidebar.scroll")
        .collect();
    assert!(
        regions.len() == 1 && regions[0]["role"] == "ScrollView",
        "{place}: {regions:?}"
    );
    let region = bounds(regions[0]);
    assert!(inside(region, window), "{place}: {region:?}");
    for link in ["help.github", "help.support"] {
        let b = bounds(tree.iter().find(|n| n["id"] == link).expect("help link"));
        assert!(
            inside(b, window) && b[1] >= region[3] - 0.5,
            "{place}: {link} {b:?}"
        );
    }
    let controls: Vec<String> = tree
        .iter()
        .filter(|n| {
            let Some(id) = n["id"].as_str().filter(|i| !i.is_empty()) else {
                return false;
            };
            if n["interactive"] != true || id.starts_with("help.") {
                return false;
            }
            let b = bounds(n);
            b[0] >= region[0] - 0.5 && b[2] <= region[2] + 0.5 && b[1] >= region[1] - 0.5
        })
        .map(|n| n["id"].as_str().unwrap().to_string())
        .collect();
    for expected in ["theme.toggle", "view.details", "updates.check"] {
        assert!(
            controls.iter().any(|c| c == expected),
            "{place}: {expected} not in {controls:?}"
        );
    }
    for control in &controls {
        driver.scroll_into_view(control);
        let b = bounds(&driver.widget(control));
        assert!(
            inside(b, region),
            "{place}: {control} {b:?} outside {region:?}"
        );
    }
    controls
}
