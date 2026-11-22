//! Scenarios that start the app again: settings surviving a restart, the
//! demo rows at the minimum window, a missing scanner, and the screenshots
//! the documentation uses.

use crate::db;
use crate::harness::{Driver, Env, read_json};
use crate::oracles::{audit, bounds};
use serde_json::{Value, json};
use std::path::Path;

/// Theme, details, page and window size survive a restart; a damaged
/// settings file falls back to defaults.
pub fn settings_persist(app: &Path, scanner: Option<&Path>, temp: &Path, env: &Env) {
    let profile = temp.join("settings profile");
    let env = env.with(&[("WPANTRY_DESKTOP_HOME", profile.as_os_str())]);
    let settings = profile.join("state").join("settings.json");
    let mut d = Driver::start(app, scanner, &env);
    d.settled();
    d.click("theme.toggle");
    d.click("view.details");
    d.click("nav.history");
    d.resize(820, 480);
    // The minimum window keeps every control inside the frame.
    for node in audit(&mut d, "minimum window") {
        if ["scan.run", "nav.history", "theme.toggle"]
            .iter()
            .any(|id| node["id"] == *id)
        {
            let [_, y0, x1, _] = bounds(&node);
            assert!(x1 <= 820.0 && y0 >= 0.0, "{node}");
        }
    }
    d.close();
    let saved = read_json(&settings);
    assert!(
        saved["light"] == true && saved["details"] == true && saved["page"] == "history",
        "{saved}"
    );
    let window: Vec<f64> = saved["window"]
        .as_array()
        .map(|w| w.iter().filter_map(Value::as_f64).collect())
        .unwrap_or_default();
    assert_eq!(window, [820.0, 480.0], "{saved}");
    let mut d = Driver::start(app, scanner, &env);
    let state = d.settled();
    assert!(
        state["light"] == true && state["details"] == true && state["page"] == "history",
        "{state}"
    );
    d.close();
    std::fs::write(&settings, "{ this is not json").expect("damage the settings");
    let mut d = Driver::start(app, scanner, &env);
    let state = d.settled();
    assert!(
        state["light"] == false && state["details"] == false && state["page"] == "attention",
        "{state}"
    );
    d.close();
}

/// At the 820 x 480 minimum, the demo High row's sentence wraps onto a
/// second line, so the consequence starts in the row, and the row's
/// accessible label and hover carry the whole sentence. Known-bad: the
/// one-line row showed only "A specially made file or message…". The whole
/// sentence (about 200 characters) does not fit in two lines of about 60
/// characters, so the second line still ends cut short.
pub fn demo_row_fits(d: &mut Driver) {
    let report = d.state()["state"]["report"].clone();
    let high = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["vuln_id"] == "DEMO-2026-0001")
        .unwrap()["id"]
        .clone();
    let high = crate::home::name(&high);
    d.action("show", json!({"page": "attention"}));
    d.resize(820, 480);
    let state = d.state();
    let row = &state["rows"][high.as_str()];
    assert_eq!(row["lines"], json!(2), "{row} {}", state["rows"]);
    let label = d.label(&format!("finding.{high}"));
    assert!(
        label.contains("run their own programs on this computer."),
        "{label}"
    );
    d.resize(1080, 740);
}

/// Scan `project` with the real scanner so the cache has its tables, then
/// replace its results with the demo data.
fn demo_results(d: &mut Driver, db_path: &Path, project: &Path, patch: &Path) -> Value {
    d.action(
        "scan",
        json!({"path": project.display().to_string(), "offline": true}),
    );
    d.settled();
    db::with_db(db_path, |tx| {
        db::clear(tx)?;
        db::demo_seed(tx, project, patch)
    });
    d.action("check_cache", Value::Null);
    d.settled()
}

/// The home rows with the documentation's demo data, at the smallest
/// window. Known-bad: a one-line row cut the High row's consequence short.
pub fn demo_rows(app: &Path, scanner: Option<&Path>, temp: &Path, env: &Env) {
    let base = temp.join("demo rows");
    let project = base.join("Projects").join("recipe-site");
    std::fs::create_dir_all(&project).expect("create the demo project");
    let (profile, db_path) = (base.join("profile"), base.join("pantry.db"));
    let env = env.with(&[
        ("WPANTRY_DESKTOP_HOME", profile.as_os_str()),
        ("WPANTRY_DB", db_path.as_os_str()),
    ]);
    let mut d = Driver::start(app, scanner, &env);
    d.settled();
    demo_results(&mut d, &db_path, &project, &base.join("demo patch"));
    demo_row_fits(&mut d);
    d.close();
}

/// Without a scanner, one plain message and a Download button.
pub fn scanner_missing(app: &Path, temp: &Path, env: &Env) {
    let alone = temp.join("app alone");
    std::fs::create_dir(&alone).expect("create the lone folder");
    let copy = alone.join(app.file_name().unwrap());
    std::fs::copy(app, &copy).expect("copy the app");
    let path: Vec<&str> = ["/usr/bin", "/bin"]
        .into_iter()
        .filter(|p| Path::new(p).is_dir())
        .collect();
    let path = std::env::join_paths(path).expect("PATH joins");
    let env = env.with(&[("PATH", path.as_os_str())]);
    let mut d = Driver::start(&copy, None, &env);
    let state = d.settled();
    assert_eq!(state["scanner_found"], json!(false));
    let banner = d.state()["banner"].clone();
    assert_eq!(banner["kind"], "scanner_missing", "{banner}");
    assert!(
        !banner["summary"]
            .as_str()
            .unwrap_or("")
            .contains("os error"),
        "{banner}"
    );
    assert_eq!(json!(d.label("error.message")), banner["summary"]);
    assert_eq!(d.widget("scan.run")["enabled"], json!(false));
    let browser = d.click("error.download")["browser"].clone();
    assert!(
        browser
            .as_str()
            .is_some_and(|b| b.ends_with("/releases/latest")),
        "{browser}"
    );
    audit(&mut d, "scanner missing");
    d.close();
}

/// Render each main screen to PNG in both palettes, headless (no window).
pub fn screens(app: &Path, scanner: Option<&Path>, temp: &Path, env: &Env, out: &Path) {
    std::fs::create_dir_all(out).expect("create the screens folder");
    let project = temp.join("Projects").join("recipe-site");
    std::fs::create_dir_all(&project).expect("create the demo project");
    let db_path = env.path("WPANTRY_DB");
    let mut d = Driver::start(app, scanner, env);
    for theme in ["dark", "light"] {
        let shot = |d: &mut Driver, name: &str| {
            let path = out.join(format!("{name}-{theme}.png"));
            d.ok("screenshot", json!({"path": path}));
        };
        d.action("set_theme", json!({"theme": theme}));
        if theme == "dark" {
            d.settled();
        }
        if db_path.exists() {
            // The tables exist only after the first scan.
            db::with_db(&db_path, |tx| {
                for table in ["scans", "exposures", "findings"] {
                    let _ = tx.execute(&format!("DELETE FROM {table}"), []);
                }
                Ok(())
            });
        }
        d.action("refresh", Value::Null);
        d.settled();
        shot(&mut d, "01-first-run");
        let state = demo_results(&mut d, &db_path, &project, &temp.join("screens patch"));
        d.action("show", json!({"page": "attention"}));
        shot(&mut d, "02-home");
        d.action("show_lower_priority", json!({"open": true}));
        shot(&mut d, "03-home-all");
        let find = |id: &str| {
            state["report"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["vuln_id"] == id)
                .unwrap()["id"]
                .clone()
        };
        let (auto, manual) = (find("DEMO-2026-0001"), find("DEMO-2026-0002"));
        d.action("fix_all", Value::Null);
        d.settled();
        shot(&mut d, "04-fix-all-confirm");
        d.action("cancel_fix_all", Value::Null);
        d.action("select", json!({"id": manual}));
        shot(&mut d, "05-show-me-how");
        d.action("select", json!({"id": auto}));
        shot(&mut d, "11-what-is-this");
        d.action("set_details", json!({"on": true}));
        shot(&mut d, "12-technical-details");
        d.action("set_details", json!({"on": false}));
        d.action("fix_it", Value::Null);
        d.settled();
        shot(&mut d, "06-fix-confirm");
        d.action("cancel_fix", Value::Null);
        d.action("close_finding", Value::Null);
        d.action("show", json!({"page": "results"}));
        shot(&mut d, "07-latest-scan");
        d.action("show", json!({"page": "history"}));
        shot(&mut d, "08-history");
        d.action("show", json!({"page": "attention"}));
        d.action("set_details", json!({"on": true}));
        shot(&mut d, "09-home-details");
        d.action("set_details", json!({"on": false}));
        d.resize(820, 480);
        shot(&mut d, "10-minimum-window");
        demo_row_fits(&mut d);
        d.resize(1080, 740);
    }
    d.close();
    eprintln!("Saved screens to {}", out.display());
}
