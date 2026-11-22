//! End-to-end checks of Pantry Desktop: the production egui widgets driven
//! through AccessKit over `--automation` (JSON Lines on stdio, never a
//! window), against the real scanner and against stand-in scanners
//! (tests/standin, the `wpantry-standin` binary).
//!
//! How to run:
//!
//! ```text
//! (cd rust && cargo build -p wpantry-cli)   # the real scanner
//! cd desktop && cargo test --test e2e       # every default check
//! ```
//!
//! The real scanner is `PANTRY_E2E_SCANNER` when set (it must exist), else
//! `../rust/target/debug/wpantry`. Without either, `desktop_suite` is skipped
//! with a message locally and fails under CI (`CI` set). The stand-in
//! scenarios (Cancel, outcomes, machine scope) need no scanner; like the
//! Python suite they ran under, they run on macOS and Linux.
//!
//! The release workflow runs the same checks against built downloads. They
//! are `#[ignore]`d so a plain `cargo test` skips them; relative paths are
//! from `desktop/`:
//!
//! ```text
//! PANTRY_E2E_BUNDLE=../dist/wpantry-desktop-<target>.zip cargo test --test e2e -- --ignored --exact bundle
//! PANTRY_E2E_SETUP=../dist/wpantry-setup-<target>.<ext>   cargo test --test e2e -- --ignored --exact setup
//! PANTRY_E2E_SCREENS=/tmp/screens                         cargo test --test e2e -- --ignored --exact screens
//! ```
//!
//! `screens` only renders PNGs of each main screen in both palettes, for the
//! documentation. Set `PANTRY_E2E_KEEP=1` to keep each scenario's folder
//! (under target/tmp); a failing scenario always keeps it.

mod archive;
#[cfg(unix)]
mod cancel;
mod db;
mod first_run;
mod fixes;
mod harness;
mod home;
mod lifecycle;
#[cfg(unix)]
mod machine;
mod oracles;
#[cfg(unix)]
mod outcomes;
#[cfg(unix)]
mod outcomes_more;
mod package;
mod restart;
mod sidebar;
mod tools;

use first_run::Main;
use harness::{Ctx, Driver, app};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A path from the environment, which must exist; relative to `desktop/`.
fn required(var: &str) -> Option<PathBuf> {
    let path = std::path::absolute(std::env::var_os(var)?).expect("an absolute path");
    assert!(path.exists(), "{var}={} does not exist", path.display());
    Some(path)
}

/// The real scanner for the checks that drive one.
fn scanner() -> Option<PathBuf> {
    if let Some(path) = required("PANTRY_E2E_SCANNER") {
        return Some(path);
    }
    let built = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rust/target/debug")
        .join(format!("wpantry{}", std::env::consts::EXE_SUFFIX));
    if built.is_file() {
        return Some(std::path::absolute(built).unwrap());
    }
    let message = format!(
        "No scanner at {}: build it with `cd rust && cargo build -p wpantry-cli`, or set PANTRY_E2E_SCANNER.",
        built.display()
    );
    assert!(std::env::var_os("CI").is_none(), "{message}");
    eprintln!("SKIPPED the desktop suite on the real scanner. {message}");
    None
}

/// The checks every platform runs on one app: the main flow on a long-lived
/// driver, then settings, the demo rows and (when the scanner is passed
/// explicitly, not found beside the app) a missing scanner. With
/// `unix_scenarios`, the stand-in scenarios follow on the same app.
fn ui_suite(app: &Path, scanner: &Path, explicit: bool, mut ctx: Ctx, unix_scenarios: bool) {
    let tools = ctx.fake_scheduler();
    let passed = explicit.then_some(scanner);
    let mut m = Main {
        driver: Driver::start(app, passed, &ctx.env),
        scanner: scanner.to_path_buf(),
        temp: ctx.temp.clone(),
        env: ctx.env.clone(),
        tools,
        project: PathBuf::new(),
        applied: PathBuf::new(),
        patch: String::new(),
        scan: 0,
        auto: Value::Null,
        manual: Value::Null,
        earlier: Value::Null,
    };
    first_run::first_run(&mut m);
    first_run::schedule(&mut m);
    first_run::palettes_and_details(&mut m);
    first_run::first_scan(&mut m);
    home::seeded_home(&mut m);
    home::manual_finding(&mut m);
    home::advisory_finding(&mut m);
    fixes::fix_it(&mut m);
    fixes::stale_then_confirmed(&mut m);
    fixes::verified_fix(&mut m);
    fixes::fix_all(&mut m);
    sidebar::updates(&mut m);
    sidebar::minimum_sidebar(&mut m);
    sidebar::dispatcher(&mut m);
    sidebar::schedule_plan(&mut m);
    m.driver.close();

    restart::settings_persist(app, passed, &ctx.temp, &ctx.env);
    restart::demo_rows(app, passed, &ctx.temp, &ctx.env);
    if explicit {
        restart::scanner_missing(app, &ctx.temp, &ctx.env);
    }
    if unix_scenarios {
        #[cfg(unix)]
        stand_in_scenarios(app, &ctx);
    }
}

#[cfg(unix)]
fn stand_in_scenarios(app: &Path, ctx: &Ctx) {
    cancel::cancel_and_timeout(app, ctx);
    fix_outcomes_on(app, ctx);
    machine::machine_scope(app, ctx, false);
    machine::machine_scope(app, ctx, true);
}

#[cfg(unix)]
fn fix_outcomes_on(app: &Path, ctx: &Ctx) {
    let mut o = outcomes::Outcome::new(app, ctx);
    outcomes::scanner_text_and_earlier(&mut o);
    outcomes::busy_guard_and_cancelled_reload(&mut o);
    outcomes::still_open_gap_and_failed(&mut o);
    outcomes::cancelled_fix(&mut o);
    outcomes_more::garbage_and_updates(&mut o);
    outcomes_more::refused_previews(&mut o);
    outcomes_more::cancel_during_fix_all(&mut o);
    outcomes_more::offline_and_background_reload(&mut o);
    outcomes_more::dismiss_saved_and_rows_below_fold(&mut o);
    outcomes_more::exit_stops_scan(o, app);
}

/// A scenario's folder with the scheduler stand-ins on PATH, as the Python
/// suite gave every scenario after the main one.
#[cfg(unix)]
fn unix_ctx(name: &str) -> Ctx {
    let mut ctx = Ctx::new(name);
    ctx.fake_scheduler();
    ctx
}

#[test]
fn oracles_reject_known_bad() {
    oracles::audit_rejects_known_bad();
    oracles::shown_once_rejects_known_bad();
    oracles::inside_rejects_known_bad();
    tools::quote_rejects_known_bad();
    package::plist_rejects_known_bad();
    package::desktop_exec_rejects_known_bad();
}

#[test]
fn desktop_suite() {
    let Some(scanner) = scanner() else { return };
    ui_suite(&app(), &scanner, true, Ctx::new("main"), false);
}

#[cfg(unix)]
#[test]
fn cancel_and_time_limit() {
    cancel::cancel_and_timeout(&app(), &unix_ctx("cancel"));
}

#[cfg(unix)]
#[test]
fn fix_outcomes() {
    fix_outcomes_on(&app(), &unix_ctx("outcomes"));
}

#[cfg(unix)]
#[test]
fn machine_scope_skipped_folders() {
    machine::machine_scope(&app(), &unix_ctx("machine"), false);
}

#[cfg(unix)]
#[test]
fn machine_scope_with_a_real_gap() {
    machine::machine_scope(&app(), &unix_ctx("machine-gap"), true);
}

/// The portable bundle from the release workflow: its app finds the scanner
/// beside it.
#[test]
#[ignore = "needs PANTRY_E2E_BUNDLE, a built wpantry-desktop-<target>.zip"]
fn bundle() {
    let zip = required("PANTRY_E2E_BUNDLE").expect("set PANTRY_E2E_BUNDLE to the bundle ZIP");
    let ctx = Ctx::new("bundle");
    let (app, scanner) = package::extract_bundle(&zip, &ctx.temp);
    ui_suite(&app, &scanner, false, ctx, true);
}

/// Pantry Setup from the release workflow: unpack, the lifecycle checks,
/// install, then the UI checks on the installed app.
#[test]
#[ignore = "needs PANTRY_E2E_SETUP, a built wpantry-setup-<target> download"]
fn setup() {
    let download =
        required("PANTRY_E2E_SETUP").expect("set PANTRY_E2E_SETUP to the Setup download");
    let mut ctx = Ctx::new("setup");
    let (app, scanner) = package::setup_install(&download, &ctx.temp, &mut ctx.env);
    ui_suite(&app, &scanner, false, ctx, true);
}

#[test]
#[ignore = "renders documentation screenshots into PANTRY_E2E_SCREENS"]
fn screens() {
    let out = std::path::absolute(
        std::env::var_os("PANTRY_E2E_SCREENS").expect("set PANTRY_E2E_SCREENS to a folder"),
    )
    .unwrap();
    let scanner = scanner().expect("the screens need the real scanner");
    let mut ctx = Ctx::new("screens");
    ctx.fake_scheduler();
    restart::screens(&app(), Some(&scanner), &ctx.temp, &ctx.env, &out);
}
