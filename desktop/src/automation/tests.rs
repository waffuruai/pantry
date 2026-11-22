//! The window shows the version the scanner reports, not the app's own.
//!
//! Oracle: the stand-in scanner's answer. Each stand-in reports a version
//! the app was never built as (9.9.x), so a footer that printed the app's
//! compile-time version would read `Pantry 0.6.0` and fail. Known-bad: a
//! scanner that can't say must leave no version at all, never the app's.

use super::*;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

/// A stand-in scanner in a fresh folder of its own: `script` is the body
/// of a `sh` script. Removed (only what this made) on drop. Unix only:
/// Windows would need a batch file.
#[cfg(unix)]
struct StandIn {
    dir: PathBuf,
    path: PathBuf,
}

#[cfg(unix)]
impl StandIn {
    fn new(name: &str, script: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pantry-desktop-version-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wpantry");
        std::fs::write(&path, format!("#!/bin/sh\n{script}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir, path }
    }

    fn driver(&self) -> Driver {
        Driver::new(Pantry::locate(Some(self.path.clone())), None)
    }
}

#[cfg(unix)]
impl Drop for StandIn {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Answers `version --json` and `update --check --json` like the real
/// scanner, with versions of its own; anything else fails.
#[cfg(unix)]
const ANSWERS: &str = r#"case "$*" in
  "version --json") echo '{"version": "9.9.9", "impl": "rust", "schema": 1}' ;;
  "update --check --json") echo '{"current": "9.9.10", "latest": "9.9.10", "available": false, "assets": []}' ;;
  *) echo "not in this stand-in: $*" >&2; exit 2 ;;
esac
"#;

/// The footer's version label (`updates.version`), and every label in
/// the window that names a version: none may be the app's own build.
fn shown_version(driver: &Driver) -> Option<String> {
    let tree = driver.tree();
    let nodes = tree.as_array().unwrap();
    let own = format!("Pantry {}", env!("CARGO_PKG_VERSION"));
    assert!(
        !nodes.iter().any(|node| node["label"] == own.as_str()),
        "the window names the app's build: {tree}"
    );
    nodes
        .iter()
        .find(|node| node["id"] == "updates.version")
        .and_then(|node| node["label"].as_str())
        .map(str::to_owned)
}

#[cfg(unix)]
#[test]
fn the_footer_shows_the_scanners_version_and_follows_it() {
    let stand_in = StandIn::new("answers", ANSWERS);
    let mut driver = stand_in.driver();
    let state = driver.request(Request::Wait).unwrap();
    assert_eq!(state["state"]["scanner_version"], "9.9.9", "{state}");
    assert_eq!(shown_version(&driver).as_deref(), Some("Pantry 9.9.9"));
    assert_ne!(
        env!("CARGO_PKG_VERSION"),
        "9.9.9",
        "the oracle needs a version the app is not"
    );

    // An update check is the scanner talking too: the footer follows it,
    // and the app and scanner still differ, so the mismatch is still said.
    driver
        .request(Request::Dispatch {
            command: app::Action::CheckUpdates,
        })
        .unwrap();
    let state = driver.request(Request::Wait).unwrap();
    assert_eq!(state["state"]["scanner_version"], "9.9.10", "{state}");
    assert_eq!(shown_version(&driver).as_deref(), Some("Pantry 9.9.10"));
    assert_eq!(state["banner"]["kind"], "version_mismatch", "{state}");
}

#[cfg(unix)]
#[test]
fn a_scanner_that_cannot_say_shows_no_version() {
    let stand_in = StandIn::new("silent", "echo 'no such command' >&2\nexit 2\n");
    let mut driver = stand_in.driver();
    let state = driver.request(Request::Wait).unwrap();
    assert!(state["state"]["scanner_version"].is_null(), "{state}");
    assert_eq!(shown_version(&driver), None);
}

/// The footer never names the app's own build when the scanner is missing.
#[test]
fn a_missing_scanner_shows_no_version() {
    let missing = Path::new("/nonexistent/pantry-desktop-test/wpantry");
    let mut driver = Driver::new(Pantry::locate(Some(missing.to_path_buf())), None);
    let state = driver.request(Request::State).unwrap();
    assert!(state["state"]["scanner_version"].is_null(), "{state}");
    assert_eq!(shown_version(&driver), None);
}
