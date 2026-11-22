//! Setup's shortcuts, running-app guards and `--uninstall`, in a profile of
//! their own so the main install stays for the UI checks. Dialog tools and
//! schedulers are stand-ins that only record their arguments.

use crate::harness::Env;
use crate::package::run_setup;
#[cfg(unix)]
use crate::package::setup_stderr;
use std::path::Path;

/// Windows: the install adds the Start menu shortcut. The locks and
/// schedulers below are POSIX-only stand-ins.
#[cfg(windows)]
pub fn setup_shortcut(launcher: &Path, temp: &Path, env: &Env) {
    let profile = temp.join("lifecycle profile");
    let env = env.with(&[("WPANTRY_DESKTOP_HOME", profile.as_os_str())]);
    assert!(
        run_setup(launcher, &env, &["--install-only"])
            .status
            .success()
    );
    assert!(profile.join("shortcuts").join("Pantry.lnk").is_file());
}

/// Hold an exclusive lock on `path` (as the app and Setup take theirs)
/// until the guard drops.
#[cfg(unix)]
fn held(path: &Path) -> std::fs::File {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open the lock file");
    lock.try_lock().expect("take the lock");
    lock
}

#[cfg(unix)]
pub fn setup_lifecycle(launcher: &Path, temp: &Path, env: &Env) {
    let profile = temp.join("lifecycle profile");
    let mut env = env.with(&[("WPANTRY_DESKTOP_HOME", profile.as_os_str())]);
    let log = temp.join("lifecycle tools.log");
    let tools = temp.join("lifecycle bin");
    crate::tools::fake_tools(
        &tools,
        &[
            "osascript",
            "open",
            "zenity",
            "kdialog",
            "notify-send",
            "launchctl",
            "systemctl",
            "crontab",
        ],
        &log,
    );
    env.prepend_path(&tools);
    let run = |extra: &[&str]| run_setup(launcher, &env, extra);
    assert!(run(&["--install-only"]).status.success());
    let (destination, state) = (profile.join("installed"), profile.join("state"));
    let marker = destination.join(".waffuru-pantry-desktop");
    let bundled = std::fs::read_to_string(&marker).expect("the install marker");
    let shortcuts = profile.join("shortcuts");
    let menu_entry = shortcuts.join("applications/ai.waffuru.pantry.desktop");
    if cfg!(target_os = "linux") {
        let exec = crate::package::desktop_exec(&menu_entry, &[]);
        assert_eq!(
            exec,
            [destination.join("wpantry-desktop").display().to_string()]
        );
        let text = std::fs::read_to_string(&menu_entry).unwrap();
        assert!(
            text.contains("StartupWMClass=ai.waffuru.pantry.desktop"),
            "{text}"
        );
        let icon =
            std::fs::read(shortcuts.join("icons/hicolor/256x256/apps/ai.waffuru.pantry.png"))
                .expect("the icon");
        assert!(icon.starts_with(b"\x89PNG"));
    }
    let read = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();

    // Pantry open and the install older: refuse in plain words, change nothing.
    std::fs::write(&marker, "0.0.1").unwrap();
    {
        let _window = held(&state.join("window.lock"));
        let result = run(&["--install-only"]);
        assert!(
            !result.status.success()
                && setup_stderr(&result).contains("Pantry is open. Quit Pantry"),
            "{result:?}"
        );
        let result = run(&[]); // a double-click also shows the dialog
        assert!(
            !result.status.success() && read(&log).contains("Pantry is open"),
            "{result:?}"
        );
        assert_eq!(read(&marker), "0.0.1");
        // Up to date: a plain relaunch only brings the window forward.
        std::fs::write(&marker, &bundled).unwrap();
        let activation = state.join("activate");
        let before = std::fs::metadata(&activation).map_or(0, |m| m.len());
        std::fs::remove_file(&log).expect("clear the tools log");
        assert!(run(&[]).status.success());
        assert_eq!(
            std::fs::metadata(&activation).map_or(0, |m| m.len()),
            before + 1
        );
        assert!(!log.exists());
        assert!(setup_stderr(&run(&["--uninstall"])).contains("Pantry is open"));
    }
    // A second Setup while one runs exits quietly and installs nothing.
    std::fs::write(&marker, "0.0.1").unwrap();
    {
        let _setup = held(&state.join("setup.lock"));
        assert!(run(&["--install-only"]).status.success() && read(&marker) == "0.0.1");
    }
    // A staging folder from a killed run is cleaned on the next install.
    let stale = profile.join(".pantry-setup-999999");
    std::fs::create_dir_all(stale.join("Pantry")).unwrap();
    assert!(run(&["--install-only"]).status.success() && read(&marker) == bundled);
    assert!(!stale.exists());

    // Uninstall removes the app and its menu entry, asks the installed
    // scanner to drop the schedule, and keeps the state folder.
    std::fs::write(state.join("keep"), "user data").unwrap();
    let result = run(&["--uninstall"]);
    assert!(result.status.success(), "{result:?}");
    assert!(!destination.exists() && read(&state.join("keep")) == "user data");
    assert!(!menu_entry.exists());
    let calls = read(&log);
    assert!(
        ["launchctl bootout", "systemctl", "crontab"]
            .iter()
            .any(|tool| calls.contains(tool)),
        "{calls}"
    );
}
