use super::*;
use crate::install::{clean_stale_stages, install};
use crate::tests::{Scratch, app_payload, entries};
use crate::{LEFTOVER_REMOVED, NOT_INSTALLED, SCANNER};
// Only the Unix checks (file modes, a scanner that fails) use these.
#[cfg(unix)]
use crate::install::{Installed, installed_version};
#[cfg(unix)]
use crate::schedule::remove_schedule;
#[cfg(target_os = "linux")]
use crate::shortcuts::{LINUX_ENTRY, LINUX_ENTRY_KEY, LINUX_ICON};
#[cfg(unix)]
use crate::tests::payload;
#[cfg(unix)]
use crate::{APP, NO_PERMISSION, REMOVED};

// Oracle: uninstall removes our folder, then asks the installed scanner
// (its bytes intact) to remove the schedule, and leaves the state folder
// and nothing else beside the install; a foreign folder stays and the
// schedule is not touched.
#[test]
fn uninstall_removes_only_what_setup_made() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    let state = scratch.0.join("state");
    fs::create_dir(&state).unwrap();
    fs::write(state.join("history.db"), b"keep").unwrap();
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();

    let mut called = None;
    let removal = uninstall(
        &destination,
        None,
        |scanner| {
            // The folder step is done before the schedule is touched.
            assert!(!destination.exists());
            called = Some(fs::read(scanner).unwrap());
            Ok(())
        },
        || panic!("the scanner worked"),
    )
    .unwrap();
    assert_eq!(removal, Removal::Removed);
    assert_eq!(called.as_deref(), Some(&b"scanner"[..]));
    assert!(!destination.exists());
    assert_eq!(entries(&scratch.0), ["state"]);
    assert_eq!(fs::read(state.join("history.db")).unwrap(), b"keep");

    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("mine"), b"x").unwrap();
    let error = uninstall(
        &destination,
        None,
        |_| panic!("not ours"),
        || panic!("not ours"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("left it in place"), "{error}");
    assert!(destination.join("mine").is_file());
}

// Oracle: a failed uninstall leaves an install Setup still owns:
// the marker and the files it could not remove are back in place, the
// schedule is untouched, the error says plainly what happened, and a
// later uninstall (once the problem is gone) removes it. Known-bad: the
// old `remove_dir_all` deleted the marker first and then failed, so
// both install and uninstall refused with "found a folder it did not
// create".
#[cfg(unix)]
#[test]
fn failed_uninstall_keeps_the_marker() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(
        &payload(&[
            (APP, b"app", true),
            (SCANNER, b"scanner", true),
            ("zz/locked/file", b"x", false),
        ]),
        &destination,
        "1.0.0",
    )
    .unwrap();
    let locked = destination.join("zz/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    // Root ignores the mode bits; the check needs a refusal to exist.
    if fs::write(locked.join("probe"), b"").is_ok() {
        return;
    }
    let error = uninstall(
        &destination,
        None,
        |_| panic!("schedule touched after a failed folder step"),
        || panic!("schedule touched after a failed folder step"),
    )
    .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("put back what was left") && text.contains(NO_PERMISSION),
        "{text}"
    );
    assert_eq!(installed_version(&destination), Some([1, 0, 0]));
    assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
    assert!(locked.join("file").is_file());
    assert_eq!(entries(&scratch.0), ["installed"]);
    // Setup still owns it: repair works, and so does a later uninstall.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap(),
        Installed::Bundled
    );
    let removal = uninstall(&destination, None, |_| Ok(()), || Ok(())).unwrap();
    assert_eq!(removal, Removal::Removed);
    assert!(scratch.0.read_dir().unwrap().next().is_none());
}

// Oracle: with no install folder, uninstall reports NotInstalled
// (run() prints NOT_INSTALLED, never REMOVED) and touches no schedule.
// Known-bad: the old code returned Ok(()) and run() said "removed".
#[test]
fn uninstall_with_nothing_installed_says_so() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    let removal = uninstall(
        &destination,
        None,
        |_| panic!("nothing installed"),
        || panic!("nothing installed"),
    )
    .unwrap();
    assert_eq!(removal, Removal::NotInstalled);
    assert!(!NOT_INSTALLED.contains("removed Pantry"));
}

// Oracle: an install whose scanner is gone, or whose scanner fails,
// still gets its schedule removed by the direct route; if that cannot
// finish, the error says a scheduled scan may remain and gives the
// steps, and the kept scanner is named. Known-bad: the old code skipped
// the schedule when the scanner was missing and said "removed Pantry".
#[test]
fn uninstall_without_a_scanner_still_removes_the_schedule() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
    fs::remove_file(destination.join(SCANNER)).unwrap();
    let mut direct = false;
    let removal = uninstall(
        &destination,
        None,
        |_| panic!("no scanner"),
        || {
            direct = true;
            Ok(())
        },
    )
    .unwrap();
    assert!(direct && removal == Removal::Removed);
    assert!(scratch.0.read_dir().unwrap().next().is_none());

    // The scanner fails and the direct route cannot finish either.
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
    let error = uninstall(
        &destination,
        None,
        |_| Err(io::Error::other("scanner broke")),
        || Err("To remove it, do X.".into()),
    )
    .unwrap_err();
    let text = error.to_string();
    let keep = scratch
        .0
        .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
    assert!(
        text.contains("a scheduled scan may remain")
            && text.contains("do X")
            && text.contains("scanner broke")
            && text.contains(&keep.display().to_string()),
        "{text}"
    );
    assert!(!destination.exists());
    assert!(keep.join(Path::new(SCANNER).file_name().unwrap()).is_file());
    // A later Setup run clears the kept scanner once it is stale.
    clean_stale_stages(&scratch.0, std::process::id() + 1).unwrap();
    assert!(!keep.exists());
}

// Oracle: the folder an earlier failed uninstall kept is how its
// schedule gets removed. A second uninstall retries with that scanner
// and removes the folder only once the schedule is gone; if it is still
// there the uninstall fails (exit 1), says so, and keeps the folder.
// Known-bad: the old code deleted the kept folder as a stale stage,
// touched no schedule, and printed "removed nothing" with exit 0.
#[test]
fn a_second_uninstall_retries_the_kept_scanner() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
    uninstall(
        &destination,
        None,
        |_| Err(io::Error::other("scanner broke")),
        || Err("To remove it, do X.".into()),
    )
    .unwrap_err();
    // That run's pid is now another process's.
    let ours = scratch
        .0
        .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
    let earlier = scratch.0.join(format!(
        "{UNINSTALL_SCANNER_PREFIX}{}",
        std::process::id() + 1
    ));
    fs::rename(&ours, &earlier).unwrap();
    let kept = earlier.join(Path::new(SCANNER).file_name().unwrap());

    // Still failing: an error, not "removed nothing", and the folder stays.
    let mut tried = Vec::new();
    let error = uninstall(
        &destination,
        None,
        |scanner| {
            tried.push(scanner.to_path_buf());
            Err(io::Error::other("still broken"))
        },
        || Err("To remove it, do Y.".into()),
    )
    .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("is still there") && text.contains("do Y") && text.contains("still broken"),
        "{text}"
    );
    assert!(text.contains(&kept.display().to_string()), "{text}");
    assert_eq!(tried, std::slice::from_ref(&kept));
    assert!(
        kept.is_file(),
        "the kept scanner stays until the schedule is gone"
    );

    // Now it works: the schedule goes first, then the folder.
    let removal = uninstall(
        &destination,
        None,
        |scanner| {
            assert!(scanner.is_file(), "the folder is removed only afterwards");
            Ok(())
        },
        || panic!("the kept scanner worked"),
    )
    .unwrap();
    assert_eq!(removal, Removal::LeftoverRemoved);
    assert!(!earlier.exists());
    assert!(!LEFTOVER_REMOVED.contains("removed nothing"));
    // A third run has nothing left to do.
    let removal = uninstall(&destination, None, |_| panic!("gone"), || panic!("gone")).unwrap();
    assert_eq!(removal, Removal::NotInstalled);
}

// Oracle: through the real `remove_schedule`, an installed scanner
// whose `schedule uninstall` exits 1 (as it does now when launchd still
// has the job) is a failure, never "removed Pantry". The stand-in
// scanner only exits 1.
#[cfg(unix)]
#[test]
fn a_scanner_that_cannot_remove_the_schedule_is_reported() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    let failing: &[u8] = b"#!/bin/sh\nexit 1\n";
    install(
        &payload(&[(APP, b"app", true), (SCANNER, failing, true)]),
        &destination,
        "1.0.0",
    )
    .unwrap();
    let error = uninstall(&destination, None, remove_schedule, || {
        Err("To remove it, do X.".into())
    })
    .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("a scheduled scan may remain")
            && text.contains("schedule uninstall failed")
            && text.contains("do X"),
        "{text}"
    );
    assert!(!text.contains(REMOVED), "{text}");
    // Positive control: when the direct route works, it is removed.
    let earlier = scratch
        .0
        .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
    fs::remove_dir_all(&earlier).unwrap();
    install(
        &payload(&[(APP, b"app", true), (SCANNER, failing, true)]),
        &destination,
        "1.0.0",
    )
    .unwrap();
    let removal = uninstall(&destination, None, remove_schedule, || Ok(())).unwrap();
    assert_eq!(removal, Removal::Removed);
}

// Oracle: with nothing installed, Setup's own menu entry and icon from
// an earlier install still go; someone else's entry stays.
#[cfg(target_os = "linux")]
#[test]
fn stale_shortcuts_go_when_nothing_is_installed() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    let root = scratch.0.join("share");
    let entry = root.join(LINUX_ENTRY);
    let icon = root.join(LINUX_ICON);
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::create_dir_all(icon.parent().unwrap()).unwrap();
    fs::write(&entry, format!("[Desktop Entry]\n{LINUX_ENTRY_KEY}=1\n")).unwrap();
    fs::write(&icon, b"png").unwrap();
    let removal = uninstall(
        &destination,
        Some(&root),
        |_| panic!("none"),
        || panic!("none"),
    )
    .unwrap();
    assert_eq!(removal, Removal::NotInstalled);
    assert!(!entry.exists() && !icon.exists());
}
