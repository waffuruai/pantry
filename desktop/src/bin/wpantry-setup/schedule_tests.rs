use super::*;
use crate::tests::Scratch;

/// A finished helper's output, for the launchd checks.
fn answer(code: i32, stdout: &str, stderr: &str) -> Option<std::process::Output> {
    use std::os::unix::process::ExitStatusExt;
    Some(std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    })
}

// Oracle: launchd's own answer. After the bootout and the plist delete,
// `launchctl print` must fail; if it still lists the job, the direct
// route fails with the bootout step, and a failed bootout's words are
// kept. Known-bad: the old code discarded the bootout result and never
// asked, so Setup said "removed Pantry" with exit 0. Only stand-in
// answers are used: no real launchctl runs.
#[test]
fn the_direct_route_checks_launchd_let_go() {
    use std::sync::Mutex;
    let scratch = Scratch::new();
    let agents = scratch.0.join("Library/LaunchAgents");
    let plist = agents.join(format!("{SCHEDULE_LABEL}.plist"));
    let calls = Mutex::new(Vec::new());
    let stand_in = |loaded: bool, bootout_fails: bool| {
        let calls = &calls;
        move |program: &str, args: &[&str]| {
            calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            match (program, args.first().copied()) {
                ("id", _) => answer(0, "501\n", ""),
                ("launchctl", Some("bootout")) if bootout_fails => {
                    answer(5, "", "Boot-out failed: 5: Input/output error")
                }
                ("launchctl", Some("print")) if !loaded => {
                    answer(113, "", "Could not find service")
                }
                _ => answer(0, "", ""),
            }
        }
    };
    fs::create_dir_all(&agents).unwrap();
    fs::write(&plist, b"<plist/>").unwrap();
    let error = remove_launchd_job(&scratch.0, &stand_in(true, true)).unwrap_err();
    assert!(
        error.contains("still loaded")
            && error.contains(&format!("launchctl bootout gui/501/{SCHEDULE_LABEL}"))
            && error.contains("Boot-out failed"),
        "{error}"
    );
    assert!(!plist.exists(), "the plist goes either way");
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "id -u".to_owned(),
            format!("launchctl bootout gui/501/{SCHEDULE_LABEL}"),
            format!("launchctl print gui/501/{SCHEDULE_LABEL}"),
        ]
    );
    assert_eq!(
        remove_launchd_job(&scratch.0, &stand_in(false, false)),
        Ok(())
    );
    // launchctl that cannot run, or no user id, is not proof it is gone.
    let missing = |program: &str, _: &[&str]| {
        if program == "id" {
            answer(0, "501\n", "")
        } else {
            None
        }
    };
    assert!(remove_launchd_job(&scratch.0, &missing).is_err());
    let no_id = |_: &str, _: &[&str]| answer(1, "", "");
    assert!(
        remove_launchd_job(&scratch.0, &no_id)
            .unwrap_err()
            .contains("log out")
    );
}
