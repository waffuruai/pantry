use super::super::files::test_home;
use super::super::temp::TempDir;
use super::*;

#[test]
fn exec_captures_and_times_out() {
    let o = exec(
        &[OsStr::new("sh"), OsStr::new("-c"), OsStr::new("echo out; echo err >&2; echo $NO_COLOR; exit 3")],
        &[],
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!((o.code, o.stdout.as_str(), o.stderr.as_str()), (Some(3), "out\n1\n", "err\n"));
    assert!(exec(&[OsStr::new("sleep"), OsStr::new("5")], &[], Duration::from_millis(100)).is_err());
    assert_eq!(run(&["/nonexistent/binary"], Duration::from_secs(1)), "");
}

/// A background process holding the pipes doesn't hold the call: not
/// when the program is killed at the deadline, nor when it exits first.
#[test]
fn exec_deadline_covers_processes_left_holding_the_pipes() {
    for script in ["sleep 5 & wait", "sleep 5 &"] {
        let start = Instant::now();
        let got = exec(&[OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)], &[], Duration::from_millis(100));
        assert!(got.is_err(), "{script}");
        assert!(start.elapsed() < Duration::from_secs(3), "{script}: {:?}", start.elapsed());
    }
}

#[test]
fn which_takes_a_path_as_given() {
    assert_eq!(which("/bin/sh"), Some(PathBuf::from("/bin/sh")));
    assert_eq!(which("/nonexistent/wpantry-no-such-binary"), None);
    assert_eq!(which("wpantry-no-such-binary-on-path"), None);
}

#[cfg(unix)]
fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn on_path_lists_distinct_binaries_from_extra_dirs() {
    let d = TempDir::new("onpath").unwrap();
    let name = "wpantry-no-such-binary-on-path";
    executable(&d.path().join("a/bin").join(name), "#!/bin/sh\n");
    std::fs::create_dir_all(d.path().join("b")).unwrap();
    std::os::unix::fs::symlink(d.path().join("a/bin").join(name), d.path().join("b").join(name)).unwrap();
    std::fs::create_dir_all(d.path().join("c")).unwrap();
    std::fs::write(d.path().join("c").join(name), "not executable").unwrap();
    let root = d.path().display().to_string();
    let got = on_path(name, &[format!("{root}/*/bin/"), format!("{root}/b"), format!("{root}/c")]);
    let real = realpath(&format!("{root}/a/bin/{name}"));
    assert_eq!(got, [(format!("{root}/a/bin/{name}"), real)], "the symlink in b is the same binary");
    assert_eq!(realpath("/nonexistent/x"), "/nonexistent/x");
}

#[test]
fn app_clis_live_in_applications() {
    let _home = test_home();
    let cli = home().join("Applications/Wpantry Test.app/Contents/Resources/app/bin/cli");
    std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
    std::fs::write(&cli, "").unwrap();
    assert_eq!(app_cli(&["Wpantry Missing", "Wpantry Test"], "bin/cli"), cli.display().to_string());
    assert_eq!(app_cli(&["Wpantry Missing"], "bin/cli"), "");
}
