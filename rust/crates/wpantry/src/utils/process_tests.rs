use super::super::files::test_home;
use super::super::temp::TempDir;
use super::*;

#[cfg(unix)]
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
#[cfg(unix)]
#[test]
fn exec_deadline_covers_processes_left_holding_the_pipes() {
    for script in ["sleep 5 & wait", "sleep 5 &"] {
        let start = Instant::now();
        let got = exec(&[OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)], &[], Duration::from_millis(100));
        assert!(got.is_err(), "{script}");
        assert!(start.elapsed() < Duration::from_secs(3), "{script}: {:?}", start.elapsed());
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn app_clis_live_in_applications() {
    let _home = test_home();
    let cli = home().join("Applications/Wpantry Test.app/Contents/Resources/app/bin/cli");
    std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
    std::fs::write(&cli, "").unwrap();
    assert_eq!(app_cli(&["Wpantry Missing", "Wpantry Test"], "bin/cli"), cli.display().to_string());
    assert_eq!(app_cli(&["Wpantry Missing"], "bin/cli"), "");
}

#[cfg(unix)]
#[test]
fn a_pipe_hands_over_each_line_and_ends_at_its_deadline() {
    let mut got = Vec::new();
    let printf = [OsStr::new("printf"), OsStr::new("a\\nbb\\n")];
    pipe_lines(&printf, &[OsStr::new("cat")], Duration::from_secs(10), |l| got.push(l.to_vec())).unwrap();
    assert_eq!(got, [b"a".to_vec(), b"bb".to_vec()]);
    let sleep = [OsStr::new("sleep"), OsStr::new("10")];
    let started = Instant::now();
    let e = pipe_lines(&sleep, &[OsStr::new("cat")], Duration::from_millis(200), |_| {}).unwrap_err();
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(5), "both are killed at the deadline");
    assert!(
        pipe_lines(&[OsStr::new("/no/such/program")], &[OsStr::new("cat")], Duration::from_secs(1), |_| {}).is_err()
    );
}

#[test]
fn a_process_is_alive_while_it_runs() {
    assert!(alive(std::process::id()));
    let mut child = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    assert!(!alive(pid), "reaped: gone");
}

/// Risk: wpantry started with a PATH that leaves out the `sbin` folders
/// runs `spctl`, `scutil` and the other system tools by name and gets
/// nothing, so posture checks say they couldn't tell. Oracle: the tool's
/// own copy in a system folder, and PATH still winning when it has one.
#[cfg(unix)]
#[test]
fn a_system_tool_runs_from_its_folder_when_path_leaves_it_out() {
    let d = TempDir::new("resolve").unwrap();
    // `sysctl` is in /usr/sbin or /sbin on every Unix CI runs on.
    let in_system = |p: &Path| SYSTEM_DIRS.iter().any(|dir| p == Path::new(dir).join("sysctl"));
    let tool = resolve(OsStr::new("sysctl"), Some(d.path().as_os_str()));
    assert!(in_system(&tool), "{}", tool.display());
    let tool = resolve(OsStr::new("sysctl"), None);
    assert!(in_system(&tool), "no PATH at all: {}", tool.display());
    // PATH has its own: the spawn finds it there, so the name stays.
    executable(&d.path().join("sysctl"), "#!/bin/sh\necho mine\n");
    assert_eq!(resolve(OsStr::new("sysctl"), Some(d.path().as_os_str())), PathBuf::from("sysctl"));
    // A path, or a name no folder has, is left as it is; so is a tool of
    // the bin folders, which the spawn's own search already covers.
    assert_eq!(resolve(OsStr::new("./sysctl"), None), PathBuf::from("./sysctl"));
    let missing = "wpantry-no-such-tool";
    assert_eq!(resolve(OsStr::new(missing), Some(d.path().as_os_str())), PathBuf::from(missing));
    assert_eq!(resolve(OsStr::new("sh"), Some(d.path().as_os_str())), PathBuf::from("sh"));
}

/// Risk: `which` and `resolve` look in different places, so a check that
/// asks `which` whether a tool is there says "unknown" about one `exec` would
/// run (or the reverse). Oracle: for each case the answer is fixed by the
/// folders laid out below, not by running either function twice: a tool on
/// PATH is found there (and PATH wins over the system folder), a tool only in
/// a system folder is found there by both, a file that isn't executable and a
/// missing name are found by neither.
#[cfg(unix)]
#[test]
fn which_and_resolve_agree_on_where_a_tool_is() {
    let d = TempDir::new("lookup").unwrap();
    let (bin, sbin) = (d.path().join("bin"), d.path().join("sbin"));
    executable(&bin.join("on-path-only"), "#!/bin/sh\n");
    executable(&sbin.join("sbin-only"), "#!/bin/sh\n");
    executable(&bin.join("in-both"), "#!/bin/sh\n");
    executable(&sbin.join("in-both"), "#!/bin/sh\n");
    std::fs::write(sbin.join("not-executable"), "data").unwrap();
    let system = [sbin.to_str().unwrap()];
    let path = bin.as_os_str();
    // (name, `which`, `resolve`): `resolve` keeps the bare name when the
    // spawn finds the tool by itself (PATH) or can't find it at all.
    let on_path = |n: &str| (Some(bin.join(n)), PathBuf::from(n));
    let in_sbin = |n: &str| (Some(sbin.join(n)), sbin.join(n));
    let nowhere = |n: &str| (None, PathBuf::from(n));
    for (name, (which, resolved)) in [
        ("on-path-only", on_path("on-path-only")),
        ("sbin-only", in_sbin("sbin-only")),
        ("in-both", on_path("in-both")),
        ("not-executable", nowhere("not-executable")),
        ("no-such-tool", nowhere("no-such-tool")),
    ] {
        assert_eq!(which_with(name, Some(path), &system), which, "which({name})");
        assert_eq!(resolve_with(OsStr::new(name), Some(path), &system), resolved, "resolve({name})");
        // The invariant itself: when `resolve` turns a name into a path, that
        // is the path `which` reports; when it keeps the name, `which` has
        // it on PATH or not at all.
        let w = which_with(name, Some(path), &system);
        if resolved.is_absolute() {
            assert_eq!(w, Some(resolved), "{name}");
        } else {
            assert!(w.is_none_or(|p| p.starts_with(&bin)), "{name}");
        }
    }
    // No PATH at all: the system folder still answers, for both.
    assert_eq!(which_with("sbin-only", None, &system), Some(sbin.join("sbin-only")));
    assert_eq!(resolve_with(OsStr::new("sbin-only"), None, &system), sbin.join("sbin-only"));
    // The real folders: `sysctl` is in /usr/sbin or /sbin on every Unix CI
    // runs on, and PATH here has neither.
    let nope = Some(OsStr::new("/nowhere"));
    let found = which_in("sysctl", nope).expect("sysctl is in a system folder");
    assert_eq!(found, resolve(OsStr::new("sysctl"), nope));
    assert!(SYSTEM_DIRS.iter().any(|dir| found == Path::new(dir).join("sysctl")), "{}", found.display());
    assert_eq!(which_in("wpantry-no-such-tool", nope), None);
}

/// Risk: a spawn as root takes the bare name, so a tool the probe found in a
/// system folder fails to start (the rule file is written, nothing loads it).
/// Oracle: the program the command would start is the one `resolve` names for
/// the same PATH; through sudo the whole argv goes to sudo untouched.
#[cfg(unix)]
#[test]
fn a_root_command_runs_the_program_the_probe_resolved() {
    let nope = Some(OsStr::new("/nowhere"));
    let argv = [OsStr::new("sysctl"), OsStr::new("-n"), OsStr::new("kern.ostype")];
    let direct = root_command(&argv, true, nope);
    assert_eq!(Path::new(direct.get_program()), resolve(OsStr::new("sysctl"), nope), "resolved, not the bare name");
    assert!(Path::new(direct.get_program()).is_absolute());
    assert_eq!(direct.get_args().collect::<Vec<_>>(), [OsStr::new("-n"), OsStr::new("kern.ostype")]);
    let sudo = root_command(&argv, false, nope);
    assert_eq!(sudo.get_program(), "sudo");
    assert_eq!(sudo.get_args().collect::<Vec<_>>(), argv);
    // A tool PATH has is left to the spawn's own search.
    let d = TempDir::new("rootcmd").unwrap();
    executable(&d.path().join("sysctl"), "#!/bin/sh\n");
    assert_eq!(root_command(&argv, true, Some(d.path().as_os_str())).get_program(), "sysctl");
}

/// Risk: only `which` left out the folders a scan must not open
/// (`--no-personal-files`), so the tool inventory (`on_path`, which stats
/// `dir/name` in every PATH folder) and the Python search (which lists
/// `python3.*` in each) still touched a PATH folder like `~/Documents/bin`,
/// which on macOS raises the privacy prompt. Oracle: what a consumer finds.
/// A tool in a left-out PATH folder is found when nothing is left out (the
/// witness: the consumer does look there), and not when its folder is, for
/// PATH's folders and for the extra folders a caller adds; the reachable
/// folder is still searched. Known bad: filter only in `which`.
#[cfg(unix)]
#[test]
fn no_path_consumer_looks_inside_a_left_out_folder() {
    let _home = test_home();
    let h = home();
    let name = "wpantry-no-such-binary-left-out";
    let (shut, open) = (h.join("Documents/bin"), h.join("tools/bin"));
    executable(&shut.join(name), "#!/bin/sh\n");
    executable(&open.join(name), "#!/bin/sh\n");
    let path = std::env::join_paths([&shut, &open]).unwrap();
    let extra = [shut.display().to_string()];
    let none: &[&str] = &[];
    // The witness: with nothing left out both are searched.
    assert_eq!(path_dirs_of(Some(&path)).len(), 2);
    assert_eq!(on_path_in(name, path_dirs_of(Some(&path)), none).len(), 2);
    assert_eq!(on_path_in(name, Vec::new(), &extra).len(), 1);
    let guard = crate::utils::privacy::leave_out(crate::utils::privacy::folders(&h, false), Vec::new());
    assert_eq!(path_dirs_of(Some(&path)), [open.display().to_string()], "PATH without the left-out folder");
    let got = on_path_in(name, path_dirs_of(Some(&path)), none);
    assert_eq!(got.iter().map(|(shown, _)| shown.clone()).collect::<Vec<_>>(), [format!("{}/{name}", open.display())]);
    assert!(on_path_in(name, Vec::new(), &extra).is_empty(), "an extra folder is left out too");
    assert_eq!(reachable(vec![shut.display().to_string(), open.display().to_string()]), [open.display().to_string()]);
    drop(guard);
    assert_eq!(path_dirs_of(Some(&path)).len(), 2, "the folder is back once the guard ends");
}

/// Risk: after `which`, `resolve` and the spawns share one `lookup`, a
/// filter on only one of them would let another still stat a left-out PATH
/// folder. Oracle: what each returns. With a tool in a left-out PATH folder
/// and a copy in a system folder, both give the system copy once the folder
/// is left out (the system folder is never filtered), and the PATH copy when
/// nothing is. Known bad: no filter in `lookup`.
#[cfg(unix)]
#[test]
fn which_and_resolve_skip_a_left_out_path_folder_but_not_the_system_folders() {
    let _home = test_home();
    let h = home();
    let name = "wpantry-no-such-tool-lookup";
    let (shut, sys) = (h.join("Documents/bin"), h.join("sysbin"));
    executable(&shut.join(name), "#!/bin/sh\n");
    executable(&sys.join(name), "#!/bin/sh\n");
    let path = std::env::join_paths([&shut]).unwrap();
    let system = [sys.to_str().unwrap()];
    assert_eq!(which_with(name, Some(&path), &system), Some(shut.join(name)), "the witness: it looks there");
    let guard = crate::utils::privacy::leave_out(crate::utils::privacy::folders(&h, false), Vec::new());
    assert_eq!(which_with(name, Some(&path), &system), Some(sys.join(name)));
    assert_eq!(resolve_with(OsStr::new(name), Some(&path), &system), sys.join(name));
    drop(guard);
}
