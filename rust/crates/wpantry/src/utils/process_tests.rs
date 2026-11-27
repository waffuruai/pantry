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
    // PATH has its own: it is spawned by the path found there, not by a name the spawn would look up again.
    executable(&d.path().join("sysctl"), "#!/bin/sh\necho mine\n");
    assert_eq!(resolve(OsStr::new("sysctl"), Some(d.path().as_os_str())), d.path().join("sysctl"));
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
    // (name, `which`, `resolve`): `resolve` keeps the bare name only when the tool is nowhere
    // (the spawn then fails as it would have).
    let on_path = |n: &str| (Some(bin.join(n)), bin.join(n));
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
    // A tool PATH has is spawned by the path it was found at.
    let d = TempDir::new("rootcmd").unwrap();
    executable(&d.path().join("sysctl"), "#!/bin/sh\n");
    assert_eq!(
        root_command(&argv, true, Some(d.path().as_os_str())).get_program(),
        d.path().join("sysctl").as_os_str()
    );
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

/// #326: an app or a service starts with `PATH=/usr/bin:/bin`, and `brew`
/// is not on it. Oracle: brew is found at `$HOMEBREW_PREFIX/bin` or its
/// standard prefix, as it would be from a terminal. The known-bad control
/// (no variable, a home with nothing in it) finds a brew only where the
/// machine really has one at a standard prefix, so the answer follows the
/// disk and not the PATH. Files only: nothing is run.
#[cfg(unix)]
#[test]
fn brew_is_found_at_its_prefix_when_path_is_minimal() {
    let d = TempDir::new("brewprefix").unwrap();
    let prefix = d.path().join("prefix");
    executable(&prefix.join("bin/brew"), "#!/bin/sh\n");
    let minimal = Some(std::ffi::OsString::from("/usr/bin:/bin"));
    let with = |k: &str| (k == "HOMEBREW_PREFIX").then(|| prefix.clone().into_os_string());
    let home = d.path().join("home");
    assert_eq!(find_tool_in("brew", minimal.clone(), &home, &with), Some(prefix.join("bin/brew")));
    // Control: without the variable, only a real standard prefix can answer.
    let none = |_: &str| None;
    let standard = ["/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"]
        .iter()
        .map(|p| Path::new(p).join("bin/brew"))
        .find(|p| is_executable(p));
    let on_path = which_in("brew", minimal.as_deref());
    assert_eq!(find_tool_in("brew", minimal, &home, &none), on_path.or(standard));
    // A tool with no standard place is on PATH or nowhere.
    assert_eq!(find_tool_in("wpantry-no-such-tool", Some("/usr/bin:/bin".into()), &home, &with), None);
}

/// Risk: as root, the scan runs a `brew` or `mise` from a folder its owner
/// (not root) can write to. Oracle: this process's own answer follows who it
/// is: root looks on PATH alone.
#[test]
fn root_finds_a_tool_on_path_alone() {
    if is_root() {
        assert_eq!(find_tool("brew"), which("brew"));
        assert_eq!(find_tool("mise"), which("mise"));
    } else {
        assert_eq!(
            find_tool("brew"),
            find_tool_in("brew", std::env::var_os("PATH"), &home(), &|k| std::env::var_os(k))
        );
    }
    assert_eq!(is_root(), cfg!(unix) && run(&["id", "-u"], Duration::from_secs(5)).trim() == "0");
}

/// Risk: under `--no-personal-files` the lookup skips a PATH folder that is
/// left out and finds `tool` in a later one, but hands the spawn the bare name
/// `tool`, and the operating system then searches the whole PATH again, the
/// left-out folder first: it opens the folder the scan promised not to touch
/// and runs another program than the one found. Oracle: what is spawned is
/// the file the filtered lookup found, by its path, and `which` and `resolve`
/// name the same file.
#[cfg(unix)]
#[test]
fn a_tool_found_past_a_left_out_folder_is_spawned_by_the_path_that_was_found() {
    let d = TempDir::new("leftout-spawn").unwrap();
    let (left, ok) = (d.path().join("Documents/bin"), d.path().join("bin"));
    executable(&left.join("tool"), "#!/bin/sh\necho left-out copy\n");
    executable(&ok.join("tool"), "#!/bin/sh\necho the copy that was found\n");
    let path = std::env::join_paths([&left, &ok]).unwrap();
    // Nothing left out: the first one on PATH, spawned by its path.
    assert_eq!(which_in("tool", Some(&path)), Some(left.join("tool")));
    let guard = crate::utils::privacy::leave_out(vec![d.path().join("Documents")], Vec::new());
    let found = which_in("tool", Some(&path)).expect("the copy outside the folder is found");
    assert_eq!(found, ok.join("tool"));
    assert_eq!(resolve(OsStr::new("tool"), Some(&path)), found, "the spawn gets the path, not the bare name");
    assert_eq!(root_command(&[OsStr::new("tool")], true, Some(&path)).get_program(), found.as_os_str());
    drop(guard);
}

/// Risk: a tool that only a left-out PATH folder has (`~/Documents/bin/tool`)
/// is found nowhere by the filtered lookup, and the spawn then gets the bare
/// name, so the operating system searches the unfiltered PATH: it opens the
/// folder the scan promised not to touch, and runs that copy. Oracle: (1) the
/// call fails with the "not found, and where it looked" text, which names the
/// folders it searched and says one was left out; (2) the copy never ran (it
/// writes a marker file when it does). Neither can notice a stat: (2) notices
/// a run, (1) notices that the spawn was refused before the operating system
/// searched. A mode-000 folder was tried and does not help: macOS's exec
/// search swallows the permission error and reports "No such file" either way.
#[cfg(unix)]
#[test]
fn a_tool_only_a_left_out_path_folder_has_fails_before_the_spawn() {
    let d = TempDir::new("leftout-only").unwrap();
    let marker = d.path().join("ran");
    let (docs, left, ok) = (d.path().join("Documents"), d.path().join("Documents/bin"), d.path().join("bin"));
    executable(&left.join("tool"), &format!("#!/bin/sh\n: > '{}'\n", marker.display()));
    std::fs::create_dir_all(&ok).unwrap();
    let path = std::env::join_paths([&left, &ok]).unwrap();
    let _guard = crate::utils::privacy::leave_out(vec![docs], Vec::new());
    // The child's own PATH is the same one, so a spawn by name would search it.
    let child_path = path.to_str().unwrap();
    let err = exec_in(&[OsStr::new("tool")], &[("PATH", child_path)], Duration::from_secs(5), Some(&path));
    let text = err.unwrap_err().to_string();
    assert!(text.starts_with("`tool` was not found: wpantry looked in PATH ("), "{text}");
    assert!(text.contains(&ok.display().to_string()), "names the folder it did search: {text}");
    assert!(!text.contains(&left.display().to_string()), "names a folder it did not search: {text}");
    assert!(text.contains("leaves out"), "says a PATH folder was left out: {text}");
    // No PATH to look on at all: also not found, never the bare name.
    let err = exec_in(&[OsStr::new("tool")], &[("PATH", child_path)], Duration::from_secs(5), None);
    assert!(err.is_err_and(|e| e.to_string().contains("was not found")));
    assert!(!marker.exists(), "the left-out copy ran");
}

/// Risk: the same hole through other spellings of the left-out PATH folder.
/// Oracle: each is skipped by the lookup, so the call fails with not-found
/// and the copy never ran (marker). A spelling the lookup mistook for another
/// folder would find the copy and run it.
#[cfg(unix)]
#[test]
fn a_left_out_path_folder_spelled_oddly_is_still_not_spawned() {
    let d = TempDir::new("leftout-spellings").unwrap();
    let marker = d.path().join("ran");
    let docs = d.path().join("Documents");
    executable(&docs.join("bin/tool"), &format!("#!/bin/sh\n: > '{}'\n", marker.display()));
    let _guard = crate::utils::privacy::leave_out(vec![docs.clone()], Vec::new());
    let root = d.path().display().to_string();
    let mut spellings = vec![
        format!("{root}/Documents/bin/"),
        format!("{root}/Documents/./bin"),
        format!("{root}/Documents/x/../bin"),
        format!("{root}/other/../Documents/bin"),
    ];
    if cfg!(target_os = "macos") {
        spellings.push(format!("{root}/documents/BIN"));
    }
    for entry in spellings {
        let path = std::ffi::OsString::from(&entry);
        let got = try_resolve_with(OsStr::new("tool"), Some(&path), &[]);
        assert!(got.is_err(), "{entry}: {got:?}");
        let got = exec_in(&[OsStr::new("tool")], &[("PATH", &entry)], Duration::from_secs(5), Some(&path));
        assert!(got.is_err_and(|e| e.to_string().contains("was not found")), "{entry}");
    }
    assert!(!marker.exists(), "the left-out copy ran");
}

/// Risk: failing for a bare name that is not found must not change what a
/// path or a relative PATH folder means. Oracle: a name with a slash is left
/// as it is (its spawn never searches PATH, and says itself that it is not
/// there); a copy in a relative PATH folder is found and spelled with that
/// folder, so the spawn does not search PATH for it; an empty entry (the
/// current directory) with no copy there is not-found, never the bare name.
/// Not run: an empty entry that does have a copy, which needs a file in the
/// working directory.
#[cfg(unix)]
#[test]
fn a_path_or_a_relative_or_empty_path_entry_is_still_spawned_as_given() {
    let d = TempDir::new("resolve-odd").unwrap();
    let missing = d.path().join("nothing");
    assert_eq!(try_resolve_with(missing.as_os_str(), None, &[]).unwrap(), missing);
    executable(&d.path().join("bin/tool"), "#!/bin/sh\n");
    // The same folder spelled relative to wherever the tests run.
    let up = "../".repeat(std::env::current_dir().unwrap().components().count());
    let rel = format!("{up}{}", d.path().join("bin").to_string_lossy().trim_start_matches('/'));
    let found = try_resolve_with(OsStr::new("tool"), Some(OsStr::new(&rel)), &[]).unwrap();
    assert_eq!(found, Path::new(&rel).join("tool"));
    assert!(found.components().count() > 1, "a bare name would search PATH again");
    assert!(try_resolve_with(OsStr::new("wpantry-odd-entry-tool"), Some(OsStr::new("")), &[]).is_err());
}

/// Risk: on Windows a tool that has the operating system's name (`whoami`,
/// `schtasks`) is found in a PATH folder ahead of the system folder, and the
/// spawn then runs another program with that name (Git's `usr\bin` has a
/// `whoami.exe` that rejects `/user`), which `CreateProcess` by name never
/// did. Oracle: the folders laid out below, not a second call of the same
/// function: a folder searched first wins over PATH, PATH still answers for
/// what the first folders lack, and no first folder changes nothing.
#[test]
fn the_folders_searched_before_path_win_over_path() {
    let d = TempDir::new("first").unwrap();
    let (system, bin) = (d.path().join("system"), d.path().join("bin"));
    for dir in [&system, &bin] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let put = |dir: &Path, name: &str| {
        let file = dir.join(name);
        std::fs::write(&file, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    };
    put(&system, "in-both");
    put(&bin, "in-both");
    put(&bin, "path-only");
    put(&system, "system-only");
    let path = bin.as_os_str();
    let first = [system.clone()];
    let found = |name: &str, first: &[PathBuf]| lookup_with(OsStr::new(name), Some(path), first, &[]);
    assert_eq!(found("in-both", &first), Some(Found::Path(system.join("in-both"))));
    assert_eq!(found("path-only", &first), Some(Found::Path(bin.join("path-only"))));
    assert_eq!(found("system-only", &first), Some(Found::Path(system.join("system-only"))));
    // Without a first folder PATH decides, as before.
    assert_eq!(found("in-both", &[]), Some(Found::Path(bin.join("in-both"))));
    assert_eq!(found("system-only", &[]), None);
    // Off Windows nothing is searched ahead of PATH; on Windows the operating system's own folders are.
    assert_eq!(first_dirs().is_empty(), !cfg!(windows));
    if cfg!(windows) {
        assert!(first_dirs().iter().all(|d| d.is_absolute()), "{:?}", first_dirs());
    }
}

/// Risk: a variable meant to be left out reaches the program, or it runs
/// in the caller's folder (where a repo's config lives). Oracle: `env`
/// prints no `HOME=` line once the prefix `HOME` is scrubbed, `PATH` stays,
/// and `pwd` names the folder given.
#[cfg(unix)]
#[test]
fn run_scrubbed_leaves_out_the_prefix_and_runs_in_the_folder() {
    let d = crate::utils::temp::TempDir::new("scrub").unwrap();
    let out = run_scrubbed(&["env"], Duration::from_secs(10), "HOME", d.path());
    assert!(!out.lines().any(|l| l.starts_with("HOME=")), "{out}");
    assert!(out.lines().any(|l| l.starts_with("PATH=")), "{out}");
    let pwd = run_scrubbed(&["sh", "-c", "pwd -P"], Duration::from_secs(10), "UV_", d.path());
    assert_eq!(pwd.trim(), crate::utils::files::realpath(&d.path().display().to_string()));
}
