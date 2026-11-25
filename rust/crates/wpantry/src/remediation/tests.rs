use super::*;

fn f(cmd: &str, auto: bool, status: &str) -> Finding {
    Finding {
        kind: "tool".into(),
        component: cmd.rsplit(' ').next().unwrap_or("").into(),
        version: "1".into(),
        vuln_id: "CVE-1".into(),
        status: status.into(),
        fix_cmd: cmd.into(),
        fix_auto: auto,
        ..Default::default()
    }
}

// The test vectors the Python implementation had (`Plan` and `Mise`).
#[test]
fn plan_dedupes_and_splits() {
    let (auto, manual, optional) = plan(&[
        f("brew upgrade a", true, "fail"),
        f("brew upgrade a", true, "fail"),
        f("sudo apt-get install b", false, "fail"),
        f("Update App", false, "warn"),
    ]);
    assert_eq!(
        (auto, manual, optional),
        (
            vec!["brew upgrade a".to_string()],
            vec!["sudo apt-get install b".to_string()],
            vec!["Update App".to_string()]
        )
    );
}

/// Seventeen generic hits in one test-vector file are one decision in
/// the plan, not seventeen steps: one script for all of them.
#[test]
fn secret_hits_in_one_file_are_one_step() {
    use crate::checks::supply_chain::leaks;
    let hit = |n: i64| Finding {
        kind: "secret".into(),
        component: "repo/TestVectors/xts.txt".into(),
        location: format!("line {n}, commit abc"),
        vuln_id: "generic-api-key".into(),
        status: "warn".into(),
        fix_cmd: leaks::fix("~/repo", "TestVectors/xts.txt", &[("generic-api-key", n, "abc")], true),
        ..Default::default()
    };
    let fs: Vec<Finding> = (1..=5).map(hit).collect();
    let (auto, manual, optional) = plan(&fs);
    assert!(auto.is_empty() && manual.is_empty());
    assert_eq!(optional.len(), 1, "{optional:?}");
    let step = &optional[0];
    assert!(step.starts_with("# 5 hits in TestVectors/xts.txt (generic rules: review). If any is real"), "{step}");
    assert!(step.contains("\ngit -C \"$repo\" show abc:TestVectors/xts.txt | sed -n '1p;2p;3p;4p;5p'\n"), "{step}");
    assert!(
        step.ends_with("printf '\\n[secret generic-api-key]\\n%s\\n' /TestVectors/xts.txt >> \"$repo/.pantryignore\""),
        "{step}"
    );
    // Hits of two rules: the section for every secret rule.
    let mut two: Vec<Finding> = (1..=2).map(hit).collect();
    two[1].vuln_id = "jwt".into();
    let (_, _, optional) = plan(&two);
    assert!(
        optional[0].ends_with("printf '\\n[secret]\\n%s\\n' /TestVectors/xts.txt >> \"$repo/.pantryignore\""),
        "{}",
        optional[0]
    );
}

#[test]
fn steps_keep_the_findings_each_command_covers() {
    let fs = [
        f("brew upgrade a", true, "fail"),
        f("brew upgrade a", true, "fail"),
        Finding { component: "b".into(), ..f("sudo apt-get install b", false, "warn") },
        Finding { component: "c".into(), ..f("sudo apt-get install b", false, "fail") },
        Finding { fix_cmd: String::new(), ..f("", false, "fail") },
    ];
    let steps = steps(&fs);
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(
        (steps[0].cmd.as_str(), steps[0].mode(), steps[0].findings.as_slice()),
        ("brew upgrade a", "auto", &[0, 1][..])
    );
    // Two components sharing a command are one step; a failing one anywhere makes it manual, not optional.
    assert_eq!(
        (steps[1].cmd.as_str(), steps[1].mode(), steps[1].findings.as_slice()),
        ("sudo apt-get install b", "manual", &[3, 2][..])
    );
}

#[test]
fn one_fix_per_component_covers_every_advisory() {
    let fs: Vec<Finding> = [("CVE-1", "0.23.45"), ("CVE-2", "0.23.46")]
        .iter()
        .map(|(id, safe)| Finding {
            component: "rustls".into(),
            vuln_id: id.to_string(),
            fixed: safe.to_string(),
            ..f(&format!("cargo update -p rustls --precise {safe}"), false, "fail")
        })
        .collect();
    assert_eq!(plan(&fs).1, ["cargo update -p rustls --precise 0.23.46"]);
}

#[test]
fn dryrun_runs_nothing() {
    let mut lines = Vec::new();
    assert_eq!(apply(&[f("false", true, "fail")], true, &|_| true, &mut |l| lines.push(l.to_string())).status, 0);
    assert!(lines.contains(&"  would run: false".to_string()));
    let mut lines = Vec::new();
    assert_eq!(apply(&[f("false", true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string())).status, 1);
    assert!(lines.contains(&"  ✗ failed: false".to_string()));
    // Declined: the command is offered, and nothing runs.
    let mut lines = Vec::new();
    let offered = std::cell::RefCell::new(Vec::new());
    let decline = |cmds: &[String]| {
        offered.borrow_mut().extend_from_slice(cmds);
        false
    };
    assert_eq!(apply(&[f("false", true, "fail")], false, &decline, &mut |l| lines.push(l.to_string())).status, 0);
    assert_eq!(*offered.borrow(), ["false"]);
    assert!(lines.contains(&"  Nothing was changed.".to_string()));
    assert!(!lines.iter().any(|l| l.contains("failed")));
}

#[test]
fn update_never_upgrades_mise() {
    let fs = [
        Finding { component: "mise".into(), ..f("brew upgrade mise", true, "fail") },
        Finding { component: "node".into(), ..f("mise install node@24.11.1", true, "fail") },
        Finding { component: "all".into(), ..f("brew upgrade", true, "warn") },
    ];
    let (auto, manual, optional) = plan(&fs);
    assert_eq!(
        (auto, manual, optional),
        (vec!["mise install node@24.11.1".to_string()], vec![MISE_FIX.to_string()], vec![])
    );
}

#[test]
fn shlex() {
    assert_eq!(
        shlex_split(r#"cd '/w/my app' && echo "a \"b\" \x" c\ d"#).unwrap(),
        ["cd", "/w/my app", "&&", "echo", r#"a "b" \x"#, "c d"]
    );
    assert_eq!(shlex_split("x 'unclosed"), None);
}

// -- why a fix failed ---------------------------------------------------------
//
// Risk: "✗ failed: <command>" with nothing else leaves the person unable to
// tell a missing tool from a refused version from a full disk. Oracle: what
// the command itself said, as a person reading the terminal would need it:
// its exit code and the end of its stderr, bounded, home shortened, no
// environment, no terminal escapes. The commands are `sh` one-liners: stand-ins
// that print and exit, never a package manager.

#[cfg(unix)]
fn failing(script: &str) -> (Applied, Vec<String>) {
    let mut lines = Vec::new();
    let cmd = format!("sh -c '{script}'");
    let applied = apply(&[f(&cmd, true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string()));
    (applied, lines)
}

#[cfg(unix)]
#[test]
fn a_failed_fix_says_its_exit_code_and_what_it_wrote_to_stderr() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home().display().to_string();
    let (applied, lines) =
        failing(&format!("echo mise ERROR no such version >&2; echo cannot write {h}/.cache/x >&2; exit 4"));
    assert_eq!(applied.status, 1);
    assert_eq!(applied.ran.len(), 1);
    assert!(!applied.ran[0].1);
    // The line that was there before stays as it was.
    assert!(lines.iter().any(|l| l.starts_with("  ✗ failed: sh -c ")), "{lines:?}");
    assert!(lines.contains(&"    exit code: 4".to_string()), "{lines:?}");
    assert!(lines.contains(&"      mise ERROR no such version".to_string()), "{lines:?}");
    assert!(lines.contains(&"      cannot write ~/.cache/x".to_string()), "{lines:?}");
    let shown = lines.iter().position(|l| l == "    exit code: 4").unwrap();
    assert!(!lines[shown..].iter().any(|l| l.contains(&h)), "the home directory is shortened: {lines:?}");
    let x = &applied.failures[0];
    assert_eq!((x.exit_code, x.reason.as_str()), (Some(4), ""));
    assert_eq!(x.stderr, "mise ERROR no such version\ncannot write ~/.cache/x");
    drop(home);
}

#[cfg(unix)]
#[test]
fn a_success_has_no_failure() {
    let mut lines = Vec::new();
    let a = apply(&[f("sh -c 'echo noise >&2'", true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string()));
    assert_eq!((a.status, a.ran.len(), a.failures.len()), (0, 1, 0));
    assert!(!lines.iter().any(|l| l.contains("failed") || l.contains("stderr")), "{lines:?}");
}

#[cfg(unix)]
#[test]
fn the_stderr_tail_is_bounded() {
    // 3000 lines of ~10 bytes: more than 20 lines and more than 4 KiB.
    let (a, lines) = failing("i=0; while [ $i -lt 3000 ]; do echo line$i >&2; i=$((i+1)); done; exit 1");
    let x = &a.failures[0];
    let kept: Vec<&str> = x.stderr.lines().collect();
    assert_eq!(kept.len(), run::TAIL_LINES, "{kept:?}");
    assert_eq!((kept[0], kept[19]), ("line2980", "line2999"));
    assert!(x.stderr.len() <= run::TAIL_BYTES);
    assert!(lines.contains(&"    stderr (last 20 lines):".to_string()));
    // One enormous line is cut, not printed whole.
    let (a, _) = failing("head -c 9000 /dev/zero | tr \"\\\\0\" x >&2; exit 1");
    assert!(a.failures[0].stderr.chars().count() <= 401, "{}", a.failures[0].stderr.len());
}

#[test]
fn clean_tail_drops_environment_lines_escapes_and_redraws() {
    // An environment dump is never carried; a line that merely has an `=` is.
    let text = "PATH=/usr/bin\nSECRET_TOKEN=abc\nHOME=/h\nerror: version=3.14 is not installed\n";
    assert_eq!(run::clean_tail(text.as_bytes(), false), "error: version=3.14 is not installed");
    // Colour codes and a progress bar's redraws: what the screen ended on.
    let text = "\u{1b}[31merror\u{1b}[0m: boom\n10%\r50%\rdone\n\u{1b}]0;title\u{7}ok\u{0}\n";
    assert_eq!(run::clean_tail(text.as_bytes(), false), "error: boom\ndone\nok");
    // Cut output starts mid-line: that line is not shown.
    assert_eq!(run::clean_tail(b"rtial line\nwhole line\n", true), "whole line");
    assert_eq!(run::clean_tail(b"", false), "");
    // Invalid UTF-8 doesn't fail it.
    assert_eq!(run::clean_tail(b"bad \xff byte\n", false), "bad \u{fffd} byte");
}

#[cfg(unix)]
#[test]
fn a_fix_that_cannot_start_or_is_stopped_says_so_without_an_exit_code() {
    let r = run::run_bounded(&["/nonexistent/wpantry-no-such-tool".to_string()], std::time::Duration::from_secs(5));
    assert!(
        !r.ok && r.exit_code.is_none() && r.reason.starts_with("`/nonexistent/wpantry-no-such-tool` was not found"),
        "{r:?}"
    );
    let sh = |s: &str| vec!["sh".to_string(), "-c".to_string(), s.to_string()];
    let r = run::run_bounded(&sh("echo slow >&2; sleep 5"), std::time::Duration::from_millis(200));
    assert!(!r.ok && r.exit_code.is_none(), "{r:?}");
    assert_eq!(r.reason, "timed out after 200 ms and was stopped");
    assert_eq!(r.stderr, "slow");
    let r = run::run_bounded(&sh("kill -9 $$"), std::time::Duration::from_secs(5));
    assert_eq!((r.exit_code, r.reason.as_str()), (None, "stopped by a signal"));
    // A command that isn't one word list at all.
    let mut lines = Vec::new();
    let a = apply(&[f("echo 'unclosed", true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string()));
    assert_eq!(a.status, 1);
    assert!(lines.contains(&"    not a command wpantry can run unattended".to_string()), "{lines:?}");
}

/// A process the fix left running holds stderr open; the report doesn't wait for it.
#[cfg(unix)]
#[test]
fn a_left_behind_process_holding_stderr_does_not_hold_the_report() {
    let start = std::time::Instant::now();
    let (a, _) = failing("sleep 6 & echo partial >&2; exit 2");
    assert!(start.elapsed() < std::time::Duration::from_secs(4), "{:?}", start.elapsed());
    assert_eq!((a.failures[0].exit_code, a.failures[0].stderr.as_str()), (Some(2), "partial"));
}

/// #330: mise was not on the app's PATH, the spawn failed, and the user saw
/// only "failed". Oracle: the line says the program was not found and where
/// wpantry looked (PATH, and the places its installer uses). A name no
/// installer is known for gets PATH only.
#[test]
fn a_fix_program_that_is_not_found_says_where_wpantry_looked() {
    let mut lines = Vec::new();
    let a = apply(&[f("wpantry-no-such-tool upgrade x", true, "fail")], false, &|_| true, &mut |l| {
        lines.push(l.to_string())
    });
    assert_eq!(a.status, 1);
    let why = lines.iter().find(|l| l.contains("was not found")).unwrap_or_else(|| panic!("{lines:?}"));
    assert!(why.contains("`wpantry-no-such-tool` was not found: wpantry looked in PATH ("), "{why}");
    assert!(!why.contains(", and in "), "no installer places for an unknown program: {why}");
    // mise and brew name their installers' places too.
    let m = run::run_bounded(&["wpantry-never-a-tool".to_string()], std::time::Duration::from_secs(1));
    assert!(m.exit_code.is_none() && !m.ok);
    let places = crate::utils::process::tool_places("mise", std::path::Path::new("/h"), &|_| None);
    assert_eq!(
        places.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        ["/h/.local/bin/mise", "/opt/homebrew/bin/mise", "/usr/local/bin/mise", "/home/linuxbrew/.linuxbrew/bin/mise"]
    );
    let env = |k: &str| match k {
        "MISE_INSTALL_PATH" => Some("/opt/m/mise".into()),
        "HOMEBREW_PREFIX" => Some("/brew".into()),
        _ => None,
    };
    let places = crate::utils::process::tool_places("mise", std::path::Path::new("/h"), &env);
    assert_eq!(places[0].display().to_string(), "/opt/m/mise");
    let brew = crate::utils::process::tool_places("brew", std::path::Path::new("/h"), &env);
    assert_eq!(
        brew.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        ["/brew/bin/brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew", "/home/linuxbrew/.linuxbrew/bin/brew"]
    );
    assert!(crate::utils::process::tool_places("jq", std::path::Path::new("/h"), &env).is_empty());
}

/// A program only in an installer's place is found there when PATH lacks it:
/// only located here, never run (a real mise may be on PATH or not).
#[cfg(unix)]
#[test]
fn a_program_in_its_installers_place_is_found_when_path_lacks_it() {
    use std::os::unix::fs::PermissionsExt;
    let _home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    let mise = h.join(".local/bin/mise");
    std::fs::create_dir_all(mise.parent().unwrap()).unwrap();
    std::fs::write(&mise, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&mise, std::fs::Permissions::from_mode(0o755)).unwrap();
    let found = crate::utils::process::find_tool("mise").unwrap();
    assert!(found == mise || crate::utils::process::which("mise").as_deref() == Some(found.as_path()), "{found:?}");
}

/// A fix of two mise commands is two steps, the first as the finding says
/// and the second never unattended; a script stays one step.
#[test]
fn a_two_line_mise_fix_is_two_steps_and_only_the_first_may_run() {
    let fix = "mise install python@3.14.10\nmise uninstall python@3.14.9";
    let fs = [Finding { component: "python".into(), ..f(fix, true, "fail") }];
    let got: Vec<(String, &str)> = steps(&fs).into_iter().map(|s| (s.cmd.clone(), s.mode())).collect();
    assert_eq!(
        got,
        [("mise install python@3.14.10".to_string(), "auto"), ("mise uninstall python@3.14.9".to_string(), "manual")]
    );
    assert!(is_step_of(fix, "mise uninstall python@3.14.9") && is_step_of(fix, "mise install python@3.14.10"));
    assert!(is_step_of("brew upgrade a", "brew upgrade a") && !is_step_of(fix, "mise install node@1"));
    let script = "# 3 hits\ngit -C x show y";
    assert_eq!(steps(&[f(script, false, "warn")]).len(), 1);
}
