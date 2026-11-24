use super::*;
use std::sync::Mutex;
use wpantry::utils::files::test_home;
#[cfg(unix)]
use wpantry::utils::temp::TempDir;

fn p() -> Paths {
    let state = PathBuf::from("/s/wpantry");
    Paths { log: state.join("schedule.log"), last: state.join("last.json"), lock: state.join("schedule.lock"), state }
}

#[test]
fn launchd_plist_names_the_program_and_the_time() {
    let text = plist(Path::new("/u/.local/bin/wpantry"), Every::Day, 9, 30, &p());
    assert!(text.contains("<string>/u/.local/bin/wpantry</string>"));
    assert!(text.contains("<key>Hour</key>\n      <integer>9</integer>"));
    assert!(text.contains("<key>Minute</key>\n      <integer>30</integer>"));
    assert!(text.contains("<string>schedule</string>\n      <string>run</string>"));
    assert!(text.contains("<key>Nice</key>"));
    let hourly = plist(Path::new("/x"), Every::Hour, 0, 0, &p());
    assert!(hourly.contains("<key>StartInterval</key>\n    <integer>3600</integer>"));
    let weekly = plist(Path::new("/x"), Every::Week, 7, 5, &p());
    assert!(weekly.contains("<key>Weekday</key>\n      <integer>1</integer>"));
    let odd = plist(Path::new("/a&b/<w>"), Every::Day, 0, 0, &p());
    assert!(odd.contains("/a&amp;b/&lt;w&gt;"));
}

#[test]
fn systemd_and_cron_entries() {
    let (service, timer) = unit(Path::new("/u/bin/wpantry"), Every::Week, 6, 15, &p());
    assert!(service.contains("ExecStart=/u/bin/wpantry schedule run"));
    assert!(timer.contains("OnCalendar=Mon *-*-* 06:15:00"));
    assert!(timer.contains("Persistent=true"));
    assert!(unit(Path::new("/x"), Every::Hour, 0, 0, &p()).1.contains("OnCalendar=hourly"));
    let line = cron_line(Path::new("/u/bin/wpantry"), Every::Day, 9, 30, &p());
    assert!(line.starts_with("30 9 * * * nice -n 10 /u/bin/wpantry schedule run"));
    assert!(line.ends_with(CRON_MARK));
    assert!(cron_line(Path::new("/x"), Every::Week, 1, 2, &p()).starts_with("2 1 * * 1 "));
}

#[test]
fn every_parses_and_ago_reads() {
    assert_eq!(Every::parse("day"), Some(Every::Day));
    assert_eq!(Every::parse("sometimes"), None);
    assert_eq!(ago(30), "30 s");
    assert_eq!(ago(3600), "60 min");
    assert_eq!(ago(7200), "2 h");
    assert_eq!(ago(3 * 86400), "3 days");
}

#[test]
fn the_lock_is_exclusive_and_stale_locks_are_taken() {
    let d = wpantry::utils::temp::TempDir::new("lock").unwrap();
    let path = d.path().join("schedule.lock");
    let held = Lock::take(&path).unwrap();
    assert!(Lock::take(&path).is_err(), "our own live pid holds it");
    drop(held);
    assert!(!path.exists());
    std::fs::write(&path, "999999999").unwrap();
    let taken = Lock::take(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), std::process::id().to_string());
    drop(taken);
}

#[cfg(unix)]
#[test]
fn words_escapes_and_every_spelling() {
    assert_eq!(Every::parse("hour"), Some(Every::Hour));
    assert_eq!(Every::parse("week"), Some(Every::Week));
    assert_eq!(word(Every::Hour), "every hour");
    assert_eq!(word(Every::Day), "every day");
    assert_eq!(word(Every::Week), "every week (Mondays)");
    assert_eq!(xml_escape("a&b<c>"), "a&amp;b&lt;c&gt;");
    assert_eq!(ago(89), "89 s");
    assert_eq!(ago(90), "1 min");
    assert_eq!(ago(36 * 3600), "1 days");
    let (service, timer) = unit(Path::new("/x"), Every::Day, 9, 5, &p());
    assert!(service.contains("StandardOutput=append:/s/wpantry/systemd.log"));
    assert!(timer.contains("OnCalendar=*-*-* 09:05:00"));
    assert!(cron_line(Path::new("/x"), Every::Hour, 9, 15, &p()).starts_with("15 * * * * "));
}

#[test]
fn the_files_sit_under_home_and_the_program_is_this_one() {
    let _home = test_home();
    let p = paths();
    if hermetic() {
        assert_eq!(p.state, home().join(".local/state/wpantry"));
    }
    assert_eq!(p.lock, p.state.join("schedule.lock"));
    assert_eq!(p.last, p.state.join("last.json"));
    assert_eq!(p.log, p.state.join("schedule.log"));
    assert_eq!(plist_path(), home().join("Library/LaunchAgents").join(format!("{LABEL}.plist")));
    if hermetic() {
        assert_eq!(unit_dir(), home().join(".config/systemd/user"));
    }
    assert!(program().unwrap().is_file());
    let b = backend();
    assert!(!cfg!(target_os = "macos") || b == Backend::Launchd);
    assert_eq!(uid(&|_, _| Err(Error::Failed("no id".into()))), "501");
    assert_eq!(uid(&|_, _| ok("777\n")), "777");
}

/// The job's files land under the temp home only while the XDG
/// overrides are unset (they are on CI); with one set, a test that
/// writes them does nothing.
fn hermetic() -> bool {
    ["XDG_STATE_HOME", "XDG_CONFIG_HOME"].iter().all(|k| std::env::var_os(k).is_none())
}

fn ok(stdout: &str) -> Result<Output> {
    Ok(Output { code: Some(0), stdout: stdout.into(), stderr: String::new() })
}

fn failed(stderr: &str) -> Result<Output> {
    Ok(Output { code: Some(1), stdout: String::new(), stderr: stderr.into() })
}

/// A runner that records each command line and answers from `answer`.
fn recorder<'a>(
    calls: &'a Mutex<Vec<String>>,
    answer: impl Fn(&str) -> Result<Output> + 'a,
) -> impl Fn(&[&OsStr], Duration) -> Result<Output> + 'a {
    move |argv, _| {
        let line = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ");
        let out = answer(&line);
        calls.lock().unwrap().push(line);
        out
    }
}

#[test]
fn a_dry_run_prints_the_job_and_runs_nothing() {
    let _home = test_home();
    let never = |argv: &[&OsStr], _: Duration| -> Result<Output> { panic!("ran {argv:?}") };
    for b in [Backend::Launchd, Backend::Systemd, Backend::Cron] {
        assert_eq!(install_with(Every::Week, (7, 5), true, b, &never).unwrap(), EXIT_OK);
    }
    assert!(!plist_path().exists());
}

#[test]
fn launchd_install_status_and_uninstall() {
    let _home = test_home();
    let calls = Mutex::new(Vec::new());
    // A real launchctl prints the job only while it is loaded; this one
    // answers as if the bootout worked.
    let run = recorder(&calls, |cmd| {
        if cmd.starts_with("launchctl print") {
            failed("Could not find service")
        } else {
            ok(if cmd == "id -u" { "777\n" } else { "" })
        }
    });
    assert_eq!(install_with(Every::Day, (9, 30), false, Backend::Launchd, &run).unwrap(), EXIT_OK);
    let plist = plist_path();
    let text = std::fs::read_to_string(&plist).unwrap();
    assert!(text.contains("<key>Hour</key>\n      <integer>9</integer>"), "{text}");
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "id -u".to_string(),
            format!("launchctl bootout gui/777/{LABEL}"),
            format!("launchctl bootstrap gui/777 {}", plist.display())
        ]
    );
    assert!(paths().state.is_dir());
    assert_eq!(status_with(Backend::Launchd, &run, false).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
    assert!(!plist.exists());
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_OK, "nothing scheduled is not an error");
    assert_eq!(status_with(Backend::Launchd, &run, false).unwrap(), EXIT_OK);
    let run = recorder(&calls, |cmd| {
        if cmd.starts_with("launchctl bootstrap") {
            failed("Bootstrap failed: 5: Input/output error\n")
        } else {
            ok("")
        }
    });
    let err = install_with(Every::Hour, (0, 0), false, Backend::Launchd, &run).unwrap_err();
    assert!(err.to_string().contains("launchctl bootstrap failed: Bootstrap failed"), "{err}");
}

#[test]
fn systemd_install_status_and_uninstall() {
    let _home = test_home();
    if !hermetic() {
        return;
    }
    let calls = Mutex::new(Vec::new());
    // The timer reads inactive once disabled, as systemd answers after `disable --now`.
    let run = recorder(&calls, |cmd| if cmd.contains("is-active") { failed("") } else { ok("") });
    assert_eq!(install_with(Every::Week, (6, 15), false, Backend::Systemd, &run).unwrap(), EXIT_OK);
    let dir = unit_dir();
    assert!(dir.join("wpantry.service").is_file());
    let timer = std::fs::read_to_string(dir.join("wpantry.timer")).unwrap();
    assert!(timer.contains("OnCalendar=Mon *-*-* 06:15:00"), "{timer}");
    assert_eq!(
        *calls.lock().unwrap(),
        ["systemctl --user daemon-reload", "systemctl --user enable --now wpantry.timer"]
    );
    assert_eq!(status_with(Backend::Systemd, &run, false).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert!(!dir.join("wpantry.timer").exists() && !dir.join("wpantry.service").exists());
    assert_eq!(uninstall_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert_eq!(status_with(Backend::Systemd, &run, false).unwrap(), EXIT_OK);
    let run =
        recorder(
            &calls,
            |cmd| {
                if cmd.ends_with("daemon-reload") { failed("Failed to connect to bus\n") } else { ok("") }
            },
        );
    let err = install_with(Every::Day, (1, 2), false, Backend::Systemd, &run).unwrap_err();
    assert!(err.to_string().contains("systemctl --user daemon-reload failed: Failed to connect to bus"), "{err}");
}

/// Oracle: `schedule uninstall` exits 0 and says "removed" only when
/// the job is gone by the scheduler's own evidence (the file no longer
/// exists, the timer is not active, the crontab has no wpantry line, the
/// task is not listed); otherwise it exits 1. Known bad: before the fix each
/// case below returned EXIT_OK and printed "✓ removed ..." while the job
/// stayed (the launchd case is a plist that `remove_file` can't delete).
#[test]
fn uninstall_fails_when_the_job_is_still_there() {
    let _home = test_home();
    // launchd: a plist path remove_file can't delete (a non-empty directory).
    let plist = plist_path();
    std::fs::create_dir_all(plist.join("stuck")).unwrap();
    let run = |argv: &[&OsStr], _: Duration| if argv[1] == "print" { failed("not found") } else { ok("") };
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_FAIL);
    assert!(plist.exists());
    std::fs::remove_dir_all(&plist).unwrap();
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_OK, "nothing scheduled");

    // cron: `crontab FILE` answers 0 but the table keeps our line.
    let table = format!("5 5 * * * old {CRON_MARK}\n");
    let sticky = |argv: &[&OsStr], _: Duration| if argv[1] == "-l" { ok(&table) } else { ok("") };
    assert_eq!(uninstall_with(Backend::Cron, &sticky).unwrap(), EXIT_FAIL);

    // Windows: /delete answers 0 but the task is still listed.
    let stays = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        let tool = argv[0].to_string_lossy();
        if tool.eq_ignore_ascii_case("whoami") || tool.ends_with("whoami.exe") {
            return ok("\"me\",\"S-1-5-21-123\"\n");
        }
        match argv.get(1).map(|a| a.to_string_lossy().into_owned()).as_deref() {
            Some("/query") if argv.get(2).is_some_and(|a| *a == "/fo") => ok(""),
            Some("/query") => ok("<Task><Settings><Enabled>true</Enabled></Settings></Task>"),
            _ => ok(""),
        }
    };
    assert_eq!(uninstall_with(Backend::Windows, &stays).unwrap(), EXIT_FAIL);
}

/// Oracle (launchd): the plist is gone but `launchctl print` still lists
/// the job, so it is still loaded and will run: exit 1 with a next step,
/// never "removed". A launchctl that cannot be asked is no proof either.
/// Known bad: the old code ignored the bootout and never asked, so it
/// printed "removed" and exited 0. Only a recorded launchctl runs here.
#[test]
fn launchd_uninstall_fails_while_the_job_is_still_loaded() {
    let _home = test_home();
    let calls = Mutex::new(Vec::new());
    let loaded = recorder(&calls, |cmd| {
        if cmd.starts_with("launchctl bootout") {
            failed("Boot-out failed: 5: Input/output error")
        } else {
            ok(if cmd == "id -u" { "777\n" } else { "" })
        }
    });
    let plist = plist_path();
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "<plist/>").unwrap();
    assert_eq!(uninstall_with(Backend::Launchd, &loaded).unwrap(), EXIT_FAIL);
    // The plist goes either way: one left in LaunchAgents would load the
    // job again at the next login.
    assert!(!plist.exists(), "the file goes either way");
    assert!(calls.lock().unwrap().contains(&format!("launchctl print gui/777/{LABEL}")), "{:?}", calls.lock().unwrap());
    // Status still reports the job launchd holds.
    let doc = status_json(Backend::Launchd, &loaded).unwrap();
    assert!(doc.contains(r#""installed": false"#) && doc.contains(r#""loaded": true"#), "{doc}");
    let unknown = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        if argv[1] == "print" { Err(Error::Failed("launchctl did not answer".into())) } else { ok("") }
    };
    assert_eq!(uninstall_with(Backend::Launchd, &unknown).unwrap(), EXIT_FAIL);
    let gone =
        |argv: &[&OsStr], _: Duration| if argv[1] == "print" { failed("Could not find service") } else { ok("") };
    assert_eq!(uninstall_with(Backend::Launchd, &gone).unwrap(), EXIT_OK);
}

/// Oracle: `launchctl print` answering 0 means launchd still holds the job.
/// With the plist gone (an older uninstall deleted it after a failed
/// bootout), status says not installed but still loaded. Known bad: the
/// old status read only the plist and reported nothing scheduled.
#[test]
fn launchd_status_reports_a_job_still_loaded_without_its_plist() {
    let _home = test_home();
    let loaded = |argv: &[&OsStr], _: Duration| ok(if argv[0] == "id" { "777\n" } else { "" });
    let doc = status_json(Backend::Launchd, &loaded).unwrap();
    assert!(doc.contains(r#""installed": false"#) && doc.contains(r#""loaded": true"#), "{doc}");
    let gone =
        |argv: &[&OsStr], _: Duration| if argv[1] == "print" { failed("Could not find service") } else { ok("") };
    assert!(status_json(Backend::Launchd, &gone).unwrap().contains(r#""loaded": false"#));
    let unknown = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        if argv.get(1).is_some_and(|a| *a == "print") { Err(Error::Failed("no launchctl".into())) } else { ok("") }
    };
    assert!(status_json(Backend::Launchd, &unknown).unwrap().contains(r#""loaded": null"#));
    let cron = |_: &[&OsStr], _: Duration| ok("");
    assert!(status_json(Backend::Cron, &cron).unwrap().contains(r#""loaded": null"#));
}

/// Oracle (systemd): after removing the unit files, a timer systemd
/// still reports active is a leftover: exit 1. Known bad: the old code
/// never asked and exited 0.
#[test]
fn systemd_uninstall_fails_while_the_timer_is_active() {
    let _home = test_home();
    if !hermetic() {
        return;
    }
    let run = |_: &[&OsStr], _: Duration| ok("");
    assert_eq!(install_with(Every::Day, (6, 15), false, Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Systemd, &run).unwrap(), EXIT_FAIL, "is-active answered 0");
    assert!(!unit_dir().join("wpantry.timer").exists());
}

/// A crontab the runner keeps: `crontab -l` reads it, `crontab FILE` replaces it.
fn crontab_of(table: &Mutex<Option<String>>) -> impl Fn(&[&OsStr], Duration) -> Result<Output> + '_ {
    move |argv, _| {
        assert_eq!(argv[0], "crontab");
        let arg = argv[1].to_string_lossy().into_owned();
        if arg == "-l" {
            return match table.lock().unwrap().clone() {
                Some(t) => ok(&t),
                None => failed("no crontab for me\n"),
            };
        }
        *table.lock().unwrap() = Some(std::fs::read_to_string(&arg).unwrap());
        ok("")
    }
}

#[test]
fn cron_install_replaces_its_own_line_and_keeps_the_rest() {
    let _home = test_home();
    let table = Mutex::new(Some(format!("0 0 * * * other\n5 5 * * * old {CRON_MARK}\n")));
    let run = crontab_of(&table);
    assert_eq!(install_with(Every::Day, (9, 30), false, Backend::Cron, &run).unwrap(), EXIT_OK);
    let now = table.lock().unwrap().clone().unwrap();
    let lines: Vec<&str> = now.lines().collect();
    assert_eq!(lines.len(), 2, "{now}");
    assert_eq!(lines[0], "0 0 * * * other");
    assert!(lines[1].starts_with("30 9 * * * nice -n 10 ") && lines[1].ends_with(CRON_MARK), "{now}");
    assert_eq!(status_with(Backend::Cron, &run, false).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK);
    assert_eq!(table.lock().unwrap().as_deref(), Some("0 0 * * * other\n"));
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK, "nothing left to remove");
    assert_eq!(status_with(Backend::Cron, &run, false).unwrap(), EXIT_OK);
}

#[test]
fn an_empty_crontab_gets_only_our_line_and_a_refusal_is_an_error() {
    let _home = test_home();
    let table = Mutex::new(None);
    let run = crontab_of(&table);
    assert_eq!(install_with(Every::Hour, (0, 10), false, Backend::Cron, &run).unwrap(), EXIT_OK);
    let now = table.lock().unwrap().clone().unwrap();
    assert_eq!(now.lines().count(), 1, "{now}");
    assert!(now.starts_with("10 * * * * nice -n 10 "), "{now}");
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK);
    assert_eq!(table.lock().unwrap().as_deref(), Some(""));
    let refuse = |argv: &[&OsStr], _: Duration| if argv[1] == "-l" { ok("") } else { failed("bad minute\n") };
    let err = install_with(Every::Day, (9, 30), false, Backend::Cron, &refuse).unwrap_err();
    assert!(err.to_string().contains("crontab failed: bad minute"), "{err}");
}

#[test]
fn status_reads_the_last_run_and_the_log_tail() {
    let _home = test_home();
    if !hermetic() {
        return;
    }
    let p = paths();
    std::fs::create_dir_all(&p.state).unwrap();
    std::fs::write(&p.last, r#"{"findings": [{"status": "fail"}, {"status": "warn"}, {"status": "fail"}]}"#).unwrap();
    std::fs::write(
        &p.log,
        "1 sync=0 check=1 3s a\n2 sync=0 check=0 2s b\n3 sync=0 check=0 2s c\n4 sync=1 check=0 9s d\n",
    )
    .unwrap();
    let run = |_: &[&OsStr], _: Duration| ok("");
    assert_eq!(status_with(Backend::Launchd, &run, false).unwrap(), EXIT_OK);
    std::fs::write(&p.last, "not json").unwrap();
    assert_eq!(status_with(Backend::Launchd, &run, false).unwrap(), EXIT_OK);
}

#[cfg(unix)]
#[test]
fn a_scheduled_run_records_the_check_and_logs_one_line() {
    use std::os::unix::fs::PermissionsExt;
    let _home = test_home();
    if !hermetic() {
        return;
    }
    let p = paths();
    std::fs::create_dir_all(&p.state).unwrap();
    let d = TempDir::new("prog").unwrap();
    let prog = d.path().join("wpantry");
    let script = |body: &str| {
        std::fs::write(&prog, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o700)).unwrap();
    };
    let argv_file = d.path().join("argv");
    script(&format!(
        "[ \"$1\" = scan ] && echo \"$@\" > '{}'\ncase \"$1\" in scan) printf '{{\"findings\": []}}'; echo 'done: 0 failing' >&2;; esac\nexit 0",
        argv_file.display()
    ));
    assert_eq!(run_with(&p, &prog).unwrap(), EXIT_OK);
    // Oracle: the arguments the scan really received, not the constant.
    let want =
        if cfg!(target_os = "macos") { "scan --json --no-input --no-personal-files" } else { "scan --json --no-input" };
    assert_eq!(std::fs::read_to_string(&argv_file).unwrap().trim_end(), want);
    assert_eq!(std::fs::read_to_string(&p.last).unwrap(), "{\"findings\": []}");
    let log = std::fs::read_to_string(&p.log).unwrap();
    assert!(log.contains(" sync=0 check=0 ") && log.trim_end().ends_with("done: 0 failing"), "{log}");
    // Findings (exit 1) are a normal run; a crash (exit 3) fails it.
    script("[ \"$1\" = scan ] && exit 1\nexit 0");
    assert_eq!(run_with(&p, &prog).unwrap(), EXIT_OK);
    script("exit 3");
    assert_eq!(run_with(&p, &prog).unwrap(), EXIT_FAIL);
    assert_eq!(std::fs::read_to_string(&p.log).unwrap().lines().count(), 3);
    // The real entry point takes the lock and runs this very binary,
    // which is no wpantry: a failed check, logged.
    assert_eq!(run().unwrap(), EXIT_FAIL);
    assert!(!p.lock.exists());
}

#[test]
fn a_month_quarter_and_year_start_at_the_period_start() {
    let month = plist(Path::new("/x"), Every::Month, 7, 0, &p());
    assert!(month.contains("<key>Day</key>\n      <integer>1</integer>"));
    let quarter = plist(Path::new("/x"), Every::Quarter, 7, 0, &p());
    assert!(quarter.contains("<key>StartCalendarInterval</key>\n    <array>"));
    assert_eq!(quarter.matches("<key>Month</key>").count(), 4);
    assert!(quarter.contains("<key>Month</key>\n      <integer>10</integer>"));
    let year = plist(Path::new("/x"), Every::Year, 7, 0, &p());
    assert!(
        year.contains("<key>Month</key>\n      <integer>1</integer>\n      <key>Day</key>\n      <integer>1</integer>")
    );
    assert!(unit(Path::new("/x"), Every::Month, 7, 0, &p()).1.contains("OnCalendar=*-*-01 07:00:00"));
    assert!(unit(Path::new("/x"), Every::Quarter, 7, 0, &p()).1.contains("OnCalendar=*-01,04,07,10-01 07:00:00"));
    assert!(unit(Path::new("/x"), Every::Year, 7, 0, &p()).1.contains("OnCalendar=*-01-01 07:00:00"));
    assert!(cron_line(Path::new("/x"), Every::Month, 7, 0, &p()).starts_with("0 7 1 * * "));
    assert!(cron_line(Path::new("/x"), Every::Quarter, 7, 0, &p()).starts_with("0 7 1 1,4,7,10 * "));
    assert!(cron_line(Path::new("/x"), Every::Year, 7, 0, &p()).starts_with("0 7 1 1 * "));
    assert_eq!(Every::NAMES.map(|n| Every::parse(n).is_some()), [true; 6]);
    assert_eq!(word(Every::Quarter), "every quarter (1 January, April, July, October)");
}

#[test]
fn reporting_identifies_all_the_intervals_the_schedulers_write() {
    use calendar::read_cadence;
    let program = Path::new("/opt/Pantry tools/wpantry");
    for name in Every::NAMES {
        let period = Every::parse(name).unwrap();
        let at = (8, 25);
        let unix_at = if period == Every::Hour { (0, 0) } else { at };
        let minute_at = if period == Every::Hour { (0, at.1) } else { at };
        assert_eq!(read_cadence(Backend::Launchd, &plist(program, period, 8, 25, &p())), Some((period, unix_at)));
        assert_eq!(read_cadence(Backend::Systemd, &unit(program, period, 8, 25, &p()).1), Some((period, unix_at)));
        assert_eq!(read_cadence(Backend::Cron, &cron_line(program, period, 8, 25, &p())), Some((period, minute_at)));
        assert_eq!(
            read_cadence(Backend::Windows, &windows::definition(program, None, period, at, "S-1-5-21-123")),
            Some((period, at))
        );
    }
    let launcher = Path::new(r"C:\Pantry\wpantry-desktop.exe");
    for name in Every::NAMES {
        let period = Every::parse(name).unwrap();
        let text = windows::definition(program, Some(launcher), period, (8, 25), "S-1-5-21-123");
        assert_eq!(read_cadence(Backend::Windows, &text), Some((period, (8, 25))), "{text}");
    }
    assert_eq!(read_cadence(Backend::Systemd, "OnCalendar=Mon,Wed 14:09"), None);
    assert_eq!(read_cadence(Backend::Cron, "*/5 * * * * true"), None);
    assert!(unit(program, Every::Day, 8, 25, &p()).0.contains(r#"ExecStart="/opt/Pantry tools/wpantry" schedule run"#));
    assert!(cron_line(program, Every::Day, 8, 25, &p()).contains("'/opt/Pantry tools/wpantry' schedule run"));
}

#[test]
fn windows_installs_only_the_current_users_scan_and_checks_its_state() {
    let installed = std::cell::Cell::new(false);
    let run = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        let args = argv.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        match args[0].as_ref() {
            "whoami.exe" => ok("\"fixture\\user\",\"S-1-5-21-123\"\r\n"),
            "schtasks.exe" => match args[1].as_ref() {
                "/create" => {
                    assert_eq!(args[3], "Waffuru-Pantry-S-1-5-21-123");
                    let bytes = std::fs::read(argv[5]).unwrap();
                    assert_eq!(&bytes[..2], &[0xff, 0xfe]);
                    let units =
                        bytes[2..].as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p)).collect::<Vec<_>>();
                    let definition = String::from_utf16(&units).unwrap();
                    assert!(definition.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"));
                    assert!(definition.contains("<UserId>S-1-5-21-123</UserId>"));
                    assert!(definition.contains("<LogonType>InteractiveToken</LogonType>"));
                    assert!(definition.contains("<RunLevel>LeastPrivilege</RunLevel>"));
                    assert!(definition.contains("<Command>C:\\Pantry &amp; tools\\wpantry.exe</Command>"));
                    assert!(definition.contains("<Arguments>schedule run</Arguments>"));
                    assert!(!definition.contains(" fix"));
                    installed.set(true);
                    ok("")
                }
                "/query" if args.get(2).is_some_and(|arg| arg == "/fo") => ok(""),
                "/query" if installed.get() => ok("<Task><Settings><Enabled>false</Enabled></Settings></Task>"),
                "/query" => failed("task not registered"),
                "/delete" => {
                    installed.set(false);
                    ok("")
                }
                other => panic!("unexpected task command {other}"),
            },
            other => panic!("unexpected scheduler tool {other}"),
        }
    };
    assert!(windows::query(&run).unwrap().is_none());
    let path = Path::new(r"\\?\C:\Pantry & tools\wpantry.exe");
    windows::install(path, Every::Week, (8, 25), &run).unwrap();
    let definition = windows::query(&run).unwrap().unwrap();
    assert!(windows::disabled(&definition));
    assert!(windows::uninstall(&run).unwrap());
    assert!(!windows::uninstall(&run).unwrap());
}

/// Oracle: the task names the windowless launcher only when it sits
/// beside the scanner, and then runs `--scheduled-run`; a CLI-only folder
/// keeps the scanner and `schedule run`. Known bad: before this change both
/// cases produced `wpantry.exe schedule run`, which the first assertion on
/// `with_launcher` rejects.
#[test]
fn windows_task_runs_the_windowless_launcher_when_one_sits_beside_the_scanner() {
    let cli_only = wpantry::utils::temp::TempDir::new("cli-only").unwrap();
    let scanner = cli_only.path().join("wpantry.exe");
    std::fs::write(&scanner, b"").unwrap();
    assert_eq!(windows::launcher(&scanner), None);
    let text = windows::definition(&scanner, windows::launcher(&scanner).as_deref(), Every::Day, (9, 30), "S-1");
    assert!(text.contains("<Arguments>schedule run</Arguments>"), "{text}");
    assert!(text.contains("wpantry.exe</Command>"), "{text}");
    assert!(!text.contains("--scheduled-run"), "{text}");

    let with_launcher = wpantry::utils::temp::TempDir::new("with-launcher").unwrap();
    let scanner = with_launcher.path().join("wpantry.exe");
    let beside = with_launcher.path().join("wpantry-desktop.exe");
    std::fs::write(&scanner, b"").unwrap();
    std::fs::write(&beside, b"").unwrap();
    let found = windows::launcher(&scanner).expect("the launcher beside the scanner");
    assert_eq!(found.file_name(), beside.file_name());
    let text = windows::definition(&scanner, Some(&found), Every::Day, (9, 30), "S-1");
    assert!(text.contains("<Arguments>--scheduled-run</Arguments>"), "{text}");
    assert!(text.contains("wpantry-desktop.exe</Command>"), "{text}");
    assert!(!text.contains("schedule run"), "{text}");
    // The rest of the task is unchanged: same user, logon and limits.
    assert!(text.contains("<LogonType>InteractiveToken</LogonType>"));
    assert!(text.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    assert_eq!(calendar::read_cadence(Backend::Windows, &text), Some((Every::Day, (9, 30))));
    assert!(!windows::disabled(&text));

    // Installing through schtasks writes that same launcher task, and
    // `schedule status --json` reads it back.
    let installed = std::sync::Mutex::new(None::<String>);
    let run = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        let args = argv.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        match (args[0].as_ref(), args.get(1).map(|a| a.as_ref())) {
            ("whoami.exe", _) => ok("\"fixture\\user\",\"S-1-5-21-123\"\r\n"),
            ("schtasks.exe", Some("/create")) => {
                let bytes = std::fs::read(argv[5]).unwrap();
                let units = bytes[2..].as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p)).collect::<Vec<_>>();
                *installed.lock().unwrap() = Some(String::from_utf16(&units).unwrap());
                ok("")
            }
            ("schtasks.exe", Some("/query")) => match installed.lock().unwrap().clone() {
                Some(text) if args.get(2).is_some_and(|a| a == "/tn") => ok(&text),
                _ => ok(""),
            },
            other => panic!("unexpected command {other:?}"),
        }
    };
    windows::install(&scanner, Every::Hour, (0, 15), &run).unwrap();
    let text = windows::query(&run).unwrap().unwrap();
    assert!(text.contains("<Arguments>--scheduled-run</Arguments>"), "{text}");
    assert_eq!(calendar::read_cadence(Backend::Windows, &text), Some((Every::Hour, (0, 15))));
    assert_eq!(status_with(Backend::Windows, &run, true).unwrap(), EXIT_OK);
}

/// Oracle: each definition this crate writes reads back to the very program
/// it was written with, quoting undone (spaces, quotes, `&`, `<`, `%`, `$`).
/// Known bad: a reader that returns the raw first word gives
/// `'/opt/Pantry` (cron), `"/opt/Pantry` (systemd) or `/a&amp;b` (launchd).
#[test]
fn the_program_reads_back_from_every_definition() {
    use program::read;
    let odd = ["/u/.local/bin/wpantry", "/opt/Pantry tools/wpantry", "/a&b/<w>/it's \"q\" 100%/$HOME/wpantry"];
    for path in odd {
        let program = Path::new(path);
        let want = Some(program.to_path_buf());
        assert_eq!(read(Backend::Launchd, &plist(program, Every::Day, 9, 30, &p())), want, "{path}");
        assert_eq!(read(Backend::Launchd, &plist(program, Every::Quarter, 9, 30, &p())), want, "{path}");
        assert_eq!(read(Backend::Systemd, &unit(program, Every::Week, 9, 30, &p()).0), want, "{path}");
        assert_eq!(read(Backend::Cron, &cron_line(program, Every::Hour, 9, 30, &p())), want, "{path}");
        let task = windows::definition(program, None, Every::Day, (9, 30), "S-1");
        assert_eq!(read(Backend::Windows, &task), want, "{path}");
    }
    // The Windows task names the launcher when one sits beside the scanner.
    let launcher = Path::new(r"C:\Pantry & co\wpantry-desktop.exe");
    let task = windows::definition(Path::new(r"C:\Pantry & co\wpantry.exe"), Some(launcher), Every::Day, (9, 30), "");
    assert_eq!(read(Backend::Windows, &task), Some(launcher.to_path_buf()));
    // Definitions with no program this reader knows: nothing, not a guess.
    assert_eq!(read(Backend::Launchd, "<plist><dict><key>ProgramArguments</key><array></array></dict></plist>"), None);
    assert_eq!(read(Backend::Launchd, "<plist/>"), None);
    assert_eq!(read(Backend::Systemd, "[Service]\nType=oneshot\n"), None);
    assert_eq!(read(Backend::Systemd, "ExecStart=\"/unterminated"), None);
    assert_eq!(read(Backend::Cron, "5 5 * * * old # wpantry schedule"), None);
    assert_eq!(read(Backend::Windows, "<Task/>"), None);
}

fn program_in(doc: &str) -> Option<String> {
    let value = wpantry::utils::json::parse(doc.as_bytes(), wpantry::utils::json::MAX_DOCUMENT).unwrap();
    assert!(value.get("program").is_some(), "the field is always there: {doc}");
    value.get("program").and_then(|v| v.as_str()).map(str::to_owned)
}

/// Oracle: `schedule status --json` reports the program baked into the job
/// on disk (written here for another wpantry, `/opt/standalone/wpantry`),
/// not this test binary's [`program`]; null with no job. Every scheduler is
/// faked: the job files sit in the temp home and the commands are recorded
/// answers. Known bad: a `program` field filled from `program()` reports
/// this binary, which the first assertion rejects.
#[test]
fn status_json_reports_the_program_another_wpantry_registered() {
    let _home = test_home();
    let other = Path::new("/opt/standalone/wpantry");
    assert_ne!(program().unwrap(), other);
    let quiet = |argv: &[&OsStr], _: Duration| ok(if argv[0] == "id" { "777\n" } else { "" });
    assert_eq!(program_in(&status_json(Backend::Launchd, &quiet).unwrap()), None);
    let plist_file = plist_path();
    std::fs::create_dir_all(plist_file.parent().unwrap()).unwrap();
    std::fs::write(&plist_file, plist(other, Every::Day, 6, 10, &p())).unwrap();
    assert_eq!(program_in(&status_json(Backend::Launchd, &quiet).unwrap()).as_deref(), Some("/opt/standalone/wpantry"));
    // A plist with no ProgramArguments: installed, program unknown.
    std::fs::write(&plist_file, "<plist><dict></dict></plist>").unwrap();
    let doc = status_json(Backend::Launchd, &quiet).unwrap();
    assert!(doc.contains(r#""installed": true"#), "{doc}");
    assert_eq!(program_in(&doc), None);

    let table = Mutex::new(Some(format!("0 0 * * * other\n{}\n", cron_line(other, Every::Day, 6, 10, &p()))));
    assert_eq!(
        program_in(&status_json(Backend::Cron, &crontab_of(&table)).unwrap()).as_deref(),
        Some(other.to_str().unwrap())
    );
    let empty = Mutex::new(None);
    assert_eq!(program_in(&status_json(Backend::Cron, &crontab_of(&empty)).unwrap()), None);

    let task = windows::definition(Path::new(r"C:\Tools\wpantry.exe"), None, Every::Day, (6, 10), "S-1-5-21-123");
    let windows_run = |argv: &[&OsStr], _: Duration| -> Result<Output> {
        match argv[0].to_string_lossy().as_ref() {
            "whoami.exe" => ok("\"fixture\\user\",\"S-1-5-21-123\"\r\n"),
            _ if argv.get(2).is_some_and(|a| *a == "/tn") => ok(&task),
            _ => ok(""),
        }
    };
    assert_eq!(
        program_in(&status_json(Backend::Windows, &windows_run).unwrap()).as_deref(),
        Some(r"C:\Tools\wpantry.exe")
    );

    if hermetic() {
        let dir = unit_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let (service, timer) = unit(other, Every::Day, 6, 10, &p());
        std::fs::write(dir.join("wpantry.timer"), timer).unwrap();
        let systemd = |_: &[&OsStr], _: Duration| ok("");
        // The timer alone names no program.
        assert_eq!(program_in(&status_json(Backend::Systemd, &systemd).unwrap()), None);
        std::fs::write(dir.join("wpantry.service"), service).unwrap();
        assert_eq!(
            program_in(&status_json(Backend::Systemd, &systemd).unwrap()).as_deref(),
            Some(other.to_str().unwrap())
        );
    }
}
