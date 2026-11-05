use super::*;
use std::sync::Mutex;
use wpantry::utils::files::test_home;
use wpantry::utils::temp::TempDir;

fn p() -> Paths {
    let state = PathBuf::from("/s/wpantry");
    Paths { log: state.join("schedule.log"), last: state.join("last.json"), lock: state.join("schedule.lock"), state }
}

#[test]
fn launchd_plist_names_the_program_and_the_time() {
    let text = plist(Path::new("/u/.local/bin/wpantry"), Every::Daily, 9, 30, &p());
    assert!(text.contains("<string>/u/.local/bin/wpantry</string>"));
    assert!(text.contains("<key>Hour</key>\n      <integer>9</integer>"));
    assert!(text.contains("<key>Minute</key>\n      <integer>30</integer>"));
    assert!(text.contains("<string>schedule</string>\n      <string>run</string>"));
    assert!(text.contains("<key>Nice</key>"));
    let hourly = plist(Path::new("/x"), Every::Hourly, 0, 0, &p());
    assert!(hourly.contains("<key>StartInterval</key>\n    <integer>3600</integer>"));
    let weekly = plist(Path::new("/x"), Every::Weekly, 7, 5, &p());
    assert!(weekly.contains("<key>Weekday</key>\n      <integer>1</integer>"));
    let odd = plist(Path::new("/a&b/<w>"), Every::Daily, 0, 0, &p());
    assert!(odd.contains("/a&amp;b/&lt;w&gt;"));
}

#[test]
fn systemd_and_cron_entries() {
    let (service, timer) = unit(Path::new("/u/bin/wpantry"), Every::Weekly, 6, 15, &p());
    assert!(service.contains("ExecStart=/u/bin/wpantry schedule run"));
    assert!(timer.contains("OnCalendar=Mon *-*-* 06:15:00"));
    assert!(timer.contains("Persistent=true"));
    assert!(unit(Path::new("/x"), Every::Hourly, 0, 0, &p()).1.contains("OnCalendar=hourly"));
    let line = cron_line(Path::new("/u/bin/wpantry"), Every::Daily, 9, 30, &p());
    assert!(line.starts_with("30 9 * * * nice -n 10 /u/bin/wpantry schedule run"));
    assert!(line.ends_with(CRON_MARK));
    assert!(cron_line(Path::new("/x"), Every::Weekly, 1, 2, &p()).starts_with("2 1 * * 1 "));
}

#[test]
fn every_parses_and_ago_reads() {
    assert_eq!(Every::parse("daily"), Some(Every::Daily));
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

#[test]
fn words_escapes_and_every_spelling() {
    assert_eq!(Every::parse("hourly"), Some(Every::Hourly));
    assert_eq!(Every::parse("weekly"), Some(Every::Weekly));
    assert_eq!(word(Every::Hourly), "hourly");
    assert_eq!(word(Every::Daily), "daily");
    assert_eq!(word(Every::Weekly), "weekly (Mondays)");
    assert_eq!(xml_escape("a&b<c>"), "a&amp;b&lt;c&gt;");
    assert_eq!(ago(89), "89 s");
    assert_eq!(ago(90), "1 min");
    assert_eq!(ago(36 * 3600), "1 days");
    let (service, timer) = unit(Path::new("/x"), Every::Daily, 9, 5, &p());
    assert!(service.contains("StandardOutput=append:/s/wpantry/systemd.log"));
    assert!(timer.contains("OnCalendar=*-*-* 09:05:00"));
    assert!(cron_line(Path::new("/x"), Every::Hourly, 9, 15, &p()).starts_with("15 * * * * "));
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
        assert_eq!(install_with(Every::Weekly, (7, 5), true, b, &never).unwrap(), EXIT_OK);
    }
    assert!(!plist_path().exists());
}

#[test]
fn launchd_install_status_and_uninstall() {
    let _home = test_home();
    let calls = Mutex::new(Vec::new());
    let run = recorder(&calls, |cmd| ok(if cmd == "id -u" { "777\n" } else { "" }));
    assert_eq!(install_with(Every::Daily, (9, 30), false, Backend::Launchd, &run).unwrap(), EXIT_OK);
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
    assert_eq!(status_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
    assert!(!plist.exists());
    assert_eq!(uninstall_with(Backend::Launchd, &run).unwrap(), EXIT_OK, "nothing scheduled is not an error");
    assert_eq!(status_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
    let run = recorder(&calls, |cmd| {
        if cmd.starts_with("launchctl bootstrap") {
            failed("Bootstrap failed: 5: Input/output error\n")
        } else {
            ok("")
        }
    });
    let err = install_with(Every::Hourly, (0, 0), false, Backend::Launchd, &run).unwrap_err();
    assert!(err.to_string().contains("launchctl bootstrap failed: Bootstrap failed"), "{err}");
}

#[test]
fn systemd_install_status_and_uninstall() {
    let _home = test_home();
    if !hermetic() {
        return;
    }
    let calls = Mutex::new(Vec::new());
    let run = recorder(&calls, |_| ok(""));
    assert_eq!(install_with(Every::Weekly, (6, 15), false, Backend::Systemd, &run).unwrap(), EXIT_OK);
    let dir = unit_dir();
    assert!(dir.join("wpantry.service").is_file());
    let timer = std::fs::read_to_string(dir.join("wpantry.timer")).unwrap();
    assert!(timer.contains("OnCalendar=Mon *-*-* 06:15:00"), "{timer}");
    assert_eq!(
        *calls.lock().unwrap(),
        ["systemctl --user daemon-reload", "systemctl --user enable --now wpantry.timer"]
    );
    assert_eq!(status_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert!(!dir.join("wpantry.timer").exists() && !dir.join("wpantry.service").exists());
    assert_eq!(uninstall_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    assert_eq!(status_with(Backend::Systemd, &run).unwrap(), EXIT_OK);
    let run =
        recorder(
            &calls,
            |cmd| {
                if cmd.ends_with("daemon-reload") { failed("Failed to connect to bus\n") } else { ok("") }
            },
        );
    let err = install_with(Every::Daily, (1, 2), false, Backend::Systemd, &run).unwrap_err();
    assert!(err.to_string().contains("systemctl --user daemon-reload failed: Failed to connect to bus"), "{err}");
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
    assert_eq!(install_with(Every::Daily, (9, 30), false, Backend::Cron, &run).unwrap(), EXIT_OK);
    let now = table.lock().unwrap().clone().unwrap();
    let lines: Vec<&str> = now.lines().collect();
    assert_eq!(lines.len(), 2, "{now}");
    assert_eq!(lines[0], "0 0 * * * other");
    assert!(lines[1].starts_with("30 9 * * * nice -n 10 ") && lines[1].ends_with(CRON_MARK), "{now}");
    assert_eq!(status_with(Backend::Cron, &run).unwrap(), EXIT_OK);
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK);
    assert_eq!(table.lock().unwrap().as_deref(), Some("0 0 * * * other\n"));
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK, "nothing left to remove");
    assert_eq!(status_with(Backend::Cron, &run).unwrap(), EXIT_OK);
}

#[test]
fn an_empty_crontab_gets_only_our_line_and_a_refusal_is_an_error() {
    let _home = test_home();
    let table = Mutex::new(None);
    let run = crontab_of(&table);
    assert_eq!(install_with(Every::Hourly, (0, 10), false, Backend::Cron, &run).unwrap(), EXIT_OK);
    let now = table.lock().unwrap().clone().unwrap();
    assert_eq!(now.lines().count(), 1, "{now}");
    assert!(now.starts_with("10 * * * * nice -n 10 "), "{now}");
    assert_eq!(uninstall_with(Backend::Cron, &run).unwrap(), EXIT_OK);
    assert_eq!(table.lock().unwrap().as_deref(), Some(""));
    let refuse = |argv: &[&OsStr], _: Duration| if argv[1] == "-l" { ok("") } else { failed("bad minute\n") };
    let err = install_with(Every::Daily, (9, 30), false, Backend::Cron, &refuse).unwrap_err();
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
    assert_eq!(status_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
    std::fs::write(&p.last, "not json").unwrap();
    assert_eq!(status_with(Backend::Launchd, &run).unwrap(), EXIT_OK);
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
    script("case \"$1\" in scan) printf '{\"findings\": []}'; echo 'done: 0 failing' >&2;; esac\nexit 0");
    assert_eq!(run_with(&p, &prog).unwrap(), EXIT_OK);
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
