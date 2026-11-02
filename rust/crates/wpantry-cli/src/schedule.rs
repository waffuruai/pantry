//! `wpantry schedule`: a daily (hourly, weekly) `sync` and `check` run by
//! the user's own scheduler, launchd on macOS, a systemd user timer on
//! Linux, cron where there is no systemd. Never `--update`: a scheduled run
//! only refreshes the cache and records what it found
//! (`$XDG_STATE_HOME/wpantry/last.json`, `schedule.log`), so `check
//! --offline` and the next interactive run have fresh answers.

use crate::{EXIT_FAIL, EXIT_OK, say};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wpantry::error::{Error, Result};
use wpantry::system::{Output, exec, home, which};

pub const LABEL: &str = "ai.waffuru.wpantry";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Every {
    Hourly,
    Daily,
    Weekly,
}

impl Every {
    pub fn parse(s: &str) -> Option<Every> {
        match s {
            "hourly" => Some(Every::Hourly),
            "daily" => Some(Every::Daily),
            "weekly" => Some(Every::Weekly),
            _ => None,
        }
    }
}

/// The job's files, where this machine keeps them.
pub struct Paths {
    pub state: PathBuf,
    pub log: PathBuf,
    pub last: PathBuf,
    pub lock: PathBuf,
}

pub fn paths() -> Paths {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"))
        .join("wpantry");
    Paths { log: state.join("schedule.log"), last: state.join("last.json"), lock: state.join("schedule.lock"), state }
}

/// How the scheduled job is wired on this OS.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Backend {
    Launchd,
    Systemd,
    Cron,
}

fn backend() -> Backend {
    if cfg!(target_os = "macos") {
        Backend::Launchd
    } else if which("systemctl").is_some() && std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        Backend::Systemd
    } else {
        Backend::Cron
    }
}

fn plist_path() -> PathBuf {
    home().join("Library/LaunchAgents").join(format!("{LABEL}.plist"))
}

fn unit_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("systemd/user")
}

/// What runs the scheduler's own commands (launchctl, systemctl, crontab,
/// id): `exec` for real, recorded answers in tests.
type Run<'a> = &'a dyn Fn(&[&OsStr], Duration) -> Result<Output>;

fn real_run(argv: &[&OsStr], timeout: Duration) -> Result<Output> {
    exec(argv, &[], timeout)
}

/// The binary the job runs: the `wpantry` on PATH when it is this one (a
/// stable link that survives updates), else this executable.
fn program() -> Result<PathBuf> {
    let me = std::env::current_exe()?.canonicalize()?;
    if let Some(on_path) = which("wpantry")
        && on_path.canonicalize().ok().as_ref() == Some(&me)
    {
        return Ok(on_path);
    }
    Ok(me)
}

pub fn install(every: Every, at: (u32, u32), dry_run: bool) -> Result<i32> {
    install_with(every, at, dry_run, backend(), &real_run)
}

fn install_with(every: Every, at: (u32, u32), dry_run: bool, backend: Backend, run: Run) -> Result<i32> {
    let p = paths();
    let program = program()?;
    let (hour, minute) = at;
    let text = match backend {
        Backend::Launchd => plist(&program, every, hour, minute, &p),
        Backend::Systemd => {
            let (service, timer) = unit(&program, every, hour, minute, &p);
            format!("# wpantry.service\n{service}\n# wpantry.timer\n{timer}")
        }
        Backend::Cron => cron_line(&program, every, hour, minute, &p),
    };
    if dry_run {
        say(&text);
        return Ok(EXIT_OK);
    }
    std::fs::create_dir_all(&p.state)?;
    match backend {
        Backend::Launchd => {
            let plist_file = plist_path();
            std::fs::create_dir_all(plist_file.parent().expect("LaunchAgents has a parent"))?;
            std::fs::write(&plist_file, text)?;
            let domain = format!("gui/{}", uid(run));
            let _ = run(
                &[OsStr::new("launchctl"), OsStr::new("bootout"), OsStr::new(&format!("{domain}/{LABEL}"))],
                Duration::from_secs(30),
            );
            let out = run(
                &[OsStr::new("launchctl"), OsStr::new("bootstrap"), OsStr::new(&domain), plist_file.as_os_str()],
                Duration::from_secs(30),
            )?;
            if out.code != Some(0) {
                return Err(Error::Failed(format!("launchctl bootstrap failed: {}", out.stderr.trim())));
            }
            say(&format!(
                "✓ scheduled {} at {hour:02}:{minute:02} with launchd ({})",
                word(every),
                plist_file.display()
            ));
        }
        Backend::Systemd => {
            let dir = unit_dir();
            std::fs::create_dir_all(&dir)?;
            let (service, timer) = unit(&program, every, hour, minute, &p);
            std::fs::write(dir.join("wpantry.service"), service)?;
            std::fs::write(dir.join("wpantry.timer"), timer)?;
            for args in [vec!["daemon-reload"], vec!["enable", "--now", "wpantry.timer"]] {
                let mut argv: Vec<&OsStr> = vec![OsStr::new("systemctl"), OsStr::new("--user")];
                argv.extend(args.iter().map(OsStr::new));
                let out = run(&argv, Duration::from_secs(30))?;
                if out.code != Some(0) {
                    return Err(Error::Failed(format!(
                        "systemctl --user {} failed: {}",
                        args.join(" "),
                        out.stderr.trim()
                    )));
                }
            }
            say(&format!(
                "✓ scheduled {} at {hour:02}:{minute:02} with a systemd user timer ({})",
                word(every),
                dir.display()
            ));
        }
        Backend::Cron => {
            let current = crontab(run);
            let kept: Vec<&str> = current.lines().filter(|l| !l.contains(CRON_MARK)).collect();
            let mut new = kept.join("\n");
            if !new.is_empty() {
                new.push('\n');
            }
            new.push_str(&text);
            new.push('\n');
            set_crontab(&new, run)?;
            say(&format!("✓ scheduled {} at {hour:02}:{minute:02} with cron", word(every)));
        }
    }
    say(&format!(
        "  It runs `wpantry sync`, then `wpantry check`, and writes {} and {}.",
        p.last.display(),
        p.log.display()
    ));
    say("  It never updates anything: run `wpantry --update` yourself.");
    Ok(EXIT_OK)
}

pub fn uninstall() -> Result<i32> {
    uninstall_with(backend(), &real_run)
}

fn uninstall_with(backend: Backend, run: Run) -> Result<i32> {
    match backend {
        Backend::Launchd => {
            let _ = run(
                &[OsStr::new("launchctl"), OsStr::new("bootout"), OsStr::new(&format!("gui/{}/{LABEL}", uid(run)))],
                Duration::from_secs(30),
            );
            let f = plist_path();
            let was = f.exists();
            let _ = std::fs::remove_file(&f);
            say(if was { "✓ removed the launchd job" } else { "nothing scheduled" });
        }
        Backend::Systemd => {
            let _ = run(
                &[
                    OsStr::new("systemctl"),
                    OsStr::new("--user"),
                    OsStr::new("disable"),
                    OsStr::new("--now"),
                    OsStr::new("wpantry.timer"),
                ],
                Duration::from_secs(30),
            );
            let dir = unit_dir();
            let was = dir.join("wpantry.timer").exists();
            let _ = std::fs::remove_file(dir.join("wpantry.timer"));
            let _ = std::fs::remove_file(dir.join("wpantry.service"));
            say(if was { "✓ removed the systemd user timer" } else { "nothing scheduled" });
        }
        Backend::Cron => {
            let current = crontab(run);
            let kept: Vec<&str> = current.lines().filter(|l| !l.contains(CRON_MARK)).collect();
            let was = kept.len() != current.lines().count();
            if was {
                let mut new = kept.join("\n");
                if !new.is_empty() {
                    new.push('\n');
                }
                set_crontab(&new, run)?;
            }
            say(if was { "✓ removed the cron entry" } else { "nothing scheduled" });
        }
    }
    Ok(EXIT_OK)
}

pub fn status() -> Result<i32> {
    status_with(backend(), &real_run)
}

fn status_with(backend: Backend, run: Run) -> Result<i32> {
    let p = paths();
    let installed = match backend {
        Backend::Launchd => plist_path().exists(),
        Backend::Systemd => unit_dir().join("wpantry.timer").exists(),
        Backend::Cron => crontab(run).contains(CRON_MARK),
    };
    say(&format!("scheduled: {}", if installed { "yes" } else { "no (wpantry schedule install)" }));
    match std::fs::metadata(&p.last) {
        Ok(m) => {
            let age = m.modified().ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs()).unwrap_or(0);
            let text = std::fs::read_to_string(&p.last).unwrap_or_default();
            let (fails, warns) = wpantry::json::parse(text.as_bytes(), wpantry::json::MAX_DOCUMENT)
                .ok()
                .map(|v| {
                    let fs = v.get("findings").and_then(|f| f.as_array()).cloned().unwrap_or_default();
                    (
                        fs.iter().filter(|f| f.get("status").and_then(|s| s.as_str()) == Some("fail")).count(),
                        fs.iter().filter(|f| f.get("status").and_then(|s| s.as_str()) == Some("warn")).count(),
                    )
                })
                .unwrap_or((0, 0));
            say(&format!("last run: {} ago, {fails} failing, {warns} warnings ({})", ago(age), p.last.display()));
        }
        Err(_) => say("last run: never"),
    }
    if let Ok(log) = std::fs::read_to_string(&p.log) {
        for l in log.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev() {
            say(&format!("  {l}"));
        }
    }
    Ok(EXIT_OK)
}

/// What the scheduler runs: a sync, then a check whose JSON goes to
/// last.json and whose outcome goes to the log. One at a time.
pub fn run() -> Result<i32> {
    let p = paths();
    std::fs::create_dir_all(&p.state)?;
    let _lock = Lock::take(&p.lock)?;
    let program = program()?;
    run_with(&p, &program)
}

/// `run` with the lock held: `program` is the wpantry to run.
fn run_with(p: &Paths, program: &Path) -> Result<i32> {
    let started = std::time::Instant::now();
    let stamp = || {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        format!("{secs}")
    };
    let sync = exec(
        &[program.as_os_str(), OsStr::new("sync"), OsStr::new("--no-input")],
        &[("WPANTRY_NO_UPDATE_CHECK", "1")],
        Duration::from_secs(60 * 60),
    )?;
    let check = exec(
        &[program.as_os_str(), OsStr::new("check"), OsStr::new("--json"), OsStr::new("--no-input")],
        &[("WPANTRY_NO_UPDATE_CHECK", "1")],
        Duration::from_secs(3 * 60 * 60),
    )?;
    let tmp = p.state.join(".last.json.tmp");
    std::fs::write(&tmp, &check.stdout)?;
    std::fs::rename(&tmp, &p.last)?;
    let line = format!(
        "{} sync={} check={} {:.0}s {}",
        stamp(),
        sync.code.map_or("signal".into(), |c| c.to_string()),
        check.code.map_or("signal".into(), |c| c.to_string()),
        started.elapsed().as_secs_f64(),
        check.stderr.trim().lines().last().unwrap_or("").chars().take(200).collect::<String>()
    );
    use std::io::Write;
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&p.log)?;
    writeln!(log, "{line}")?;
    say(&line);
    Ok(if check.code == Some(0) || check.code == Some(1) { EXIT_OK } else { EXIT_FAIL })
}

/// One scheduled run at a time: the lock file names the pid holding it;
/// a lock whose pid is gone is stale and taken over.
struct Lock(PathBuf);

impl Lock {
    fn take(path: &Path) -> Result<Lock> {
        for _ in 0..2 {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = write!(f, "{}", std::process::id());
                    return Ok(Lock(path.to_path_buf()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let pid = std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u32>().ok());
                    if pid.is_some_and(alive) {
                        return Err(Error::Failed(format!(
                            "another scheduled wpantry run (pid {}) is still going; {} holds its lock",
                            pid.unwrap_or(0),
                            path.display()
                        )));
                    }
                    let _ = std::fs::remove_file(path);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Failed(format!("couldn't take {}", path.display())))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    // `kill -0` through the shell-free route: ps says whether the pid exists.
    exec(
        &[OsStr::new("ps"), OsStr::new("-p"), OsStr::new(&pid.to_string()), OsStr::new("-o"), OsStr::new("pid=")],
        &[],
        Duration::from_secs(5),
    )
    .is_ok_and(|o| o.code == Some(0) && !o.stdout.trim().is_empty())
}

/// tasklist's filtered listing names the pid in its own column when the
/// process exists, and says "No tasks" otherwise.
#[cfg(windows)]
fn alive(pid: u32) -> bool {
    exec(
        &[OsStr::new("tasklist"), OsStr::new("/FI"), OsStr::new(&format!("PID eq {pid}")), OsStr::new("/NH")],
        &[],
        Duration::from_secs(5),
    )
    .is_ok_and(|o| o.code == Some(0) && o.stdout.contains(&format!(" {pid} ")))
}

#[cfg(not(any(unix, windows)))]
fn alive(_pid: u32) -> bool {
    false
}

fn uid(run: Run) -> String {
    run(&[OsStr::new("id"), OsStr::new("-u")], Duration::from_secs(5))
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_else(|_| "501".into())
}

fn word(every: Every) -> &'static str {
    match every {
        Every::Hourly => "hourly",
        Every::Daily => "daily",
        Every::Weekly => "weekly (Mondays)",
    }
}

fn ago(secs: u64) -> String {
    match secs {
        s if s < 90 => format!("{s} s"),
        s if s < 90 * 60 => format!("{} min", s / 60),
        s if s < 36 * 3600 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86400),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The launchd job: a calendar start, low priority, its output in the log.
pub fn plist(program: &Path, every: Every, hour: u32, minute: u32, p: &Paths) -> String {
    let when = match every {
        Every::Hourly => "    <key>StartInterval</key>\n    <integer>3600</integer>\n".to_string(),
        Every::Daily => format!(
            "    <key>StartCalendarInterval</key>\n    <dict>\n      <key>Hour</key>\n      <integer>{hour}</integer>\n      <key>Minute</key>\n      <integer>{minute}</integer>\n    </dict>\n"
        ),
        Every::Weekly => format!(
            "    <key>StartCalendarInterval</key>\n    <dict>\n      <key>Weekday</key>\n      <integer>1</integer>\n      <key>Hour</key>\n      <integer>{hour}</integer>\n      <key>Minute</key>\n      <integer>{minute}</integer>\n    </dict>\n"
        ),
    };
    let out = xml_escape(&p.state.join("launchd.log").to_string_lossy());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n    <string>{LABEL}</string>\n\
    <key>ProgramArguments</key>\n    <array>\n      <string>{}</string>\n      <string>schedule</string>\n      <string>run</string>\n    </array>\n\
{when}\
    <key>RunAtLoad</key>\n    <false/>\n\
    <key>ProcessType</key>\n    <string>Background</string>\n\
    <key>LowPriorityIO</key>\n    <true/>\n\
    <key>Nice</key>\n    <integer>10</integer>\n\
    <key>StandardOutPath</key>\n    <string>{out}</string>\n\
    <key>StandardErrorPath</key>\n    <string>{out}</string>\n\
    <key>EnvironmentVariables</key>\n    <dict>\n      <key>PATH</key>\n      <string>{}</string>\n    </dict>\n\
</dict>\n\
</plist>\n",
        xml_escape(&program.to_string_lossy()),
        xml_escape(&std::env::var("PATH").unwrap_or_default()),
    )
}

/// The systemd user service and timer.
pub fn unit(program: &Path, every: Every, hour: u32, minute: u32, p: &Paths) -> (String, String) {
    let calendar = match every {
        Every::Hourly => "hourly".to_string(),
        Every::Daily => format!("*-*-* {hour:02}:{minute:02}:00"),
        Every::Weekly => format!("Mon *-*-* {hour:02}:{minute:02}:00"),
    };
    let service = format!(
        "[Unit]\nDescription=wpantry: refresh the advisory cache and scan\n\n[Service]\nType=oneshot\nExecStart={} schedule run\nNice=10\nIOSchedulingClass=idle\nEnvironment=PATH={}\nStandardOutput=append:{}\nStandardError=append:{}\n",
        program.display(),
        std::env::var("PATH").unwrap_or_default(),
        p.state.join("systemd.log").display(),
        p.state.join("systemd.log").display(),
    );
    let timer = format!(
        "[Unit]\nDescription=wpantry {}\n\n[Timer]\nOnCalendar={calendar}\nPersistent=true\nRandomizedDelaySec=10m\n\n[Install]\nWantedBy=timers.target\n",
        word(every)
    );
    (service, timer)
}

const CRON_MARK: &str = "# wpantry schedule";

pub fn cron_line(program: &Path, every: Every, hour: u32, minute: u32, p: &Paths) -> String {
    let when = match every {
        Every::Hourly => format!("{minute} * * * *"),
        Every::Daily => format!("{minute} {hour} * * *"),
        Every::Weekly => format!("{minute} {hour} * * 1"),
    };
    format!(
        "{when} nice -n 10 {} schedule run >> {} 2>&1 {CRON_MARK}",
        program.display(),
        p.state.join("cron.log").display()
    )
}

fn crontab(run: Run) -> String {
    run(&[OsStr::new("crontab"), OsStr::new("-l")], Duration::from_secs(10)).map(|o| o.stdout).unwrap_or_default()
}

fn set_crontab(text: &str, run: Run) -> Result<()> {
    let dir = wpantry::system::TempDir::new("cron")?;
    let f = dir.path().join("crontab");
    std::fs::write(&f, text)?;
    let out = run(&[OsStr::new("crontab"), f.as_os_str()], Duration::from_secs(10))?;
    if out.code != Some(0) {
        return Err(Error::Failed(format!("crontab failed: {}", out.stderr.trim())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[cfg(unix)]
    use wpantry::system::TempDir;
    use wpantry::system::test_home;

    fn p() -> Paths {
        let state = PathBuf::from("/s/wpantry");
        Paths {
            log: state.join("schedule.log"),
            last: state.join("last.json"),
            lock: state.join("schedule.lock"),
            state,
        }
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
        let d = wpantry::system::TempDir::new("lock").unwrap();
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
        let run = recorder(&calls, |cmd| {
            if cmd.ends_with("daemon-reload") { failed("Failed to connect to bus\n") } else { ok("") }
        });
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
        std::fs::write(&p.last, r#"{"findings": [{"status": "fail"}, {"status": "warn"}, {"status": "fail"}]}"#)
            .unwrap();
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
        script("case \"$1\" in check) printf '{\"findings\": []}'; echo 'done: 0 failing' >&2;; esac\nexit 0");
        assert_eq!(run_with(&p, &prog).unwrap(), EXIT_OK);
        assert_eq!(std::fs::read_to_string(&p.last).unwrap(), "{\"findings\": []}");
        let log = std::fs::read_to_string(&p.log).unwrap();
        assert!(log.contains(" sync=0 check=0 ") && log.trim_end().ends_with("done: 0 failing"), "{log}");
        // Findings (exit 1) are a normal run; a crash (exit 3) fails it.
        script("[ \"$1\" = check ] && exit 1\nexit 0");
        assert_eq!(run_with(&p, &prog).unwrap(), EXIT_OK);
        script("exit 3");
        assert_eq!(run_with(&p, &prog).unwrap(), EXIT_FAIL);
        assert_eq!(std::fs::read_to_string(&p.log).unwrap().lines().count(), 3);
        // The real entry point takes the lock and runs this very binary,
        // which is no wpantry: a failed check, logged.
        assert_eq!(run().unwrap(), EXIT_FAIL);
        assert!(!p.lock.exists());
    }
}
