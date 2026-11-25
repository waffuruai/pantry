//! `wpantry schedule`: a `sync` and `scan` once a day (or an hour, week,
//! month, quarter or year, each at the start of the period) run by
//! the user's own scheduler, launchd on macOS, a systemd user timer on
//! Linux, cron where there is no systemd, or Windows Task Scheduler. Never `fix`: a scheduled run
//! only refreshes the cache and records what it found
//! (`$XDG_STATE_HOME/wpantry/last.json`, `schedule.log`), so `scan
//! --offline` and the next interactive run have fresh answers.

use crate::{EXIT_FAIL, EXIT_OK, say};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wpantry::error::{Error, Result};
use wpantry::utils::files::home;
use wpantry::utils::process::Output;
use wpantry::utils::process::exec;
use wpantry::utils::process::which;

mod calendar;
mod program;
mod windows;

pub const LABEL: &str = "ai.waffuru.wpantry";

/// How often the job runs: once a period, at the period's start (a week
/// on Monday, a month on the 1st, a quarter on 1 January, April, July and
/// October, a year on 1 January), at `--at`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Every {
    Hour,
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

impl Every {
    pub const NAMES: [&'static str; 6] = ["hour", "day", "week", "month", "quarter", "year"];

    pub fn parse(s: &str) -> Option<Every> {
        match s {
            "hour" => Some(Every::Hour),
            "day" => Some(Every::Day),
            "week" => Some(Every::Week),
            "month" => Some(Every::Month),
            "quarter" => Some(Every::Quarter),
            "year" => Some(Every::Year),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Quarter => "quarter",
            Self::Year => "year",
        }
    }

    /// The start dates of a period: (month, day of month, weekday), any
    /// left out matching every one; one entry per start in a year.
    fn starts(self) -> Vec<(Option<u32>, Option<u32>, Option<u32>)> {
        match self {
            Every::Hour | Every::Day => vec![(None, None, None)],
            Every::Week => vec![(None, None, Some(1))],
            Every::Month => vec![(None, Some(1), None)],
            Every::Quarter => [1, 4, 7, 10].iter().map(|m| (Some(*m), Some(1), None)).collect(),
            Every::Year => vec![(Some(1), Some(1), None)],
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
    Windows,
}

fn backend() -> Backend {
    if cfg!(windows) {
        Backend::Windows
    } else if cfg!(target_os = "macos") {
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
    install_for(&program()?, every, at, dry_run, backend, run)
}

/// The launcher the launchd, systemd and cron jobs run instead of the
/// scanner, when one sits beside it: an executable `wpantry-desktop` (a
/// regular file or a link to one) in the scanner's folder, or in the folder
/// of the file a `wpantry` link points at. A caller that ships the scanner
/// puts it there to run the scheduled scan on its behalf: the job then runs
/// `wpantry-desktop --scheduled-run` and nothing else. Without that file the
/// job runs the scanner's `schedule run`. The Windows task has the same rule
/// with `wpantry-desktop.exe` ([`windows::launcher`]).
///
/// ```ignore
/// // /Applications/Some App.app/Contents/MacOS/wpantry, with wpantry-desktop beside it
/// launcher(program) == Some("/Applications/Some App.app/Contents/MacOS/wpantry-desktop".into())
/// ```
fn launcher(program: &Path) -> Option<PathBuf> {
    let real = program.canonicalize().unwrap_or_else(|_| program.to_path_buf());
    [program, real.as_path()]
        .into_iter()
        .filter_map(|path| Some(path.parent()?.join("wpantry-desktop")))
        .find(|path| runnable(path))
}

/// A file (links followed) with an execute bit set, the test PATH lookups use.
fn runnable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// `install` for the scanner at `program`. Re-running it rewrites the job,
/// so a launcher that appeared or went since the last install is picked up.
fn install_for(program: &Path, every: Every, at: (u32, u32), dry_run: bool, backend: Backend, run: Run) -> Result<i32> {
    install_lines(program, every, at, dry_run, backend, run)?.iter().for_each(|line| say(line));
    Ok(EXIT_OK)
}

/// What `install_for` does, returning the lines it then prints: the dry
/// run's job text, or the line naming the scheduler and [`install_summary`].
fn install_lines(
    program: &Path,
    every: Every,
    at: (u32, u32),
    dry_run: bool,
    backend: Backend,
    run: Run,
) -> Result<Vec<String>> {
    let mut said = Vec::new();
    let p = paths();
    let program = program.to_path_buf();
    let (hour, minute) = at;
    let launcher = job_launcher(backend, &program);
    let launcher = launcher.as_deref();
    if matches!(backend, Backend::Systemd | Backend::Cron)
        && [Some(program.as_path()), launcher, Some(p.state.as_path())]
            .into_iter()
            .flatten()
            .any(|path| path.to_string_lossy().contains(['\n', '\r']))
    {
        return Err(Error::Failed("A schedule path contains a line break.".into()));
    }
    let text = match backend {
        Backend::Launchd => plist(&program, launcher, every, hour, minute, &p),
        Backend::Systemd => {
            let (service, timer) = unit(&program, launcher, every, hour, minute, &p);
            format!("# wpantry.service\n{service}\n# wpantry.timer\n{timer}")
        }
        Backend::Cron => cron_line(&program, launcher, every, hour, minute, &p),
        Backend::Windows => windows::definition(&program, launcher, every, at, ""),
    };
    if dry_run {
        // Line by line: `say` drops control characters, newlines included.
        return Ok(text.lines().map(str::to_owned).collect());
    }
    std::fs::create_dir_all(&p.state)?;
    match backend {
        Backend::Windows => {
            windows::install(&program, launcher, every, at, run)?;
            said.push(format!("✓ scheduled {} with Windows Task Scheduler", calendar::description(every, at)));
        }
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
            said.push(format!(
                "✓ scheduled {} at {hour:02}:{minute:02} with launchd ({})",
                word(every),
                plist_file.display()
            ));
        }
        Backend::Systemd => {
            let dir = unit_dir();
            std::fs::create_dir_all(&dir)?;
            let (service, timer) = unit(&program, launcher, every, hour, minute, &p);
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
            said.push(format!(
                "✓ scheduled {} at {hour:02}:{minute:02} with a systemd user timer ({})",
                word(every),
                dir.display()
            ));
        }
        Backend::Cron => {
            let current = crontab(run);
            let kept: Vec<&str> = current.lines().filter(|l| !ours(l)).collect();
            let mut new = kept.join("\n");
            if !new.is_empty() {
                new.push('\n');
            }
            new.push_str(&text);
            new.push('\n');
            set_crontab(&new, run)?;
            said.push(format!("✓ scheduled {} at {hour:02}:{minute:02} with cron", word(every)));
        }
    }
    said.extend(install_summary(launcher, &p));
    Ok(said)
}

/// The launcher the job for `backend` runs instead of the scanner, if one
/// sits beside it ([`launcher`] on macOS and Linux, [`windows::launcher`] on
/// Windows). `install` makes this one lookup and uses it both for the job it
/// registers and for what it says the job runs.
fn job_launcher(backend: Backend, program: &Path) -> Option<PathBuf> {
    match backend {
        Backend::Windows => windows::launcher(program),
        _ => launcher(program),
    }
}

/// What `install` says the job runs, after the line naming the scheduler.
///
/// ```ignore
/// install_summary(Some(Path::new("/opt/x/wpantry-desktop")), &paths())[0]
///     == "  It runs /opt/x/wpantry-desktop --scheduled-run, the launcher beside the scanner."
/// ```
fn install_summary(launcher: Option<&Path>, p: &Paths) -> [String; 2] {
    [
        match launcher {
            Some(launcher) => {
                format!("  It runs {} --scheduled-run, the launcher beside the scanner.", launcher.display())
            }
            None => format!(
                "  It runs `wpantry sync`, then `wpantry scan`, and writes {} and {}.",
                p.last.display(),
                p.log.display()
            ),
        },
        "  It never fixes anything: run `wpantry fix` yourself.".to_string(),
    ]
}

/// Whether launchd has the job loaded: `launchctl print` answers 0 only
/// while it does. None when launchctl could not be asked, which is not
/// proof either way.
fn launchd_loaded(run: Run, target: &str) -> Option<bool> {
    run(&["launchctl", "print", target].map(OsStr::new), Duration::from_secs(10)).ok().map(|out| out.code == Some(0))
}

pub fn uninstall() -> Result<i32> {
    uninstall_with(backend(), &real_run)
}

/// Remove the job, then check it is gone before saying so.
///
/// Oracle: "removed" is printed only when the scheduler's own state
/// shows nothing left: the plist or unit files no longer exist, systemd
/// no longer reports the timer active, the crontab no longer carries our
/// mark, Windows no longer lists the task. Otherwise each leftover is named
/// on stderr and the exit is 1, so a program that drives wpantry never treats
/// a job that still runs as uninstalled.
fn uninstall_with(backend: Backend, run: Run) -> Result<i32> {
    // What is still there after the removal, one line each.
    let mut left: Vec<String> = Vec::new();
    let what = match backend {
        Backend::Windows => {
            let removed = windows::uninstall(run)?;
            if windows::query(run)?.is_some() {
                left.push("the Windows task is still registered (schtasks /query lists it)".into());
            }
            removed.then_some("the Windows task")
        }
        Backend::Launchd => {
            let target = format!("gui/{}/{LABEL}", uid(run));
            let _ =
                run(&[OsStr::new("launchctl"), OsStr::new("bootout"), OsStr::new(&target)], Duration::from_secs(30));
            let f = plist_path();
            let was = f.exists();
            // The plist goes even when the bootout failed: launchd loads
            // every plist in LaunchAgents at login, so one left behind would
            // bring the job back after the log out this message suggests.
            // `schedule status` asks launchd too, so the loaded job is still
            // reported.
            let removed = std::fs::remove_file(&f);
            if f.exists() {
                let why = removed.err().map(|e| format!(": {e}")).unwrap_or_default();
                left.push(format!("{} is still there{why}", f.display()));
            }
            match launchd_loaded(run, &target) {
                Some(false) => {}
                Some(true) => left.push(format!(
                    "launchd still has the job loaded. Log out and back in, or run `launchctl bootout {target}`, then run `wpantry schedule uninstall` again"
                )),
                None => left.push(format!(
                    "could not ask launchd whether the job is gone. Run `launchctl print {target}`: if it lists the job, run `launchctl bootout {target}`"
                )),
            }
            was.then_some("the launchd job")
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
            let was = dir.join("wpantry.timer").exists() || dir.join("wpantry.service").exists();
            for name in ["wpantry.timer", "wpantry.service"] {
                let f = dir.join(name);
                let removed = std::fs::remove_file(&f);
                if f.exists() {
                    let why = removed.err().map(|e| format!(": {e}")).unwrap_or_default();
                    left.push(format!("{} is still there{why}", f.display()));
                }
            }
            let active = run(
                &["systemctl", "--user", "is-active", "--quiet", "wpantry.timer"].map(OsStr::new),
                Duration::from_secs(10),
            )
            .is_ok_and(|o| o.code == Some(0));
            if active {
                left.push("systemd still reports wpantry.timer active".into());
            }
            was.then_some("the systemd user timer")
        }
        Backend::Cron => {
            let current = crontab(run);
            let kept: Vec<&str> = current.lines().filter(|l| !ours(l)).collect();
            let was = kept.len() != current.lines().count();
            if was {
                let mut new = kept.join("\n");
                if !new.is_empty() {
                    new.push('\n');
                }
                set_crontab(&new, run)?;
                if crontab(run).lines().any(ours) {
                    left.push("the crontab still has the wpantry line (crontab -l)".into());
                }
            }
            was.then_some("the cron entry")
        }
    };
    if !left.is_empty() {
        for l in &left {
            eprintln!("{}", crate::style::clean(&format!("✗ not removed: {l}")));
        }
        return Ok(EXIT_FAIL);
    }
    say(&what.map_or_else(|| "nothing scheduled".to_string(), |w| format!("✓ removed {w}")));
    Ok(EXIT_OK)
}

pub fn status(json: bool) -> Result<i32> {
    status_with(backend(), &real_run, json)
}

/// What the scheduler holds now: the job's definition (plist, timer unit,
/// crontab line or task) and, on macOS, whether launchd has it loaded.
fn current(backend: Backend, run: Run) -> Result<(Option<String>, Option<bool>)> {
    let definition = match backend {
        Backend::Launchd => calendar::read(&plist_path())?,
        Backend::Systemd => calendar::read(&unit_dir().join("wpantry.timer"))?,
        Backend::Cron => crontab(run).lines().find(|l| ours(l)).map(str::to_owned),
        Backend::Windows => windows::query(run)?,
    };
    // launchd can hold a job whose plist is gone (an uninstall whose
    // bootout failed): ask it, so "not installed" never hides a job that
    // still runs.
    let loaded = match backend {
        Backend::Launchd => launchd_loaded(run, &format!("gui/{}/{LABEL}", uid(run))),
        _ => None,
    };
    Ok((definition, loaded))
}

/// The executable the registered job runs, read from the job itself (the
/// plist, `wpantry.service`, the crontab line or the task), never from
/// [`program`]: another copy of `wpantry` may have
/// registered it. `None` with no job, or when its program cannot be read.
///
/// ```ignore
/// // A job another copy of wpantry registered, asked from this one:
/// assert_eq!(job_program(Backend::Launchd, Some(&plist_text)), Some("/u/.local/bin/wpantry".into()));
/// ```
fn job_program(backend: Backend, definition: Option<&str>) -> Option<PathBuf> {
    let definition = definition?;
    match backend {
        // The definition `current` reads is the timer; the program is in
        // the service beside it.
        Backend::Systemd => calendar::read(&unit_dir().join("wpantry.service"))
            .ok()
            .flatten()
            .and_then(|text| program::read(backend, &text)),
        _ => program::read(backend, definition),
    }
}

fn status_with(backend: Backend, run: Run, json: bool) -> Result<i32> {
    if json {
        crate::emit(&status_json(backend, run)?);
        return Ok(EXIT_OK);
    }
    let p = paths();
    let (definition, loaded) = current(backend, run)?;
    let installed = definition.is_some();
    say(&format!(
        "scheduled: {}",
        match (installed, loaded) {
            (true, _) => "yes",
            (false, Some(true)) => "no, but launchd still has the job loaded (wpantry schedule uninstall)",
            (false, _) => "no (wpantry schedule install)",
        }
    ));
    if let Some(program) = job_program(backend, definition.as_deref()) {
        say(&format!("runs: {}", program.display()));
    }
    match std::fs::metadata(&p.last) {
        Ok(m) => {
            let age = m.modified().ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs()).unwrap_or(0);
            let text = std::fs::read_to_string(&p.last).unwrap_or_default();
            let (fails, warns) = wpantry::utils::json::parse(text.as_bytes(), wpantry::utils::json::MAX_DOCUMENT)
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

/// `schedule status --json`, as one JSON document.
fn status_json(backend: Backend, run: Run) -> Result<String> {
    let p = paths();
    let (definition, loaded) = current(backend, run)?;
    let definition = definition.as_deref();
    let installed = definition.is_some();
    let cadence = definition.and_then(|text| calendar::read_cadence(backend, text));
    let last_run = calendar::read(&p.last)?
        .and_then(|text| wpantry::utils::json::parse(text.as_bytes(), wpantry::utils::json::MAX_DOCUMENT).ok())
        .filter(|report| report.get("findings").and_then(|value| value.as_array()).is_some())
        .and_then(|_| std::fs::metadata(&p.last).ok()?.modified().ok())
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|time| wpantry::history::stamp(time.as_secs_f64()));
    // A scheduler tool that cannot be run makes `enabled` unknown (null),
    // never a failed status: the same rule `loaded` follows.
    let enabled = match (backend, definition) {
        (_, None) => None,
        (Backend::Windows, Some(text)) => Some(!windows::disabled(text)),
        // The one `launchctl print` that `current` made: a second query
        // could see a different answer, or fail where the first did not.
        (Backend::Launchd, Some(_)) => loaded,
        (Backend::Systemd, Some(_)) => run(
            &["systemctl", "--user", "is-active", "--quiet", "wpantry.timer"].map(OsStr::new),
            Duration::from_secs(5),
        )
        .ok()
        .map(|out| out.code == Some(0)),
        (Backend::Cron, Some(_)) => Some(true),
    };
    use wpantry::utils::json::{J, obj};
    let string = |value: Option<String>| value.map_or(J::Null, J::from);
    Ok(obj([
        ("schema", J::Int(wpantry::SCHEMA)),
        ("installed", installed.into()),
        ("enabled", enabled.map_or(J::Null, J::from)),
        ("loaded", loaded.map_or(J::Null, J::from)),
        (
            "backend",
            match backend {
                Backend::Launchd => "launchd",
                Backend::Systemd => "systemd",
                Backend::Cron => "cron",
                Backend::Windows => "windows",
            }
            .into(),
        ),
        (
            "interval",
            string(cadence.map(|(every, at)| {
                if every == Every::Hour && matches!(backend, Backend::Cron | Backend::Windows) {
                    format!("Every hour at :{:02}", at.1)
                } else {
                    calendar::description(every, at)
                }
            })),
        ),
        ("every", string(cadence.map(|(every, _)| every.name().to_owned()))),
        (
            "at",
            string(cadence.and_then(|(every, (h, m))| {
                (every != Every::Hour || matches!(backend, Backend::Cron | Backend::Windows))
                    .then(|| format!("{h:02}:{m:02}"))
            })),
        ),
        ("last_run", string(last_run)),
        ("program", string(job_program(backend, definition).map(|path| path.to_string_lossy().into_owned()))),
    ])
    .dumps())
}

/// What the scheduler runs: a sync, then a scan whose JSON goes to
/// last.json and whose outcome goes to the log. One at a time.
pub fn run() -> Result<i32> {
    let p = paths();
    std::fs::create_dir_all(&p.state)?;
    let _lock = Lock::take(&p.lock)?;
    let program = program()?;
    run_with(&p, &program)
}

/// The scan a scheduled run makes. On macOS it adds `--no-personal-files`:
/// an unattended run must not open Downloads, Desktop and Documents (that
/// raises a privacy prompt nobody is there to answer), and it then records
/// the same history scope as any machine scan with `--no-personal-files`
/// (`machine:~;no-personal-files`). That scope also resolves the open
/// `machine:~` exposures outside the personal folders that it no longer
/// lists (what an earlier full scan recorded), and never one inside them
/// (`wpantry::history`). Linux and Windows have no such prompt and keep the full scan.
///
/// ```ignore
/// assert_eq!(scan_args(), ["scan", "--json", "--no-input", "--no-personal-files"]); // macOS
/// ```
pub(crate) fn scan_args() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["scan", "--json", "--no-input", "--no-personal-files"]
    } else {
        &["scan", "--json", "--no-input"]
    }
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
    let mut argv = vec![program.as_os_str()];
    argv.extend(scan_args().iter().map(OsStr::new));
    let check = exec(&argv, &[("WPANTRY_NO_UPDATE_CHECK", "1")], Duration::from_secs(3 * 60 * 60))?;
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
        Every::Hour => "every hour",
        Every::Day => "every day",
        Every::Week => "every week (Mondays)",
        Every::Month => "every month (the 1st)",
        Every::Quarter => "every quarter (1 January, April, July, October)",
        Every::Year => "every year (1 January)",
    }
}

pub(crate) fn ago(secs: u64) -> String {
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

/// What a job runs: `launcher --scheduled-run` when there is one, else
/// `program schedule run`.
fn command<'a>(program: &'a Path, launcher: Option<&'a Path>) -> (&'a Path, &'static [&'static str]) {
    match launcher {
        Some(launcher) => (launcher, &["--scheduled-run"]),
        None => (program, &["schedule", "run"]),
    }
}

/// The launchd job: a calendar start, low priority, its output in the log.
/// `ProgramArguments` is an array, so no shell reads the path.
pub fn plist(program: &Path, launcher: Option<&Path>, every: Every, hour: u32, minute: u32, p: &Paths) -> String {
    let when = if every == Every::Hour {
        "    <key>StartInterval</key>\n    <integer>3600</integer>\n".to_string()
    } else {
        let int = |k: &str, v: u32| format!("      <key>{k}</key>\n      <integer>{v}</integer>\n");
        let dicts: String = every
            .starts()
            .iter()
            .map(|(month, day, weekday)| {
                let mut d = String::from("    <dict>\n");
                for (k, v) in [("Month", month), ("Day", day), ("Weekday", weekday)] {
                    if let Some(v) = v {
                        d.push_str(&int(k, *v));
                    }
                }
                d.push_str(&int("Hour", hour));
                d.push_str(&int("Minute", minute));
                d + "    </dict>\n"
            })
            .collect();
        // One start a period is a dict; several (a quarter's) an array of them.
        if every.starts().len() == 1 {
            format!("    <key>StartCalendarInterval</key>\n{dicts}")
        } else {
            format!("    <key>StartCalendarInterval</key>\n    <array>\n{dicts}    </array>\n")
        }
    };
    let out = xml_escape(&p.state.join("launchd.log").to_string_lossy());
    let (run, args) = command(program, launcher);
    let arguments: String = std::iter::once(run.to_string_lossy().into_owned())
        .chain(args.iter().map(|a| a.to_string()))
        .map(|a| format!("      <string>{}</string>\n", xml_escape(&a)))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n    <string>{LABEL}</string>\n\
    <key>ProgramArguments</key>\n    <array>\n{arguments}    </array>\n\
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
        xml_escape(&std::env::var("PATH").unwrap_or_default()),
    )
}

/// The systemd user service and timer. `ExecStart`'s program is one word:
/// in double quotes when it has a space, a quote or a backslash, with `%%`
/// for `%` and `$$` for `$`.
pub fn unit(
    program: &Path,
    launcher: Option<&Path>,
    every: Every,
    hour: u32,
    minute: u32,
    p: &Paths,
) -> (String, String) {
    let (run, args) = command(program, launcher);
    let time = format!("{hour:02}:{minute:02}:00");
    let calendar = match every {
        Every::Hour => "hourly".to_string(),
        Every::Day => format!("*-*-* {time}"),
        Every::Week => format!("Mon *-*-* {time}"),
        Every::Month => format!("*-*-01 {time}"),
        Every::Quarter => format!("*-01,04,07,10-01 {time}"),
        Every::Year => format!("*-01-01 {time}"),
    };
    let service = format!(
        "[Unit]\nDescription=wpantry: refresh the advisory cache and scan\n\n[Service]\nType=oneshot\nExecStart={} {}\nNice=10\nIOSchedulingClass=idle\nEnvironment=PATH={}\nStandardOutput=append:{}\nStandardError=append:{}\n",
        unit_word(&run.to_string_lossy().replace('$', "$$")),
        args.join(" "),
        unit_word(&std::env::var("PATH").unwrap_or_default()),
        p.state.join("systemd.log").to_string_lossy().replace('%', "%%"),
        p.state.join("systemd.log").to_string_lossy().replace('%', "%%"),
    );
    let timer = format!(
        "[Unit]\nDescription=wpantry {}\n\n[Timer]\nOnCalendar={calendar}\nPersistent=true\nRandomizedDelaySec=10m\n\n[Install]\nWantedBy=timers.target\n",
        word(every)
    );
    (service, timer)
}

fn unit_word(word: &str) -> String {
    let word = word.replace('%', "%%");
    if word.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\\' | '\'')) {
        let escaped = word.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
        format!("\"{escaped}\"")
    } else {
        word
    }
}

fn cron_word(word: &str) -> String {
    let escaped = if word.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/-._".contains(&byte)) {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    };
    // Cron processes % before handing the line to the shell, even inside quotes.
    escaped.replace('%', r"\%")
}

const CRON_MARK: &str = "# wpantry schedule";

/// Whether a crontab line is ours: it ends with [`CRON_MARK`] as its own
/// word, as [`cron_line`] writes it. A line that only contains the mark's
/// text (in a quoted argument, or as the start of a longer word such as
/// `# wpantry schedules`) is the user's, and install, uninstall and status
/// all leave it alone.
///
/// ```ignore
/// assert!(ours("5 5 * * * nice -n 10 wpantry schedule run >> log 2>&1 # wpantry schedule"));
/// assert!(!ours("0 2 * * * backup # wpantry schedules"));
/// ```
fn ours(line: &str) -> bool {
    let line = line.trim_end();
    line.strip_suffix(CRON_MARK).is_some_and(|before| before.is_empty() || before.ends_with(char::is_whitespace))
}

/// The crontab line; the shell reads it, so each path is a quoted word.
pub fn cron_line(program: &Path, launcher: Option<&Path>, every: Every, hour: u32, minute: u32, p: &Paths) -> String {
    let (run, args) = command(program, launcher);
    let when = match every {
        Every::Hour => format!("{minute} * * * *"),
        Every::Day => format!("{minute} {hour} * * *"),
        Every::Week => format!("{minute} {hour} * * 1"),
        Every::Month => format!("{minute} {hour} 1 * *"),
        Every::Quarter => format!("{minute} {hour} 1 1,4,7,10 *"),
        Every::Year => format!("{minute} {hour} 1 1 *"),
    };
    format!(
        "{when} nice -n 10 {} {} >> {} 2>&1 {CRON_MARK}",
        cron_word(&run.to_string_lossy()),
        args.join(" "),
        cron_word(&p.state.join("cron.log").to_string_lossy())
    )
}

fn crontab(run: Run) -> String {
    run(&[OsStr::new("crontab"), OsStr::new("-l")], Duration::from_secs(10)).map(|o| o.stdout).unwrap_or_default()
}

fn set_crontab(text: &str, run: Run) -> Result<()> {
    let dir = wpantry::utils::temp::TempDir::new("cron")?;
    let f = dir.path().join("crontab");
    std::fs::write(&f, text)?;
    let out = run(&[OsStr::new("crontab"), f.as_os_str()], Duration::from_secs(10))?;
    if out.code != Some(0) {
        return Err(Error::Failed(format!("crontab failed: {}", out.stderr.trim())));
    }
    Ok(())
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod tests;
