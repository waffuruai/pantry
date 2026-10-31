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
use wpantry::system::{exec, home, which};

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
    let p = paths();
    let program = program()?;
    let (hour, minute) = at;
    let text = match backend() {
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
    match backend() {
        Backend::Launchd => {
            let plist_file = plist_path();
            std::fs::create_dir_all(plist_file.parent().expect("LaunchAgents has a parent"))?;
            std::fs::write(&plist_file, text)?;
            let domain = format!("gui/{}", uid());
            let _ = exec(
                &[OsStr::new("launchctl"), OsStr::new("bootout"), OsStr::new(&format!("{domain}/{LABEL}"))],
                &[],
                Duration::from_secs(30),
            );
            let out = exec(
                &[OsStr::new("launchctl"), OsStr::new("bootstrap"), OsStr::new(&domain), plist_file.as_os_str()],
                &[],
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
                let out = exec(&argv, &[], Duration::from_secs(30))?;
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
            let current = crontab();
            let kept: Vec<&str> = current.lines().filter(|l| !l.contains(CRON_MARK)).collect();
            let mut new = kept.join("\n");
            if !new.is_empty() {
                new.push('\n');
            }
            new.push_str(&text);
            new.push('\n');
            set_crontab(&new)?;
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
    match backend() {
        Backend::Launchd => {
            let _ = exec(
                &[OsStr::new("launchctl"), OsStr::new("bootout"), OsStr::new(&format!("gui/{}/{LABEL}", uid()))],
                &[],
                Duration::from_secs(30),
            );
            let f = plist_path();
            let was = f.exists();
            let _ = std::fs::remove_file(&f);
            say(if was { "✓ removed the launchd job" } else { "nothing scheduled" });
        }
        Backend::Systemd => {
            let _ = exec(
                &[
                    OsStr::new("systemctl"),
                    OsStr::new("--user"),
                    OsStr::new("disable"),
                    OsStr::new("--now"),
                    OsStr::new("wpantry.timer"),
                ],
                &[],
                Duration::from_secs(30),
            );
            let dir = unit_dir();
            let was = dir.join("wpantry.timer").exists();
            let _ = std::fs::remove_file(dir.join("wpantry.timer"));
            let _ = std::fs::remove_file(dir.join("wpantry.service"));
            say(if was { "✓ removed the systemd user timer" } else { "nothing scheduled" });
        }
        Backend::Cron => {
            let current = crontab();
            let kept: Vec<&str> = current.lines().filter(|l| !l.contains(CRON_MARK)).collect();
            let was = kept.len() != current.lines().count();
            if was {
                let mut new = kept.join("\n");
                if !new.is_empty() {
                    new.push('\n');
                }
                set_crontab(&new)?;
            }
            say(if was { "✓ removed the cron entry" } else { "nothing scheduled" });
        }
    }
    Ok(EXIT_OK)
}

pub fn status() -> Result<i32> {
    let p = paths();
    let installed = match backend() {
        Backend::Launchd => plist_path().exists(),
        Backend::Systemd => unit_dir().join("wpantry.timer").exists(),
        Backend::Cron => crontab().contains(CRON_MARK),
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

#[cfg(not(unix))]
fn alive(_pid: u32) -> bool {
    false
}

fn uid() -> String {
    exec(&[OsStr::new("id"), OsStr::new("-u")], &[], Duration::from_secs(5))
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

fn crontab() -> String {
    exec(&[OsStr::new("crontab"), OsStr::new("-l")], &[], Duration::from_secs(10)).map(|o| o.stdout).unwrap_or_default()
}

fn set_crontab(text: &str) -> Result<()> {
    let dir = wpantry::system::TempDir::new("cron")?;
    let f = dir.path().join("crontab");
    std::fs::write(&f, text)?;
    let out = exec(&[OsStr::new("crontab"), f.as_os_str()], &[], Duration::from_secs(10))?;
    if out.code != Some(0) {
        return Err(Error::Failed(format!("crontab failed: {}", out.stderr.trim())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
