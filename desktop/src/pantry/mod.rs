//! Runs the `wpantry` scanner as a child process: one job at a time, with a
//! time limit, a Cancel that kills it, and the scanner's last status line.
//!
//! Example:
//! ```ignore
//! let pantry = Pantry::locate(None);
//! let (job, task) = pantry.for_task();
//! std::thread::spawn(move || job.report());
//! task.cancel(); // kills the child within ~50 ms
//! ```

use crate::data::{Period, Report, ScannerVersion, Schedule, Update};
use output::{checked, excerpt, json, verified_preview};
use process::{spawn, supervise};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod output;
mod problem;
mod process;

pub use output::clean;
pub use problem::{Problem, ProblemKind};

pub type Result<T> = std::result::Result<T, String>;

/// A scan can read a whole home folder: give it half an hour.
pub const SCAN_LIMIT: Duration = Duration::from_secs(30 * 60);
/// Package managers can be slow, but a fix should not run forever.
pub const FIX_LIMIT: Duration = Duration::from_secs(15 * 60);
/// Reports, schedules and update checks.
pub const SHORT_LIMIT: Duration = Duration::from_secs(60);

/// Test hook: a shorter limit for every task, set by the automation
/// driver's `set_time_limit` op (milliseconds, 0 = the normal limits).
static LIMIT_OVERRIDE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn set_time_limit_for_test(milliseconds: u64) {
    LIMIT_OVERRIDE.store(milliseconds, Ordering::SeqCst);
}

fn limit(normal: Duration) -> Duration {
    match LIMIT_OVERRIDE.load(Ordering::SeqCst) {
        0 => normal,
        ms => Duration::from_millis(ms),
    }
}

/// Exact texts the friendly error mapping recognises.
pub const CANCELLED: &str = "Pantry stopped the scanner because the task was cancelled.";
const TIMED_OUT: &str = "Pantry stopped the scanner because it ran longer than";
const START_FAILED: &str = "Could not start Pantry's scanner at";
const NEWER_FORMAT: &str = "This scanner uses a newer";
const UNSUPPORTED: &str = "Pantry returned an unsupported response.";
/// Output that is empty or not the JSON asked for: not proof of a version
/// mismatch, so it never says "Reinstall".
const UNEXPECTED: &str = "Pantry's scanner returned something unexpected.";
/// A fix preview Pantry could not show exactly as it would run.
pub const UNVERIFIED: &str = "Pantry could not verify the command for this fix.";

/// Shared handle for one running job: Cancel, the current step's label and
/// the scanner's last stderr line.
#[derive(Clone, Default)]
pub struct Task {
    cancel: Arc<AtomicBool>,
    note: Arc<Mutex<String>>,
    stage: Arc<Mutex<Option<&'static str>>>,
}

impl Task {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// The scanner's last status line, if it printed one.
    pub fn note(&self) -> String {
        self.note.lock().map(|n| n.clone()).unwrap_or_default()
    }

    /// The label of the step running now, when a job has several.
    pub fn stage(&self) -> Option<&'static str> {
        self.stage.lock().ok().and_then(|s| *s)
    }

    pub fn set_stage(&self, label: &'static str) {
        if let Ok(mut stage) = self.stage.lock() {
            *stage = Some(label);
        }
        if let Ok(mut note) = self.note.lock() {
            note.clear();
        }
    }
}

#[derive(Clone)]
pub struct Pantry {
    pub path: PathBuf,
    /// False when no scanner file was found anywhere Pantry looks.
    pub found: bool,
    task: Task,
}

/// Where the scanner is, in order: the `--scanner` flag, the file beside
/// this executable (inside Pantry.app on macOS), and, in debug builds only,
/// PATH. Release builds never pick up a different `wpantry` from PATH.
fn find(
    explicit: Option<PathBuf>,
    exe: Option<&Path>,
    allow_path: bool,
    path_var: Option<&OsStr>,
) -> (PathBuf, bool) {
    if let Some(path) = explicit {
        let found = path.is_file();
        return (path, found);
    }
    let name = format!("wpantry{}", std::env::consts::EXE_SUFFIX);
    let sibling = exe.map(|path| path.with_file_name(&name));
    if let Some(path) = sibling.as_ref().filter(|path| path.is_file()) {
        return (path.clone(), true);
    }
    if allow_path
        && let Some(path) = path_var.and_then(|path| {
            std::env::split_paths(path)
                .filter(|directory| directory.is_absolute())
                .map(|directory| directory.join(&name))
                .find(|path| path.is_file())
        })
    {
        return (path, true);
    }
    (sibling.unwrap_or_else(|| PathBuf::from(name)), false)
}

impl Pantry {
    pub fn locate(explicit: Option<PathBuf>) -> Self {
        let exe = std::env::current_exe().ok();
        let path_var = std::env::var_os("PATH");
        let (path, found) = find(
            explicit,
            exe.as_deref(),
            cfg!(debug_assertions),
            path_var.as_deref(),
        );
        Self {
            path,
            found,
            task: Task::default(),
        }
    }

    /// A copy for one background job, and the handle that controls it.
    pub fn for_task(&self) -> (Self, Task) {
        let task = Task::default();
        let mut job = self.clone();
        job.task = task.clone();
        (job, task)
    }

    pub fn task(&self) -> &Task {
        &self.task
    }

    /// The scanner command for copied steps: `wpantry` when that is the
    /// one on PATH, else its full path in quotes.
    pub fn shell_name(&self) -> String {
        let on_path = std::env::var_os("PATH").is_some_and(|path| {
            std::env::split_paths(&path).any(|dir| {
                dir.join(format!("wpantry{}", std::env::consts::EXE_SUFFIX)) == self.path
            })
        });
        if on_path {
            "wpantry".into()
        } else {
            format!("\"{}\"", self.path.display())
        }
    }

    fn run(&self, args: &[&str], limit_for: Duration) -> Result<Output> {
        if self.task.cancelled() {
            return Err(CANCELLED.into());
        }
        let mut command = Command::new(&self.path);
        command
            .args(args)
            .stdin(Stdio::null())
            .env("NO_COLOR", "1")
            .env("WPANTRY_NO_UPDATE_CHECK", "1");
        let child = spawn(command)
            .map_err(|error| format!("{START_FAILED} {}. {error}", self.path.display()))?;
        supervise(child, limit(limit_for), &self.task)
    }

    /// The report after a job: read even when the job was cancelled, so a
    /// cancelled scan or fix never leaves the window without results. The
    /// read is short and has its own time limit.
    pub fn reload(&self) -> Result<Option<Report>> {
        if self.task.cancelled() {
            self.for_task().0.report()
        } else {
            self.report()
        }
    }

    pub fn report(&self) -> Result<Option<Report>> {
        let out = self.run(&["report", "all", "--json"], SHORT_LIMIT)?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.code() == Some(1) && out.stdout.is_empty() && stderr.contains("no scan yet") {
            return Ok(None);
        }
        let report: Report = json(out, &[0, 1])?;
        if report.schema != 1 {
            return Err(format!("{NEWER_FORMAT} report format ({}).", report.schema));
        }
        Ok(Some(report))
    }

    pub fn schedule(&self) -> Result<Schedule> {
        let schedule: Schedule = json(
            self.run(&["schedule", "status", "--json"], SHORT_LIMIT)?,
            &[0],
        )?;
        if schedule.schema != 1 {
            return Err(format!(
                "{NEWER_FORMAT} schedule format ({}).",
                schedule.schema
            ));
        }
        Ok(schedule)
    }

    pub fn scan(&self, request: &ScanRequest) -> Result<String> {
        let mut args = vec!["scan", "--json", "--no-input"];
        if !request.machine {
            args.push("--no-machine");
        }
        for path in &request.paths {
            args.extend(["--path", path.as_str()]);
        }
        if request.machine && cfg!(target_os = "macos") && !request.include_personal_files {
            args.push("--no-personal-files");
        }
        if request.offline {
            args.push("--offline");
        }
        let output = checked(self.run(&args, SCAN_LIMIT)?, &[0, 1])?;
        let document: serde_json::Value = serde_json::from_str(&output).map_err(|e| {
            format!(
                "{UNEXPECTED} It did not return a scan result. {e}\n{}",
                excerpt(&output)
            )
        })?;
        if document["schema"] != 1 || !document["findings"].is_array() {
            return Err(format!("{UNSUPPORTED} The scan result has another format."));
        }
        Ok("Scan complete.".into())
    }

    pub fn save_schedule(&self, every: Period, at: &str) -> Result<String> {
        checked(
            self.run(
                &["schedule", "install", "--every", every.name(), "--at", at],
                SHORT_LIMIT,
            )?,
            &[0],
        )
    }

    pub fn remove_schedule(&self) -> Result<String> {
        checked(self.run(&["schedule", "uninstall"], SHORT_LIMIT)?, &[0])
    }

    pub fn preview_fix(&self, scan: i64, id: &str) -> Result<String> {
        let output = self.run(
            &[
                "fix",
                id,
                "--from-scan",
                &scan.to_string(),
                "--no-input",
                "--dry-run",
                "--json",
            ],
            SHORT_LIMIT,
        )?;
        verified_preview(output, scan)
    }

    pub fn fix(&self, scan: i64, id: &str) -> Result<String> {
        let scan = scan.to_string();
        checked(
            self.run(
                &["fix", id, "--from-scan", &scan, "--no-input", "--yes"],
                FIX_LIMIT,
            )?,
            &[0],
        )
    }

    /// The version the scanner reports (`version --json`). Offline and
    /// quick: it reads nothing but the scanner's own build.
    pub fn version(&self) -> Result<String> {
        json::<ScannerVersion>(self.run(&["version", "--json"], SHORT_LIMIT)?, &[0])
            .map(|answer| answer.version)
    }

    pub fn check_updates(&self) -> Result<Update> {
        json(
            self.run(&["update", "--check", "--json"], SHORT_LIMIT)?,
            &[0, 10],
        )
    }
}

/// What one scan covers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanRequest {
    pub machine: bool,
    pub paths: Vec<String>,
    pub include_personal_files: bool,
    pub offline: bool,
}

impl ScanRequest {
    /// The scan that repeats a report's scope (`machine:~`,
    /// `machine:~;no-personal-files`, `repos:/a,/b`), so a fix is checked
    /// against the same ground. `None` for scopes the window can't repeat
    /// exactly, such as license or policy scans.
    pub fn for_scope(scope: &str, offline: bool) -> Option<Self> {
        let (base, personal) = match scope.strip_suffix(";no-personal-files") {
            Some(base) => (base, false),
            None => (scope, true),
        };
        if base.contains(['+', ';']) {
            return None;
        }
        let (kind, paths) = base.split_once(':')?;
        let machine = match kind {
            "machine" => true,
            "repos" => false,
            _ => return None,
        };
        let paths: Vec<String> = if paths == "~" {
            Vec::new()
        } else {
            paths.split(',').map(str::to_owned).collect()
        };
        if paths.iter().any(|path| !Path::new(path).is_dir()) {
            return None;
        }
        if !machine && paths.is_empty() {
            return None;
        }
        Some(Self {
            machine,
            paths,
            include_personal_files: machine && personal,
            offline,
        })
    }
}

/// The folders a scope names that are no longer there.
pub fn missing_folders(scope: &str) -> Vec<String> {
    let base = scope.split([';', '+']).next().unwrap_or("");
    match base.split_once(':') {
        Some(("repos" | "machine", paths)) if paths != "~" => paths
            .split(',')
            .filter(|path| !Path::new(path).is_dir())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

pub fn valid_time(value: &str) -> bool {
    let Some((hour, minute)) = value.split_once(':') else {
        return false;
    };
    hour.len() == 2
        && minute.len() == 2
        && hour
            .bytes()
            .chain(minute.bytes())
            .all(|b| b.is_ascii_digit())
        && hour.parse::<u32>().is_ok_and(|h| h < 24)
        && minute.parse::<u32>().is_ok_and(|m| m < 60)
}

pub fn explicit(args: &mut impl Iterator<Item = OsString>, flag: &OsStr) -> Result<PathBuf> {
    let path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{} needs a path.", flag.to_string_lossy()))?;
    std::fs::canonicalize(&path).map_err(|error| format!("{}: {error}", Path::new(&path).display()))
}

#[cfg(test)]
mod tests;
