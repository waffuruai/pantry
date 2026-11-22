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

use crate::data::{Period, Report, Schedule, Update};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

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

fn spawn(mut command: Command) -> std::io::Result<Child> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group, so Cancel also stops what it started.
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command.spawn()
}

/// Stop the child and everything it started.
fn kill(child: &mut Child) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{}", child.id())])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &child.id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The last line worth showing from the scanner's stderr: no colour codes,
/// no leading markers, at most 120 characters.
fn status_line(line: &str) -> Option<String> {
    let mut clean = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip an ANSI escape such as ESC [ 1 ; 31 m.
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if !c.is_control() {
            clean.push(c);
        }
    }
    let clean = clean
        .trim()
        .trim_start_matches(['ℹ', '✓', '✗', '⚠', '•'])
        .trim();
    if clean.is_empty() {
        return None;
    }
    Some(if clean.chars().count() > 120 {
        clean.chars().take(119).collect::<String>() + "…"
    } else {
        clean.to_owned()
    })
}

/// Wait for `child`, reading its output on two threads. Cancel and the
/// time limit kill it. Polls every 50 ms.
pub(crate) fn supervise(mut child: Child, limit: Duration, task: &Task) -> Result<Output> {
    let (send, receive) = mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        let send = send.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            let _ = send.send((true, bytes));
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let send = send.clone();
        let note = task.note.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let mut line = Vec::new();
            // Split on \n and \r so a redrawn progress line also counts.
            while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
                bytes.extend_from_slice(&line);
                for part in String::from_utf8_lossy(&line).split('\r') {
                    if let (Some(text), Ok(mut note)) = (status_line(part), note.lock()) {
                        *note = text;
                    }
                }
                line.clear();
            }
            let _ = send.send((false, bytes));
        });
    }
    drop(send);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                kill(&mut child);
                return Err(format!("Pantry lost track of the scanner. {error}"));
            }
        }
        if task.cancelled() {
            kill(&mut child);
            return Err(CANCELLED.into());
        }
        if started.elapsed() > limit {
            kill(&mut child);
            return Err(format!(
                "{TIMED_OUT} {} minutes.",
                limit.as_secs().div_ceil(60)
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Something the scanner started may still hold a pipe open; don't wait
    // on it for long.
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        match receive.recv_timeout(Duration::from_secs(5)) {
            Ok((true, bytes)) => stdout = bytes,
            Ok((false, bytes)) => stderr = bytes,
            Err(_) => break,
        }
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn checked(out: Output, codes: &[i32]) -> Result<String> {
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.code().is_some_and(|code| codes.contains(&code)) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let message = [stdout.as_str(), stderr.trim()]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if message.is_empty() {
        Err(format!("Pantry exited with {}.", out.status))
    } else {
        Err(message)
    }
}

/// The command a fix dry run says it would run, checked on the raw text
/// before anything is cleaned: a command with hidden characters, a line
/// break or a tab cannot be shown as it would run, and an answer for a
/// different scan is not the fix that was asked about. Both are refused
/// with [`UNVERIFIED`].
///
/// ```ignore
/// verified_preview(output(0, r#"{"schema":1,"scan":7,"command":"brew upgrade x"}"#, ""), 7)
///     == Ok("brew upgrade x".into());
/// ```
fn verified_preview(out: Output, scan: i64) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Preview {
        schema: i64,
        scan: i64,
        command: String,
    }
    let text = checked(out, &[0])?;
    let preview: Preview = serde_json::from_str(&text)
        .map_err(|error| format!("{UNEXPECTED} {error}\n{}", excerpt(&text)))?;
    if preview.schema != 1 || preview.scan != scan || !shown_as_runs(&preview.command) {
        return Err(UNVERIFIED.into());
    }
    Ok(preview.command)
}

/// Longest fix command Pantry will show and run.
pub const COMMAND_MAX: usize = 2000;

/// True when a fix command reads on screen exactly as it runs. An
/// allow-list: printable ASCII only (so no look-alike letters, Unicode
/// spaces, variation selectors or blank symbols), no leading or trailing
/// space, single spaces between words outside quotes (a long run of spaces
/// can push the rest of the command out of view), and at most
/// [`COMMAND_MAX`] bytes. A command with a non-ASCII path is refused too,
/// rather than shown in a form people can't check.
///
/// ```text
/// npm install left-pad@2.0              -> true
/// npm install left-pad@2.0\u{a0}x        -> false (no-break space)
/// npm install left-pad@2.0    ; x       -> false (a run of spaces)
/// touch 'a  b'                          -> true  (spaces inside quotes)
/// ```
pub fn shown_as_runs(command: &str) -> bool {
    if command.is_empty()
        || command.len() > COMMAND_MAX
        || command.trim() != command
        || !command.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return false;
    }
    let mut quote = None;
    let mut previous = 0u8;
    for b in command.bytes() {
        match (quote, b) {
            (None, b'\'' | b'"') => quote = Some(b),
            (Some(q), _) if b == q => quote = None,
            (None, b' ') if previous == b' ' => return false,
            _ => {}
        }
        previous = b;
    }
    true
}

/// The scanner's JSON, with every string made safe to show (`clean`).
/// Empty or broken output is `UNEXPECTED`, with what it said in details.
fn json<T: serde::de::DeserializeOwned>(out: Output, codes: &[i32]) -> Result<T> {
    let text = checked(out, codes)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{UNEXPECTED} {error}\n{}", excerpt(&text)))?;
    clean_value(&mut value);
    serde_json::from_value(value).map_err(|error| format!("{UNSUPPORTED} {error}"))
}

/// The start of what the scanner printed, for Show details.
fn excerpt(text: &str) -> String {
    let text = clean(text);
    if text.trim().is_empty() {
        return "It printed nothing.".into();
    }
    let mut short: String = text.chars().take(500).collect();
    if short.len() < text.len() {
        short.push('…');
    }
    format!("It printed: {short}")
}

/// Characters that change how text reads without being seen: controls
/// other than newline and tab, line and paragraph separators,
/// bidirectional overrides and isolates, zero-width marks, the old
/// formatting controls U+206A-206F, tag characters, blank Hangul fillers,
/// and the soft hyphen.
pub fn hidden(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Scanner text made safe to show: `hidden` characters removed.
pub fn clean(text: &str) -> String {
    text.chars().filter(|c| !hidden(*c)).collect()
}

/// `clean` every string in a JSON document, keys included.
fn clean_value(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::String(text) if text.chars().any(hidden) => *text = clean(text),
        Value::Array(items) => items.iter_mut().for_each(clean_value),
        Value::Object(map) => {
            let dirty = map.keys().any(|key| key.chars().any(hidden));
            if dirty {
                let entries: Vec<_> = std::mem::take(map).into_iter().collect();
                map.extend(entries.into_iter().map(|(key, value)| (clean(&key), value)));
            }
            map.values_mut().for_each(clean_value);
        }
        _ => {}
    }
}

/// What went wrong, in words for people who never open a terminal. The
/// scanner's own text stays in `details`, shown behind "Show details".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// A message Pantry wrote itself, already plain.
    Notice,
    ScannerMissing,
    ScannerBlocked,
    Permission,
    Offline,
    VersionMismatch,
    Cancelled,
    TimedOut,
    /// A fix that was cancelled or ran out of time: it may have partly run.
    FixStopped,
    NeedsPassword,
    StaleFix,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Problem {
    pub kind: ProblemKind,
    pub summary: String,
    pub details: String,
}

impl Problem {
    pub fn notice(text: impl Into<String>) -> Self {
        Self {
            kind: ProblemKind::Notice,
            summary: text.into(),
            details: String::new(),
        }
    }

    pub fn missing(path: &Path) -> Self {
        Self {
            kind: ProblemKind::ScannerMissing,
            summary: "Pantry's scanner is missing. Reinstall Pantry to get it back.".into(),
            details: format!("Pantry looked for its scanner at {}.", path.display()),
        }
    }

    pub fn version_mismatch(scanner: &str) -> Self {
        Self {
            kind: ProblemKind::VersionMismatch,
            summary: format!(
                "This copy of Pantry has parts from two versions (app {}, scanner {scanner}). Reinstall Pantry so they match.",
                env!("CARGO_PKG_VERSION")
            ),
            details: String::new(),
        }
    }

    /// Map scanner output or a start error to a plain summary. Anything
    /// unrecognised becomes a generic summary with the raw text in details.
    pub fn from_scanner(raw: &str) -> Self {
        let lower = raw.to_lowercase();
        let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
        let (kind, summary) = if raw.starts_with(UNVERIFIED) {
            (ProblemKind::Failed, UNVERIFIED)
        } else if raw.starts_with(CANCELLED) {
            (ProblemKind::Cancelled, "Stopped. Nothing else was changed.")
        } else if raw.starts_with(TIMED_OUT) {
            (
                ProblemKind::TimedOut,
                "This took too long, so Pantry stopped it. Try again.",
            )
        } else if raw.starts_with(START_FAILED) && has(&["os error 2", "not found", "cannot find"])
        {
            (
                ProblemKind::ScannerMissing,
                "Pantry's scanner is missing. Reinstall Pantry to get it back.",
            )
        } else if raw.starts_with(START_FAILED) {
            (
                ProblemKind::ScannerBlocked,
                "Pantry's scanner could not start. Reinstall Pantry, or check that your security software allows it.",
            )
        } else if has(&["sudo:", "a password is required", "terminal is required"]) {
            (
                ProblemKind::NeedsPassword,
                "This fix needs your computer password, which Pantry does not ask for. Use the steps below to run it yourself.",
            )
        } else if has(&["newer scan"]) {
            (
                ProblemKind::StaleFix,
                "Pantry has newer results than this fix was checked against. Choose Fix it again to review it.",
            )
        } else if has(&[
            "permission denied",
            "os error 13",
            "access is denied",
            "operation not permitted",
        ]) {
            (
                ProblemKind::Permission,
                "Pantry was not allowed to read or change something. Check that you can open the folder, then try again.",
            )
        } else if has(&[
            "could not resolve",
            "failed to lookup address",
            "dns error",
            "network is unreachable",
            "connection refused",
            "no route to host",
            "error trying to connect",
            "temporary failure in name resolution",
            "nodename nor servname",
            "connection reset",
        ]) {
            (
                ProblemKind::Offline,
                "Pantry could not reach the internet to check for security notices. Check your connection, or scan with saved data.",
            )
        } else if raw.starts_with(UNEXPECTED) {
            (
                ProblemKind::Failed,
                "Pantry's scanner returned something unexpected. Show details to see what it said.",
            )
        } else if raw.starts_with(NEWER_FORMAT)
            || raw.starts_with(UNSUPPORTED)
            || has(&[
                "unexpected argument",
                "unrecognized option",
                "unknown command",
            ])
        {
            (
                ProblemKind::VersionMismatch,
                "Pantry's app and scanner are from different versions. Reinstall Pantry so they match.",
            )
        } else {
            (
                ProblemKind::Failed,
                "Pantry could not finish this task. Show details to see what the scanner said.",
            )
        };
        // Details that only repeat the summary would be a second copy.
        let details = if raw.trim() == summary {
            String::new()
        } else {
            clean(raw.trim())
        };
        Self {
            kind,
            summary: summary.into(),
            details,
        }
    }

    /// A scan's problem: a scan that ran out of time can cover less.
    pub fn for_scan(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        if problem.kind == ProblemKind::TimedOut {
            problem.summary =
                "This scan took too long, so Pantry stopped it. Try again. If it happens again, scan fewer folders at a time."
                    .into();
        }
        problem
    }

    /// A fix's problem: one that was stopped part way may have changed
    /// something, so it says so and offers Scan now.
    pub fn for_fix(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        let stopped = match problem.kind {
            ProblemKind::Cancelled => "You stopped the fix",
            ProblemKind::TimedOut => "The fix took too long, so Pantry stopped it",
            _ => return problem,
        };
        problem.kind = ProblemKind::FixStopped;
        problem.summary = format!(
            "{stopped}. It may have partly run. Choose Scan now to see where things stand."
        );
        problem
    }

    /// An update check's problem, in words about updates, not about
    /// security notices or saved data.
    pub fn for_update(raw: &str) -> Self {
        let mut problem = Self::from_scanner(raw);
        problem.summary = match problem.kind {
            ProblemKind::Offline => {
                "Pantry could not reach the internet to check for updates. Check your connection, then try again."
            }
            ProblemKind::Cancelled | ProblemKind::TimedOut => {
                "Pantry stopped checking for updates. Try again later."
            }
            ProblemKind::Notice
            | ProblemKind::ScannerMissing
            | ProblemKind::ScannerBlocked
            | ProblemKind::VersionMismatch => return problem,
            _ => "Pantry could not check for updates. Show details to see what the scanner said.",
        }
        .into();
        // Not an Offline banner: "Scan with saved data" is no answer here.
        if problem.kind == ProblemKind::Offline {
            problem.kind = ProblemKind::Failed;
        }
        problem
    }

    /// True when "Download Pantry" is the way out.
    pub fn needs_reinstall(&self) -> bool {
        matches!(
            self.kind,
            ProblemKind::ScannerMissing
                | ProblemKind::ScannerBlocked
                | ProblemKind::VersionMismatch
        )
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
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pantry-desktop-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn locate_prefers_flag_then_sibling_and_uses_path_only_in_debug() {
        let root = scratch("locate");
        let name = format!("wpantry{}", std::env::consts::EXE_SUFFIX);
        let app_dir = root.join("app");
        let path_dir = root.join("bin");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::create_dir_all(&path_dir).unwrap();
        let exe = app_dir.join("wpantry-desktop");
        let on_path = path_dir.join(&name);
        std::fs::write(&on_path, b"").unwrap();
        let path_var = std::env::join_paths([&path_dir]).unwrap();

        // No sibling: release builds must not take the PATH copy.
        let (path, found) = find(None, Some(&exe), false, Some(&path_var));
        assert_eq!((path, found), (app_dir.join(&name), false));
        // Debug builds may.
        let (path, found) = find(None, Some(&exe), true, Some(&path_var));
        assert_eq!((path, found), (on_path.clone(), true));
        // The sibling wins over PATH in every build.
        std::fs::write(app_dir.join(&name), b"").unwrap();
        let (path, found) = find(None, Some(&exe), true, Some(&path_var));
        assert_eq!((path, found), (app_dir.join(&name), true));
        // An explicit flag wins over both.
        let (path, found) = find(Some(on_path.clone()), Some(&exe), false, None);
        assert_eq!((path, found), (on_path, true));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn friendly_errors_map_known_failures() {
        let missing = Problem::from_scanner(&format!(
            "{START_FAILED} /x/wpantry. No such file or directory (os error 2)"
        ));
        assert_eq!(missing.kind, ProblemKind::ScannerMissing);
        assert!(!missing.summary.contains("os error"));
        assert!(missing.details.contains("os error 2"));
        let cases = [
            (CANCELLED.to_owned(), ProblemKind::Cancelled),
            (format!("{TIMED_OUT} 30 minutes."), ProblemKind::TimedOut),
            (
                "sudo: a terminal is required to read the password".into(),
                ProblemKind::NeedsPassword,
            ),
            (
                "A newer scan is available. Refresh and preview the fix again.".into(),
                ProblemKind::StaleFix,
            ),
            (
                "open /Users/x/Documents: Permission denied (os error 13)".into(),
                ProblemKind::Permission,
            ),
            (
                "error sending request: dns error: failed to lookup address".into(),
                ProblemKind::Offline,
            ),
            (
                format!("{NEWER_FORMAT} report format (2)."),
                ProblemKind::VersionMismatch,
            ),
            (
                "error: unexpected argument '--no-personal-files' found".into(),
                ProblemKind::VersionMismatch,
            ),
        ];
        for (raw, kind) in cases {
            let problem = Problem::from_scanner(&raw);
            assert_eq!(problem.kind, kind, "{raw}");
            assert_eq!(problem.details, raw.trim(), "raw text stays under details");
            assert_ne!(problem.summary, raw);
        }
    }

    /// A finished child's output, for the parsing checks.
    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        #[cfg(unix)]
        let status = std::os::unix::process::ExitStatusExt::from_raw(code << 8);
        #[cfg(windows)]
        let status = std::os::windows::process::ExitStatusExt::from_raw(code as u32);
        Output {
            status,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// Oracle: the words fit the task. A fix stopped part way says it may
    /// have partly run; only a scan is told to scan fewer folders; an
    /// update check never talks about security notices or saved data.
    #[test]
    fn problems_are_worded_for_their_task() {
        let timeout = format!("{TIMED_OUT} 15 minutes.");
        let fix = Problem::for_fix(&timeout);
        assert_eq!(fix.kind, ProblemKind::FixStopped);
        assert!(
            fix.summary.contains("may have partly run"),
            "{}",
            fix.summary
        );
        assert!(!fix.summary.contains("fewer folders"), "{}", fix.summary);
        let cancelled = Problem::for_fix(CANCELLED);
        assert_eq!(cancelled.kind, ProblemKind::FixStopped);
        assert!(!cancelled.summary.contains("Nothing else was changed"));
        let scan = Problem::for_scan(&timeout).summary;
        assert!(scan.contains("fewer folders"), "{scan}");
        assert!(!scan.contains("smaller folder"), "{scan}");
        assert!(
            !Problem::from_scanner(&timeout)
                .summary
                .contains("fewer folders")
        );
        // Other fix failures keep their own words.
        assert_eq!(
            Problem::for_fix("sudo: a password is required").kind,
            ProblemKind::NeedsPassword
        );
        let update =
            Problem::for_update("error sending request: dns error: failed to lookup address");
        assert_eq!(
            update.kind,
            ProblemKind::Failed,
            "no Scan with saved data button"
        );
        assert!(
            update.summary.contains("check for updates"),
            "{}",
            update.summary
        );
        for word in ["security notice", "saved data"] {
            assert!(!update.summary.contains(word), "{}", update.summary);
        }
    }

    /// Known-bad: "offline" inside other text (a flag name, a file name)
    /// is not a network failure.
    #[test]
    fn offline_is_not_matched_inside_other_words() {
        for raw in [
            "error: --offline needs a saved copy; the cache has none",
            "could not open /tmp/offline-cache.db: Permission denied",
        ] {
            assert_ne!(
                Problem::from_scanner(raw).kind,
                ProblemKind::Offline,
                "{raw}"
            );
        }
    }

    /// Oracle: empty or broken output is the scanner misbehaving, not a
    /// version mismatch: never "Reinstall", and what it printed is kept.
    #[test]
    fn garbage_output_is_unexpected_not_reinstall() {
        for (stdout, said) in [
            ("", "It printed nothing."),
            ("<html>proxy error</html>", "proxy error"),
        ] {
            let error = json::<Update>(output(0, stdout, ""), &[0]).err().unwrap();
            let problem = Problem::from_scanner(&error);
            assert_eq!(problem.kind, ProblemKind::Failed, "{error}");
            assert!(!problem.needs_reinstall());
            assert!(
                problem.summary.contains("something unexpected"),
                "{}",
                problem.summary
            );
            assert!(problem.details.contains(said), "{}", problem.details);
        }
    }

    /// Known-bad: bidi overrides and isolates, zero-width marks, tag
    /// characters, blank fillers and escape codes in any string the
    /// scanner sends, object keys included, are removed before anything
    /// shows them.
    #[test]
    fn scanner_text_loses_hidden_characters() {
        let raw = "{\"current\":\"0.6.0\",\"latest\":\"0.6\\u202e1.0\\u001b[31m\",\"available\":false,\"assets\":[\"a\\u200bb\\u2066c\\u2069\"]}";
        let update: Update = json(output(0, raw, ""), &[0]).unwrap();
        assert_eq!(update.latest, "0.61.0[31m");
        assert_eq!(update.assets.unwrap(), ["abc"]);
        let mut keyed: serde_json::Value =
            serde_json::from_str("{\"na\\u2067me\":{\"k\\u200d\":\"v\\u2028w\"}}").unwrap();
        clean_value(&mut keyed);
        assert_eq!(keyed, serde_json::json!({"name": {"k": "vw"}}));
        for c in [
            '\u{2028}',
            '\u{2029}',
            '\u{2066}',
            '\u{2069}',
            '\u{206A}',
            '\u{206F}',
            '\u{E0000}',
            '\u{E0041}',
            '\u{E007F}',
            '\u{3164}',
            '\u{115F}',
            '\u{FFA0}',
        ] {
            assert!(hidden(c), "U+{:04X}", c as u32);
            assert_eq!(clean(&format!("a{c}b")), "ab", "U+{:04X}", c as u32);
        }
        // Ordinary text, accents and other scripts are never hidden.
        assert_eq!(clean("café 한국 ✓ — x"), "café 한국 ✓ — x");
        assert_eq!(
            clean("tab\tand\nnewline stay\u{7}"),
            "tab\tand\nnewline stay"
        );
        let problem = Problem::from_scanner("bad \u{202E}txt.exe");
        assert_eq!(problem.details, "bad txt.exe");
    }

    /// Known-bad: the dry-run command is checked as the scanner sent it,
    /// before cleaning. A right-to-left override, a tag character, a line
    /// break or a tab in it, or an answer for another scan, is refused
    /// with the plain "could not verify" sentence, which is also what the
    /// person sees.
    #[test]
    fn fix_previews_are_checked_before_cleaning() {
        let preview = |command: &str, scan: i64| {
            let body = serde_json::json!({"schema": 1, "scan": scan, "command": command});
            verified_preview(output(0, &body.to_string(), ""), 7)
        };
        assert_eq!(preview("brew upgrade jq", 7).unwrap(), "brew upgrade jq");
        for command in [
            "npm install left-pad@1.3.0 \u{202E}gpj.exe",
            "brew upgrade jq\u{E0072}\u{E006D}",
            "brew upgrade jq\nrm marker",
            "brew upgrade jq\r",
            "brew\tupgrade jq",
            "brew upgrade\u{2028}jq",
            "brew upgrade \u{3164}jq",
            "   ",
        ] {
            assert_eq!(preview(command, 7).unwrap_err(), UNVERIFIED, "{command:?}");
        }
        assert_eq!(preview("brew upgrade jq", 8).unwrap_err(), UNVERIFIED);
        let wrong_schema = verified_preview(
            output(
                0,
                r#"{"schema":2,"scan":7,"command":"brew upgrade jq"}"#,
                "",
            ),
            7,
        );
        assert_eq!(wrong_schema.unwrap_err(), UNVERIFIED);
        let problem = Problem::from_scanner(UNVERIFIED);
        assert_eq!(problem.summary, UNVERIFIED);
        assert_eq!(problem.details, "", "no second copy under Show details");
        assert!(!problem.needs_reinstall());
    }

    /// Oracle: a command is accepted only when every byte is printable
    /// ASCII with single spaces outside quotes. Known-bad: each character
    /// a deny-list missed (Unicode spaces, blank symbols, variation
    /// selectors, look-alike letters, fullwidth and ligature forms,
    /// combining marks), a padded command, a 20000-byte command and a
    /// non-ASCII path.
    #[test]
    fn only_plain_ascii_commands_count_as_shown() {
        for good in [
            "npm install pkg0@2.0",
            "cargo update -p rustls --precise 0.23.18",
            "touch 'a  b'",
            "sudo apt-get update && sudo apt-get install --only-upgrade curl",
        ] {
            assert!(shown_as_runs(good), "{good:?}");
        }
        let base = "npm install pkg0@2.0";
        let long = format!("npm install {} ; touch marker", "a".repeat(20000));
        let padded = format!("{base}{}; touch marker", " ".repeat(300));
        let mut bad: Vec<String> = [
            "\u{00A0}",
            "\u{2000}",
            "\u{200A}",
            "\u{202F}",
            "\u{205F}",
            "\u{3000}",
            "\u{1680}",
            "\u{2800}",
            "\u{034F}",
            "\u{FE0F}",
            "\u{E0100}",
            "\u{2065}",
            "\u{180B}",
            "\u{FFF9}",
            "\u{FFFC}",
            "\u{1D173}",
            "\u{17B5}",
            "\u{0301}",
            "\u{FFFD}",
            "\u{E000}",
            "\u{0378}",
            "\u{FF1B}",
        ]
        .iter()
        .map(|c| format!("{base}{c}x"))
        .collect();
        bad.extend([
            "npm install \u{0440}kg0@2.0".into(),
            "npm install \u{FF50}\u{FF4B}\u{FF47}\u{FF10}@2.0".into(),
            "npm install con\u{FB01}g@2.0".into(),
            "touch /Users/s\u{00E9}b/marker".into(),
            format!(" {base}"),
            format!("{base} "),
            format!("{base}  ; touch marker"),
            padded,
            long,
            String::new(),
        ]);
        for command in &bad {
            assert!(!shown_as_runs(command), "{command:?}");
            let body = serde_json::json!({"schema": 1, "scan": 7, "command": command});
            assert_eq!(
                verified_preview(output(0, &body.to_string(), ""), 7).unwrap_err(),
                UNVERIFIED,
                "{command:?}"
            );
        }
        assert!(shown_as_runs(&"a".repeat(COMMAND_MAX)));
        assert!(!shown_as_runs(&"a".repeat(COMMAND_MAX + 1)));
    }

    /// Oracle: garbage with an escape code in it is reported as unexpected
    /// output, and the details shown for it carry no escape code.
    #[test]
    fn garbage_output_has_clean_details() {
        let error = verified_preview(output(0, "\u{1b}[31mnot json\u{202E}", ""), 7).unwrap_err();
        let problem = Problem::from_scanner(&error);
        assert!(problem.summary.contains("something unexpected"));
        assert!(
            problem.details.contains("[31mnot json"),
            "{}",
            problem.details
        );
        assert!(
            !problem.details.chars().any(hidden),
            "{:?}",
            problem.details
        );
    }

    #[test]
    fn missing_folders_names_only_folders_that_are_gone() {
        let here = std::env::temp_dir();
        let gone = here.join("pantry-no-such-folder-for-this-test");
        let scope = format!("repos:{},{}+licenses", here.display(), gone.display());
        assert_eq!(missing_folders(&scope), [gone.display().to_string()]);
        assert!(missing_folders("machine:~").is_empty());
        assert!(missing_folders("machine:~;no-personal-files").is_empty());
    }

    /// Known-bad input: text the mapping does not know must not be
    /// guessed at. It gets the generic summary, raw text under details.
    #[test]
    fn unknown_errors_stay_raw_under_details() {
        let raw = "thread 'main' panicked at src/x.rs:1:1: index out of bounds";
        let problem = Problem::from_scanner(raw);
        assert_eq!(problem.kind, ProblemKind::Failed);
        assert_eq!(problem.details, raw);
        assert!(!problem.summary.contains("panicked"));
    }

    #[test]
    fn status_lines_drop_colour_and_markers() {
        assert_eq!(
            status_line("\u{1b}[2m  ℹ reading /tmp/x\u{1b}[0m").as_deref(),
            Some("reading /tmp/x")
        );
        assert_eq!(status_line("   "), None);
        assert_eq!(status_line(&"x".repeat(300)).unwrap().chars().count(), 120);
    }

    #[test]
    fn scope_round_trips_to_a_scan() {
        let here = std::env::temp_dir().to_string_lossy().into_owned();
        assert_eq!(
            ScanRequest::for_scope("machine:~;no-personal-files", true),
            Some(ScanRequest {
                machine: true,
                paths: vec![],
                include_personal_files: false,
                offline: true
            })
        );
        assert!(
            ScanRequest::for_scope("machine:~", false)
                .unwrap()
                .include_personal_files
        );
        assert_eq!(
            ScanRequest::for_scope(&format!("repos:{here}"), false)
                .unwrap()
                .paths,
            vec![here.clone()]
        );
        assert_eq!(ScanRequest::for_scope("repos:~+licenses", false), None);
        assert_eq!(ScanRequest::for_scope("repos:/no/such/dir", false), None);
        assert_eq!(ScanRequest::for_scope("nonsense", false), None);
    }

    /// Oracle: after Cancel the child's pid no longer exists (`kill -0`
    /// fails), and supervise returns well before the child's 30 s sleep.
    #[cfg(unix)]
    #[test]
    fn cancel_kills_the_child() {
        let root = scratch("cancel");
        let pid_file = root.join("pid");
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(format!(
            "echo $$ > '{}'; echo working >&2; exec sleep 30",
            pid_file.display()
        ));
        command.stdin(Stdio::null());
        let child = spawn(command).unwrap();
        let task = Task::default();
        let canceller = task.clone();
        let started = Instant::now();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            canceller.cancel();
        });
        let result = supervise(child, Duration::from_secs(60), &task);
        assert_eq!(result.unwrap_err(), CANCELLED);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(task.note(), "working");
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!alive, "the cancelled child {pid} is still running");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn time_limit_kills_the_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).stdin(Stdio::null());
        let child = spawn(command).unwrap();
        let started = Instant::now();
        let error = supervise(child, Duration::from_millis(300), &Task::default()).unwrap_err();
        assert!(error.starts_with(TIMED_OUT), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn finished_child_returns_its_output() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "echo out; echo err >&2; exit 3"])
            .stdin(Stdio::null());
        let output = supervise(spawn(command).unwrap(), SHORT_LIMIT, &Task::default()).unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }
}
