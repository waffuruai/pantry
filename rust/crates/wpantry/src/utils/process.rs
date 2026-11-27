//! Running programs: always from an argument vector, never a shell string
//! (S6), with stdin closed, `NO_COLOR=1`, a deadline and capped output;
//! finding them on PATH and inside installed apps.

use super::files::{expand, home, realpath};
use crate::error::{Error, Result};
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// PATH's directories, in order, split as the platform does (`:` on unix,
/// `;` on Windows); an empty entry stays "" (the current directory). A
/// directory inside a folder the scan leaves out (`crate::utils::privacy`)
/// is not among them: every PATH consumer (the tool inventory, the Python
/// search, the browsers) goes through here, so none of them stats or lists
/// it, which would raise the privacy prompt the flag exists to avoid.
pub fn path_dirs() -> Vec<String> {
    path_dirs_of(std::env::var_os("PATH").as_deref())
}

/// [`path_dirs`] for the PATH value `path`.
pub(crate) fn path_dirs_of(path: Option<&OsStr>) -> Vec<String> {
    match path {
        Some(p) => std::env::split_paths(p)
            .filter(|d| !crate::utils::privacy::is_left_out(d))
            .map(|d| d.to_string_lossy().into_owned())
            .collect(),
        None => Vec::new(),
    }
}

/// `dirs` without the ones inside a folder the scan leaves out: for the
/// extra directories a caller searches beside PATH.
pub fn reachable(dirs: Vec<String>) -> Vec<String> {
    dirs.into_iter().filter(|d| !crate::utils::privacy::is_left_out(d)).collect()
}

/// The first executable called `name` on PATH (Python: `shutil.which`), else
/// in a [`SYSTEM_DIRS`] folder. On Windows a bare name also matches
/// `name.exe`, `.cmd` and `.bat`. It looks where [`resolve`] and so the
/// spawns in this module look, in the same order (see `lookup`), so a tool
/// this finds is one [`exec`] runs.
pub fn which(name: &str) -> Option<PathBuf> {
    which_in(name, std::env::var_os("PATH").as_deref())
}

/// [`which`] against the PATH `path` (`None`: no PATH at all).
pub fn which_in(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    which_with(name, path, SYSTEM_DIRS)
}

/// [`which_in`] with the system folders given (the tests' own).
pub(crate) fn which_with(name: &str, path: Option<&OsStr>, system: &[&str]) -> Option<PathBuf> {
    lookup(OsStr::new(name), path, system).map(Found::into_path)
}

/// Where the system's administration tools live on Unix. A program that
/// starts wpantry may give it a PATH without the `sbin` folders (a job
/// runner, another program's child, `env -i`); the checks that run `spctl`,
/// `scutil`, `system_profiler`, `cupsctl` or `sysadminctl` by name would then
/// get nothing back and report that they couldn't tell. Root-owned folders
/// only: a folder a user can write to (Homebrew's, mise's) does not belong
/// here, since what is found here is run, sometimes as root.
#[cfg(unix)]
pub const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin"];
/// No system folders to fall back to off Unix.
#[cfg(not(unix))]
pub const SYSTEM_DIRS: &[&str] = &[];

/// Where [`lookup`] found a program.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// A path was given, or PATH has it: the spawn finds it there.
    Path(PathBuf),
    /// Only a [`SYSTEM_DIRS`] folder has it: a spawn by name would not.
    System(PathBuf),
}

impl Found {
    fn into_path(self) -> PathBuf {
        match self {
            Found::Path(p) | Found::System(p) => p,
        }
    }
}

/// The folders Windows' `CreateProcess` searches before PATH: the system
/// folder (`System32`) and the Windows folder, so `whoami`, `schtasks` or
/// `reg` is the operating system's own even when a program's folder earlier
/// on PATH (Git's `usr\bin` has a `whoami.exe` that takes other arguments)
/// has a tool of the same name. Both are administrator-owned. None off
/// Windows.
pub(crate) fn first_dirs() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return Vec::new();
    }
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    vec![root.join("System32"), root]
}

/// The one lookup behind [`which`] and [`resolve`] (and so every spawn here),
/// so they cannot disagree about whether a tool is there: a name with a
/// separator is that path when it is executable; a bare name is the first
/// executable of that name in the [`first_dirs`] (Windows), else on `path`,
/// else in the `system` folders (in order); anything not executable is
/// skipped.
pub(crate) fn lookup(name: &OsStr, path: Option<&OsStr>, system: &[&str]) -> Option<Found> {
    lookup_with(name, path, &first_dirs(), system)
}

/// [`lookup`] with the folders searched before PATH given (the tests' own).
pub(crate) fn lookup_with(name: &OsStr, path: Option<&OsStr>, first: &[PathBuf], system: &[&str]) -> Option<Found> {
    let text = name.to_string_lossy();
    if text.contains('/') || (cfg!(windows) && text.contains('\\')) {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(Found::Path(p));
    }
    let suffixes: &[&str] = if cfg!(windows) && !text.contains('.') { &["", ".exe", ".cmd", ".bat"] } else { &[""] };
    let named = |dir: &Path, suffix: &str| {
        let mut file = name.to_os_string();
        file.push(suffix);
        dir.join(file)
    };
    if let Some(p) = first.iter().flat_map(|d| suffixes.iter().map(move |s| named(d, s))).find(|p| is_executable(p)) {
        return Some(Found::Path(p));
    }
    let on_path = path.and_then(|path| {
        // A PATH folder inside a folder the scan leaves out (`crate::utils::privacy`) is not
        // looked in: even a stat there raises a privacy prompt. The system folders are not
        // filtered: they are fixed, root-owned places.
        std::env::split_paths(path)
            .filter(|d| !crate::utils::privacy::is_left_out(d))
            .flat_map(|d| suffixes.iter().map(move |s| named(&d, s)))
            .find(|p| is_executable(p))
    });
    if let Some(p) = on_path {
        return Some(Found::Path(p));
    }
    system.iter().map(|d| named(Path::new(d), "")).find(|p| is_executable(p)).map(Found::System)
}

/// What a command named `prog` runs, given PATH `path`: the file `which`
/// finds (`prog` itself when it has a slash), PATH's copy before the one
/// in a [`SYSTEM_DIRS`] folder, else `prog` as given, to show or compare: the
/// spawns here refuse a bare name that is not found, as it must not be searched again.
///
/// ```
/// # #[cfg(unix)] {
/// use std::ffi::OsStr;
/// use wpantry::utils::process::resolve;
/// // sysctl is in /usr/sbin or /sbin; PATH here has neither.
/// let tool = resolve(OsStr::new("sysctl"), Some(OsStr::new("/nowhere")));
/// assert!(tool.is_absolute() && tool.ends_with("sysctl"));
/// # }
/// ```
pub fn resolve(prog: &OsStr, path: Option<&OsStr>) -> PathBuf {
    resolve_with(prog, path, SYSTEM_DIRS)
}

/// [`resolve`] with the system folders given (the tests' own). A bare name
/// that is not found stays the bare name, for a caller that only compares or
/// shows it: never spawn that (see [`try_resolve_with`]).
pub(crate) fn resolve_with(prog: &OsStr, path: Option<&OsStr>, system: &[&str]) -> PathBuf {
    try_resolve_with(prog, path, system).unwrap_or_else(|_| PathBuf::from(prog))
}

/// What a spawn of `prog` runs, or the reason it must not happen. A tool
/// found is spelled by its path, never the bare name: the operating system
/// would search PATH again, including the folders a scan leaves out
/// (`--no-personal-files`), and could start another copy than the one
/// [`which`] reported. An empty PATH entry (the current directory) is spelled
/// out for the same reason. A bare name that is not found is an error, for
/// the same reason: the spawn by name would search the whole PATH, left-out
/// folders first, so it fails here with where wpantry looked. A name with a
/// separator is a path, which a spawn never searches PATH for.
pub(crate) fn try_resolve_with(prog: &OsStr, path: Option<&OsStr>, system: &[&str]) -> Result<PathBuf> {
    match lookup(prog, path, system) {
        Some(found) => {
            let found = found.into_path();
            Ok(if found.parent().is_some_and(|p| p.as_os_str().is_empty()) {
                Path::new(".").join(found)
            } else {
                found
            })
        }
        None if has_separator(prog) => Ok(PathBuf::from(prog)),
        None => Err(Error::Failed(not_found(&prog.to_string_lossy(), path))),
    }
}

/// Whether `name` is a path (it has a separator) rather than a bare name.
fn has_separator(name: &OsStr) -> bool {
    let text = name.to_string_lossy();
    text.contains('/') || (cfg!(windows) && text.contains('\\'))
}

/// Why a bare `prog` can't be run: where wpantry looked (PATH's folders it
/// may search, home shortened to `~`), and that PATH folders were left out
/// when a scan skips them. The left-out ones are not named: they were not
/// opened, and naming them would say where they are.
fn not_found(prog: &str, path: Option<&OsStr>) -> String {
    let dirs = path_dirs_of(path);
    let short = |p: &String| crate::utils::files::short(p);
    let shown: Vec<String> = dirs.iter().take(8).map(short).collect();
    let more = if dirs.len() > 8 { format!(" and {} more", dirs.len() - 8) } else { String::new() };
    let skipped =
        path.map_or(0, |p| std::env::split_paths(p).filter(|d| crate::utils::privacy::is_left_out(d)).count());
    let left = match skipped {
        0 => String::new(),
        1 => ", and one PATH folder it leaves out (--no-personal-files)".to_string(),
        n => format!(", and {n} PATH folders it leaves out (--no-personal-files)"),
    };
    format!("`{prog}` was not found: wpantry looked in PATH ({}{more}){left}", shown.join(":"))
}

/// The program a spawn of `prog` runs when PATH is this process's; the
/// reason it can't be spawned otherwise (see [`try_resolve_with`]).
pub(crate) fn program(prog: &OsStr) -> Result<PathBuf> {
    program_in(prog, std::env::var_os("PATH").as_deref())
}

/// [`program`] against the PATH `path`.
pub(crate) fn program_in(prog: &OsStr, path: Option<&OsStr>) -> Result<PathBuf> {
    try_resolve_with(prog, path, SYSTEM_DIRS)
}

/// The command that runs `argv` as root: directly when `root` (the program
/// is resolved as [`exec`] resolves it, so a tool the probe found through
/// the system folders is the one run), else through `sudo`, whose own search
/// path applies. `path` is the PATH to resolve against.
pub(crate) fn root_command(argv: &[&OsStr], root: bool, path: Option<&OsStr>) -> Command {
    let mut c;
    if root {
        c = Command::new(resolve(argv[0], path));
        c.args(&argv[1..]);
    } else {
        c = Command::new("sudo");
        c.args(argv);
    }
    c
}

pub(crate) fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Where a program's own installer puts it, tried after PATH when PATH
/// does not have it (an app started from the Finder, a launchd job or a
/// cron entry has a short one): `mise` in `$MISE_INSTALL_PATH` (when set)
/// and `~/.local/bin`; `brew` in `$HOMEBREW_PREFIX/bin`; both in the three
/// Homebrew prefixes. Other names have no standard place.
///
/// Example: `tool_places("brew", "/Users/x", env)` with no variables set is
/// `/opt/homebrew/bin/brew`, `/usr/local/bin/brew` and
/// `/home/linuxbrew/.linuxbrew/bin/brew`.
pub fn tool_places(name: &str, home: &Path, env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Vec<PathBuf> {
    tool_places_on(cfg!(windows), name, home, env)
}

/// [`tool_places`] for Windows (`windows`) or the Unixes. On Windows only
/// `$MISE_INSTALL_PATH` is named: the Unix prefixes and `~/.local/bin` mean
/// nothing there, there is no Homebrew, and mise's own Windows install
/// locations are not documented well enough to guess (winget and scoop put
/// it on PATH).
pub fn tool_places_on(
    windows: bool,
    name: &str,
    home: &Path,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<PathBuf> {
    let set = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if windows {
        return if name == "mise" { set("MISE_INSTALL_PATH").into_iter().collect() } else { Vec::new() };
    }
    let prefixes = ["/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"];
    let mut out = Vec::new();
    match name {
        "mise" => {
            out.extend(set("MISE_INSTALL_PATH"));
            out.push(home.join(".local/bin/mise"));
        }
        "brew" => out.extend(set("HOMEBREW_PREFIX").map(|p| p.join("bin/brew"))),
        _ => return out,
    }
    out.extend(prefixes.iter().map(|p| Path::new(p).join("bin").join(name)));
    out
}

/// `name` on PATH, else in one of its [`tool_places`]; as root, on PATH
/// only. The places belong to whoever installed the tool (Homebrew's prefix,
/// `~/.local/bin`), and what is found is run: as root that would run a
/// program an unprivileged user can replace, which is why [`SYSTEM_DIRS`]
/// names root-owned folders only. Root's PATH is root's to set.
pub fn find_tool(name: &str) -> Option<PathBuf> {
    if is_root() {
        return which(name);
    }
    find_tool_in(name, std::env::var_os("PATH"), &home(), &|k| std::env::var_os(k))
}

/// Whether this process runs as root (`id -u` is 0), asked once. Never on Windows.
pub fn is_root() -> bool {
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| cfg!(unix) && run(&["id", "-u"], Duration::from_secs(5)).trim() == "0")
}

/// [`find_tool`] for a PATH value, a home directory and an environment.
pub fn find_tool_in(
    name: &str,
    path: Option<std::ffi::OsString>,
    home: &Path,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    which_in(name, path.as_deref()).or_else(|| tool_places(name, home, env).into_iter().find(|p| is_executable(p)))
}

/// What a finished program printed.
#[derive(Debug, Default)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// The most of a program's stdout or stderr kept; the rest is read and
/// dropped, so the program never blocks on a full pipe.
pub const MAX_OUTPUT: u64 = 64 << 20;

/// `cmd.spawn()`, retried briefly on "text file busy": on Unix a program
/// written moments ago can still be open for writing in a child another
/// thread forked between our close and its exec (the descriptor leaks until
/// that exec), and the kernel refuses to run it until then. Transient, so
/// try again for up to a second before giving up.
pub(crate) fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    let mut tries = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) && tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            r => return r,
        }
    }
}

/// errno for "text file busy" on Linux and the BSDs (macOS included).
#[cfg(unix)]
const ETXTBSY: i32 = 26;
#[cfg(not(unix))]
const ETXTBSY: i32 = -1;

/// Run `argv` with stdin closed and `NO_COLOR=1`, killing it after
/// `timeout`. An error only when it can't start or times out. The deadline
/// covers the program and its output: a process it started in the
/// background that keeps the pipes open (a daemon, a `sleep &`) doesn't
/// hold the call past `timeout` (plus a second's grace once it's killed).
pub fn exec(argv: &[&OsStr], env: &[(&str, &str)], timeout: Duration) -> Result<Output> {
    exec_in(argv, env, timeout, std::env::var_os("PATH").as_deref())
}

/// [`exec`] with the program looked up on the PATH `path` (the tests').
pub(crate) fn exec_in(
    argv: &[&OsStr],
    env: &[(&str, &str)],
    timeout: Duration,
    path: Option<&OsStr>,
) -> Result<Output> {
    let (prog, args) = argv.split_first().ok_or_else(|| Error::Failed("empty command".into()))?;
    let mut cmd = Command::new(program_in(prog, path)?);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = spawn(&mut cmd).map_err(|e| Error::Failed(format!("{}: {e}", prog.to_string_lossy())))?;
    let drain = |pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut pipe = pipe;
            let _ = pipe.by_ref().take(MAX_OUTPUT).read_to_end(&mut buf);
            let _ = std::io::copy(&mut pipe, &mut std::io::sink());
            let _ = tx.send(buf);
        });
        rx
    };
    let out = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let err = drain(Box::new(child.stderr.take().expect("piped stderr")));
    let start = Instant::now();
    let timed_out = || Error::Failed(format!("{} timed out after {}s", prog.to_string_lossy(), timeout.as_secs()));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(timed_out());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // The program has exited; its output ends when the last process holding
    // the pipes does. A reader still blocked at the deadline is left to end
    // with that process, and the call reports the timeout.
    let deadline = (start + timeout).max(Instant::now() + Duration::from_secs(1));
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).map_err(|_| timed_out())
    };
    let stdout = String::from_utf8_lossy(&collect(out)?).into_owned();
    let stderr = String::from_utf8_lossy(&collect(err)?).into_owned();
    Ok(Output { code: status.code(), stdout, stderr })
}

/// stdout and stderr of `argv`, or "" when it can't run (Python: `system.run`).
pub fn run<S: AsRef<OsStr>>(argv: &[S], timeout: Duration) -> String {
    let argv: Vec<&OsStr> = argv.iter().map(AsRef::as_ref).collect();
    match exec(&argv, &[], timeout) {
        Ok(o) => o.stdout + &o.stderr,
        Err(_) => String::new(),
    }
}

/// Every distinct executable called `name` on PATH, then in the `extra`
/// directory globs, as (shown path, real path).
pub fn on_path<S: AsRef<str>>(name: &str, extra: &[S]) -> Vec<(String, String)> {
    on_path_in(name, path_dirs(), extra)
}

/// [`on_path`] over `dirs` (PATH's) and then the `extra` globs, none of them
/// inside a left-out folder.
fn on_path_in<S: AsRef<str>>(name: &str, mut dirs: Vec<String>, extra: &[S]) -> Vec<(String, String)> {
    dirs.extend(reachable(expand(extra)));
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for d in dirs {
        let p = if d.is_empty() { name.to_string() } else { format!("{}/{name}", d.trim_end_matches('/')) };
        if is_executable(Path::new(&p)) {
            let real = realpath(&p);
            if !seen.contains(&real) {
                seen.push(real.clone());
                out.push((p, real));
            }
        }
    }
    out
}

/// A CLI shipped inside an installed macOS app, or "".
pub fn app_cli(app_names: &[&str], cli_rel: &str) -> String {
    for name in app_names {
        for root in ["/Applications".to_string(), format!("{}/Applications", home().display())] {
            let cli = format!("{root}/{name}.app/Contents/Resources/app/{cli_rel}");
            if Path::new(&cli).exists() {
                return cli;
            }
        }
    }
    String::new()
}

// The tests run sh and fake executables by mode bit.
#[cfg(all(test, unix))]
#[path = "process_tests.rs"]
mod tests;

/// `first | second`, each from an argument vector, with stdin closed and
/// `NO_COLOR=1`: `each` gets every line `second` prints as it comes, so an
/// output of any size costs only what `each` keeps. Both are killed at
/// `timeout`. An error only when either can't start, or at the deadline.
pub fn pipe_lines(first: &[&OsStr], second: &[&OsStr], timeout: Duration, each: impl FnMut(&[u8])) -> Result<()> {
    stream(first, Some(second), timeout, each)
}

/// One command's output, line by line as it comes, as [`pipe_lines`].
pub fn lines(argv: &[&OsStr], timeout: Duration, each: impl FnMut(&[u8])) -> Result<()> {
    stream(argv, None, timeout, each)
}

fn stream(first: &[&OsStr], second: Option<&[&OsStr]>, timeout: Duration, mut each: impl FnMut(&[u8])) -> Result<()> {
    use std::io::BufRead;
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};
    let start = |argv: &[&OsStr], stdin: Stdio| -> Result<std::process::Child> {
        let (prog, args) = argv.split_first().ok_or_else(|| Error::Failed("empty command".into()))?;
        let mut cmd = Command::new(program(prog)?);
        cmd.args(args).stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::null()).env("NO_COLOR", "1");
        // A read of a partial clone never makes git fetch what it's missing.
        cmd.env("GIT_NO_LAZY_FETCH", "1");
        spawn(&mut cmd).map_err(|e| Error::Failed(format!("{}: {e}", prog.to_string_lossy())))
    };
    let mut a = start(first, Stdio::null())?;
    let mut b = match second {
        None => None,
        Some(second) => {
            let into = Stdio::from(a.stdout.take().expect("piped stdout"));
            match start(second, into) {
                Ok(b) => Some(b),
                Err(e) => {
                    let _ = a.kill();
                    let _ = a.wait();
                    return Err(e);
                }
            }
        }
    };
    let out = match &mut b {
        Some(b) => b.stdout.take(),
        None => a.stdout.take(),
    }
    .expect("piped stdout");
    let (tx, rx) = sync_channel::<Vec<u8>>(1024);
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(out).split(b'\n') {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let result = loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => each(&line),
            Err(RecvTimeoutError::Disconnected) => break Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                let _ = a.kill();
                if let Some(b) = &mut b {
                    let _ = b.kill();
                }
                let prog = first.first().map(|p| p.to_string_lossy()).unwrap_or_default();
                break Err(Error::Failed(format!("{prog} timed out after {}s", timeout.as_secs())));
            }
        }
    };
    let _ = a.wait();
    if let Some(b) = &mut b {
        let _ = b.wait();
    }
    result
}

/// Keep the machine from sleeping while this process runs: a first scan
/// can take an hour, and a Mac left alone sleeps through it. macOS's
/// Whether process `pid` is running. Unix asks `kill -0` (no signal is
/// sent); elsewhere there is no cheap way to ask, and the answer is no.
pub fn alive(pid: u32) -> bool {
    // By the path found: a spawn by name would search PATH again, the folders a scan leaves out included.
    cfg!(unix)
        && program(OsStr::new("kill")).is_ok_and(|kill| {
            Command::new(kill)
                .args(["-0", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
}

/// `caffeinate` holds the assertion and ends with us (`-w`); elsewhere,
/// and when it can't start, nothing happens.
pub fn stay_awake() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/caffeinate")
            .args(["-i", "-w", &std::process::id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}
