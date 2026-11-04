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

/// The first executable called `name` on PATH (Python: `shutil.which`).
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
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
fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
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
    let (prog, args) = argv.split_first().ok_or_else(|| Error::Failed("empty command".into()))?;
    let mut cmd = Command::new(prog);
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
    let mut dirs: Vec<String> = std::env::var("PATH").unwrap_or_default().split(':').map(str::to_string).collect();
    dirs.extend(expand(extra));
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

#[cfg(test)]
mod tests {
    use super::super::files::test_home;
    use super::super::temp::TempDir;
    use super::*;

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
    #[test]
    fn exec_deadline_covers_processes_left_holding_the_pipes() {
        for script in ["sleep 5 & wait", "sleep 5 &"] {
            let start = Instant::now();
            let got = exec(&[OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)], &[], Duration::from_millis(100));
            assert!(got.is_err(), "{script}");
            assert!(start.elapsed() < Duration::from_secs(3), "{script}: {:?}", start.elapsed());
        }
    }

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

    #[test]
    fn app_clis_live_in_applications() {
        let _home = test_home();
        let cli = home().join("Applications/Wpantry Test.app/Contents/Resources/app/bin/cli");
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::write(&cli, "").unwrap();
        assert_eq!(app_cli(&["Wpantry Missing", "Wpantry Test"], "bin/cli"), cli.display().to_string());
        assert_eq!(app_cli(&["Wpantry Missing"], "bin/cli"), "");
    }
}
