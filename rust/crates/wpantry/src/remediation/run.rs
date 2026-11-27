//! Running one unattended fix command, and saying why it failed: its exit
//! code and the end of what it wrote to stderr, bounded, with the home
//! directory shortened to `~`.
//!
//! The command's stdout stays on the terminal as before. Its stderr is
//! passed through to ours as it arrives (so a long install still shows its
//! progress) while the last [`TAIL_BYTES`] are kept for the failure line.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The most of a failed command's stderr kept, in bytes.
pub const TAIL_BYTES: usize = 4096;
/// The most lines of it shown.
pub const TAIL_LINES: usize = 20;
/// The longest line shown; a longer one is cut with `…`.
const MAX_LINE: usize = 400;

/// How a fix command ended.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Run {
    pub ok: bool,
    /// The exit code; None when it never started, timed out or was killed
    /// by a signal.
    pub exit_code: Option<i32>,
    /// A sentence for a failure that has no exit code to show (or none
    /// that explains it), "" for a plain non-zero exit.
    pub reason: String,
    /// The end of its stderr as [`clean_tail`] makes it; "" when none.
    pub stderr: String,
}

/// One unattended fix that failed, as `apply` reports it and the
/// remediation log keeps it.
#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    pub cmd: String,
    pub exit_code: Option<i32>,
    pub reason: String,
    pub stderr: String,
}

impl Failure {
    /// The lines the human output prints under `✗ failed: <cmd>`.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        match self.exit_code {
            Some(code) => out.push(format!("    exit code: {code}")),
            None => out.push(format!("    {}", if self.reason.is_empty() { "no exit code" } else { &self.reason })),
        }
        if !self.stderr.is_empty() {
            out.push(format!("    stderr (last {} lines):", self.stderr.lines().count()));
            out.extend(self.stderr.lines().map(|l| format!("      {l}")));
        }
        if let Some(why) = self.why() {
            out.push(format!("    Why: {why}"));
        }
        out
    }

    /// One plain sentence saying why the fix failed, when the cause is
    /// recognised, else None. Only characters a package name or version may
    /// hold are ever copied from stderr into it.
    pub fn why(&self) -> Option<String> {
        const NO_MATCH: &str = "No matching distribution found for";
        if self.stderr.contains("externally-managed-environment") {
            return Some(
                "This Python is managed by a package manager, so pip will not change it. \
                 Upgrade the package through that package manager instead."
                    .to_string(),
            );
        }
        if let Some(at) = self.stderr.find(NO_MATCH) {
            let wanted = match self.stderr[at + NO_MATCH.len()..].split_whitespace().next().and_then(parse_requirement)
            {
                Some((name, version)) => format!("No release of {name} at or above {version}"),
                None => "No release that fixes this".to_string(),
            };
            return Some(format!("{wanted} supports this Python. Upgrade Python itself, or remove the package."));
        }
        // The failure type has no spawn variant; `not_found` words the
        // reason for a program that is not there, so that is what is read.
        if self.exit_code.is_none() && self.reason.contains("was not found") {
            let program = self.cmd.split_whitespace().next().unwrap_or("");
            let plain = |c: char| c.is_ascii_alphanumeric() || "._/+@-".contains(c);
            if !program.is_empty() && program.len() <= 200 && program.chars().all(plain) {
                return Some(format!(
                    "The program this fix runs is no longer at {program}. \
                     Scan again so the fix names what is installed now."
                ));
            }
        }
        None
    }

    /// One string for the log: the exit code or reason, then the stderr tail.
    pub fn summary(&self) -> String {
        let head = match self.exit_code {
            Some(code) => format!("exit code {code}"),
            None => self.reason.clone(),
        };
        if self.stderr.is_empty() { head } else { format!("{head}\n{}", self.stderr) }
    }
}

/// `name>=version` from pip's message, as (name, version); None unless the
/// whole word is a plain name, `>=` and a plain version (a trailing `,<N`
/// bound is allowed), so nothing odd from stderr is ever repeated.
fn parse_requirement(word: &str) -> Option<(&str, &str)> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    let ok = |s: &str, max: usize| !s.is_empty() && s.len() <= max && s.chars().all(plain);
    let (name, rest) = word.split_once(">=")?;
    let version = rest.split(',').next()?;
    (ok(name, 100) && ok(version, 40)).then_some((name, version))
}

/// Why `program` can't be found: where wpantry looked (PATH, then the
/// places its own installer uses), home shortened to `~`.
fn not_found(program: &str) -> String {
    use crate::utils::process::{path_dirs, tool_places};
    let home = crate::utils::files::home();
    let short = |p: &str| crate::utils::files::short(p);
    if program.contains('/') || program.contains('\\') {
        return format!("`{}` was not found, or is not executable", short(program));
    }
    let dirs = path_dirs();
    let shown: Vec<String> = dirs.iter().take(8).map(|d| short(d)).collect();
    let more = if dirs.len() > 8 { format!(" and {} more", dirs.len() - 8) } else { String::new() };
    let places: Vec<String> =
        tool_places(program, &home, &|k| std::env::var_os(k)).iter().map(|p| short(&p.to_string_lossy())).collect();
    let also = if places.is_empty() { String::new() } else { format!(", and in {}", places.join(", ")) };
    format!("`{program}` was not found: wpantry looked in PATH ({}{more}){also}", shown.join(":"))
}

/// Run `argv` as is (no shell), with stdin closed and stdout on the
/// terminal, killing it after `timeout`.
pub fn run_bounded(argv: &[String], timeout: Duration) -> Run {
    run_bounded_with(argv, timeout, &crate::utils::stop::kill_tree)
}

/// [`run_bounded`] with the way a program past its deadline is stopped given
/// (the tests' own); it says what could not be stopped.
pub(crate) fn run_bounded_with(
    argv: &[String],
    timeout: Duration,
    stop: &dyn Fn(&mut std::process::Child) -> Result<(), String>,
) -> Run {
    // The program as PATH has it, else where its installer puts it: a fix
    // started from an app or a service has a short PATH (`mise` is in
    // ~/.local/bin, `brew` under /opt/homebrew).
    let Some(program) = crate::utils::process::find_tool(&argv[0]) else {
        return Run { reason: not_found(&argv[0]), ..Run::default() };
    };
    let mut cmd = Command::new(&program);
    cmd.args(&argv[1..]).stdin(Stdio::null()).stderr(Stdio::piped());
    let mut child = match crate::utils::process::spawn(&mut cmd) {
        Ok(c) => c,
        Err(e) => {
            return Run { reason: format!("could not be started: {e}"), ..Run::default() };
        }
    };
    // Drain stderr on its own thread, or a chatty command blocks on a full pipe.
    let tail = Arc::new(Mutex::new(Tail::default()));
    let reader = child.stderr.take().map(|pipe| {
        let tail = Arc::clone(&tail);
        std::thread::spawn(move || drain(pipe, &tail))
    });
    let start = Instant::now();
    // What a timeout could not stop, when it could not stop everything.
    let mut not_stopped: Option<String> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() > timeout => {
                not_stopped = stop(&mut child).err();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                return Run { reason: format!("could not be waited for: {e}"), ..Run::default() };
            }
        }
    };
    // Its stderr ends when the last process holding the pipe does: a
    // daemon it left behind must not hold us, so wait a second at most.
    if let Some(reader) = reader {
        let until = Instant::now() + Duration::from_secs(1);
        while !reader.is_finished() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let tail = tail.lock().map(|t| (t.bytes.clone(), t.cut)).unwrap_or_default();
    let stderr = clean_tail(&tail.0, tail.1);
    match status {
        Some(s) if s.success() => Run { ok: true, exit_code: Some(0), reason: String::new(), stderr: String::new() },
        Some(s) => Run {
            ok: false,
            exit_code: s.code(),
            reason: if s.code().is_none() { "stopped by a signal".into() } else { String::new() },
            stderr,
        },
        None => Run {
            ok: false,
            exit_code: None,
            reason: {
                let after = if timeout.as_secs() >= 60 {
                    format!("{} minutes", timeout.as_secs() / 60)
                } else {
                    format!("{} ms", timeout.as_millis())
                };
                match not_stopped {
                    None => format!("timed out after {after} and was stopped"),
                    Some(why) => {
                        // A step run through sudo is root's: wpantry can't signal it.
                        let sudo = std::path::Path::new(&argv[0]).file_name().is_some_and(|n| n == "sudo");
                        let hint = if sudo && why.contains("not permitted") {
                            " (the program runs as root, which wpantry cannot signal; stop it as root)"
                        } else {
                            ""
                        };
                        format!("timed out after {after} and not everything was stopped: {why}{hint}")
                    }
                }
            },
            stderr,
        },
    }
}

#[derive(Default)]
struct Tail {
    bytes: Vec<u8>,
    /// Whether older bytes were dropped, so the first line may be partial.
    cut: bool,
}

fn drain(mut pipe: impl Read, tail: &Mutex<Tail>) {
    let mut buf = [0u8; 4096];
    let mut ours = std::io::stderr();
    loop {
        match pipe.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = ours.write_all(&buf[..n]);
                if let Ok(mut t) = tail.lock() {
                    t.bytes.extend_from_slice(&buf[..n]);
                    if t.bytes.len() > 2 * TAIL_BYTES {
                        let drop = t.bytes.len() - TAIL_BYTES;
                        t.bytes.drain(..drop);
                        t.cut = true;
                    }
                }
            }
        }
    }
}

/// The end of a command's stderr, safe to print: the last
/// [`TAIL_BYTES`] bytes, as text, with terminal escapes and control
/// characters removed, carriage-return progress redrawn lines reduced to
/// their last state, `NAME=value` lines (an environment dump) left out, the
/// home directory shortened to `~`, at most [`TAIL_LINES`] lines of at most
/// [`MAX_LINE`] characters. `cut` says older output was dropped, so the first
/// line is partial and is left out.
pub fn clean_tail(bytes: &[u8], cut: bool) -> String {
    let start = bytes.len().saturating_sub(TAIL_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[start..]).into_owned();
    if (cut || start > 0)
        && let Some((_, rest)) = text.split_once('\n')
    {
        // (One cut line with no newline at all is kept: it is all there is.)
        text = rest.to_string();
    }
    let text = strip_escapes(&text);
    let home = crate::utils::files::home().to_string_lossy().trim_end_matches(['/', '\\']).to_string();
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.rsplit('\r').find(|s| !s.trim().is_empty()).unwrap_or("").trim_end().to_string())
        .filter(|l| !l.is_empty() && !looks_like_env(l))
        .map(|l| if home.len() > 1 { l.replace(&home, "~") } else { l })
        .map(|l| {
            if l.chars().count() > MAX_LINE {
                format!("{}…", l.chars().take(MAX_LINE).collect::<String>())
            } else {
                l
            }
        })
        .collect();
    lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n")
}

/// A `NAME=value` line with an upper-case name: what `env` prints. A
/// failure report never carries one.
fn looks_like_env(line: &str) -> bool {
    match line.split_once('=') {
        Some((name, _)) => {
            name.len() >= 3
                && name.starts_with(|c: char| c.is_ascii_uppercase())
                && name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
        None => false,
    }
}

/// `text` without ANSI escape sequences and other control characters
/// (tab becomes a space; newline and carriage return stay).
fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                // CSI: parameters, then a final byte in @..~
                Some('[') => {
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or ESC \
                Some(']') => {
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\t' => out.push(' '),
            '\n' | '\r' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}
