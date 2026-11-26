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
        out
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
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
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
            reason: format!(
                "timed out after {} and was stopped",
                if timeout.as_secs() >= 60 {
                    format!("{} minutes", timeout.as_secs() / 60)
                } else {
                    format!("{} ms", timeout.as_millis())
                }
            ),
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
        .map(|l| if home.len() > 1 { shorten_home(&l, &home) } else { l })
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

/// `line` with the home directory `home` written `~`, wherever it is a whole
/// path name: it does not begin inside a longer name and ends at a `/`, a
/// `\`, a space, a quote or other punctuation, or the end of the line. A
/// folder that only starts like it (`/Users/samantha` for `/Users/sam`) is
/// left as it is.
///
/// Example: with home `/Users/sam`, `cannot write /Users/sam/x` is
/// `cannot write ~/x` and `/Users/samantha/x` stays.
fn shorten_home(line: &str, home: &str) -> String {
    let before_ok = |c: Option<char>| c.is_none_or(|c| c.is_whitespace() || "\"'`=:([{<,;".contains(c));
    let after_ok = |c: Option<char>| c.is_none_or(|c| c.is_whitespace() || "/\\\"'`:)]}>,;".contains(c));
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(home) {
        let (head, tail) = rest.split_at(at);
        let after = &tail[home.len()..];
        let whole = before_ok(format!("{out}{head}").chars().next_back()) && after_ok(after.chars().next());
        out.push_str(head);
        out.push_str(if whole { "~" } else { home });
        rest = after;
    }
    out.push_str(rest);
    out
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

/// `text` without terminal escape sequences, other control characters and
/// the invisible characters that change how a line reads (tab becomes a
/// space; newline and carriage return stay): CSI sequences, the strings that
/// end at BEL or `ESC \` (OSC, and the device-control, start-of-string,
/// privacy-message and application-command strings, payload included), and a
/// character-set or other two-byte escape with its final character.
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
                // OSC, DCS, SOS, PM, APC: a string up to BEL or ESC \
                Some(']' | 'P' | 'X' | '^' | '_') => {
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
                // ESC, intermediate bytes (0x20..=0x2F), then a final one: `ESC ( B`
                Some(n) if ('\u{20}'..='\u{2f}').contains(&n) => {
                    while chars.next_if(|m| ('\u{20}'..='\u{2f}').contains(m)).is_some() {}
                    chars.next();
                }
                _ => {}
            },
            '\t' => out.push(' '),
            '\n' | '\r' => out.push(c),
            c if c.is_control() || invisible(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// A character that draws nothing but changes how the text around it reads:
/// the bidirectional marks, embeddings, overrides and isolates, the
/// zero-width spaces and joiners, the invisible operators and the byte order
/// mark. Left in a report line, `\u{202e}` makes the rest of it run backwards.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}')
}
