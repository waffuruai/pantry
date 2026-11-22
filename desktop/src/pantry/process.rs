//! Running the scanner as a child: its own process group, a time limit,
//! Cancel, and its status lines while it runs.

use super::{CANCELLED, Result, TIMED_OUT, Task};
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(super) fn spawn(mut command: Command) -> std::io::Result<Child> {
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

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
