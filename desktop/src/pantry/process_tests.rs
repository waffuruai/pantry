use super::*;
// Only the child-process checks (Unix) use these.
#[cfg(unix)]
use crate::pantry::tests::scratch;
#[cfg(unix)]
use crate::pantry::{CANCELLED, SHORT_LIMIT, TIMED_OUT, Task};

#[test]
fn status_lines_drop_colour_and_markers() {
    assert_eq!(
        status_line("\u{1b}[2m  ℹ reading /tmp/x\u{1b}[0m").as_deref(),
        Some("reading /tmp/x")
    );
    assert_eq!(status_line("   "), None);
    assert_eq!(status_line(&"x".repeat(300)).unwrap().chars().count(), 120);
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
