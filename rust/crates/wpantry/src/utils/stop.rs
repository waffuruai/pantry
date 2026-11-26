//! Stopping a program that ran past its deadline, and what it started.
//!
//! A program that times out is usually a wrapper (a package manager, a shell
//! script) whose own children keep working, holding locks and writing into
//! what the report says was stopped. [`kill_tree`] ends the program and the
//! processes below it, and says whether it could.
//!
//! On Unix the tree is found from `ps` listings and ended with `kill`, so
//! that no `unsafe` and no process group is needed (a group would also be the
//! scanner's own if it were ever started in it):
//!
//! 1. List the tree below the program, send `SIGSTOP` to every member not yet
//!    stopped, and list again, until a listing shows no member that is not
//!    stopped (at most [`FREEZE_ROUNDS`] listings). A stopped process cannot
//!    fork, so a descendant started between a listing and the signal turns up
//!    in the next listing; and it cannot exit, so its pid is not reused while
//!    it is stopped. A stopped pid that the next listing does not show (it
//!    exited first, and the pid may belong to another program now) is sent
//!    `SIGCONT`, and is never killed.
//! 2. `SIGKILL` the program, then the rest, only the pids a listing showed
//!    while they were stopped.
//! 3. List again, for at most [`SETTLE`]: the tree is "stopped" only when
//!    none of those pids is left.
//!
//! What it cannot do, and says so when it cannot: a pid it may not signal
//! (a program running as another user, as `sudo`'s is), a listing that fails,
//! a tree still growing after the last listing. A process that left the tree
//! before the first listing (a daemon, a double fork) is out of reach, and a
//! process forked in the instant its parent's `SIGSTOP` was being delivered
//! can be missed.
//!
//! On Windows `taskkill /T /F /PID` ends the program and the processes it
//! started that it can still find from their parent ids.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The most listings step 1 makes before it gives up on a tree that keeps growing.
#[cfg(unix)]
pub(crate) const FREEZE_ROUNDS: usize = 8;

/// The longest the end waits for the stopped processes to be gone.
pub(crate) const SETTLE: Duration = Duration::from_secs(2);

/// The programs the stop runs, as paths (the tests give stand-ins).
#[cfg(unix)]
pub(crate) struct Tools {
    pub ps: std::path::PathBuf,
    pub kill: std::path::PathBuf,
}

#[cfg(unix)]
impl Tools {
    pub(crate) fn system() -> Tools {
        use super::process::program;
        use std::ffi::OsStr;
        Tools { ps: program(OsStr::new("ps")), kill: program(OsStr::new("kill")) }
    }
}

/// End `child` and every process below it; `Ok` only when none of them is
/// left (the child is reaped), else what could not be stopped. On `Err` the
/// child may still be running and is not waited for.
pub(crate) fn kill_tree(child: &mut Child) -> Result<(), String> {
    #[cfg(unix)]
    {
        kill_tree_with(child, &Tools::system(), SETTLE)
    }
    #[cfg(windows)]
    {
        taskkill(child, SETTLE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        child.kill().map_err(|e| format!("could not stop the program: {e}"))?;
        reaped(child, SETTLE).then_some(()).ok_or_else(|| "the program did not end".to_string())
    }
}

/// Whether `child` has ended (and is reaped) within `wait`.
#[cfg(not(unix))]
fn reaped(child: &mut Child, wait: Duration) -> bool {
    let until = std::time::Instant::now() + wait;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if std::time::Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `taskkill /T /F /PID`: the program and what it started.
#[cfg(windows)]
fn taskkill(child: &mut Child, wait: Duration) -> Result<(), String> {
    let out = Command::new(super::process::program(std::ffi::OsStr::new("taskkill")))
        .args(["/T", "/F", "/PID", &child.id().to_string()])
        .stdin(Stdio::null())
        .output();
    let mut problem = match out {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "taskkill exited {}: {}",
            o.status.code().map_or("by a signal".to_string(), |c| c.to_string()),
            first_line(&o.stderr)
        )),
        Err(e) => Some(format!("could not run taskkill: {e}")),
    };
    if problem.is_some() {
        // At least the program itself.
        let _ = child.kill();
    }
    if !reaped(child, wait) {
        problem.get_or_insert_with(|| "the program did not end".to_string());
    }
    problem.map_or(Ok(()), Err)
}

/// What `cmd` prints, with stdin closed. Started as [`super::process::spawn`]
/// starts programs, which tries again when the kernel says the program is
/// still open for writing (a script written a moment ago).
#[cfg(unix)]
fn output_of(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    super::process::spawn(cmd)?.wait_with_output()
}

/// The first non-empty line of what a program wrote, for a message.
fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no message").chars().take(200).collect()
}

/// Pids that are never signalled, whatever a listing says: this process, the
/// one that started it, and init and below. A tree below a child of ours has
/// none of them; this is the guard if a listing or a bug says otherwise.
#[cfg(unix)]
fn never(pid: u32) -> bool {
    pid <= 1 || pid == std::process::id() || pid == std::os::unix::process::parent_id()
}

/// The `(pid, ppid)` pairs one `ps` lists, as `ps` prints them: a pid and a
/// parent pid on a line, spaces around them, any other line (a header) left
/// out.
#[cfg(unix)]
pub(crate) fn parse_listing(text: &str) -> Vec<(u32, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let pid = f.next()?.parse().ok()?;
            let ppid = f.next()?.parse().ok()?;
            f.next().is_none().then_some((pid, ppid))
        })
        .collect()
}

/// Every process, as `(pid, ppid)`. Tries `-A` (POSIX's "all processes", which
/// a `ps` without it lists only the caller's terminal for), then without it
/// (BusyBox's `ps` has no `-A` and lists everything); `-o pid= -o ppid=` is
/// the spelling POSIX gives for a listing with no header. With `root`, a
/// listing that does not show it is not the whole list and is not used.
#[cfg(unix)]
pub(crate) fn list_processes(ps: &std::path::Path, root: Option<u32>) -> Result<Vec<(u32, u32)>, String> {
    const SPELLINGS: [&[&str]; 2] = [&["-A", "-o", "pid=", "-o", "ppid="], &["-o", "pid=", "-o", "ppid="]];
    let mut why = Vec::new();
    for args in SPELLINGS {
        let shown = format!("ps {}", args.join(" "));
        let out = output_of(Command::new(ps).args(args));
        let out = match out {
            Ok(o) => o,
            Err(e) => return Err(format!("could not run ps: {e}")),
        };
        if !out.status.success() {
            let code = out.status.code().map_or("by a signal".to_string(), |c| c.to_string());
            why.push(format!("`{shown}` exited {code}: {}", first_line(&out.stderr)));
            continue;
        }
        let pairs = parse_listing(&String::from_utf8_lossy(&out.stdout));
        if pairs.is_empty() {
            why.push(format!("`{shown}` listed nothing"));
        } else if root.is_some_and(|r| !pairs.iter().any(|(p, _)| *p == r)) {
            why.push(format!("`{shown}` did not list the program itself"));
        } else {
            return Ok(pairs);
        }
    }
    Err(format!("could not list the processes ({})", why.join("; ")))
}

/// `root` and every pid below it in `pairs`, the root first, parents before
/// children; never a pid [`never`] names, nor anything below one.
#[cfg(unix)]
pub(crate) fn tree_of(pairs: &[(u32, u32)], root: u32) -> Vec<u32> {
    let mut found = vec![root];
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        for (pid, ppid) in pairs {
            if *ppid == parent && !never(*pid) && !found.contains(pid) {
                found.push(*pid);
            }
        }
        i += 1;
    }
    found
}

/// Send `kill -SIG pid`. A pid that is already gone is not an error.
#[cfg(unix)]
fn signal(tools: &Tools, sig: &str, pid: u32) -> Result<(), String> {
    if never(pid) {
        return Err(format!("refused to signal pid {pid}"));
    }
    match output_of(Command::new(&tools.kill).arg(format!("-{sig}")).arg(pid.to_string())) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let said = first_line(&o.stderr);
            if said.contains("No such process") { Ok(()) } else { Err(said) }
        }
        Err(e) => Err(format!("could not run kill: {e}")),
    }
}

/// [`kill_tree`] with the programs and the settling time given.
#[cfg(unix)]
pub(crate) fn kill_tree_with(child: &mut Child, tools: &Tools, settle: Duration) -> Result<(), String> {
    let root = child.id();
    let mut problems: Vec<String> = Vec::new();
    // Stopped, and shown by the last listing.
    let mut frozen: Vec<u32> = Vec::new();
    // Pids that could not be signalled.
    let mut refused: Vec<(u32, String)> = Vec::new();

    let mut settled = false;
    for _ in 0..FREEZE_ROUNDS {
        let tree = match list_processes(&tools.ps, Some(root)) {
            Ok(pairs) => tree_of(&pairs, root),
            Err(why) => {
                problems.push(why);
                settled = true;
                break;
            }
        };
        // Stopped, but not below the program any more: it exited and its pid
        // may be another program's. Let it go.
        for pid in frozen.iter().copied().filter(|p| !tree.contains(p)).collect::<Vec<_>>() {
            let _ = signal(tools, "CONT", pid);
        }
        frozen.retain(|p| tree.contains(p));
        let fresh: Vec<u32> =
            tree.iter().copied().filter(|p| !frozen.contains(p) && !refused.iter().any(|(r, _)| r == p)).collect();
        if fresh.is_empty() {
            settled = true;
            break;
        }
        for pid in fresh {
            match signal(tools, "STOP", pid) {
                Ok(()) => frozen.push(pid),
                Err(why) => refused.push((pid, why)),
            }
        }
    }
    if !settled {
        problems.push(format!("what it started was still growing after {FREEZE_ROUNDS} listings"));
    }

    // The program first (a shell that outlives the children it started
    // reports "Killed" on its own stderr, which would end up in the report),
    // then the rest. With no listing the program is all there is to kill.
    if frozen.is_empty() && !refused.iter().any(|(p, _)| *p == root) {
        frozen.push(root);
    }
    let mut killed: Vec<u32> = Vec::new();
    for pid in frozen {
        match signal(tools, "KILL", pid) {
            Ok(()) => killed.push(pid),
            Err(why) => {
                // Do not leave it stopped.
                let _ = signal(tools, "CONT", pid);
                refused.push((pid, why));
            }
        }
    }
    for (pid, why) in &refused {
        problems.push(format!(
            "pid {pid}{} could not be stopped: {why}",
            if *pid == root { " (the program itself)" } else { "" }
        ));
    }

    // Gone? The program is reaped as it ends; the rest are looked for in a
    // listing. A refused program is already a problem and is not waited for.
    let root_killed = killed.contains(&root);
    let others: Vec<u32> = killed.iter().copied().filter(|p| *p != root).collect();
    let until = std::time::Instant::now() + settle;
    loop {
        let root_done = matches!(child.try_wait(), Ok(Some(_)));
        let left = if others.is_empty() {
            Ok(Vec::new())
        } else {
            list_processes(&tools.ps, None)
                .map(|pairs| others.iter().copied().filter(|k| pairs.iter().any(|(p, _)| p == k)).collect::<Vec<u32>>())
        };
        match left {
            Ok(left) if left.is_empty() && (root_done || !root_killed) => break,
            Ok(left) => {
                if std::time::Instant::now() >= until {
                    if !left.is_empty() {
                        let pids: Vec<String> = left.iter().map(u32::to_string).collect();
                        problems.push(format!("still running after the kill: pid {}", pids.join(", ")));
                    }
                    if root_killed && !root_done {
                        problems.push(format!("pid {root} (the program itself) did not end after the kill"));
                    }
                    break;
                }
            }
            Err(why) => {
                problems.push(format!("could not check that they ended: {why}"));
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("; ")) }
}

#[cfg(all(test, unix))]
#[path = "stop_tests.rs"]
mod tests;
