//! Stopping a program and what it started. Every test tree hangs under a
//! process this test started and the code under test is given only that
//! process; the programs a test starts carry a marker nobody else's do (a
//! `sleep` with a duration of its own, scripts in its own temp directory) so
//! that what is left running can be found, counted and killed by its exact
//! pid at the end, and the test fails if any was left. `ps` and `kill` are
//! stand-ins on the scratch directory where a test needs one to misbehave;
//! none of them is found through PATH, and none signals a process a test did
//! not start (a recording `kill` signals nothing).

use super::*;
use crate::utils::temp::TempDir;
use std::path::{Path, PathBuf};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The processes whose command line has one of `markers`, never this one.
fn marked(markers: &[String]) -> Vec<u32> {
    let out = Command::new("ps").args(["-A", "-o", "pid=", "-o", "command="]).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, rest) = l.split_once(' ')?;
            let pid: u32 = pid.parse().ok()?;
            (pid != std::process::id() && markers.iter().any(|m| rest.contains(m.as_str()))).then_some(pid)
        })
        .collect()
}

/// What a test started: its directory, its markers and the program at the
/// root of its tree. Dropping it kills what is left of them, by pid.
struct Tree {
    dir: TempDir,
    markers: Vec<String>,
    root: Option<Child>,
}

impl Tree {
    fn new(name: &str, sleep: &str) -> Tree {
        let dir = TempDir::new(name).unwrap();
        let markers = vec![format!("sleep {sleep}"), dir.path().display().to_string()];
        Tree { dir, markers, root: None }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn start(&mut self, program: &Path, args: &[&str]) -> u32 {
        let child = Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::null()).spawn().unwrap();
        let pid = child.id();
        self.root = Some(child);
        pid
    }

    fn root(&mut self) -> &mut Child {
        self.root.as_mut().unwrap()
    }

    /// Kill what is left, by exact pid, and say which pids it was.
    fn clean(&mut self) -> Vec<u32> {
        let left = marked(&self.markers);
        for pid in &left {
            let _ = Command::new("/bin/kill").args(["-KILL", &pid.to_string()]).status();
        }
        if let Some(root) = self.root.as_mut() {
            let _ = root.kill();
            let _ = root.wait();
        }
        for _ in 0..50 {
            if marked(&self.markers).is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        left
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.clean();
    }
}

/// A recording `kill`: appends `SIG pid` to a log and signals nothing.
fn recording_kill(dir: &Path) -> PathBuf {
    script(dir, "kill-record", &format!("echo \"$1 $2\" >> '{}'", dir.join("kill.log").display()))
}

fn logged(dir: &Path) -> Vec<(String, u32)> {
    std::fs::read_to_string(dir.join("kill.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (sig, pid) = l.split_once(' ')?;
            Some((sig.trim_start_matches('-').to_string(), pid.parse().ok()?))
        })
        .collect()
}

/// A `kill` that refuses `pid` as a user may refuse a root-owned process and
/// signals the others for real.
fn refusing_kill(dir: &Path, pid: u32) -> PathBuf {
    script(
        dir,
        "refusing-kill",
        &format!(
            "if [ \"$2\" = {pid} ]; then echo \"kill: $2: Operation not permitted\" >&2; exit 1; fi\nexec /bin/kill \"$@\""
        ),
    )
}

// ---- reading `ps` ----------------------------------------------------------

/// Risk: a listing is read wrongly (a header, extra spaces, a column of
/// another width) and a pid is missed or a wrong one signalled. Oracle: the
/// pairs a listing holds, and nothing from lines that are not a pid and a
/// parent pid.
#[test]
fn a_listing_is_read_as_pairs_whatever_the_spacing_and_headers() {
    let text = "  PID  PPID\n    1     0\n  412\t 1  \n\n 9000   412\nUSER PID\n12 1 extra\n7\nx y\n";
    assert_eq!(parse_listing(text), [(1, 0), (412, 1), (9000, 412)]);
    assert!(parse_listing("").is_empty());
}

/// Risk: the tree is wrong: a pid below an unrelated one is taken, a cycle
/// loops, the scanner itself (or its parent, or init) is put in the kill
/// list. Oracle: exactly the root and what hangs under it, never those.
#[test]
fn the_tree_is_the_root_and_what_hangs_under_it_and_never_ourselves() {
    let me = std::process::id();
    let parent = std::os::unix::process::parent_id();
    let pairs =
        [(10, 1), (20, 10), (21, 10), (30, 20), (40, 99), (me, 10), (50, me), (parent, 10), (60, parent), (1, 10)];
    assert_eq!(tree_of(&pairs, 10), [10, 20, 21, 30]);
    // A cycle ends.
    assert_eq!(tree_of(&[(10, 20), (20, 10)], 10), [10, 20]);
}

/// Risk: a `ps` that rejects `-A` (BusyBox's), prints a header, pads with
/// spaces, fails, or prints nothing makes the stop silently fall back to
/// killing the program alone. Oracle: the listing is read from whichever
/// spelling works, and every failure is an error that says what `ps` said.
#[test]
fn stand_in_ps_programs_are_read_or_refused_visibly() {
    let d = TempDir::new("ps").unwrap();
    // BusyBox style: no -A, a header, padded columns, everything listed.
    let busybox = script(
        d.path(),
        "busybox-ps",
        "for a; do [ \"$a\" = -A ] && { echo \"ps: invalid option -- 'A'\" >&2; exit 1; }; done\n\
         echo '  PID  PPID'; echo '    1     0'; echo '  500     1'; echo '  501   500'",
    );
    assert_eq!(list_processes(&busybox, Some(500)).unwrap(), [(1, 0), (500, 1), (501, 500)]);
    // A `ps` that lists only the caller's terminal without -A.
    let user_only = script(
        d.path(),
        "user-only-ps",
        "for a; do [ \"$a\" = -A ] && { echo '  500     1'; echo '  501   500'; exit 0; }; done\necho '  900     1'",
    );
    assert_eq!(list_processes(&user_only, Some(500)).unwrap(), [(500, 1), (501, 500)]);
    // Fails whatever it is given.
    let broken = script(d.path(), "broken-ps", "echo 'ps: cannot read /proc' >&2; exit 2");
    let e = list_processes(&broken, Some(500)).unwrap_err();
    assert!(e.contains("exited 2") && e.contains("cannot read /proc"), "{e}");
    // Prints nothing, successfully.
    let silent = script(d.path(), "silent-ps", "exit 0");
    let e = list_processes(&silent, Some(500)).unwrap_err();
    assert!(e.contains("listed nothing"), "{e}");
    // Never shows the program itself.
    let without = script(d.path(), "without-ps", "echo '  900     1'");
    let e = list_processes(&without, Some(500)).unwrap_err();
    assert!(e.contains("did not list the program itself"), "{e}");
    // Not there at all.
    let e = list_processes(&d.path().join("no-such-ps"), None).unwrap_err();
    assert!(e.contains("could not run ps"), "{e}");
}

// ---- stopping a real tree ---------------------------------------------------

/// A root shell that starts `mid`, which starts 60 `sleep`s 20 ms apart: a
/// descendant that keeps forking while it is being stopped.
fn forking_tree(t: &mut Tree, sleep: &str) -> u32 {
    let mid = script(
        t.path(),
        "mid.sh",
        &format!("i=0; while [ $i -lt 60 ]; do sleep {sleep} & i=$((i+1)); sleep 0.02; done; wait"),
    );
    let root = script(t.path(), "root.sh", &format!("sh '{}' & wait", mid.display()));
    t.start(Path::new("sh"), &[root.to_str().unwrap()])
}

/// Risk: a descendant forked between the `ps` snapshot and the `kill`
/// survives, and the report says stopped. Oracle: with a `ps` that prints its
/// snapshot 0.3 s late (the window), after `kill_tree` says it stopped
/// everything, no process of the tree is left, however many the forking
/// descendant had made.
#[test]
fn a_descendant_forked_after_the_listing_does_not_survive() {
    let mut t = Tree::new("race", "31.4001");
    let slow = script(t.path(), "slow-ps", "ps \"$@\"; r=$?; sleep 0.3; exit $r");
    let root = forking_tree(&mut t, "31.4001");
    std::thread::sleep(Duration::from_millis(150));
    let tools = Tools { ps: slow, kill: "kill".into() };
    let started = std::time::Instant::now();
    let got = kill_tree_with(t.root(), &tools, Duration::from_secs(3));
    assert_eq!(got, Ok(()), "after {:?}", started.elapsed());
    assert!(!alive(root));
    let left = t.clean();
    assert!(left.is_empty(), "left running after a stop that said Ok: {left:?}");
}

/// Risk: a tree that cannot be fully stopped is reported as stopped. Oracle:
/// with one member's pid refused by `kill` ("Operation not permitted"), the
/// answer is an error that names that pid and says why, and the rest of the
/// tree is gone.
#[test]
fn a_member_that_cannot_be_signalled_is_named_and_the_rest_is_stopped() {
    let mut t = Tree::new("refused", "31.4002");
    let root = forking_tree(&mut t, "31.4002");
    std::thread::sleep(Duration::from_millis(150));
    let victim = marked(&["sleep 31.4002".to_string()])[0];
    let tools = Tools { ps: "ps".into(), kill: refusing_kill(t.path(), victim) };
    let got = kill_tree_with(t.root(), &tools, Duration::from_millis(500));
    let why = got.expect_err("a member that could not be stopped was reported as stopped");
    assert!(
        why.contains(&format!("pid {victim} could not be stopped: kill: {victim}: Operation not permitted")),
        "{why}"
    );
    assert!(!alive(root), "the rest of the tree was stopped, the program first");
    let left = t.clean();
    assert_eq!(left, [victim], "only the refused one was left, and it is now killed");
}

/// Risk: the program itself cannot be signalled (a `sudo` step runs as
/// root), and the stop waits for it forever or says it stopped it. Oracle: it
/// returns promptly with an error that says so, and the program is left as
/// it was (not stopped).
#[test]
fn a_program_that_cannot_be_signalled_is_reported_not_waited_for() {
    let mut t = Tree::new("sudo", "31.4003");
    let sudo = script(t.path(), "sudo", "trap '' TERM; while :; do sleep 31.4003; done");
    let root = t.start(Path::new("sh"), &[sudo.to_str().unwrap()]);
    std::thread::sleep(Duration::from_millis(200));
    let tools = Tools { ps: "ps".into(), kill: refusing_kill(t.path(), root) };
    let started = std::time::Instant::now();
    let got = kill_tree_with(t.root(), &tools, Duration::from_millis(500));
    let why = got.expect_err("an unsignalled program was reported as stopped");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert!(why.contains(&format!("pid {root} (the program itself) could not be stopped")), "{why}");
    assert!(why.contains("Operation not permitted"), "{why}");
    assert!(alive(root), "the program is left as it was");
    assert!(t.root().try_wait().unwrap().is_none());
    let left = t.clean();
    assert!(left.contains(&root) || left.len() <= 2, "{left:?}");
}

/// Risk: `ps` fails (BusyBox rejects a flag, no `ps` at all) and the stop
/// quietly kills the program alone while the report says everything was
/// stopped. Oracle: the program is killed, and the answer is an error that
/// says the processes could not be listed and what `ps` said.
#[test]
fn a_failed_listing_is_in_the_answer_not_a_silent_fallback() {
    let mut t = Tree::new("nolist", "31.4004");
    let root = forking_tree(&mut t, "31.4004");
    std::thread::sleep(Duration::from_millis(100));
    let broken = script(t.path(), "broken-ps", "echo 'ps: invalid option' >&2; exit 1");
    let tools = Tools { ps: broken, kill: "kill".into() };
    let why = kill_tree_with(t.root(), &tools, Duration::from_millis(500)).expect_err("a failed listing was hidden");
    assert!(why.contains("could not list the processes") && why.contains("ps: invalid option"), "{why}");
    assert!(!alive(root), "the program itself is still killed");
    let left = t.clean();
    assert!(!left.is_empty(), "what it started was out of reach, and the answer said so");
}

// ---- what is signalled, and how many times ----------------------------------

/// Risk: the scanner's own pid, the pid of the program that started it, or
/// init ends up in the kill list (a listing that names them as below the
/// program, or a bug). Oracle: with a `ps` that does name them, nothing logged
/// by a recording `kill` is any of those, and what is signalled is the root
/// and the real descendants, all stopped before the first is killed.
#[test]
fn our_own_pid_and_our_parent_are_never_signalled() {
    let mut t = Tree::new("never", "31.4005");
    let root = t.start(Path::new("sleep"), &["31.4005"]);
    let me = std::process::id();
    let parent = std::os::unix::process::parent_id();
    let ps = script(
        t.path(),
        "lying-ps",
        &format!(
            "echo '{root} 1'; echo '{me} {root}'; echo '{parent} {root}'; echo '1 {root}'; echo '5000000 {root}'; echo '5000001 {me}'; echo '5000002 5000000'"
        ),
    );
    let tools = Tools { ps, kill: recording_kill(t.path()) };
    let _ = kill_tree_with(t.root(), &tools, Duration::from_millis(200));
    let log = logged(t.path());
    assert!(!log.is_empty());
    for (sig, pid) in &log {
        assert!(*pid != me && *pid != parent && *pid > 1, "{sig} {pid} was signalled");
    }
    let stopped: Vec<u32> = log.iter().filter(|(s, _)| s == "STOP").map(|(_, p)| *p).collect();
    let killed: Vec<u32> = log.iter().filter(|(s, _)| s == "KILL").map(|(_, p)| *p).collect();
    assert_eq!(stopped, [root, 5000000, 5000002]);
    assert_eq!(killed, [root, 5000000, 5000002], "the program first");
    let first_kill = log.iter().position(|(s, _)| s == "KILL").unwrap();
    assert!(log[..first_kill].iter().all(|(s, _)| s == "STOP"), "everything is stopped before the first kill");
    t.clean();
}

/// Risk: a pid that was stopped and then left the tree (it exited, and the
/// pid may be another program's) is killed. Oracle: it is sent `CONT` and
/// never `KILL`.
#[test]
fn a_stopped_pid_that_left_the_listing_is_let_go_not_killed() {
    let mut t = Tree::new("left", "31.4006");
    let root = t.start(Path::new("sleep"), &["31.4006"]);
    let count = t.path().join("calls");
    let ps = script(
        t.path(),
        "changing-ps",
        &format!(
            "n=$(cat '{c}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{c}'\n\
             echo '{root} 1'; echo '5000100 {root}'\n[ $n -le 1 ] && echo '5000101 {root}'; exit 0",
            c = count.display()
        ),
    );
    let tools = Tools { ps, kill: recording_kill(t.path()) };
    let _ = kill_tree_with(t.root(), &tools, Duration::from_millis(100));
    let log = logged(t.path());
    assert!(log.contains(&("STOP".into(), 5000101)), "{log:?}");
    assert!(log.contains(&("CONT".into(), 5000101)), "{log:?}");
    assert!(!log.contains(&("KILL".into(), 5000101)), "{log:?}");
    assert!(log.contains(&("KILL".into(), 5000100)), "{log:?}");
    t.clean();
}

/// Risk: a tree that grows with every listing loops forever. Oracle: the
/// stopping is bounded: one new pid is stopped per listing, `FREEZE_ROUNDS`
/// listings and no more, and the answer says the tree was still growing.
#[test]
fn a_tree_that_keeps_growing_is_given_up_on_after_a_bound() {
    let mut t = Tree::new("grow", "31.4007");
    let root = t.start(Path::new("sleep"), &["31.4007"]);
    let count = t.path().join("calls");
    let ps = script(
        t.path(),
        "growing-ps",
        &format!(
            "n=$(cat '{c}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{c}'\necho '{root} 1'\ni=0; while [ $i -lt $n ]; do echo \"$((5000000+i)) {root}\"; i=$((i+1)); done",
            c = count.display()
        ),
    );
    let tools = Tools { ps, kill: recording_kill(t.path()) };
    let why = kill_tree_with(t.root(), &tools, Duration::from_millis(100)).unwrap_err();
    assert!(why.contains(&format!("still growing after {FREEZE_ROUNDS} listings")), "{why}");
    let stops = logged(t.path()).iter().filter(|(s, _)| s == "STOP").count();
    assert_eq!(stops, FREEZE_ROUNDS + 1, "the root, then one new pid per listing after the first");
    t.clean();
}

// ---- through the fix runner, as a `sudo` step --------------------------------

/// Risk: a step run through `sudo` ignores TERM and has children; the
/// stop has to end it without relying on TERM. Oracle: a stand-in named
/// `sudo` that ignores TERM and runs a `sleep` is stopped with that `sleep`,
/// the reason says stopped, and nothing is left.
#[test]
fn a_stand_in_sudo_that_ignores_term_is_stopped_with_what_it_started() {
    let mut t = Tree::new("sudo-run", "31.4008");
    let sudo = script(t.path(), "sudo", "trap '' TERM; sleep 31.4008 & wait");
    let r = crate::remediation::run::run_bounded(&[sudo.display().to_string()], Duration::from_millis(500));
    assert_eq!(r.reason, "timed out after 500 ms and was stopped");
    let left = t.clean();
    assert!(left.is_empty(), "left running: {left:?}");
}

/// Risk: the report for a program that could not be signalled says
/// "stopped". Oracle: the reason says not everything was stopped, gives the
/// system's words, and for `sudo` that the program runs as root.
#[test]
fn the_report_for_a_step_that_could_not_be_stopped_says_so() {
    let mut t = Tree::new("sudo-report", "31.4009");
    let sudo = script(t.path(), "sudo", "trap '' TERM; sleep 31.4009 & wait");
    let refuse = script(t.path(), "refusing-kill", "echo \"kill: $2: Operation not permitted\" >&2; exit 1");
    let tools = Tools { ps: "ps".into(), kill: refuse };
    let started = std::time::Instant::now();
    let r =
        crate::remediation::run::run_bounded_with(&[sudo.display().to_string()], Duration::from_millis(300), &|c| {
            kill_tree_with(c, &tools, Duration::from_millis(300))
        });
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(!r.ok && r.exit_code.is_none());
    assert!(r.reason.starts_with("timed out after 300 ms and not everything was stopped: "), "{}", r.reason);
    assert!(r.reason.contains("Operation not permitted"), "{}", r.reason);
    assert!(
        r.reason.ends_with("(the program runs as root, which wpantry cannot signal; stop it as root)"),
        "{}",
        r.reason
    );
    t.clean();
}
