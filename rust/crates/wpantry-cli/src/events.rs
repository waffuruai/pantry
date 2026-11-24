//! `scan --events`: the scan's progress as JSON Lines on stderr, for a
//! caller that runs the scanner as a child process (a script, a CI
//! wrapper, an editor, a dashboard) and wants to follow a scan while it
//! runs. One object per line, flushed per line, each with `v` (this
//! format's version) and `event`; the schema is in specs/cli-contract.md
//! (`scan --events`). Stdout is untouched.
//!
//! The scan's thread never writes: it queues lines for a writer thread,
//! so a reader that is slow or gone never holds the scan up. `step`,
//! `finding`, `note` and `done` are always queued; `at` and `tally` are
//! state the writer samples at most every [`TICK`], so they are the only
//! lines rate limiting drops, and the one written is the newest. A step
//! that goes [`BEAT`] without a line gets the tally again (a heartbeat), so
//! a long read or a long look over a big tree is never silent.
//!
//! ```text
//! {"v":1,"event":"step","id":"secrets","title":"Looking for secrets in git history","state":"begin","index":4,"of":10}
//! {"v":1,"event":"at","step":"secrets","path":"/home/me/src/app","kind":"dir"}
//! {"v":1,"event":"step","id":"secrets","state":"end","index":4,"of":10,"findings":1,"unchecked":0,"ms":812}
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use wpantry::checks::watch::{At, Step, Watch};
use wpantry::finding::Finding;
use wpantry::utils::json::{J, obj};

/// The event format's version, `v` on every line.
pub const VERSION: i64 = 1;
/// The most often an `at` or a `tally` line is written.
pub const TICK: Duration = Duration::from_millis(100);
/// The longest a step goes without a line: then the tally is written again
/// even when no count moved, so a long read is never silent.
pub const BEAT: Duration = Duration::from_secs(1);
/// How long the end of a run waits for a reader to take the last lines.
pub const DRAIN: Duration = Duration::from_secs(5);
/// The step the CLI adds after the library's: the report written.
pub const REPORT: Step = Step { id: "report", title: "Writing the report" };
/// The most of a finding's note its event's title keeps.
const TITLE: usize = 200;

/// A line for the writer thread.
enum Msg {
    Line(String),
    /// A step's `begin` (its 1-based index): `at` lines for it may follow.
    Begin(usize, String),
    /// A step's `end`: the tally first, when it changed, and the newest
    /// `at` when none was written in the last [`TICK`].
    End(usize, String),
    /// The last line: written, then the writer stops.
    Done(String),
}

/// What the writer samples: the newest `at`, and the counts.
#[derive(Default)]
struct Shared {
    /// The steps' ids, in order, for the `at` lines.
    names: Vec<&'static str>,
    /// The step in progress (1-based); 0 between steps, when an `at` is dropped.
    step: AtomicUsize,
    /// (step, path, file or dir), the newest not yet written.
    pending: Mutex<Option<(usize, PathBuf, At)>>,
    repos: AtomicU64,
    files: AtomicU64,
    findings: AtomicU64,
    unchecked: AtomicU64,
    /// Files the scan's folder walks have listed so far.
    listed: AtomicU64,
}

impl Shared {
    fn tally(&self) -> [u64; 5] {
        [&self.repos, &self.files, &self.findings, &self.unchecked, &self.listed].map(|a| a.load(Ordering::Relaxed))
    }
}

/// The scan thread's side: which step it is in and what it made there.
struct Steps {
    list: Vec<Step>,
    /// Index into `list` of the step in progress.
    current: Option<usize>,
    began: Instant,
    findings: u64,
    unchecked: u64,
    /// `done` was queued: nothing more is.
    done: bool,
    /// The final counts, once the scan has an outcome.
    outcome: Option<(u64, u64)>,
    /// A panic's message, for `done`.
    panic: Option<String>,
}

pub struct Events {
    tx: Mutex<Option<Sender<Msg>>>,
    shared: Arc<Shared>,
    steps: Mutex<Steps>,
    writer: Mutex<Option<JoinHandle<()>>>,
    /// The writer says here that it has stopped.
    stopped: Mutex<Option<Receiver<()>>>,
    started: Instant,
}

/// The run's events, once `scan --events` has started them.
static EVENTS: OnceLock<Events> = OnceLock::new();

/// Start the events on stderr: the `start` line, and the writer thread.
/// Once per process; later calls return the first.
pub fn start(steps: Vec<Step>, paths: &[PathBuf]) -> &'static Events {
    let ev = EVENTS.get_or_init(|| Events::new(Box::new(std::io::stderr()), steps, paths));
    // A panic's text would break the stream: it goes in `done` instead.
    std::panic::set_hook(Box::new(|info| {
        if let Some(ev) = EVENTS.get() {
            ev.steps.lock().unwrap_or_else(|p| p.into_inner()).panic = Some(info.to_string());
        }
    }));
    ev
}

/// The events of this run, when `--events` started them.
pub fn active() -> Option<&'static Events> {
    EVENTS.get()
}

fn line(event: &str, fields: Vec<(&str, J)>) -> String {
    let mut all = vec![("v".to_string(), J::Int(VERSION)), ("event".to_string(), event.into())];
    all.extend(fields.into_iter().map(|(k, v)| (k.to_string(), v)));
    J::Obj(all).dumps()
}

fn text(p: &Path) -> J {
    p.to_string_lossy().as_ref().into()
}

/// A finding's title: the first line of its note, cut, else what it is about.
pub fn title(f: &Finding) -> String {
    let first = f.note.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return format!("{} {}", f.component, f.vuln_id).trim().to_string();
    }
    if first.chars().count() <= TITLE {
        first.to_string()
    } else {
        format!("{}…", first.chars().take(TITLE - 1).collect::<String>())
    }
}

/// A finding's event: only what the report shows of it (no file contents,
/// no secret: a secret finding names its rule, file and line).
pub fn finding_line(step: &str, f: &Finding) -> String {
    line(
        "finding",
        vec![
            ("step", step.into()),
            ("id", f.id().into()),
            ("kind", f.kind.as_str().into()),
            ("severity", f.severity.as_str().into()),
            ("status", f.status.as_str().into()),
            ("title", title(f).into()),
            ("component", f.component.as_str().into()),
            ("location", f.location.as_str().into()),
            ("vuln_id", f.vuln_id.as_str().into()),
        ],
    )
}

fn tally_line(t: [u64; 5]) -> String {
    let n = |i: usize| J::Int(t[i] as i64);
    line("tally", vec![("repos", n(0)), ("files", n(1)), ("findings", n(2)), ("unchecked", n(3)), ("listed", n(4))])
}

/// The writer thread: queued lines in order, and every [`TICK`] the
/// newest `at` and the tally when they changed, or when a step has gone
/// [`BEAT`] without a line. A write that fails (the reader closed its end)
/// stops the writing, never the scan.
fn write_all(mut out: Box<dyn Write + Send>, rx: Receiver<Msg>, shared: Arc<Shared>, stopped: Sender<()>) {
    let mut broken = false;
    // When the last line was written, for the heartbeat.
    let wrote = std::cell::Cell::new(Instant::now());
    let mut put = |l: &str| {
        if !broken
            && out.write_all(l.as_bytes()).and_then(|()| out.write_all(b"\n")).and_then(|()| out.flush()).is_err()
        {
            broken = true;
        }
        wrote.set(Instant::now());
    };
    let mut tallied = [0u64; 5];
    // The step whose `begin` was written last and whose `end` wasn't yet:
    // the only one an `at` line may name.
    let mut open = 0;
    let long_ago = Instant::now().checked_sub(TICK).unwrap_or_else(Instant::now);
    let (mut tick, mut last_at) = (long_ago, long_ago);
    // The newest `at` of the open step, taken: one of a later step stays
    // for when its `begin` is written; the scan clears the slot at a step's end.
    let take_at = |open: usize| {
        let mut p = shared.pending.lock().unwrap_or_else(|p| p.into_inner());
        if p.as_ref().is_some_and(|(step, _, _)| *step == open && open != 0) { p.take() } else { None }
    };
    loop {
        match rx.recv_timeout(TICK) {
            Ok(Msg::Line(l)) => put(&l),
            Ok(Msg::Begin(i, l)) => {
                put(&l);
                open = i;
            }
            Ok(Msg::End(i, l)) => {
                // A short step still says where it was, within the rate.
                if last_at.elapsed() >= TICK
                    && let Some((step, path, what)) = take_at(i)
                {
                    put(&at_line(&shared, step, &path, what));
                    last_at = Instant::now();
                }
                let t = shared.tally();
                if t != tallied {
                    put(&tally_line(t));
                    tallied = t;
                }
                put(&l);
                open = 0;
            }
            Ok(Msg::Done(l)) => {
                put(&l);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if tick.elapsed() >= TICK {
            tick = Instant::now();
            if last_at.elapsed() >= TICK
                && let Some((step, path, what)) = take_at(open)
            {
                put(&at_line(&shared, step, &path, what));
                last_at = Instant::now();
            }
            let t = shared.tally();
            // The heartbeat: a step that has been quiet for BEAT (a long
            // read, a slow lookup) still says it is alive.
            if open != 0 && (t != tallied || wrote.get().elapsed() >= BEAT) {
                put(&tally_line(t));
                tallied = t;
            }
        }
    }
    let _ = stopped.send(());
}

fn at_line(shared: &Shared, step: usize, path: &Path, what: At) -> String {
    let id = shared.names.get(step - 1).copied().unwrap_or("");
    line("at", vec![("step", id.into()), ("path", text(path)), ("kind", what.name().into())])
}

impl Events {
    /// Events written to `out`: the `start` line now, the rest as they come.
    pub fn new(out: Box<dyn Write + Send>, mut list: Vec<Step>, paths: &[PathBuf]) -> Events {
        if !list.contains(&REPORT) {
            list.push(REPORT);
        }
        let (tx, rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let shared = Arc::new(Shared { names: list.iter().map(|s| s.id).collect(), ..Default::default() });
        let first = line(
            "start",
            vec![
                ("version", wpantry::VERSION.into()),
                ("steps", J::Arr(list.iter().map(|s| obj([("id", s.id.into()), ("title", s.title.into())])).collect())),
                (
                    "paths",
                    J::Arr(paths.iter().map(|p| text(&std::path::absolute(p).unwrap_or_else(|_| p.clone()))).collect()),
                ),
            ],
        );
        let _ = tx.send(Msg::Line(first));
        let s = shared.clone();
        let writer = std::thread::spawn(move || write_all(out, rx, s, stop_tx));
        Events {
            tx: Mutex::new(Some(tx)),
            shared,
            steps: Mutex::new(Steps {
                list,
                current: None,
                began: Instant::now(),
                findings: 0,
                unchecked: 0,
                done: false,
                outcome: None,
                panic: None,
            }),
            writer: Mutex::new(Some(writer)),
            stopped: Mutex::new(Some(stop_rx)),
            started: Instant::now(),
        }
    }

    fn send(&self, m: Msg) {
        if let Some(tx) = self.tx.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = tx.send(m);
        }
    }

    fn steps(&self) -> std::sync::MutexGuard<'_, Steps> {
        self.steps.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// End the step in progress, if any: its `end` line (the writer puts
    /// the tally first). A path told after this waits for the next step.
    fn end(&self, s: &mut Steps) {
        let Some(i) = s.current.take() else { return };
        self.shared.step.store(0, Ordering::SeqCst);
        self.send(Msg::End(
            i + 1,
            line(
                "step",
                vec![
                    ("id", s.list[i].id.into()),
                    ("state", "end".into()),
                    ("index", J::Int(i as i64 + 1)),
                    ("of", J::Int(s.list.len() as i64)),
                    ("findings", J::Int(s.findings as i64)),
                    ("unchecked", J::Int(s.unchecked as i64)),
                    ("ms", J::Int(s.began.elapsed().as_millis() as i64)),
                ],
            ),
        ));
    }

    /// The scan's final counts (its findings after the ignore files,
    /// and what couldn't be checked), for `done`.
    pub fn outcome(&self, findings: &[Finding]) {
        let unchecked = findings.iter().filter(|f| f.kind == "unchecked").count() as u64;
        self.steps().outcome = Some((findings.len() as u64 - unchecked, unchecked));
    }

    /// A one-line note the scan would have printed on stderr.
    pub fn note(&self, text: &str) {
        if self.steps().done {
            return;
        }
        self.send(Msg::Line(line("note", vec![("text", text.into())])));
    }

    /// The last line: the open step ended, then `done` with the exit code
    /// (and on exit 3 the error). Waits up to [`DRAIN`] for the reader to
    /// take what is queued; after that the lines left are dropped.
    pub fn finish(&self, exit: i32, error: Option<&str>) {
        let done = {
            let mut s = self.steps();
            if s.done {
                return;
            }
            self.end(&mut s);
            s.done = true;
            let mut fields = vec![("exit", J::Int(exit as i64))];
            match s.outcome {
                Some((f, u)) => fields.extend([("findings", J::Int(f as i64)), ("unchecked", J::Int(u as i64))]),
                None => fields.extend([("findings", J::Null), ("unchecked", J::Null)]),
            }
            fields.push(("ms", J::Int(self.started.elapsed().as_millis() as i64)));
            let error = error.map(str::to_string).or_else(|| s.panic.clone()).filter(|_| exit != 0);
            if let Some(e) = error {
                fields.push(("error", e.as_str().into()));
            }
            line("done", fields)
        };
        self.send(Msg::Done(done));
        self.tx.lock().unwrap_or_else(|p| p.into_inner()).take();
        let stopped = self.stopped.lock().unwrap_or_else(|p| p.into_inner()).take();
        if stopped.is_some_and(|rx| rx.recv_timeout(DRAIN).is_ok())
            && let Some(w) = self.writer.lock().unwrap_or_else(|p| p.into_inner()).take()
        {
            let _ = w.join();
        }
    }
}

impl Watch for Events {
    fn step(&self, id: &str) {
        let mut s = self.steps();
        if s.done {
            return;
        }
        self.end(&mut s);
        // An id the start line didn't list would break the order it promised.
        let Some(i) = s.list.iter().position(|st| st.id == id) else {
            debug_assert!(false, "step {id} isn't in the start line's list");
            return;
        };
        s.current = Some(i);
        s.began = Instant::now();
        s.findings = 0;
        s.unchecked = 0;
        self.send(Msg::Begin(
            i + 1,
            line(
                "step",
                vec![
                    ("id", s.list[i].id.into()),
                    ("title", s.list[i].title.into()),
                    ("state", "begin".into()),
                    ("index", J::Int(i as i64 + 1)),
                    ("of", J::Int(s.list.len() as i64)),
                ],
            ),
        ));
        self.shared.step.store(i + 1, Ordering::SeqCst);
    }

    fn at(&self, path: &Path, what: At) {
        let step = self.shared.step.load(Ordering::Relaxed);
        if step == 0 {
            return;
        }
        if what == At::File {
            self.shared.files.fetch_add(1, Ordering::Relaxed);
        }
        // A reading thread never waits on another: when the slot is busy,
        // the next file's path takes it.
        if let Ok(mut p) = self.shared.pending.try_lock() {
            *p = Some((step, path.to_path_buf(), what));
        }
    }

    fn repos(&self, n: usize) {
        self.shared.repos.store(n as u64, Ordering::Relaxed);
    }

    fn listed(&self, n: usize) {
        self.shared.listed.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn finding(&self, f: &Finding) {
        let mut s = self.steps();
        let Some(i) = s.current.filter(|_| !s.done) else { return };
        if f.kind == "unchecked" {
            s.unchecked += 1;
            self.shared.unchecked.fetch_add(1, Ordering::Relaxed);
        } else {
            s.findings += 1;
            self.shared.findings.fetch_add(1, Ordering::Relaxed);
        }
        self.send(Msg::Line(finding_line(s.list[i].id, f)));
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
