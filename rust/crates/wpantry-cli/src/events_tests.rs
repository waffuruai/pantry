//! The event stream's own guarantees, against an in-memory reader.
//!
//! Risks and their oracles:
//! - an event type loses or renames a field a consumer reads: the field
//!   lists below, which are the schema in specs/cli-contract.md;
//! - the order breaks (a line after `done`, a step left without its end,
//!   an `at` outside its step): the order rules checked by [`order`];
//! - rate limiting writes a stale `at`, or drops a `step` or a `finding`:
//!   the last path told, and every queued line counted;
//! - a long read leaves a follower with nothing: the heartbeat tallies
//!   written while a step is told nothing, and how far apart they are;
//! - a reader that closes early or stops reading holds the scan up: the
//!   time the scan's calls take while the writer can't write.

use super::*;
use serde_json::Value;
use std::io;

/// A reader that keeps what it is given.
#[derive(Clone, Default)]
struct Kept(Arc<Mutex<Vec<u8>>>);

impl Write for Kept {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Kept {
    fn lines(&self) -> Vec<Value> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"))).collect()
    }
}

/// A reader that has closed its end: every write fails.
struct Closed;

impl Write for Closed {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// A reader that never reads: the first write blocks for good.
struct Stuck;

impl Write for Stuck {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const A: Step = Step { id: "a", title: "Doing a" };
const B: Step = Step { id: "b", title: "Doing b" };

fn secret_finding() -> Finding {
    Finding {
        kind: "secret".into(),
        component: "~/app/settings.txt".into(),
        location: "line 3".into(),
        vuln_id: "Any_Secret_GithubPat".into(),
        status: "fail".into(),
        note: "GitHub personal access token, in a file on this machine".into(),
        fix_cmd: "Rotate it where it was issued".into(),
        ..Default::default()
    }
}

/// A run of two steps with a finding, an unchecked source, a note and paths.
fn run(out: Box<dyn Write + Send>) -> Events {
    let ev = Events::new(out, vec![A, B], &[PathBuf::from("/scan/here")]);
    ev.step("a");
    ev.repos(2);
    ev.at(Path::new("/scan/here/x.txt"), At::File);
    ev.finding(&secret_finding());
    ev.finding(&Finding { kind: "unchecked".into(), component: "OSV".into(), ..Default::default() });
    ev.note("a note");
    std::thread::sleep(TICK * 2);
    ev.step("b");
    ev.at(Path::new("/scan/here"), At::Dir);
    std::thread::sleep(TICK * 2);
    ev.step(REPORT.id);
    ev.outcome(&[secret_finding()], 42);
    ev.finish(1, None);
    ev
}

/// A line's keys, sorted (serde_json keeps objects sorted).
fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

fn pick(v: &Value, ks: &[&str]) -> Value {
    Value::Array(ks.iter().map(|k| v[*k].clone()).collect())
}

/// The order rules; returns each line's event name.
fn order(lines: &[Value]) -> Vec<String> {
    let names: Vec<String> = lines.iter().map(|l| l["event"].as_str().unwrap().to_string()).collect();
    assert_eq!(names.first().map(String::as_str), Some("start"), "{names:?}");
    assert_eq!(names.last().map(String::as_str), Some("done"), "{names:?}");
    assert_eq!(names.iter().filter(|n| *n == "start").count(), 1);
    assert_eq!(names.iter().filter(|n| *n == "done").count(), 1);
    let steps = lines[0]["steps"].as_array().unwrap().len() as i64;
    let mut open: Option<(String, i64)> = None;
    let mut last = 0;
    for l in lines {
        assert_eq!(l["v"], 1, "{l}");
        match (l["event"].as_str().unwrap(), l["state"].as_str()) {
            ("step", Some("begin")) => {
                assert!(open.is_none(), "a step began before the last ended: {l}");
                let i = l["index"].as_i64().unwrap();
                assert!(i > last && i <= steps && l["of"] == steps, "{l}");
                last = i;
                open = Some((l["id"].as_str().unwrap().to_string(), i));
            }
            ("step", Some("end")) => {
                let (id, i) = open.take().expect("an end without its begin");
                assert_eq!((l["id"].as_str().unwrap(), l["index"].as_i64().unwrap()), (id.as_str(), i));
            }
            ("at" | "tally" | "finding", _) => {
                let (id, _) = open.as_ref().unwrap_or_else(|| panic!("outside a step: {l}"));
                if let Some(step) = l["step"].as_str() {
                    assert_eq!(step, id, "{l}");
                }
            }
            _ => {}
        }
    }
    assert!(open.is_none(), "the last step never ended");
    names
}

#[test]
fn every_event_has_its_fields() {
    let kept = Kept::default();
    run(Box::new(kept.clone()));
    let lines = kept.lines();
    let names = order(&lines);
    for want in ["start", "step", "at", "tally", "finding", "note", "done"] {
        assert!(names.iter().any(|n| n == want), "no {want}: {names:?}");
    }
    let of = |e: &str| lines.iter().filter(|l| l["event"] == e).cloned().collect::<Vec<_>>();
    let start = &of("start")[0];
    assert_eq!(keys(start), sorted(&["v", "event", "version", "steps", "paths"]));
    assert_eq!(start["version"], wpantry::VERSION);
    assert_eq!(start["steps"][2], serde_json::json!({"id": "report", "title": "Writing the report"}));
    assert!(Path::new(start["paths"][0].as_str().unwrap()).is_absolute());
    let steps = of("step");
    assert_eq!(keys(&steps[0]), sorted(&["v", "event", "id", "title", "state", "index", "of"]));
    assert_eq!(keys(&steps[1]), sorted(&["v", "event", "id", "state", "index", "of", "findings", "unchecked", "ms"]));
    assert_eq!(pick(&steps[1], &["findings", "unchecked"]), serde_json::json!([1, 1]));
    assert_eq!(steps.len(), 6, "three steps, each begun and ended");
    let at = of("at");
    assert_eq!(keys(&at[0]), sorted(&["v", "event", "step", "path", "kind"]));
    assert_eq!(pick(&at[0], &["path", "kind", "step"]), serde_json::json!(["/scan/here/x.txt", "file", "a"]));
    assert_eq!(pick(&at[1], &["kind", "step"]), serde_json::json!(["dir", "b"]));
    let tally = of("tally");
    assert_eq!(keys(&tally[0]), sorted(&["v", "event", "repos", "files", "findings", "unchecked", "listed"]));
    assert_eq!(tally.last().unwrap()["repos"], 2);
    assert_eq!(tally.last().unwrap()["files"], 1);
    let finding = &of("finding")[0];
    assert_eq!(
        keys(finding),
        sorted(&[
            "v",
            "event",
            "step",
            "id",
            "kind",
            "severity",
            "status",
            "title",
            "component",
            "location",
            "vuln_id",
            "fix_cmd",
            "fix_auto",
            "fix_provisional"
        ])
    );
    assert_eq!(finding["id"], secret_finding().id());
    assert_eq!(finding["title"], "GitHub personal access token, in a file on this machine");
    assert_eq!(
        pick(finding, &["fix_cmd", "fix_auto", "fix_provisional"]),
        serde_json::json!(["Rotate it where it was issued", false, true])
    );
    let unchecked = &of("finding")[1];
    assert_eq!(unchecked["kind"], "unchecked");
    assert!(
        unchecked.get("fix_cmd").is_none() && unchecked.get("fix_auto").is_none(),
        "no fix, no fields: {unchecked}"
    );
    assert_eq!(of("note")[0]["text"], "a note");
    let done = &of("done")[0];
    assert_eq!(keys(done), sorted(&["v", "event", "exit", "findings", "unchecked", "ms", "scan"]));
    assert_eq!(pick(done, &["exit", "findings", "unchecked", "scan"]), serde_json::json!([1, 1, 0, 42]));
}

/// Oracle: a finding's `fix_cmd` and `fix_auto` are the step the plan
/// (`remediation::steps`) gives that finding alone, so a caller acting on
/// the event does what `wpantry fix` would for it: its own command, mise's
/// manual rule instead of an upgrade of mise, nothing for a finding with no
/// fix. `fix_provisional` is true exactly where the plan at the scan's end
/// can replace the command: a component version (the highest fixed version
/// of all its findings wins) and a secret (one script per file). Known bad:
/// fields copied straight from the finding report mise's `brew upgrade mise`
/// as unattended, which `wpantry fix` never runs.
#[test]
fn a_findings_fix_is_the_plans_step_for_it() {
    let of = |f: &Finding| -> Value { serde_json::from_str(&finding_line("dependencies", f)).unwrap() };
    let upgrade = Finding {
        kind: "dependency".into(),
        component: "rustls".into(),
        version: "0.23.1".into(),
        vuln_id: "GHSA-aaaa-bbbb-cccc".into(),
        fixed: "0.23.18".into(),
        fix_cmd: "cargo update -p rustls --precise 0.23.18".into(),
        fix_auto: true,
        ..Default::default()
    };
    assert_eq!(
        pick(&of(&upgrade), &["fix_cmd", "fix_auto", "fix_provisional"]),
        serde_json::json!(["cargo update -p rustls --precise 0.23.18", true, true])
    );
    let mise = Finding {
        kind: "component".into(),
        component: "mise".into(),
        version: "2026.1.0".into(),
        fix_cmd: "brew upgrade mise".into(),
        fix_auto: true,
        ..Default::default()
    };
    assert_eq!(
        pick(&of(&mise), &["fix_cmd", "fix_auto"]),
        serde_json::json!([wpantry::remediation::MISE_FIX, false]),
        "only a person updates mise"
    );
    let setting = Finding {
        kind: "setting".into(),
        component: "Firewall".into(),
        fix_cmd: "System Settings → Network → Firewall: turn it on".into(),
        ..Default::default()
    };
    assert_eq!(pick(&of(&setting), &["fix_auto", "fix_provisional"]), serde_json::json!([false, false]));
    let nothing = Finding { kind: "setting".into(), component: "Gatekeeper".into(), ..Default::default() };
    let line = of(&nothing);
    assert!(["fix_cmd", "fix_auto", "fix_provisional"].iter().all(|k| line.get(*k).is_none()), "{line}");
    // The event is ASCII, so the arrow arrives escaped and reads back whole.
    assert!(finding_line("machine", &setting).is_ascii());
    assert_eq!(of(&setting)["fix_cmd"], "System Settings → Network → Firewall: turn it on");
}

/// Mutation guard: nothing is written after `done`, and a second
/// `finish` changes nothing.
#[test]
fn nothing_follows_done() {
    let kept = Kept::default();
    let ev = run(Box::new(kept.clone()));
    ev.step("a");
    ev.finding(&secret_finding());
    ev.note("late");
    ev.at(Path::new("/late"), At::File);
    ev.finish(0, None);
    std::thread::sleep(TICK * 2);
    let lines = kept.lines();
    order(&lines);
    assert_eq!(lines.last().unwrap()["exit"], 1);
}

/// An error, or a run that never had an outcome: `done` says so.
#[test]
fn done_carries_the_error_and_no_counts_without_an_outcome() {
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A], &[]);
    ev.step("a");
    ev.finish(3, Some("the cache can't be opened"));
    let lines = kept.lines();
    order(&lines);
    let done = lines.last().unwrap();
    assert_eq!(done["error"], "the cache can't be opened");
    assert!(done["findings"].is_null() && done["unchecked"].is_null() && done["scan"].is_null(), "{done}");
    // An error isn't reported on a run that exits 0.
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A], &[]);
    ev.steps().panic = Some("ignored".into());
    ev.finish(0, None);
    assert!(kept.lines().last().unwrap().get("error").is_none());
}

/// A flood of paths within one tick: at most one `at` per tick, and the
/// one written is the newest. Every step and finding line still arrives.
#[test]
fn rate_limiting_keeps_the_newest_path_and_every_finding() {
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A], &[]);
    let began = Instant::now();
    ev.step("a");
    for i in 0..20_000 {
        ev.at(&PathBuf::from(format!("/f/{i}")), At::File);
        if i % 1000 == 0 {
            ev.finding(&Finding { kind: "project".into(), component: format!("c{i}"), ..Default::default() });
        }
    }
    std::thread::sleep(TICK * 3);
    let elapsed = began.elapsed();
    ev.finish(0, None);
    let lines = kept.lines();
    order(&lines);
    let at: Vec<&Value> = lines.iter().filter(|l| l["event"] == "at").collect();
    let ticks = (elapsed.as_millis() / TICK.as_millis()) as usize + 1;
    assert!(!at.is_empty() && at.len() <= ticks, "{} at lines in {elapsed:?}", at.len());
    assert_eq!(at.last().unwrap()["path"], "/f/19999", "the newest path");
    assert_eq!(lines.iter().filter(|l| l["event"] == "finding").count(), 20);
    let tally = lines.iter().rfind(|l| l["event"] == "tally").unwrap();
    assert_eq!(pick(tally, &["files", "findings"]), serde_json::json!([20_000, 20]));
}

/// A path told outside a step (before the first, or by a reading thread
/// that lags past its step's end) is dropped; one told in a short step is
/// written before that step's end, naming it.
#[test]
fn a_path_outside_a_step_is_dropped_and_a_short_step_keeps_its_own() {
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A, B], &[]);
    ev.at(Path::new("/before"), At::File);
    ev.step("a");
    ev.at(Path::new("/in-a"), At::File);
    ev.step("b");
    std::thread::sleep(TICK * 2);
    ev.finish(0, None);
    ev.at(Path::new("/after"), At::File);
    let lines = kept.lines();
    order(&lines);
    let paths: Vec<&Value> = lines.iter().filter(|l| l["event"] == "at").map(|l| &l["path"]).collect();
    assert_eq!(paths, ["/in-a"], "{lines:?}");
}

/// The reader closed its end: the calls return, `finish` returns at once.
#[test]
fn a_closed_reader_never_fails_the_run() {
    let began = Instant::now();
    run(Box::new(Closed));
    assert!(began.elapsed() < TICK * 4 + Duration::from_secs(1), "{:?}", began.elapsed());
}

/// The reader stopped reading: the scan's calls don't wait on it, and
/// `finish` gives up after [`DRAIN`].
#[test]
fn a_reader_that_stops_reading_never_holds_the_scan() {
    let ev = Events::new(Box::new(Stuck), vec![A], &[]);
    let began = Instant::now();
    ev.step("a");
    for i in 0..10_000 {
        ev.finding(&Finding { kind: "project".into(), component: format!("c{i}"), ..Default::default() });
        ev.at(Path::new("/x"), At::File);
    }
    assert!(began.elapsed() < Duration::from_secs(2), "the scan waited: {:?}", began.elapsed());
    let ending = Instant::now();
    ev.finish(0, None);
    let took = ending.elapsed();
    assert!(took >= DRAIN && took < DRAIN + Duration::from_secs(2), "{took:?}");
}

#[test]
fn titles_are_the_note_first_line_cut() {
    let mut f = secret_finding();
    assert_eq!(title(&f), "GitHub personal access token, in a file on this machine");
    f.note = format!("{}\nsecond line", "x".repeat(500));
    let t = title(&f);
    assert_eq!(t.chars().count(), TITLE);
    assert!(t.ends_with('…') && !t.contains("second"));
    f.note = String::new();
    assert_eq!(title(&f), "~/app/settings.txt Any_Secret_GithubPat");
}

/// Plain ASCII, one object per line: a path with a newline, an escape
/// and non-ASCII stays on its line, with no control character.
#[test]
fn lines_are_ascii_with_no_control_characters() {
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A], &[]);
    ev.step("a");
    ev.at(Path::new("/odd\nname\u{1b}[31m\u{9b}é"), At::File);
    std::thread::sleep(TICK * 2);
    ev.finish(0, None);
    let raw = String::from_utf8(kept.0.lock().unwrap().clone()).unwrap();
    assert!(raw.chars().all(|c| c == '\n' || (' '..='~').contains(&c)), "{raw:?}");
    // `v` and `event` lead every line, so a reader can tell them at a glance.
    assert!(raw.lines().all(|l| l.starts_with("{\"v\": 1, \"event\": \"")), "{raw}");
    let lines = kept.lines();
    assert!(lines.iter().any(|l| l["path"] == "/odd\nname\u{1b}[31m\u{9b}é"));
}

/// A step that is told nothing for a while (one long read) still writes a
/// tally about every BEAT, the same counts each time, and never faster
/// than the rate limit; between steps nothing is written.
#[test]
fn a_quiet_step_still_beats() {
    let kept = Kept::default();
    let ev = Events::new(Box::new(kept.clone()), vec![A, B], &[]);
    ev.step("a");
    ev.listed(7);
    std::thread::sleep(BEAT * 3 + TICK * 3);
    ev.step(REPORT.id);
    ev.finish(0, None);
    let lines = kept.lines();
    order(&lines);
    let in_a: Vec<&Value> = lines
        .iter()
        .skip_while(|l| l["id"] != "a")
        .take_while(|l| !(l["id"] == "a" && l["state"] == "end"))
        .filter(|l| l["event"] == "tally")
        .collect();
    // The first tally is the counts changing; then one per BEAT of silence.
    assert!(in_a.len() >= 3, "{in_a:?}");
    assert!(in_a.len() <= 5, "faster than once a BEAT: {in_a:?}");
    assert!(in_a.iter().all(|l| l["listed"] == 7 && l["files"] == 0), "{in_a:?}");
}
