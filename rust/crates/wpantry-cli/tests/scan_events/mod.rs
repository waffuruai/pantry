//! `scan --events` from the outside (specs/cli-contract.md, `scan
//! --events`): the binary run on fixture folders in a temp HOME, offline,
//! its stderr read as the event stream.
//!
//! Risks and their oracles:
//! - the stream breaks its order or its schema in a real scan: the order
//!   rules in [`order`] and the field lists in the contract;
//! - the events disagree with the report: the `--json` envelope on stdout
//!   (its findings, their ids, the exit code);
//! - the flag changes what a caller already reads: stdout byte for byte
//!   against the same scan without it, and stderr without the flag;
//! - a secret reaches stderr: the secret texts of the rules' own cases
//!   (crates/wpantry/tests/secret-cases.toml), none of which may appear;
//! - a reader that stops early fails the scan: the exit code and stdout of
//!   the same scan read to the end.

use crate::common::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The event lines of a run's stderr; every line must be one.
fn events(err: &str) -> Vec<Value> {
    err.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not an event ({e}): {l:?}"))).collect()
}

/// The order rules: `start` first and `done` last, once each; the steps in
/// the order `start` lists, each begun and ended once; `at`, `tally` and
/// `finding` inside a step, naming it. Returns the step ids as begun.
fn order(lines: &[Value]) -> Vec<String> {
    assert_eq!(lines.first().map(|l| &l["event"]), Some(&Value::from("start")), "{lines:?}");
    assert_eq!(lines.last().map(|l| &l["event"]), Some(&Value::from("done")), "{lines:?}");
    let listed: Vec<String> =
        lines[0]["steps"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_string()).collect();
    let mut begun = Vec::new();
    let mut open: Option<String> = None;
    for (n, l) in lines.iter().enumerate() {
        assert_eq!(l["v"], 1, "{l}");
        let event = l["event"].as_str().unwrap();
        assert!(n == 0 || event != "start", "a second start: {l}");
        assert!(n == lines.len() - 1 || event != "done", "a line after done: {l}");
        match (event, l["state"].as_str()) {
            ("step", Some("begin")) => {
                assert!(open.is_none(), "{l} began before the last step ended");
                let id = l["id"].as_str().unwrap().to_string();
                assert_eq!(l["index"].as_u64().unwrap() as usize, begun.len() + 1, "{l}");
                assert_eq!(l["of"].as_u64().unwrap() as usize, listed.len(), "{l}");
                open = Some(id.clone());
                begun.push(id);
            }
            ("step", Some("end")) => {
                assert_eq!(open.take().as_deref(), l["id"].as_str(), "an end without its begin: {l}");
                assert!(l["ms"].as_u64().is_some(), "{l}");
            }
            ("at" | "tally" | "finding", _) => {
                let step = open.as_deref().unwrap_or_else(|| panic!("outside a step: {l}"));
                if event != "tally" {
                    assert_eq!(l["step"].as_str(), Some(step), "{l}");
                }
            }
            _ => {}
        }
    }
    assert!(open.is_none(), "a step never ended");
    assert_eq!(begun, listed, "the steps run are the ones start listed, in its order");
    begun
}

/// A path as a program compares it: no `\\?\` prefix, `/` for `\`.
fn plain(p: &str) -> String {
    p.strip_prefix(r"\\?\").unwrap_or(p).replace('\\', "/")
}

/// A folder with a lockfile and a secret: one project, findings offline.
fn fixture(t: &Ctx) -> PathBuf {
    let dir = t.home.join("project");
    mkdir(&dir);
    write(&dir.join("Cargo.lock"), "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n");
    // A GitHub token from the rules' own cases, stored reversed.
    let token: String = "gvrMOVt7kvW7QXR9RsHxWt65VWBByL5t718Z_phg".chars().rev().collect(); // gitleaks:allow
    write(&dir.join("settings.txt"), format!("token = {token}\n"));
    dir
}

fn scan_args(dir: &Path) -> Vec<&str> {
    vec!["scan", "--no-machine", "--path", s(dir), "--offline", "--no-malware", "--deep", "--json"]
}

#[test]
fn scan_help_names_the_flag_and_fix_does_not_take_it() {
    let t = Ctx::new();
    let help = t.run(&["scan", "--help"]);
    assert_eq!(help.code, 0);
    assert!(help.out.contains("--events"), "{}", help.out);
    let fix = t.run(&["fix", "--events", "--no-machine", "--path", s(&t.home), "--offline"]);
    assert_eq!(fix.code, 2, "{}", fix.err);
}

#[test]
fn the_stream_follows_the_scan_and_agrees_with_the_report() {
    let t = Ctx::new();
    let dir = fixture(&t);
    let mut argv = scan_args(&dir);
    argv.push("--events");
    let r = t.run(&argv);
    assert!([0, 1].contains(&r.code), "{}", r.err);
    let lines = events(&r.err);
    let steps = order(&lines);
    assert_eq!(steps.first().map(String::as_str), Some("sources"));
    assert_eq!(&steps[steps.len() - 3..], ["file-secrets", "rating", "report"]);
    assert!(!steps.iter().any(|s| s == "machine" || s == "malware" || s == "breach"), "{steps:?}");

    let start = &lines[0];
    let paths: Vec<String> = start["paths"].as_array().unwrap().iter().map(|p| plain(p.as_str().unwrap())).collect();
    assert_eq!(paths, [plain(s(&dir))]);
    assert!(Path::new(start["paths"][0].as_str().unwrap()).is_absolute());

    // The report on stdout is the authority the events agree with.
    let env = envelope(&r.out);
    let reported: BTreeSet<String> =
        arr(&env["findings"]).iter().map(|f| f["id"].as_str().unwrap().to_string()).collect();
    let told: BTreeSet<String> =
        lines.iter().filter(|l| l["event"] == "finding").map(|l| l["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(told, reported, "no ignore file: every finding told is reported, and the reverse");
    let done = lines.last().unwrap();
    assert_eq!(done["exit"], r.code);
    let real = arr(&env["findings"]).iter().filter(|f| f["kind"] != "unchecked").count();
    assert_eq!(done["findings"], real);
    assert_eq!(done["unchecked"], arr(&env["findings"]).len() - real);
    let secret = lines.iter().find(|l| l["event"] == "finding" && l["kind"] == "secret").expect("the token is found");
    assert_eq!(secret["step"], "file-secrets");
    assert_eq!(secret["status"], "fail");
    // Each finding's fix is the report's: its command and whether `fix`
    // runs it unattended, or no fix fields when the report has no command.
    let by_id = |id: &Value| arr(&env["findings"]).iter().find(|f| f["id"] == *id).cloned().expect("reported");
    let mut fixes = 0;
    for told in lines.iter().filter(|l| l["event"] == "finding") {
        let f = by_id(&told["id"]);
        match told.get("fix_cmd") {
            Some(cmd) => {
                fixes += 1;
                assert_eq!((cmd, &told["fix_auto"]), (&f["fix_cmd"], &f["fix_auto"]), "{told}");
                assert!(told["fix_provisional"].is_boolean(), "{told}");
            }
            None => assert_eq!(f["fix_cmd"], "", "{told}"),
        }
    }
    assert!(fixes > 0 && secret["fix_provisional"] == true, "the fixture has fixes to tell: {secret}");
    // `done` names the scan the plan is read from: the one `fix list` reads.
    let listed = t.run(&["fix", "list", "--json"]);
    let plan: Value = serde_json::from_str(&listed.out).unwrap_or_else(|e| panic!("{e}: {}", listed.out));
    assert!(done["scan"].as_i64().is_some_and(|id| id > 0), "{done}");
    assert_eq!(done["scan"], plan["scan"], "{done}");

    // What it read is inside the folder, as absolute paths.
    let at: Vec<&Value> = lines.iter().filter(|l| l["event"] == "at").collect();
    assert!(!at.is_empty());
    let canon = plain(&std::fs::canonicalize(&dir).unwrap().to_string_lossy());
    for a in &at {
        let p = plain(a["path"].as_str().unwrap());
        assert!(p.starts_with(&plain(s(&dir))) || p.starts_with(&canon), "{a}");
        assert!(["file", "dir"].contains(&a["kind"].as_str().unwrap()), "{a}");
    }
    // Each step's end counts the findings it told.
    for end in lines.iter().filter(|l| l["state"] == "end") {
        let id = end["id"].as_str().unwrap();
        let n = lines.iter().filter(|l| l["event"] == "finding" && l["step"] == id && l["kind"] != "unchecked").count();
        assert_eq!(end["findings"], n, "{end}");
    }
}

#[test]
fn the_flag_changes_nothing_on_stdout_and_nothing_without_it() {
    // One HOME (a finding's id hashes its path), a fresh cache each run.
    let t = Ctx::new();
    let dir = fixture(&t);
    for argv in [scan_args(&dir), vec!["scan", "--no-machine", "--path", s(&dir), "--offline", "--no-malware"]] {
        let without = fresh(&t).run(&argv);
        let with = fresh(&t).run(&[argv.as_slice(), &["--events"]].concat());
        assert_eq!(with.code, without.code, "{argv:?}");
        // Two scans: the report's heading names the minute each finished in.
        assert_eq!(no_clock(&with.out), no_clock(&without.out), "stdout is byte for byte the same: {argv:?}");
        assert!(!without.err.contains("\"event\""), "no event without --events: {}", without.err);
        assert_eq!(without.err, "", "without --events and without a terminal, stderr says nothing: {argv:?}");
        order(&events(&with.err));
    }
}

/// `text` with every `YYYY-MM-DD HH:MM UTC` written as `<when>`: two runs
/// a moment apart can fall in different minutes.
fn no_clock(text: &str) -> String {
    let stamp = |s: &[u8]| {
        s.len() >= 20
            && s[16..20] == *b" UTC"
            && s[..16]
                .iter()
                .zip(b"dddd-dd-dd dd:dd")
                .all(|(c, p)| if *p == b'd' { c.is_ascii_digit() } else { c == p })
    };
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if stamp(&bytes[i..]) {
            out.push_str("<when>");
            i += 20;
        } else {
            // A stamp is ASCII, so `i` only ever stops on a character's first byte.
            let ch = text[i..].chars().next().expect("a character at a boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[test]
fn a_stamp_is_the_only_thing_no_clock_changes() {
    let report = "==> Security scan #1  2026-11-26 01:51 UTC · /c/w.db\n  ✓ é 2026-11-26 01:5\n";
    assert_eq!(no_clock(report), "==> Security scan #1  <when> · /c/w.db\n  ✓ é 2026-11-26 01:5\n");
    assert_eq!(no_clock(""), "");
}

/// `t` with its cache removed, so the next run starts as the first did.
fn fresh(t: &Ctx) -> &Ctx {
    if let Some(dir) = t.db.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
    t
}

/// The rules' own secret cases, each in a file: the deep scan finds them,
/// and no secret, nor the line around it, reaches the event stream.
#[test]
fn no_secret_reaches_the_events() {
    let cases = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../wpantry/tests/secret-cases.toml"))
        .expect("the secret cases");
    let t = Ctx::new();
    let dir = t.home.join("secrets");
    mkdir(&dir);
    let mut texts = Vec::new();
    for c in wpantry::utils::toml::parse(&cases).unwrap().iter().filter(|c| c.name == "case") {
        if !c.str("name").ends_with(": a secret") {
            continue;
        }
        let text: String = c.str("reversed_text").chars().rev().collect();
        write(&dir.join(format!("case{}.txt", texts.len())), &text);
        texts.push(text);
        if texts.len() == 80 {
            break;
        }
    }
    let r = t.run(&[
        "scan",
        "--no-machine",
        "--path",
        s(&dir),
        "--offline",
        "--no-malware",
        "--deep",
        "--json",
        "--events",
    ]);
    assert!([0, 1].contains(&r.code), "{}", r.err);
    let lines = events(&r.err);
    order(&lines);
    let told = lines.iter().filter(|l| l["event"] == "finding" && l["kind"] == "secret").count();
    assert!(told >= 40, "the scan found the secrets ({told} of {}): the check isn't vacuous", texts.len());
    // Their fixes are in the stream too, so the check below covers `fix_cmd`.
    let with_fix =
        lines.iter().filter(|l| l["event"] == "finding" && l["kind"] == "secret" && l["fix_cmd"].is_string()).count();
    assert_eq!(with_fix, told, "every secret event carries its fix");
    // Secret-shaped runs: 12 or more letters, digits and token punctuation,
    // with a digit and a letter in them.
    let mut leaked = Vec::new();
    for text in &texts {
        let runs = text.split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-.".contains(c)));
        for run in runs.filter(|w| w.len() >= 12) {
            if run.chars().any(|c| c.is_ascii_digit())
                && run.chars().any(|c| c.is_ascii_alphabetic())
                && r.err.contains(run)
            {
                leaked.push(run.to_string());
            }
        }
        for line in text.lines().map(str::trim).filter(|l| l.len() >= 12) {
            if r.err.contains(line) {
                leaked.push(line.to_string());
            }
        }
    }
    assert!(leaked.is_empty(), "secret text in the events: {leaked:?}");
}

/// The caller reads the first line and closes its end: the scan carries on
/// to the same exit code and the same report.
#[test]
fn a_reader_that_closes_early_changes_nothing() {
    let t = Ctx::new();
    let dir = fixture(&t);
    let mut argv = scan_args(&dir);
    argv.push("--events");
    let read = fresh(&t).run(&argv);
    fresh(&t);
    let mut child = Command::new(BIN)
        .args(&argv)
        .env("HOME", &t.home)
        .env("WPANTRY_DB", &t.db)
        .env("NO_COLOR", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut first = String::new();
    err.read_line(&mut first).unwrap();
    assert!(first.contains("\"start\""), "{first}");
    drop(err);
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    let code = child.wait().unwrap().code();
    assert_eq!(code, Some(read.code));
    assert_eq!(out, read.out);
}

/// Notes the scan prints on stderr become `note` events: a missing
/// `--path`, and the report written to a file.
#[test]
fn notes_become_events() {
    let t = Ctx::new();
    let dir = fixture(&t);
    let gone = t.home.join("gone");
    let out = t.tmp.join("report.json");
    let r = t.run(&[
        "scan",
        "--no-machine",
        "--path",
        s(&dir),
        "--path",
        s(&gone),
        "--offline",
        "--no-malware",
        "--json",
        "-o",
        s(&out),
        "--events",
    ]);
    assert!([0, 1].contains(&r.code), "{}", r.err);
    // The report went to the file; stdout has only the scan's log lines.
    assert!(!r.out.contains("\"schema\""), "{}", r.out);
    let lines = events(&r.err);
    order(&lines);
    let notes: Vec<&str> = lines.iter().filter(|l| l["event"] == "note").map(|l| l["text"].as_str().unwrap()).collect();
    assert!(notes.iter().any(|n| n.contains("wrote the report to")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("gone")), "{notes:?}");
    envelope(&read(&out));
}

/// An unwritable `-o` is a file error (exit 3), so it is reported inside
/// the stream: `start`, then `done` with the error. Risk: a program that
/// reads the stream sees no `start` and no `done` for a run that did start.
/// Oracle: the order rules in [`order`] (every line an event, `start`
/// first, `done` last), the exit code of the same run without `--events`
/// (3), and the plain-text line that run prints.
#[test]
fn an_unwritable_report_path_is_reported_in_the_stream() {
    let t = Ctx::new();
    let dir = fixture(&t);
    let out = t.tmp.join("no-such-folder").join("r.json");
    let mut argv = scan_args(&dir);
    argv.extend(["-o", s(&out)]);
    let plain_run = t.run(&argv);
    assert_eq!(plain_run.code, 3, "{}", plain_run.err);
    argv.push("--events");
    let r = t.run(&argv);
    assert_eq!(r.code, 3, "same exit code as without --events: {}", r.err);
    let lines = events(&r.err);
    // No step ran, so the full order rules (every listed step begun) don't
    // apply: the stream is exactly `start` then `done`.
    let names: Vec<&str> = lines.iter().map(|l| l["event"].as_str().unwrap()).collect();
    assert_eq!(names, ["start", "done"], "{lines:?}");
    assert!(lines.iter().all(|l| l["v"] == 1), "{lines:?}");
    let done = lines.last().unwrap();
    assert_eq!(done["exit"], 3, "{done}");
    assert!(done["findings"].is_null() && done["unchecked"].is_null() && done["scan"].is_null(), "{done}");
    // The message is the one the run prints without --events.
    let message = plain_run.err.trim().trim_start_matches("✗ wpantry: ");
    assert_eq!(done["error"], message, "{done}");
    assert!(!out.exists(), "nothing was written");
}

/// A tree to keep a scan busy: `repos` checkouts of `dirs` folders with
/// `files` files each, the files hard links of three small seeds (quick to
/// make, read like any other file). Returns the folder holding the repos.
///
/// NTFS allows at most 1023 links to one file, so each seed is copied
/// afresh every [`LINKS_PER_SEED`] links.
fn big_tree(t: &Ctx, repos: usize, dirs: usize, files: usize) -> PathBuf {
    let seeds = t.tmp.join("seeds");
    mkdir(&seeds);
    let kinds =
        [("js", "const a = 1;\nmodule.exports = a;\n"), ("py", "def f(x):\n    return x\n"), ("txt", "notes\n")];
    let mut made = [0usize; 3];
    let code = t.home.join("code");
    for r in 0..repos {
        let repo = git_repo(&code.join(format!("repo{r}")), false);
        for d in 0..dirs {
            let dir = repo.join(format!("src/d{d}"));
            mkdir(&dir);
            for f in 0..files {
                let k = f % kinds.len();
                let (ext, text) = kinds[k];
                let seed = seeds.join(format!("seed{}.{ext}", made[k] / LINKS_PER_SEED));
                if made[k] % LINKS_PER_SEED == 0 {
                    write(&seed, text);
                }
                std::fs::hard_link(&seed, dir.join(format!("f{f}.{ext}"))).unwrap();
                made[k] += 1;
            }
        }
    }
    // Windows fails the link itself past 1023; elsewhere count, so a change
    // here shows up on every runner.
    #[cfg(unix)]
    for e in std::fs::read_dir(&seeds).unwrap() {
        use std::os::unix::fs::MetadataExt;
        let links = e.unwrap().metadata().unwrap().nlink();
        assert!(links <= 1023, "a seed has {links} links, more than NTFS allows");
    }
    code
}

/// Links made to one seed file before [`big_tree`] starts a new copy: under
/// the 1023 NTFS allows.
const LINKS_PER_SEED: usize = 1000;

/// The run's event lines, each with when it arrived after the start.
fn timed(t: &Ctx, argv: &[&str]) -> (i32, Vec<(std::time::Duration, Value)>) {
    let mut child = Command::new(BIN)
        .args(argv)
        .env("HOME", &t.home)
        .env("WPANTRY_DB", &t.db)
        .env("NO_COLOR", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let drain = std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
    let started = std::time::Instant::now();
    let mut lines = Vec::new();
    for l in BufReader::new(child.stderr.take().unwrap()).lines() {
        let l = l.unwrap();
        lines.push((started.elapsed(), serde_json::from_str(&l).unwrap_or_else(|e| panic!("not an event ({e}): {l}"))));
    }
    drain.join().unwrap().unwrap();
    (child.wait().unwrap().code().unwrap_or(-1), lines)
}

/// The longest time inside a step without an `at` or a `tally` line,
/// counted from the step's begin to its end, and the step it was in.
fn longest_silence(lines: &[(std::time::Duration, Value)]) -> (std::time::Duration, String) {
    let (mut longest, mut where_) = (std::time::Duration::ZERO, String::new());
    let mut last: Option<(std::time::Duration, String)> = None;
    for (at, l) in lines {
        let quiet = |since: &std::time::Duration| at.saturating_sub(*since);
        match (l["event"].as_str(), l["state"].as_str()) {
            (Some("step"), Some("begin")) => last = Some((*at, l["id"].as_str().unwrap().to_string())),
            (Some("at" | "tally"), _) | (Some("step"), Some("end")) => {
                if let Some((since, step)) = &last
                    && quiet(since) > longest
                {
                    (longest, where_) = (quiet(since), step.clone());
                }
                let step = last.take().map(|(_, s)| s).unwrap_or_default();
                last = (l["event"] != "step").then_some((*at, step));
            }
            _ => {}
        }
    }
    (longest, where_)
}

/// A follower is never left without a sign of life while the scan works:
/// no step goes 2 s without an `at` or a `tally`, cold and with the cache
/// warm (when nothing is read at all). The writer promises a line at least
/// every BEAT (1 s) plus a TICK; 2 s leaves room for a loaded runner. Before
/// the heartbeat and the folder lines, the files pass was silent while it
/// looked over every file: 0.8 s on this tree in a debug build, 2.9 s on
/// one of 150,000 files, which this check fails; with them, 1.04 s at most
/// on that tree. 40,000 files keep the test quick; the step that runs the
/// files pass must also name a folder before it reads the first file, which
/// fails without the folder lines at any size.
#[test]
fn a_big_tree_is_never_silent_for_long() {
    let t = Ctx::new();
    let code = big_tree(&t, 8, 25, 200);
    let argv = ["scan", "--no-machine", "--path", s(&code), "--offline", "--no-input", "--json", "--events"];
    // Cold, then warm: with the cache warm nothing is read, so only the
    // folders looked over and the heartbeat show the step is alive.
    for run in ["cold", "warm"] {
        let (code, lines) = timed(&t, &argv);
        assert!([0, 1].contains(&code), "{run}: exit {code}");
        let plain: Vec<Value> = lines.iter().map(|(_, l)| l.clone()).collect();
        order(&plain);
        let (longest, step) = longest_silence(&lines);
        assert!(longest < std::time::Duration::from_secs(2), "{run}: {step} was silent for {longest:?}");
        let files_step: Vec<&Value> =
            plain.iter().filter(|l| l["event"] == "at" && l["step"] == "repo-files").collect();
        let first_dir = files_step.iter().position(|l| l["kind"] == "dir");
        let first_file = files_step.iter().position(|l| l["kind"] == "file");
        assert!(first_dir.is_some(), "{run}: repo-files never said which folder it looked over");
        assert!(first_file.is_none() || first_dir < first_file, "{run}: a file was read before any folder was named");
        let tally = plain.iter().rfind(|l| l["event"] == "tally").unwrap();
        assert_eq!(tally["listed"], 8 * 25 * 200, "{run}: every file the walks listed is counted: {tally}");
    }
}
