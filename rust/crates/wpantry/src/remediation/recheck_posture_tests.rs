//! Posture re-checks. Oracle: the probe the scan itself runs for the rule,
//! fed a recorded `defaults` answer. No real setting is read or changed.
use super::recheck::*;
use crate::checks::Options;
use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::temp::TempDir;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(target_os = "macos")]
const TERMINAL: &str = "POSTURE-TERMINAL-SECURE-INPUT";

fn posture(vuln: &str, title: &str, fix_auto: bool) -> Finding {
    Finding {
        kind: "posture".into(),
        component: title.into(),
        location: "CIS 6.4.1".into(),
        vuln_id: vuln.into(),
        status: "warn".into(),
        severity: "MEDIUM".into(),
        fix_cmd: "defaults write com.apple.Terminal SecureKeyboardEntry -bool true".into(),
        fix_auto,
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
fn terminal(fix_auto: bool) -> Finding {
    posture(TERMINAL, "Terminal Secure Keyboard Entry", fix_auto)
}

fn scanned(dir: &TempDir, findings: &[Finding]) -> (PathBuf, i64) {
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    cache.replace_findings(findings).unwrap();
    let opts = Options { machine: true, ..Default::default() };
    let scan = crate::history::record_scan(&cache, 1.0, findings, &[], &opts).unwrap();
    let file = cache.file().to_path_buf();
    cache.close().unwrap();
    (file, scan)
}

/// Recheck `ids` with every probe command answered by `answer`; returns the
/// outcomes and every command the probes ran.
fn ask(file: &Path, ids: &[String], scan: i64, answer: &str) -> (Vec<Outcome>, Vec<Vec<String>>) {
    let ran = Mutex::new(Vec::new());
    let runner = |argv: &[&str]| {
        ran.lock().unwrap().push(argv.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        answer.to_string()
    };
    let mut out = Vec::new();
    recheck_many_with(Cache::open(Some(file)).unwrap(), ids, scan, false, &runner, &mut |o| out.push(o))
        .unwrap_or_else(|f| panic!("{}: {}", f.id, f.error));
    (out, ran.into_inner().unwrap())
}

#[cfg(target_os = "macos")]
fn findings_left(file: &Path) -> i64 {
    let c = Cache::open(Some(file)).unwrap();
    c.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap()
}

#[test]
#[cfg(target_os = "macos")]
fn a_setting_now_on_is_gone_and_recorded() {
    let d = TempDir::new("posture").unwrap();
    let f = terminal(true);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    let (out, _) = ask(&file, &[f.id()], scan, "1\n");
    assert_eq!((out[0].verdict.state, out[0].verdict.reason), (State::Gone, "fixed"), "{:?}", out[0]);
    assert_eq!(out[0].keys, [f.key()]);
    assert_eq!(findings_left(&file), 0);
}

#[test]
#[cfg(target_os = "macos")]
fn a_setting_still_off_is_still_present_and_nothing_is_written() {
    let d = TempDir::new("posture").unwrap();
    let f = terminal(true);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    let (out, _) = ask(&file, &[f.id()], scan, "0\n");
    assert_eq!((out[0].verdict.state, out[0].verdict.reason), (State::StillPresent, "setting"));
    assert!(out[0].verdict.detail.contains("off"), "{}", out[0].verdict.detail);
    assert_eq!(findings_left(&file), 1);
}

#[test]
#[cfg(target_os = "macos")]
fn only_that_rules_own_probe_runs() {
    let d = TempDir::new("posture").unwrap();
    let f = terminal(true);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    let (_, ran) = ask(&file, &[f.id()], scan, "1\n");
    assert_eq!(ran, [["defaults", "read", "com.apple.Terminal", "SecureKeyboardEntry"]], "{ran:?}");
}

#[test]
#[cfg(target_os = "macos")]
fn a_setting_that_cannot_be_read_is_unknown_never_gone() {
    let d = TempDir::new("posture").unwrap();
    let f = posture("POSTURE-SAFARI-SAFE-FILES", "Safari doesn't open downloads on its own", false);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    // Safari's container answers "not found" without Full Disk Access.
    let (out, _) = ask(&file, &[f.id()], scan, "Domain not found\n");
    assert_eq!((out[0].verdict.state, out[0].verdict.reason), (State::Unknown, "unreadable"), "{:?}", out[0]);
    assert_eq!(findings_left(&file), 1);
}

#[test]
fn a_rule_this_machine_has_no_probe_for_is_unknown_with_the_reason() {
    let d = TempDir::new("posture").unwrap();
    let f = posture("POSTURE-NO-SUCH-RULE", "Some retired rule", true);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    let (out, ran) = ask(&file, &[f.id()], scan, "1\n");
    assert_eq!((out[0].verdict.state, out[0].verdict.reason), (State::Unknown, "unsupported"));
    assert!(out[0].verdict.detail.contains("no check on this machine"), "{}", out[0].verdict.detail);
    assert!(ran.is_empty());
}

#[test]
#[cfg(target_os = "macos")]
fn a_finding_without_an_unattended_fix_is_checked_too() {
    let d = TempDir::new("posture").unwrap();
    // fix_auto false: a person ran the sudo step by hand.
    let f = terminal(false);
    let (file, scan) = scanned(&d, std::slice::from_ref(&f));
    let (out, _) = ask(&file, &[f.id()], scan, "1\n");
    assert_eq!(out[0].verdict.state, State::Gone, "{:?}", out[0]);
}
