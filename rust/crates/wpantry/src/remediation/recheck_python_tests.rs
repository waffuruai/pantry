//! Python runtime re-checks. Risk and oracle for each check:
//!
//! * a fix that upgrades in place is called gone, or a still-affected one is
//!   called gone: oracle is the version the stand-in interpreter prints
//!   against the advisory's fixed release (3.12.4), which the test states;
//! * a removed install called gone when its place is itself missing: oracle
//!   is the filesystem the test builds;
//! * more than the one interpreter run: oracle is the stand-in's own log of
//!   the arguments it was started with.
//!
//! No real Python is started: every interpreter is a shell script in a temp
//! dir that prints the one JSON line a scan reads. Each check is proven to
//! fail with the behaviour it guards against removed (see the report).
#![cfg(unix)]

use super::recheck::*;
use crate::checks::machine::components;
use crate::checks::machine::packages::{self, PythonNow};
use crate::checks::{Options, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const REPO: &str = "https://github.com/python/cpython";
const CVE: &str = "CVE-2026-2001";

/// Write a stand-in interpreter at `path`: it logs its arguments to `log`
/// and prints the JSON line a scan's probe prints, naming itself as the
/// interpreter (`exe`) and `version`. `runs` makes it a shim: it starts that
/// stand-in instead.
fn interpreter(path: &Path, version: &str, log: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$1 $2 $3 $#\" >> '{}'\nprintf '{{\"v\": \"{version}\", \"exe\": \"{}\", \"sites\": [], \"user\": \"\", \"managed\": false}}\\n'\n",
        log.display(),
        path.display()
    );
    write_exec(path, &body);
}

/// A shim at `path` that starts `target`, as a version manager's does.
fn shim(path: &Path, target: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_exec(path, &format!("#!/bin/sh\nexec '{}' \"$@\"\n", target.display()));
}

fn write_exec(path: &Path, body: &str) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// OSV and the CVE record for `CVE`: python 3.12.1 up to the fixed 3.12.4.
fn python_net() -> Fake {
    Fake::new(|r| {
        let u = r.url.as_str();
        if u.ends_with("/querybatch") {
            let body: Value = serde_json::from_slice(&r.body.clone().unwrap_or_default()).unwrap();
            let results: Vec<Value> = crate::utils::json::arr_at(&body, "queries")
                .iter()
                .map(|q| match crate::utils::json::str_at(q, "version") {
                    "v3.12.1" | "v3.12.2" => json!({"vulns": [{"id": CVE, "modified": "m"}]}),
                    _ => json!({}),
                })
                .collect();
            return Ok(Response::ok(json!({"results": results}).to_string()));
        }
        if u == format!("https://api.osv.dev/v1/vulns/{CVE}") {
            let rec = json!({
                "id": CVE, "summary": "s", "modified": "m",
                "database_specific": {"osv_generated_from": format!("https://github.com/CVEProject/cvelistV5/tree/main/cves/{CVE}.json")},
                "affected": [{
                    "ranges": [{"type": "GIT", "repo": REPO,
                                "events": [{"introduced": "0"}, {"fixed": "18da38899ee04bd023171f0c4958a4cfafb2b38c"}],
                                "database_specific": {"extracted_events": [
                                    {"source": "AFFECTED_FIELD", "range": [{"introduced": "0"}, {"fixed": "3.12.4"}]}]}}],
                    "versions": ["v3.12.1", "v3.12.2"]
                }],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
            });
            return Ok(Response::ok(rec.to_string()));
        }
        Err(crate::error::Error::Offline(format!("{u}: unreachable")))
    })
}

/// A runtime the way the scan reports one at `location`, as read through
/// the scan's own reader.
fn found_at(location: &Path) -> Component {
    let now = packages::python_now(&location.to_string_lossy(), &packages::ask_python, &|_| "");
    let PythonNow::Runtime(c) = now else { panic!("the stand-in at {} did not read as a runtime", location.display()) };
    *c
}

/// The scan of the interpreters at `places` (an online scan against
/// [`python_net`], so the cache holds what a scan leaves), recorded.
/// Returns the cache file, the scan, and the findings in `places` order.
fn scanned(dir: &TempDir, places: &[&Path]) -> (PathBuf, i64, Vec<Finding>) {
    let net = python_net();
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    // The release tags `git ls-remote` would list, so no scan asks a remote.
    cache.put_run(&format!("tags:{REPO}"), "", &json!(["v3.12.1", "v3.12.2", "v3.12.4", "v3.12.5"])).unwrap();
    let mut s = Scan::new(Options::default(), cache, &net, &|_| {}, &|_| {});
    let found: Vec<Component> = places.iter().map(|p| found_at(p)).collect();
    components::components(&mut s, &found).unwrap();
    let mut findings: Vec<Finding> = Vec::new();
    for p in places {
        let at = findings_at(&s.findings, p);
        assert_eq!(at.len(), 1, "one advisory finding per place: {:?}", s.findings);
        findings.extend(at);
    }
    let all = findings.clone();
    s.cache.replace_findings(&all).unwrap();
    let scan = crate::history::record_scan(&s.cache, 1.0, &all, &[], &Options { machine: true, ..Default::default() })
        .unwrap();
    let file = s.cache.file().to_path_buf();
    s.cache.close().unwrap();
    (file, scan, findings)
}

fn findings_at(all: &[Finding], place: &Path) -> Vec<Finding> {
    all.iter()
        .filter(|f| f.kind == "runtime" && f.component == "python" && Path::new(&f.location) == place)
        .cloned()
        .collect()
}

fn check(file: &Path, finding: &Finding, scan: i64) -> Outcome {
    recheck(Cache::open(Some(file)).unwrap(), &finding.id(), scan).unwrap()
}

fn state(o: &Outcome) -> (State, &'static str) {
    (o.verdict.state, o.verdict.reason)
}

fn lines(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log).unwrap_or_default().lines().map(str::to_string).collect()
}

#[test]
fn a_python_upgraded_in_place_is_gone_and_one_still_in_range_is_not() {
    let d = TempDir::new("recheck-python").unwrap();
    let (py, log) = (d.path().join("opt/bin/python3.12"), d.path().join("run.log"));
    interpreter(&py, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&py]);
    assert_eq!(findings[0].vuln_id, CVE);
    assert_eq!(state(&check(&file, &findings[0], scan)), (State::StillPresent, "affected"));
    // A patch inside the affected range is still affected, though OSV was asked about it.
    interpreter(&py, "3.12.2", &log);
    assert_eq!(state(&check(&file, &findings[0], scan)), (State::StillPresent, "affected"));
    // The fixed release, which OSV was never asked about: the cached record's range decides.
    interpreter(&py, "3.12.4", &log);
    let out = check(&file, &findings[0], scan);
    assert_eq!(state(&out), (State::Gone, "fixed"), "{out:?}");
    assert!(out.verdict.detail.contains("3.12.4"), "{out:?}");
    // Gone is recorded: the finding left the latest findings.
    let cache = Cache::open(Some(&file)).unwrap();
    let left: i64 = cache.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}

#[test]
fn only_the_interpreter_is_run_once_per_id_and_only_to_ask_for_its_version() {
    let d = TempDir::new("recheck-python").unwrap();
    let (py, log) = (d.path().join("opt/bin/python3.12"), d.path().join("run.log"));
    interpreter(&py, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&py]);
    std::fs::remove_file(&log).unwrap();
    check(&file, &findings[0], scan);
    let ran = lines(&log);
    assert_eq!(ran.len(), 1, "one run for one id: {ran:?}");
    assert_eq!(ran[0], "-I -S -c 4", "isolated, no site processing, the one probe script and nothing else: {ran:?}");
}

#[test]
fn a_patch_installed_beside_the_old_one_with_the_old_one_removed_is_gone_as_removed() {
    let d = TempDir::new("recheck-python").unwrap();
    let log = d.path().join("run.log");
    let versions = d.path().join("home/.pyenv/versions");
    let old = versions.join("3.12.1/bin/python3");
    interpreter(&old, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&old]);
    // A pyenv fix is not unattended; the re-check answers anyway.
    assert!(!findings[0].fix_auto, "{findings:?}");
    interpreter(&versions.join("3.12.4/bin/python3"), "3.12.4", &log);
    std::fs::remove_dir_all(versions.join("3.12.1")).unwrap();
    let out = check(&file, &findings[0], scan);
    assert_eq!(state(&out), (State::Gone, "removed"), "{out:?}");
}

#[test]
fn a_removed_install_whose_place_is_gone_too_says_nothing() {
    let d = TempDir::new("recheck-python").unwrap();
    let log = d.path().join("run.log");
    let old = d.path().join("home/.pyenv/versions/3.12.1/bin/python3");
    interpreter(&old, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&old]);
    std::fs::remove_dir_all(d.path().join("home/.pyenv")).unwrap();
    let out = check(&file, &findings[0], scan);
    assert_eq!(state(&out), (State::Unknown, "unreachable"), "{out:?}");
    // Nothing recorded for an answer that is not gone.
    let cache = Cache::open(Some(&file)).unwrap();
    let left: i64 = cache.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 1);
}

#[test]
fn a_new_install_beside_an_old_one_that_is_still_there_leaves_the_old_one_present() {
    let d = TempDir::new("recheck-python").unwrap();
    let log = d.path().join("run.log");
    let versions = d.path().join("home/.local/share/uv/python");
    let old = versions.join("cpython-3.12.1-linux-x86_64-gnu/bin/python3.12");
    interpreter(&old, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&old]);
    interpreter(&versions.join("cpython-3.12.4-linux-x86_64-gnu/bin/python3.12"), "3.12.4", &log);
    let out = check(&file, &findings[0], scan);
    assert_eq!(state(&out), (State::StillPresent, "affected"), "{out:?}");
}

#[test]
fn a_shim_moved_to_a_new_version_is_gone_while_the_old_install_beside_it_is_still_present() {
    let d = TempDir::new("recheck-python").unwrap();
    let log = d.path().join("run.log");
    let home = d.path().join("home/.pyenv");
    let old = home.join("versions/3.12.1/bin/python3");
    let new = home.join("versions/3.12.4/bin/python3");
    let shim_path = home.join("shims/python3");
    interpreter(&old, "3.12.1", &log);
    shim(&shim_path, &old);
    let (file, scan, findings) = scanned(&d, &[&shim_path, &old]);
    // The shim reads through to the interpreter it starts: what the scan sees.
    assert_eq!(state(&check(&file, &findings[0], scan)), (State::StillPresent, "affected"));
    interpreter(&new, "3.12.4", &log);
    shim(&shim_path, &new);
    let by_shim = check(&file, &findings[0], scan);
    assert_eq!(state(&by_shim), (State::Gone, "fixed"), "{by_shim:?}");
    // The old install dir remains, still on 3.12.1: its own finding is not gone.
    let by_dir = check(&file, &findings[1], scan);
    assert_eq!(state(&by_dir), (State::StillPresent, "affected"), "{by_dir:?}");
}

#[test]
fn an_interpreter_that_does_not_answer_is_unreadable_never_gone() {
    let d = TempDir::new("recheck-python").unwrap();
    let (py, log) = (d.path().join("opt/bin/python3.12"), d.path().join("run.log"));
    interpreter(&py, "3.12.1", &log);
    let (file, scan, findings) = scanned(&d, &[&py]);
    write_exec(&py, "#!/bin/sh\necho 'Segmentation fault'\n");
    assert_eq!(state(&check(&file, &findings[0], scan)), (State::Unknown, "unreadable"));
    // A folder where the interpreter was is not one either.
    std::fs::remove_file(&py).unwrap();
    std::fs::create_dir(&py).unwrap();
    assert_eq!(state(&check(&file, &findings[0], scan)), (State::Unknown, "unreadable"));
}

#[test]
fn an_interpreter_something_else_vouches_for_now_is_unsupported() {
    let d = TempDir::new("recheck-python").unwrap();
    let (py, log) = (d.path().join("opt/bin/python3.12"), d.path().join("run.log"));
    interpreter(&py, "3.12.4", &log);
    let probe = packages::ask_python;
    let gone = super::recheck_python::read(&py.to_string_lossy(), &probe, &|_| "brew");
    let verdict = gone.expect_err("a vouched-for interpreter is not read as a runtime");
    assert_eq!((verdict.state, verdict.reason), (State::Unknown, "unsupported"), "{verdict:?}");
    assert!(verdict.detail.contains("brew"), "{verdict:?}");
    // Not vouched for: the runtime a scan reports.
    let c = super::recheck_python::read(&py.to_string_lossy(), &probe, &|_| "").unwrap();
    assert_eq!((c.name.as_str(), c.version.as_str()), ("python", "3.12.4"));
}

#[test]
fn only_python_runtimes_take_this_path() {
    use super::recheck_python::applies;
    assert!(applies("runtime", "python"));
    assert!(!applies("runtime", "node"));
    assert!(!applies("package", "python"));
    assert!(!applies("package", "pip:requests"));
}
