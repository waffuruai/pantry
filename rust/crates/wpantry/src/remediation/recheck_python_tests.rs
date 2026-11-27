//! Python runtime re-checks. Risk and oracle for each check:
//!
//! * an interpreter, a shim or anything else started to read a version
//!   (#396): oracle is a marker file every stand-in interpreter and shim
//!   writes if it is ever run, and a count of the calls the injected command
//!   runner gets. Every re-check in this file goes through [`check`] or
//!   [`read_here`], which assert both are untouched, so each test is also
//!   the no-spawn guard for the case it builds;
//! * a fix that upgrades in place is called gone, or a still-affected one is
//!   called gone: oracle is the `PY_VERSION` the stand-in install's
//!   `patchlevel.h` holds against the advisory's fixed release (3.12.4),
//!   which the test states;
//! * a shim read as the wrong version: oracle is pyenv's and asdf's own
//!   documented order (environment variable, nearest local file, global
//!   file), built as files in a temp tree;
//! * a guess where the files say nothing: oracle is an install whose
//!   version is only in a folder name, which must read `unreadable`;
//! * a removed install called gone when its place is itself missing: oracle
//!   is the filesystem the test builds.
//!
//! No real Python is involved: every install is a temp folder of files.
#![cfg(unix)]

use super::recheck::*;
use super::recheck_python::{Here, applies, read};
use crate::checks::machine::{components, packages};
use crate::checks::{Options, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::files;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const REPO: &str = "https://github.com/python/cpython";
const CVE: &str = "CVE-2026-2001";

/// The file a stand-in writes when it is run, which no test may see.
fn marker(d: &TempDir) -> PathBuf {
    d.path().join("ran")
}

/// An executable at `path` that writes the marker when run, with `extra`
/// text in it (a shim's `pyenv` or `asdf`).
fn trap(d: &TempDir, path: &Path, extra: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(path);
    std::fs::write(path, format!("#!/bin/sh\n# {extra}\ntouch '{}'\n", marker(d).display())).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A stand-in install at `prefix`: `bin/<exe>` (a trap) and the
/// `include/pythonX.Y/patchlevel.h` naming `version`. Returns the interpreter.
fn install(d: &TempDir, prefix: &Path, exe: &str, version: &str) -> PathBuf {
    let py = prefix.join("bin").join(exe);
    trap(d, &py, "");
    patch(prefix, version);
    py
}

/// The headers of `prefix` now say `version` (an upgrade in place).
fn patch(prefix: &Path, version: &str) {
    let line: Vec<&str> = version.split('.').take(2).collect();
    let dir = prefix.join(format!("include/python{}", line.join(".")));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("patchlevel.h"),
        format!("#define PY_MINOR_VERSION 12\n#define PY_VERSION      \"{version}\"\n"),
    )
    .unwrap();
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn link(target: &Path, at: &Path) {
    std::fs::create_dir_all(at.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(at);
    std::os::unix::fs::symlink(target, at).unwrap();
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

/// The scan of the runtimes at `places` (location, the version the scan's
/// probe reported), built by the scan's own component builder and judged
/// online against [`python_net`], so the cache holds what a scan leaves.
/// Returns the cache file, the scan, and the findings in `places` order.
fn scanned(dir: &TempDir, places: &[(&Path, &str)]) -> (PathBuf, i64, Vec<Finding>) {
    let net = python_net();
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    // The release tags `git ls-remote` would list, so no scan asks a remote.
    cache.put_run(&format!("tags:{REPO}"), "", &json!(["v3.12.1", "v3.12.2", "v3.12.4", "v3.12.5"])).unwrap();
    let mut s = Scan::new(Options::default(), cache, &net, &|_| {}, &|_| {});
    let found: Vec<Component> = places
        .iter()
        .map(|(p, v)| {
            let at = p.display().to_string();
            packages::runtime_component(&at, &files::realpath(&at), v)
        })
        .collect();
    components::components(&mut s, &found).unwrap();
    let mut findings: Vec<Finding> = Vec::new();
    for (p, _) in places {
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

/// The re-check of `finding`, through the command runner `recheck` takes,
/// which counts its calls: none may come, and no stand-in may have run.
fn check(d: &TempDir, file: &Path, finding: &Finding, scan: i64) -> Outcome {
    let calls = AtomicUsize::new(0);
    let runner = |argv: &[&str]| -> String {
        calls.fetch_add(1, Ordering::SeqCst);
        panic!("the Python runtime re-check ran {argv:?}");
    };
    let mut got = None;
    recheck_many_with(Cache::open(Some(file)).unwrap(), &[finding.id()], scan, false, &runner, &mut |o| got = Some(o))
        .map_err(|f| f.error)
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no command may be run");
    assert!(!marker(d).exists(), "an interpreter or shim was started");
    got.unwrap()
}

fn state(o: &Outcome) -> (State, &'static str) {
    (o.verdict.state, o.verdict.reason)
}

/// A context with no variables, in `cwd`, with `home`.
fn here(home: &Path, cwd: &Path, vars: &[(&str, &str)]) -> Here {
    let vars: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Here { home: home.to_path_buf(), cwd: cwd.to_path_buf(), os: std::env::consts::OS, vars }
}

/// [`read`] of `at` in `here`, nobody vouching: the version, or the
/// verdict's reason. Asserts nothing was run.
fn read_here(d: &TempDir, at: &Path, here: &Here) -> Result<String, &'static str> {
    let got = read(&at.display().to_string(), &|_| "", here);
    assert!(!marker(d).exists(), "an interpreter or shim was started");
    got.map(|c| c.version).map_err(|v| v.reason)
}

#[test]
fn a_python_upgraded_in_place_is_gone_and_one_still_in_range_is_not() {
    let d = TempDir::new("recheck-python").unwrap();
    let prefix = d.path().join("opt/py");
    let py = install(&d, &prefix, "python3.12", "3.12.1");
    let (file, scan, findings) = scanned(&d, &[(&py, "3.12.1")]);
    assert_eq!(findings[0].vuln_id, CVE);
    assert_eq!(state(&check(&d, &file, &findings[0], scan)), (State::StillPresent, "affected"));
    // A patch inside the affected range is still affected, though OSV was asked about it.
    patch(&prefix, "3.12.2");
    assert_eq!(state(&check(&d, &file, &findings[0], scan)), (State::StillPresent, "affected"));
    // The fixed release, which OSV was never asked about: the cached record's range decides.
    patch(&prefix, "3.12.4");
    let out = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&out), (State::Gone, "fixed"), "{out:?}");
    assert!(out.verdict.detail.contains("3.12.4"), "{out:?}");
    // Gone is recorded: the finding left the latest findings.
    let cache = Cache::open(Some(&file)).unwrap();
    let left: i64 = cache.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}

#[test]
fn nothing_is_run_for_an_interpreter_a_link_chain_or_a_virtual_environment() {
    // The no-spawn guard (#396) over the whole re-check: every stand-in is an
    // executable that leaves a marker when run, and the runner counts calls.
    let d = TempDir::new("recheck-python").unwrap();
    let real = install(&d, &d.path().join("opt/py"), "python3.12", "3.12.1");
    let hop = d.path().join("opt/links/python3");
    link(&real, &hop);
    let chain = d.path().join("bin/python3");
    link(&hop, &chain);
    let venv = d.path().join("work/.venv");
    write(&venv.join("pyvenv.cfg"), &format!("home = {}\nversion = 3.12.1\n", real.parent().unwrap().display()));
    let in_venv = venv.join("bin/python");
    link(&real, &in_venv);
    let (file, scan, findings) = scanned(&d, &[(&real, "3.12.1"), (&chain, "3.12.1"), (&in_venv, "3.12.1")]);
    for f in &findings {
        let out = check(&d, &file, f, scan);
        assert_eq!(state(&out), (State::StillPresent, "affected"), "{}: {out:?}", f.location);
    }
    patch(&d.path().join("opt/py"), "3.12.4");
    for f in &findings {
        let out = check(&d, &file, f, scan);
        assert_eq!(state(&out), (State::Gone, "fixed"), "{}: {out:?}", f.location);
    }
}

#[test]
fn a_patch_installed_beside_the_old_one_with_the_old_one_removed_is_gone_as_removed() {
    let d = TempDir::new("recheck-python").unwrap();
    let versions = d.path().join("home/.pyenv/versions");
    let old = install(&d, &versions.join("3.12.1"), "python3", "3.12.1");
    let (file, scan, findings) = scanned(&d, &[(&old, "3.12.1")]);
    // A pyenv fix is not unattended; the re-check answers anyway.
    assert!(!findings[0].fix_auto, "{findings:?}");
    install(&d, &versions.join("3.12.4"), "python3", "3.12.4");
    std::fs::remove_dir_all(versions.join("3.12.1")).unwrap();
    let out = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&out), (State::Gone, "removed"), "{out:?}");
}

#[test]
fn a_removed_install_whose_place_is_gone_too_says_nothing() {
    let d = TempDir::new("recheck-python").unwrap();
    let old = install(&d, &d.path().join("home/.pyenv/versions/3.12.1"), "python3", "3.12.1");
    let (file, scan, findings) = scanned(&d, &[(&old, "3.12.1")]);
    std::fs::remove_dir_all(d.path().join("home/.pyenv")).unwrap();
    let out = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&out), (State::Unknown, "unreachable"), "{out:?}");
    // Nothing recorded for an answer that is not gone.
    let cache = Cache::open(Some(&file)).unwrap();
    let left: i64 = cache.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 1);
}

#[test]
fn a_new_uv_install_beside_an_old_one_that_is_still_there_leaves_the_old_one_present() {
    let d = TempDir::new("recheck-python").unwrap();
    let pythons = d.path().join("home/.local/share/uv/python");
    let old = install(&d, &pythons.join("cpython-3.12.1-linux-x86_64-gnu"), "python3.12", "3.12.1");
    let (file, scan, findings) = scanned(&d, &[(&old, "3.12.1")]);
    install(&d, &pythons.join("cpython-3.12.4-linux-x86_64-gnu"), "python3.12", "3.12.4");
    let out = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&out), (State::StillPresent, "affected"), "{out:?}");
}

#[test]
fn a_version_only_a_folder_name_gives_is_unreadable_not_guessed() {
    let d = TempDir::new("recheck-python").unwrap();
    let prefix = d.path().join("home/.pyenv/versions/3.12.4");
    let py = install(&d, &prefix, "python3", "3.12.1");
    let (file, scan, findings) = scanned(&d, &[(&py, "3.12.1")]);
    // No headers left: only the folder name says 3.12.4, which pyenv does not guarantee.
    std::fs::remove_dir_all(prefix.join("include")).unwrap();
    let out = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&out), (State::Unknown, "unreadable"), "{out:?}");
    assert!(out.verdict.detail.contains("without running it"), "{out:?}");
    // A folder where the interpreter was is not one either.
    std::fs::remove_file(&py).unwrap();
    std::fs::create_dir(&py).unwrap();
    assert_eq!(state(&check(&d, &file, &findings[0], scan)), (State::Unknown, "unreadable"));
}

#[test]
fn an_interpreter_something_else_vouches_for_is_unsupported() {
    let d = TempDir::new("recheck-python").unwrap();
    let py = install(&d, &d.path().join("opt/py"), "python3.12", "3.12.4");
    let h = here(d.path(), d.path(), &[]);
    let verdict = read(&py.display().to_string(), &|_| "brew", &h).expect_err("vouched-for is not a runtime");
    assert_eq!((verdict.state, verdict.reason), (State::Unknown, "unsupported"), "{verdict:?}");
    assert!(verdict.detail.contains("brew"), "{verdict:?}");
    // Not vouched for: the runtime a scan reports, with the scan's own fix.
    let c = read(&py.display().to_string(), &|_| "", &h).unwrap();
    assert_eq!((c.name.as_str(), c.version.as_str(), c.kind.as_str()), ("python", "3.12.4", "runtime"));
    let real = files::realpath(&py.display().to_string());
    assert_eq!(c.fix, packages::runtime_component(&c.path, &real, "3.12.4").fix);
    // A copied virtual environment of a vouched-for base is that base's.
    let base = files::realpath(&py.display().to_string());
    let venv = d.path().join("env");
    write(&venv.join("pyvenv.cfg"), &format!("home = {}\n", py.parent().unwrap().display()));
    trap(&d, &venv.join("bin/python3.12"), "");
    let vouch = |p: &str| if p == base { "brew" } else { "" };
    let verdict = read(&venv.join("bin/python3.12").display().to_string(), &vouch, &h).unwrap_err();
    assert_eq!(verdict.reason, "unsupported", "{verdict:?}");
    assert!(!marker(&d).exists());
}

#[test]
fn a_virtual_environment_reads_as_its_base_not_as_its_stale_config() {
    let d = TempDir::new("recheck-python").unwrap();
    let base = install(&d, &d.path().join("opt/py"), "python3.12", "3.12.4");
    let h = here(d.path(), d.path(), &[]);
    // Made when the base was 3.12.1; the base was upgraded in place since.
    let linked = d.path().join("a/.venv");
    write(&linked.join("pyvenv.cfg"), &format!("home = {}\nversion = 3.12.1\n", base.parent().unwrap().display()));
    link(&base, &linked.join("bin/python"));
    assert_eq!(read_here(&d, &linked.join("bin/python"), &h), Ok("3.12.4".into()));
    // Copies (`--copies`): `home` names the base's folder.
    let copied = d.path().join("b/.venv");
    write(&copied.join("pyvenv.cfg"), &format!("home = {}\nversion_info = 3.12.1\n", base.parent().unwrap().display()));
    trap(&d, &copied.join("bin/python3.12"), "");
    assert_eq!(read_here(&d, &copied.join("bin/python3.12"), &h), Ok("3.12.4".into()));
    // A copy whose config names no home, or a home with no interpreter, says so.
    write(&copied.join("pyvenv.cfg"), "version = 3.12.1\n");
    assert_eq!(read_here(&d, &copied.join("bin/python3.12"), &h), Err("unreadable"));
    write(&copied.join("pyvenv.cfg"), &format!("home = {}\n", d.path().join("nowhere").display()));
    assert_eq!(read_here(&d, &copied.join("bin/python3.12"), &h), Err("unreadable"));
}

#[test]
fn a_pyenv_shim_reads_as_the_version_pyenv_would_pick_here() {
    let d = TempDir::new("recheck-python").unwrap();
    let root = d.path().join("home/.pyenv");
    install(&d, &root.join("versions/3.12.1"), "python3", "3.12.1");
    install(&d, &root.join("versions/3.12.4"), "python3", "3.12.4");
    let shim = root.join("shims/python3");
    trap(&d, &shim, "export PYENV_ROOT; exec pyenv exec");
    let home = d.path().join("home");
    let work = d.path().join("work/app/src");
    std::fs::create_dir_all(&work).unwrap();
    let h = here(&home, &work, &[]);
    // Nothing set: `system`, and no python3 on PATH after the shims.
    assert_eq!(read_here(&d, &shim, &h), Err("unreadable"));
    // The global version file.
    write(&root.join("version"), "3.12.1\n");
    assert_eq!(read_here(&d, &shim, &h), Ok("3.12.1".into()));
    // A local file from the current folder up wins over it.
    write(&d.path().join("work/.python-version"), "# pinned\n3.12.4\n");
    assert_eq!(read_here(&d, &shim, &h), Ok("3.12.4".into()));
    // `PYENV_VERSION` wins over both; a prefix is the newest installed of it.
    let pinned = here(&home, &work, &[("PYENV_VERSION", "3.12")]);
    assert_eq!(read_here(&d, &shim, &pinned), Ok("3.12.4".into()));
    let first = here(&home, &work, &[("PYENV_VERSION", "3.11.9:3.12.1")]);
    assert_eq!(read_here(&d, &shim, &first), Err("unreadable"), "a version that is not installed is an error in pyenv");
    // `PYENV_DIR` moves where the local file is looked for.
    let elsewhere = here(&home, &work, &[("PYENV_DIR", &home.display().to_string())]);
    assert_eq!(read_here(&d, &shim, &elsewhere), Ok("3.12.1".into()));
    // `system`: the next python3 on PATH after the shims folder, read like any interpreter.
    let other = install(&d, &d.path().join("usr/local"), "python3", "3.12.2");
    let path = format!("{}:{}", root.join("shims").display(), other.parent().unwrap().display());
    let system = here(&home, &work, &[("PYENV_VERSION", "system"), ("PATH", &path)]);
    assert_eq!(read_here(&d, &shim, &system), Ok("3.12.2".into()));
}

#[test]
fn a_pyenv_shim_moved_to_a_new_version_is_gone_while_the_old_install_is_still_present() {
    // Through the whole re-check, which resolves from this process's folder
    // and variables: run only when pyenv's are not set for the test run.
    if std::env::var_os("PYENV_VERSION").is_some() || std::env::var_os("PYENV_DIR").is_some() {
        return;
    }
    let cwd = std::env::current_dir().unwrap();
    if cwd.ancestors().any(|a| a.join(".python-version").exists()) {
        return;
    }
    let d = TempDir::new("recheck-python").unwrap();
    let root = d.path().join("home/.pyenv");
    let old = install(&d, &root.join("versions/3.12.1"), "python3", "3.12.1");
    install(&d, &root.join("versions/3.12.4"), "python3", "3.12.4");
    let shim = root.join("shims/python3");
    trap(&d, &shim, "pyenv");
    write(&root.join("version"), "3.12.1\n");
    let (file, scan, findings) = scanned(&d, &[(&shim, "3.12.1"), (&old, "3.12.1")]);
    assert_eq!(state(&check(&d, &file, &findings[0], scan)), (State::StillPresent, "affected"));
    write(&root.join("version"), "3.12.4\n");
    let by_shim = check(&d, &file, &findings[0], scan);
    assert_eq!(state(&by_shim), (State::Gone, "fixed"), "{by_shim:?}");
    // The old install remains, still 3.12.1: its own finding is not gone.
    let by_dir = check(&d, &file, &findings[1], scan);
    assert_eq!(state(&by_dir), (State::StillPresent, "affected"), "{by_dir:?}");
}

#[test]
fn an_asdf_shim_reads_as_the_version_asdf_would_pick_here() {
    let d = TempDir::new("recheck-python").unwrap();
    let root = d.path().join("home/.asdf");
    install(&d, &root.join("installs/python/3.12.1"), "python3", "3.12.1");
    install(&d, &root.join("installs/python/3.12.4"), "python3", "3.12.4");
    let shim = root.join("shims/python3");
    trap(&d, &shim, "asdf-plugin: python 3.12.1");
    let home = d.path().join("home");
    let work = d.path().join("work/app");
    std::fs::create_dir_all(&work).unwrap();
    let h = here(&home, &work, &[]);
    assert_eq!(read_here(&d, &shim, &h), Err("unreadable"), "no version set");
    write(&home.join(".tool-versions"), "nodejs 22.1.0\npython 3.12.1\n");
    assert_eq!(read_here(&d, &shim, &h), Ok("3.12.1".into()));
    // A nearer file without python is passed over; one with it wins.
    write(&work.join(".tool-versions"), "nodejs 20.0.0\n");
    assert_eq!(read_here(&d, &shim, &h), Ok("3.12.1".into()));
    write(&d.path().join("work/.tool-versions"), "python 3.12.4 3.12.1 # newest first\n");
    assert_eq!(read_here(&d, &shim, &h), Ok("3.12.4".into()));
    // The variable wins; a version that is not installed is passed over for the next.
    let set = here(&home, &work, &[("ASDF_PYTHON_VERSION", "3.11.9 3.12.1")]);
    assert_eq!(read_here(&d, &shim, &set), Ok("3.12.1".into()));
    let source = here(&home, &work, &[("ASDF_PYTHON_VERSION", "ref:main")]);
    assert_eq!(read_here(&d, &shim, &source), Err("unreadable"));
    // Set to read `.python-version` as well, which is not read here: unknown.
    write(&home.join(".asdfrc"), "legacy_version_file = yes\n");
    assert_eq!(read_here(&d, &shim, &h), Err("unreadable"));
}

#[test]
fn a_mise_shim_or_an_unknown_script_is_unreadable() {
    let d = TempDir::new("recheck-python").unwrap();
    let mise = d.path().join("bin/mise");
    trap(&d, &mise, "");
    let shim = d.path().join("home/.local/share/mise/shims/python3");
    link(&mise, &shim);
    let h = here(&d.path().join("home"), d.path(), &[]);
    assert_eq!(read_here(&d, &shim, &h), Err("unreadable"));
    // A script in a shims folder that names no manager is read as an
    // interpreter, which keeps no version file.
    let other = d.path().join("tools/shims/python3");
    trap(&d, &other, "something else");
    assert_eq!(read_here(&d, &other, &h), Err("unreadable"));
}

#[test]
fn files_that_disagree_or_a_relative_location_are_not_guessed() {
    let d = TempDir::new("recheck-python").unwrap();
    let prefix = d.path().join("opt/py");
    let py = install(&d, &prefix, "python3.12", "3.12.4");
    let h = here(d.path(), d.path(), &[]);
    // Headers of another release line than the interpreter's name.
    std::fs::remove_dir_all(prefix.join("include")).unwrap();
    write(&prefix.join("include/python3.12/patchlevel.h"), "#define PY_VERSION \"3.11.9\"\n");
    assert_eq!(read_here(&d, &py, &h), Err("unreadable"));
    let got = read("opt/py/bin/python3.12", &|_| "", &h).unwrap_err();
    assert_eq!(got.reason, "unsupported");
}

#[test]
fn only_python_runtimes_take_this_path() {
    assert!(applies("runtime", "python"));
    assert!(!applies("runtime", "node"));
    assert!(!applies("package", "python"));
    assert!(!applies("package", "pip:requests"));
}
