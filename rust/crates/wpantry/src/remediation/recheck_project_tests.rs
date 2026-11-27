//! Project package re-checks. Oracle: the scan itself. Each finding below is
//! made by the real lockfile check (`projects`) or, for an installed Python
//! package, written as the machine check writes it; the re-check must then
//! agree with what a fresh scan of the changed place would say. Temp-dir
//! projects only; nothing here reads a real project.
use super::recheck::*;
use crate::checks::Options;
use crate::checks::supply_chain::projects::projects;
use crate::checks::supply_chain::testing;
use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn npm_lock(pkgs: &[(&str, &str)]) -> String {
    let mut packages = json!({"": {"name": "app", "dependencies": {}}});
    for (name, version) in pkgs {
        packages[format!("node_modules/{name}")] = json!({"version": version});
    }
    json!({"name": "app", "lockfileVersion": 3, "packages": packages}).to_string()
}

/// A scan (the real lockfile check, a fake OSV that knows `vulnerable`)
/// of one repo holding `files`, left in a cache. Returns the cache file,
/// the scan, the repo's root and the findings.
fn scan_of(
    d: &TempDir,
    vulnerable: &'static [(&'static str, &'static str)],
    files: &[(&str, String)],
) -> (PathBuf, i64, PathBuf, Vec<Finding>) {
    let net = testing::osv_net(vulnerable);
    let mut s = testing::scan(&net, d, Options::default());
    let (name, root) = testing::repo(d, "app");
    for (rel, text) in files {
        testing::write(&root, rel, text);
    }
    projects(&mut s, &[(name, root.clone())]).unwrap();
    let findings: Vec<Finding> = s.findings.iter().filter(|f| f.kind == "project").cloned().collect();
    s.cache.replace_findings(&findings).unwrap();
    let opts = Options { machine: true, ..Default::default() };
    let scan = crate::history::record_scan(&s.cache, 1.0, &findings, &[], &opts).unwrap();
    let file = s.cache.file().to_path_buf();
    s.cache.close().unwrap();
    (file, scan, root, findings)
}

fn ask(file: &Path, ids: &[String], scan: i64) -> Vec<Outcome> {
    let mut out = Vec::new();
    recheck_many(Cache::open(Some(file)).unwrap(), ids, scan, false, &mut |o| out.push(o))
        .unwrap_or_else(|f| panic!("{}: {}", f.id, f.error));
    out
}

fn one(file: &Path, f: &Finding, scan: i64) -> Outcome {
    ask(file, &[f.id()], scan).remove(0)
}

fn state(o: &Outcome) -> (State, &'static str) {
    (o.verdict.state, o.verdict.reason)
}

fn findings_left(file: &Path) -> i64 {
    let c = Cache::open(Some(file)).unwrap();
    c.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap()
}

const LODASH: &[(&str, &str)] = &[("npm", "lodash")];

#[test]
fn an_npm_lockfile_still_at_the_affected_version_is_still_present() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, _, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    assert_eq!(found.len(), 1, "{found:?}");
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::StillPresent, "affected"), "{out:?}");
    assert_eq!(out.keys, [found[0].key()]);
    assert_eq!(findings_left(&file), 1, "still present writes nothing");
}

#[test]
fn an_npm_lockfile_moved_past_the_fix_is_gone_and_recorded() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    testing::write(&root, "package-lock.json", npm_lock(&[("lodash", "9.9.9")]));
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::Gone, "fixed"), "{out:?}");
    assert_eq!(findings_left(&file), 0);
}

#[test]
fn a_package_dropped_from_the_lockfile_is_gone() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    testing::write(&root, "package-lock.json", npm_lock(&[("left-pad", "1.3.0")]));
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::Gone, "removed"), "{out:?}");
}

#[test]
fn another_affected_version_of_the_package_is_still_present() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    // A nested copy at a fixed version beside the top one still affected.
    let mut lock: Value = serde_json::from_str(&npm_lock(&[("lodash", "4.17.19")])).unwrap();
    lock["packages"]["node_modules/other/node_modules/lodash"] = json!({"version": "9.9.9"});
    testing::write(&root, "package-lock.json", lock.to_string());
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::StillPresent, "affected"), "{out:?}");
    assert!(out.verdict.detail.contains("4.17.19"), "{}", out.verdict.detail);
}

#[test]
fn a_lockfile_that_is_gone_or_unreadable_says_nothing() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    testing::write(&root, "package-lock.json", "this is not a lockfile");
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::Unknown, "unreadable"), "{out:?}");
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::Unknown, "unreachable"), "{out:?}");
    assert_eq!(findings_left(&file), 1, "unknown writes nothing");
}

#[test]
fn without_the_advisory_data_a_package_still_there_is_unknown_never_gone() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    {
        let c = Cache::open(Some(&file)).unwrap();
        c.conn.execute("DELETE FROM vulns", []).unwrap();
        c.close().unwrap();
    }
    testing::write(&root, "package-lock.json", npm_lock(&[("lodash", "9.9.9")]));
    let out = one(&file, &found[0], scan);
    assert_eq!(state(&out), (State::Unknown, "uncached"), "{out:?}");
    // A package that is not there needs no advisory to be gone.
    testing::write(&root, "package-lock.json", npm_lock(&[("left-pad", "1.3.0")]));
    assert_eq!(state(&one(&file, &found[0], scan)), (State::Gone, "removed"));
}

const REQUESTS: &[(&str, &str)] = &[("PyPI", "requests")];

#[test]
fn a_python_requirements_pin_is_read_again_the_way_the_scan_reads_it() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, REQUESTS, &[("requirements.txt", "Requests==2.0.0\n".to_string())]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(state(&one(&file, &found[0], scan)), (State::StillPresent, "affected"));
    testing::write(&root, "requirements.txt", "requests==9.9.9\n");
    assert_eq!(state(&one(&file, &found[0], scan)), (State::Gone, "fixed"));
}

#[test]
fn a_python_lockfile_package_is_read_again_from_that_lockfile() {
    let d = TempDir::new("project").unwrap();
    let lock = |v: &str| {
        format!(
            "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"{v}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n"
        )
    };
    let (file, scan, root, found) = scan_of(&d, REQUESTS, &[("uv.lock", lock("2.0.0"))]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(state(&one(&file, &found[0], scan)), (State::StillPresent, "affected"));
    testing::write(&root, "uv.lock", lock("9.9.9"));
    assert_eq!(state(&one(&file, &found[0], scan)), (State::Gone, "fixed"));
}

#[test]
fn a_range_with_a_gap_judges_the_new_version_by_the_stored_record() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    // The stored record says: affected from 4.0.0 to before 4.17.21, and
    // from 5.0.0 to before 5.1.0.
    let rec = json!({"id": "GHSA-lodash", "modified": "2026-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "4.0.0"}, {"fixed": "4.17.21"}, {"introduced": "5.0.0"}, {"fixed": "5.1.0"}]}]}]});
    {
        let c = Cache::open(Some(&file)).unwrap();
        c.put_vuln(&rec).unwrap();
        c.close().unwrap();
    }
    for (version, want) in [
        ("4.17.21", State::Gone),
        ("4.17.5", State::StillPresent),
        ("5.0.3", State::StillPresent),
        ("5.1.0", State::Gone),
        ("3.9.0", State::Gone),
    ] {
        testing::write(&root, "package-lock.json", npm_lock(&[("lodash", version)]));
        assert_eq!(one(&file, &found[0], scan).verdict.state, want, "{version}");
    }
}

#[test]
fn a_known_malicious_package_stays_present_at_any_version() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = scan_of(&d, LODASH, &[("package-lock.json", npm_lock(&[("lodash", "4.17.20")]))]);
    let rec = json!({"id": "MAL-2026-1", "aliases": ["GHSA-lodash"], "modified": "2026-01-01T00:00:00Z"});
    {
        let c = Cache::open(Some(&file)).unwrap();
        c.conn.execute("DELETE FROM vulns", []).unwrap();
        c.put_vuln(&rec).unwrap();
        c.close().unwrap();
    }
    testing::write(&root, "package-lock.json", npm_lock(&[("lodash", "99.0.0")]));
    assert_eq!(state(&one(&file, &found[0], scan)), (State::StillPresent, "affected"));
}

// An installed Python package, in a virtual environment ------------------------

fn pip_record(fixed: &str) -> Value {
    json!({"id": "GHSA-foo", "modified": "2026-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "foo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})
}

/// A virtual environment holding `foo` at `version`; returns its python.
fn venv(root: &Path, version: Option<&str>, system: bool) -> PathBuf {
    let site = root.join("lib/python3.12/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("bin/python"), "").unwrap();
    std::fs::write(root.join("pyvenv.cfg"), format!("home = /usr/bin\ninclude-system-site-packages = {system}\n"))
        .unwrap();
    for e in std::fs::read_dir(&site).unwrap() {
        std::fs::remove_dir_all(e.unwrap().path()).unwrap();
    }
    if let Some(v) = version {
        let info = site.join(format!("foo-{v}.dist-info"));
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(info.join("METADATA"), format!("Metadata-Version: 2.1\nName: foo\nVersion: {v}\n\nbody\n"))
            .unwrap();
    }
    root.join("bin/python")
}

fn pip_finding(python: &Path) -> Finding {
    Finding {
        kind: "package".into(),
        component: "pip:foo".into(),
        version: "1.0".into(),
        location: python.to_string_lossy().into_owned(),
        vuln_id: "GHSA-foo".into(),
        status: "fail".into(),
        fixed: "2.0".into(),
        fix_cmd: format!("{} -m pip install --upgrade 'foo>={{safe}}'", python.display()),
        fix_auto: true,
        ..Default::default()
    }
}

fn pip_scan(d: &TempDir, f: &Finding) -> (PathBuf, i64) {
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    cache.put_vuln(&pip_record("2.0")).unwrap();
    cache.replace_findings(std::slice::from_ref(f)).unwrap();
    let opts = Options { machine: true, ..Default::default() };
    let scan = crate::history::record_scan(&cache, 1.0, std::slice::from_ref(f), &[], &opts).unwrap();
    let file = cache.file().to_path_buf();
    cache.close().unwrap();
    (file, scan)
}

#[test]
fn a_package_in_a_virtual_environment_is_read_from_its_installed_metadata() {
    let d = TempDir::new("project").unwrap();
    let env = d.path().join("env");
    let python = venv(&env, Some("1.0"), false);
    let f = pip_finding(&python);
    let (file, scan) = pip_scan(&d, &f);
    assert_eq!(state(&one(&file, &f, scan)), (State::StillPresent, "affected"));
    venv(&env, Some("2.0"), false);
    assert_eq!(state(&one(&file, &f, scan)), (State::Gone, "fixed"));
    assert_eq!(findings_left(&file), 0);
}

#[test]
fn a_package_uninstalled_from_the_environment_is_gone() {
    let d = TempDir::new("project").unwrap();
    let env = d.path().join("env");
    let python = venv(&env, Some("1.0"), false);
    let f = pip_finding(&python);
    let (file, scan) = pip_scan(&d, &f);
    venv(&env, None, false);
    assert_eq!(state(&one(&file, &f, scan)), (State::Gone, "removed"));
}

#[test]
fn an_environment_that_also_reads_the_system_packages_cannot_say_a_missing_one_is_gone() {
    let d = TempDir::new("project").unwrap();
    let env = d.path().join("env");
    let python = venv(&env, Some("1.0"), true);
    let f = pip_finding(&python);
    let (file, scan) = pip_scan(&d, &f);
    venv(&env, None, true);
    let out = one(&file, &f, scan);
    assert_eq!(out.verdict.state, State::Unknown, "{out:?}");
    // What the environment's own folder shows is still believed.
    venv(&env, Some("1.0"), true);
    assert_eq!(one(&file, &f, scan).verdict.state, State::StillPresent);
}

#[test]
fn a_python_that_is_not_a_virtual_environment_needs_a_scan() {
    let d = TempDir::new("project").unwrap();
    let python = d.path().join("usr/bin/python3");
    std::fs::create_dir_all(python.parent().unwrap()).unwrap();
    std::fs::write(&python, "").unwrap();
    let f = pip_finding(&python);
    let (file, scan) = pip_scan(&d, &f);
    let out = one(&file, &f, scan);
    assert_eq!(state(&out), (State::Unknown, "unsupported"), "{out:?}");
    std::fs::remove_file(&python).unwrap();
    assert_eq!(state(&one(&file, &f, scan)), (State::Unknown, "unreachable"));
}

// Several ids -------------------------------------------------------------------

/// `places` lockfiles of `per` packages each, every package vulnerable.
fn crowd(d: &TempDir, places: usize, per: usize) -> (PathBuf, i64, PathBuf, Vec<Finding>) {
    let names: Vec<String> = (0..per).map(|i| format!("pkg{i}")).collect();
    let pairs: Vec<(&'static str, &'static str)> =
        names.iter().map(|n| ("npm", &*Box::leak(n.clone().into_boxed_str()))).collect();
    let pairs: &'static [(&'static str, &'static str)] = Box::leak(pairs.into_boxed_slice());
    let net = Fake::new(move |r| testing::osv(r, pairs).unwrap_or_else(|| Ok(Response::not_found())));
    let mut s = testing::scan(&net, d, Options::default());
    let (name, root) = testing::repo(d, "app");
    let lock = npm_lock(&names.iter().map(|n| (n.as_str(), "1.0.0")).collect::<Vec<_>>());
    for p in 0..places {
        testing::write(&root, &format!("p{p}/package-lock.json"), &lock);
    }
    projects(&mut s, &[(name, root.clone())]).unwrap();
    let findings: Vec<Finding> = s.findings.iter().filter(|f| f.kind == "project").cloned().collect();
    s.cache.replace_findings(&findings).unwrap();
    let opts = Options { machine: true, ..Default::default() };
    let scan = crate::history::record_scan(&s.cache, 1.0, &findings, &[], &opts).unwrap();
    let file = s.cache.file().to_path_buf();
    s.cache.close().unwrap();
    (file, scan, root, findings)
}

#[test]
fn many_ids_sharing_a_place_read_that_place_once() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, _, found) = crowd(&d, 20, 50);
    assert_eq!(found.len(), 1000);
    let ids: Vec<String> = found.iter().map(Finding::id).collect();
    super::recheck_project::reset_opens();
    let started = std::time::Instant::now();
    let out = ask(&file, &ids, scan);
    let took = started.elapsed();
    assert_eq!(out.len(), 1000);
    assert!(out.iter().all(|o| o.verdict.state == State::StillPresent), "{:?}", out[0]);
    assert_eq!(super::recheck_project::opens(), 20, "each file opened once");
    eprintln!("1000 ids over 20 places: {took:?}");
}

#[test]
fn each_id_in_a_crowd_is_answered_as_it_would_be_alone() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = crowd(&d, 3, 4);
    // One place fixed, one dropped, one untouched.
    let fixed: Vec<(String, &str)> = (0..4).map(|i| (format!("pkg{i}"), "9.9.9")).collect();
    testing::write(
        &root,
        "p0/package-lock.json",
        npm_lock(&fixed.iter().map(|(n, v)| (n.as_str(), *v)).collect::<Vec<_>>()),
    );
    testing::write(&root, "p1/package-lock.json", npm_lock(&[]));
    let ids: Vec<String> = found.iter().map(Finding::id).collect();
    let out = ask(&file, &ids, scan);
    for (f, o) in found.iter().zip(&out) {
        let want = if f.location.contains("/p0/") {
            (State::Gone, "fixed")
        } else if f.location.contains("/p1/") {
            (State::Gone, "removed")
        } else {
            (State::StillPresent, "affected")
        };
        assert_eq!(state(o), want, "{}", f.location);
    }
}

#[test]
fn many_gone_ids_are_each_recorded_and_still_fast() {
    let d = TempDir::new("project").unwrap();
    let (file, scan, root, found) = crowd(&d, 20, 50);
    let names: Vec<String> = (0..50).map(|i| format!("pkg{i}")).collect();
    let fixed = npm_lock(&names.iter().map(|n| (n.as_str(), "9.9.9")).collect::<Vec<_>>());
    for p in 0..20 {
        testing::write(&root, &format!("p{p}/package-lock.json"), &fixed);
    }
    let ids: Vec<String> = found.iter().map(Finding::id).collect();
    super::recheck_project::reset_opens();
    let started = std::time::Instant::now();
    let out = ask(&file, &ids, scan);
    eprintln!("1000 gone ids over 20 places: {:?}", started.elapsed());
    assert!(out.iter().all(|o| state(o) == (State::Gone, "fixed")), "{:?}", out[0]);
    assert_eq!(super::recheck_project::opens(), 20);
    assert_eq!(findings_left(&file), 0);
}

/// Each lockfile kind is read again by the reader the scan used for it:
/// the package at an affected version is still there, past the fix it is gone.
#[test]
fn other_lockfile_kinds_are_read_again_the_same_way() {
    const ALL: &[(&str, &str)] = &[("crates.io", "serde"), ("PyPI", "requests")];
    type Lock = fn(&str) -> String;
    let cases: [(&str, Lock); 3] = [
        ("Cargo.lock", |v| {
            format!(
                "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"{v}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            )
        }),
        ("Pipfile.lock", |v| json!({"_meta": {}, "default": {"requests": {"version": format!("=={v}")}}}).to_string()),
        ("poetry.lock", |v| {
            format!("[[package]]\nname = \"requests\"\nversion = \"{v}\"\n\n[metadata]\nlock-version = \"2.0\"\n")
        }),
    ];
    for (name, lock) in cases {
        let d = TempDir::new("project").unwrap();
        let (file, scan, root, found) = scan_of(&d, ALL, &[(name, lock("1.0.0"))]);
        let found: Vec<&Finding> = found.iter().filter(|f| f.location.ends_with(name)).collect();
        assert_eq!(found.len(), 1, "{name}");
        assert_eq!(state(&one(&file, found[0], scan)), (State::StillPresent, "affected"), "{name}");
        testing::write(&root, name, lock("9.9.9"));
        assert_eq!(state(&one(&file, found[0], scan)), (State::Gone, "fixed"), "{name}");
    }
}
