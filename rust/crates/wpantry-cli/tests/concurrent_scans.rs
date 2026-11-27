//! Scans at once on one cache: a scheduled scan beside one a person starts,
//! or a program running several. The built binary runs with a temp HOME and
//! cache, `--offline --no-input`, a repo locking one package and a folder of
//! advisories that flags it. Oracle: each scan alone gives its exit code and
//! its findings; three at once give the same, whether the cache is new (the
//! schema and its migrations are made by whoever gets there first) or
//! already holds a scan (the writes of one wait for the others). A scan that
//! lost the race must not fail with "database is locked", with a duplicate
//! column, or finish with the advisories turned into an `unchecked` gap.
//!
//!     cargo test -p wpantry-cli --test concurrent_scans

mod common;

use common::*;
use serde_json::{Value, json};
use std::path::PathBuf;

struct Setup {
    t: Ctx,
    argv: Vec<String>,
}

fn setup() -> Setup {
    let t = Ctx::new();
    let repo = git_repo(&t.home.join("work/app"), false);
    write(
        &repo.join("package-lock.json"),
        json!({
            "name": "app", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": {"name": "app", "version": "0.0.0", "dependencies": {"acme-internal-widget": "1.2.3"}},
                "node_modules/acme-internal-widget": {"version": "1.2.3"}
            }
        })
        .to_string(),
    );
    let folder = t.home.join("advisories");
    mkdir(&folder);
    write(
        &folder.join("TEAM-2026-0001.json"),
        json!({
            "id": "TEAM-2026-0001", "summary": "widget",
            "affected": [{"package": {"ecosystem": "npm", "name": "acme-internal-widget"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]
        })
        .to_string(),
    );
    let sources: PathBuf = t.home.join("sources.toml");
    write(
        &sources,
        format!(
            "[[source]]\nid = \"team-advisories\"\nkind = \"advisories\"\nformat = \"osv-dir\"\npath = '{}'\n",
            folder.display()
        ),
    );
    let argv =
        ["scan", "--json", "--no-input", "--offline", "--no-machine", "--path", s(&repo), "--sources", s(&sources)]
            .iter()
            .map(|a| a.to_string())
            .collect();
    Setup { t, argv }
}

fn run(x: &Setup) -> Out {
    let argv: Vec<&str> = x.argv.iter().map(String::as_str).collect();
    x.t.run(&argv)
}

/// The project findings and the unchecked ones naming a source of ours.
fn verdict(o: &Out) -> (i32, Vec<Value>, Vec<Value>) {
    let env = o.json();
    let all = env["findings"].as_array().unwrap().clone();
    let project =
        all.iter().filter(|f| f["kind"] == "project").map(|f| json!([f["vuln_id"], f["component"]])).collect();
    let gaps = all
        .iter()
        .filter(|f| f["kind"] == "unchecked" && f["component"].as_str().unwrap_or("").contains("source"))
        .cloned()
        .collect();
    (o.code, project, gaps)
}

fn three_at_once(x: &Setup) -> Vec<Out> {
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..3).map(|_| sc.spawn(|| run(x))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// Risk: three scans started together on a cache nobody has opened fail
/// (a duplicate column from the migration, or a lock) or differ. Oracle: the
/// verdict of one scan on its own cache.
#[test]
fn three_scans_at_once_on_a_new_cache_all_give_the_one_verdict() {
    let alone = verdict(&run(&setup()));
    assert_eq!(alone.0, 1, "the widget fails");
    assert_eq!(alone.1.len(), 1, "{alone:?}");
    let x = setup();
    for (i, o) in three_at_once(&x).iter().enumerate() {
        assert_eq!(verdict(o), alone, "scan {i}: {}", o.err);
    }
}

/// Risk: on a cache that already holds a scan, a scan that starts while
/// another is writing is refused with "database is locked" or has its local
/// advisories read as `unchecked` with exit 0. Oracle: as above.
#[test]
fn three_scans_at_once_on_a_warm_cache_all_give_the_one_verdict() {
    let x = setup();
    let alone = verdict(&run(&x));
    assert_eq!(alone.0, 1);
    for (i, o) in three_at_once(&x).iter().enumerate() {
        assert_eq!(verdict(o), alone, "scan {i}: {}", o.err);
    }
}

/// A repo locking `n` packages and a folder of `n` records that flag them,
/// with the sources file for it: a scan that takes seconds, not a moment.
fn long_scan(x: &Setup, n: usize) -> Vec<String> {
    let repo = git_repo(&x.t.home.join("work/long"), false);
    let mut packages = serde_json::Map::new();
    packages.insert(String::new(), json!({"name": "long", "version": "0.0.0"}));
    let folder = x.t.home.join("long-advisories");
    mkdir(&folder);
    for i in 0..n {
        packages.insert(format!("node_modules/pkg-{i}"), json!({"version": "1.0.0"}));
        write(
            &folder.join(format!("BIG-{i}.json")),
            json!({"id": format!("BIG-{i}"),
                   "affected": [{"package": {"ecosystem": "npm", "name": format!("pkg-{i}")},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]})
            .to_string(),
        );
    }
    write(
        &repo.join("package-lock.json"),
        json!({"name": "long", "lockfileVersion": 3, "packages": packages}).to_string(),
    );
    let sources = x.t.home.join("long-sources.toml");
    write(
        &sources,
        format!(
            "[[source]]\nid = \"long-advisories\"\nkind = \"advisories\"\nformat = \"osv-dir\"\npath = '{}'\n",
            folder.display()
        ),
    );
    ["scan", "--json", "--no-input", "--offline", "--no-machine", "--path", s(&repo), "--sources", s(&sources)]
        .iter()
        .map(|a| a.to_string())
        .collect()
}

/// Risk: a scan that runs for minutes (network, big folders) holds the
/// cache's write lock the whole time, so `report`, `ignore` or `cache prune`
/// started meanwhile wait the busy timeout (60 s) and fail where they used to
/// slip in; or a second scan with other sources removes what the first
/// loaded and the first reports clean. Oracle: each command's exit code and
/// output during the scan are those it gives alone (compared with a run
/// before and after), and the long scan still reports every finding.
#[test]
fn commands_run_during_a_long_scan_give_what_they_give_alone_and_the_scan_keeps_its_findings() {
    let x = setup();
    let first = run(&x); // a scan to report on
    assert_eq!(first.code, 1, "{}", first.err);
    let long = long_scan(&x, 3000);
    let others: [&[&str]; 4] =
        [&["report", "--json"], &["report", "summary", "--json"], &["ignore", "list", "--json"], &["cache", "prune"]];
    let alone: Vec<(i32, bool)> = others.iter().map(|a| (x.t.run(a).code, true)).collect();
    let started = std::time::Instant::now();
    let (scan, during) = std::thread::scope(|sc| {
        let h = sc.spawn(|| {
            let argv: Vec<&str> = long.iter().map(String::as_str).collect();
            x.t.run(&argv)
        });
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let during: Vec<(i32, bool)> = others.iter().map(|a| (x.t.run(a).code, true)).collect();
        // A second scan, of the small repo with its own sources, takes its turn.
        let second = run(&x);
        assert_eq!(verdict(&second), verdict(&first), "{}", second.err);
        (h.join().unwrap(), during)
    });
    assert_eq!(during, alone, "a command run during the scan gives what it gives alone");
    assert_eq!(scan.code, 1, "{}", scan.err);
    let findings = scan.json()["findings"].as_array().unwrap().iter().filter(|f| f["kind"] == "project").count();
    assert_eq!(findings, 3000, "the long scan kept every finding while the others ran");
    assert!(started.elapsed() < std::time::Duration::from_secs(55), "nothing waited for the busy timeout");
}
