use super::*;
use wpantry::utils::net::{Fake, Response};
use wpantry::utils::temp::TempDir;

/// A GitHub that names `tag` as the latest release.
fn github(tag: &'static str) -> Fake {
    Fake::new(move |req| {
        assert!(req.url.ends_with("/releases/latest"), "{}", req.url);
        Ok(Response::ok(format!("{{\"tag_name\": \"{tag}\"}}")))
    })
}

fn update(version: Option<&str>) -> Update {
    Update { check: false, yes: false, no_input: true, offline: false, version: version.map(String::from) }
}

const SOURCE: &str = "/w/pantry/rust/target/release/wpantry";
const FILE: &str = "/opt/bin/wpantry";

#[test]
fn a_newer_release_is_reported_and_check_exits_10() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    let net = github("v99.0.0");
    let u = Update { check: true, ..update(None) };
    assert_eq!(run_with(u, &net, Path::new(SOURCE), Some(&db)).unwrap(), EXIT_UPDATE_AVAILABLE);
    // A checkout is never replaced: the step is to rebuild it.
    assert_eq!(run_with(update(None), &net, Path::new(SOURCE), Some(&db)).unwrap(), EXIT_UPDATE_AVAILABLE);
    assert_eq!(net.requests().len(), 1, "the second run answers from the cache");
}

#[test]
fn the_latest_release_and_an_unreachable_github_are_not_updates() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    let net = github(VERSION);
    assert_eq!(run_with(update(None), &net, Path::new(FILE), Some(&db)).unwrap(), EXIT_OK);
    let empty = d.path().join("empty.db");
    assert_eq!(run_with(update(None), &Fake::offline(), Path::new(FILE), Some(&empty)).unwrap(), EXIT_OK);
}

#[test]
fn a_cache_that_cannot_remember_the_release_is_an_internal_error() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    let cache = Cache::open(Some(&db)).unwrap();
    cache
        .conn
        .execute_batch("DROP TABLE runs; CREATE VIEW runs AS SELECT '' AS source, '' AS fingerprint, 0.0 AS ran_at, '' AS result WHERE 0")
        .unwrap();
    cache.close().unwrap();
    let err = run_with(update(None), &github("v99.0.0"), Path::new(FILE), Some(&db)).unwrap_err();
    assert!(!err.is_source(), "{err}");
}

#[test]
fn a_wanted_version_must_be_a_release_version() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    let err = run_with(update(Some("nope")), &Fake::offline(), Path::new(FILE), Some(&db)).unwrap_err();
    assert!(err.to_string().contains("not a release version"), "{err}");
}

#[test]
fn without_a_yes_each_install_kind_names_its_own_update_step() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    for exe in [
        "/h/.local/share/mise/installs/packslip-github-com-waffuruai-pantry/1.0.0/bin/wpantry",
        "/h/.cargo/bin/wpantry",
        "/opt/homebrew/bin/wpantry",
        FILE,
    ] {
        let got = run_with(update(Some("v99.0.0")), &Fake::offline(), Path::new(exe), Some(&db)).unwrap();
        assert_eq!(got, EXIT_UPDATE_AVAILABLE, "{exe}");
    }
}

#[test]
fn a_file_install_downloads_before_it_replaces_anything() {
    let d = TempDir::new("update").unwrap();
    let db = d.path().join("w.db");
    let u = Update { yes: true, ..update(Some("99.0.0")) };
    let err = run_with(u, &Fake::offline(), Path::new(FILE), Some(&db)).unwrap_err();
    assert!(err.is_source(), "{err}");
}

#[test]
fn through_runs_the_owning_tool_when_it_is_here() {
    assert_eq!(through(&["wpantry-no-such-tool", "upgrade", "wpantry"]).unwrap(), EXIT_FAIL);
    assert_eq!(through(&["false"]).unwrap(), EXIT_FAIL);
    assert_eq!(through(&["true"]).unwrap(), EXIT_OK);
}

#[test]
fn describe_names_the_install_kind_and_place() {
    let exe = Path::new("/opt/bin/wpantry");
    assert_eq!(describe(&Kind::Mise, exe), "installed by mise at /opt/bin/wpantry");
    assert_eq!(describe(&Kind::Cargo, exe), "installed by cargo at /opt/bin/wpantry");
    assert_eq!(describe(&Kind::Brew, exe), "installed by Homebrew at /opt/bin/wpantry");
    assert_eq!(describe(&Kind::Source, exe), "built from a checkout at /opt/bin/wpantry");
    assert_eq!(describe(&Kind::File, exe), "at /opt/bin/wpantry");
}

#[test]
fn the_notice_names_a_newer_cached_release_only() {
    assert_eq!(notice(&Fake::offline(), true), None, "offline: no notice");
    let d = TempDir::new("notice").unwrap();
    let db = d.path().join("w.db");
    let open = || Cache::open(Some(&db)).unwrap();
    assert_eq!(notice_in(open(), &Fake::offline()), None, "nothing cached, nothing reachable");
    assert_eq!(notice_in(open(), &github(VERSION)), None, "this is the latest");
    let other = d.path().join("other.db");
    let got = notice_in(Cache::open(Some(&other)).unwrap(), &github("v99.0.0")).unwrap();
    assert_eq!(got, format!("wpantry 99.0.0 is available (you have {VERSION}): wpantry update"));
    assert!(notice_in(Cache::open(Some(&other)).unwrap(), &Fake::offline()).is_some(), "from the day's memo");
}
