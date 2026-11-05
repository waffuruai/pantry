use super::*;
use crate::utils::net::{Fake, Request, Response};
use serde_json::json;

fn cache() -> (crate::utils::temp::TempDir, Cache) {
    let d = crate::utils::temp::TempDir::new("sync").unwrap();
    let db = d.path().join("w.db");
    let c = Cache::open(Some(&db)).unwrap();
    // The malicious index fetches from a clone beside the cache: a local one here.
    crate::sources::malicious_packages::seed_clone(&db, &["osv/malicious/npm/evil/MAL-1.json"]);
    (d, c)
}

/// Every feed answers, except GitHub (down) and python's end-of-life
/// page (gone, so nothing is cached for it).
fn feeds(r: &Request) -> Result<Response> {
    let u = r.url.as_str();
    let ok = |v: serde_json::Value| Ok(Response::ok(v.to_string()));
    if u == crate::sources::file::url("cisa-kev") {
        return ok(json!({"vulnerabilities": [{"cveID": "CVE-2026-1"}]}));
    }
    if u == crate::sources::file::url("homebrew-casks") {
        return ok(json!([{"token": "firefox", "version": "145.0", "artifacts": [{"app": ["Firefox.app"]}]}]));
    }
    if u.starts_with("https://versionhistory.googleapis.com/") {
        return ok(json!({"releases": [{"version": "142.0.1"}]}));
    }
    if u.ends_with("firefox_versions.json") {
        return ok(json!({"LATEST_FIREFOX_VERSION": "145.0"}));
    }
    if u.starts_with(crate::sources::file::url("firefox-releases")) {
        return ok(json!({}));
    }
    if u == crate::sources::file::url("vscode-extension-lists") {
        return ok(json!({"malicious": []}));
    }
    if u.starts_with("https://api.github.com/") {
        return Ok(Response { status: 500, body: Vec::new(), etag: None });
    }
    if u == "https://endoflife.date/api/nodejs.json" {
        return ok(json!([{"cycle": "24", "eol": false, "latest": "24.11.0"}]));
    }
    if u.starts_with("https://endoflife.date/") {
        return Ok(Response { status: 404, body: Vec::new(), etag: None });
    }
    if u.ends_with("/querybatch") {
        return ok(json!({"results": [{"vulns": []}]}));
    }
    if u.contains("/v1/vulns/") {
        return Ok(Response { status: 404, body: Vec::new(), etag: None });
    }
    panic!("unexpected {u}");
}

#[test]
fn a_sync_refreshes_every_feed_and_names_what_failed() {
    let (_d, c) = cache();
    let net = Fake::new(feeds);
    endoflife::eol(&c, &net, "nodejs", "24", false).unwrap();
    c.conn.execute("INSERT INTO eol VALUES ('python', '3.9', 'true', '3.9.9')", []).unwrap();
    c.put_query("npm", "left-pad", "1.0.0", &[]).unwrap();
    let seen = std::sync::Mutex::new(Vec::new());
    let got = run(&c, &net, true, &|s| seen.lock().unwrap().push(s.to_string())).unwrap();
    let mut want = vec!["CISA KEV", "OpenSSF malicious packages", "Firefox releases", "VS Code extension lists", "OSV"];
    if cfg!(target_os = "macos") {
        want.extend(["Homebrew casks", "Chrome releases"]);
    }
    let mut refreshed = got.refreshed.clone();
    refreshed.sort();
    want.sort_unstable();
    assert_eq!(refreshed, want);
    assert_eq!(got.packages, 1);
    let failed: Vec<&str> = got.failed.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(failed, ["wpantry releases", "endoflife.date"]);
    assert!(got.failed[1].1.starts_with("python: "), "{:?}", got.failed[1]);
    assert!(seen.lock().unwrap().iter().any(|s| s == "Fetching end-of-life dates for 2 products"));
    assert!(net.requests().iter().any(|r| r.url.ends_with("/querybatch")));
    // The same day, nothing fresh is asked again; what failed is.
    let again = run(&c, &Fake::offline(), false, &|_| {}).unwrap();
    for name in ["CISA KEV", "OSV", "endoflife.date"] {
        assert!(again.refreshed.contains(&name.to_string()), "{name}: {again:?}");
    }
    let failed: Vec<&str> = again.failed.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(failed, ["wpantry releases"]);
}

#[test]
fn a_bug_in_a_feed_is_internal_and_one_in_end_of_life_stops_the_sync() {
    let (_d, c) = cache();
    let bug = Fake::new(|r| {
        if r.url == crate::sources::file::url("cisa-kev") {
            return Err(Error::Missing("not a source failure".into()));
        }
        feeds(r)
    });
    let got = run(&c, &bug, false, &|_| {}).unwrap();
    assert_eq!(got.failed[0].0, "CISA KEV");
    assert!(got.failed[0].1.starts_with("internal: "), "{:?}", got.failed[0]);
    assert_eq!(got.packages, 0, "nothing was ever asked of OSV");
    // An advisory OSV named but can't serve leaves a gap: OSV isn't refreshed.
    c.put_query("npm", "evil", "1.0.0", &["MAL-GHSA-1".to_string()]).unwrap();
    let got = run(&c, &Fake::new(feeds), false, &|_| {}).unwrap();
    assert_eq!(got.packages, 1);
    assert!(got.failed.iter().any(|(n, why)| n == "OSV" && why.contains("MAL-GHSA-1")), "{:?}", got.failed);
    c.conn.execute("INSERT INTO eol VALUES ('python', '3.9', 'true', '3.9.9')", []).unwrap();
    let bug = Fake::new(|r| {
        if r.url.starts_with("https://endoflife.date/") {
            return Err(Error::Missing("not a source failure".into()));
        }
        feeds(r)
    });
    assert!(matches!(run(&c, &bug, false, &|_| {}), Err(Error::Missing(_))));
}
