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
    if u == crate::sources::file::url("epss") {
        let rows: String = (0..1000).map(|i| format!("CVE-2026-{i},0.01,0.5\n")).collect();
        return Ok(Response::ok(format!("cve,epss,percentile\n{rows}")));
    }
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
    if u.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
        return Ok(Response::not_found());
    }
    panic!("unexpected {u}");
}

#[test]
fn a_sync_refreshes_every_feed_and_names_what_failed() {
    let (_d, c) = cache();
    let net = Fake::new(feeds);
    endoflife::eol(&c, &net, "nodejs", "24", false).unwrap();
    c.conn
        .execute("INSERT INTO eol (product, cycle, eol, latest) VALUES ('python', '3.9', 'true', '3.9.9')", [])
        .unwrap();
    c.put_query("npm", "left-pad", "1.0.0", &[]).unwrap();
    let seen = std::sync::Mutex::new(Vec::new());
    let got = run(&c, &net, true, &|s| seen.lock().unwrap().push(s.to_string())).unwrap();
    let mut want =
        vec!["CISA KEV", "EPSS", "OpenSSF malicious packages", "Firefox releases", "VS Code extension lists", "OSV"];
    if cfg!(target_os = "macos") {
        want.push("Homebrew casks");
    }
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        want.push("Chrome releases");
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
    c.conn
        .execute("INSERT INTO eol (product, cycle, eol, latest) VALUES ('python', '3.9', 'true', '3.9.9')", [])
        .unwrap();
    let bug = Fake::new(|r| {
        if r.url.starts_with("https://endoflife.date/") {
            return Err(Error::Missing("not a source failure".into()));
        }
        feeds(r)
    });
    assert!(matches!(run(&c, &bug, false, &|_| {}), Err(Error::Missing(_))));
}

const ASSET: &str = "https://api.github.com/repos/YARAHQ/yara-forge/releases/assets/1";

/// The sources a scan fills only for what it found: every one answers.
fn found(r: &Request) -> Result<Response> {
    let u = r.url.as_str();
    let ok = |v: serde_json::Value| Ok(Response::ok(v.to_string()));
    if u == crate::sources::file::url("yara-forge-full") {
        return ok(json!({"assets": [{"name": crate::checks::malware::yara::FORGE_ASSET, "url": ASSET}]}));
    }
    if u == ASSET {
        let rules = b"rule synced { condition: false }";
        return Ok(Response::ok(crate::checks::malware::tests::stored_zip("packages/full/yara-rules-full.yar", rules)));
    }
    if u.starts_with(crate::sources::file::url("signature-base")) || u == crate::sources::file::url("feodo") {
        return Ok(Response::ok("# none\n"));
    }
    if u == crate::sources::file::url("postgresql-security") {
        return Ok(Response::ok(
            "<table><tr><td><a>CVE-2026-1</a></td><td>18</td><td>18.6</td><td>core server<br>8.8<br>AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td><td>Overflow</td></tr></table>",
        ));
    }
    if u.starts_with("https://vulnerability.circl.lu/api/browse/") {
        return ok(json!(["server"]));
    }
    if u.starts_with("https://vulnerability.circl.lu/api/vulnerability/search/") {
        return ok(json!({"total_count": 0, "page_size": 100, "results": {"cvelistv5": []}}));
    }
    if u.starts_with("https://open-vsx.org/api/") {
        return ok(json!({"version": "2.0.0"}));
    }
    if u == crate::sources::file::url("vscode-marketplace") {
        return ok(json!({"results": [{"extensions": []}]}));
    }
    if u.starts_with(crate::sources::file::url("cve-org")) {
        return Ok(Response::not_found());
    }
    feeds(r)
}

/// A cache where a scan found all of them, each answer two weeks old.
fn scanned(c: &Cache) {
    let old = (crate::utils::os::now() - 14.0 * 86_400.0).to_string();
    for key in ["rules:yara-forge", "iocs:feodo", "cve_records_products:acme_at", "cve_records:acme\u{1f}server_at"] {
        c.set(key, &old).unwrap();
    }
    c.set("cve_records_products:acme", "[\"server\"]").unwrap();
    c.set("cve_records:acme\u{1f}server", "{\"complete\": true, \"records\": []}").unwrap();
    for key in ["postgres", "openvsx:a.b,c.d", "marketplace:ms.python"] {
        c.conn
            .execute("INSERT INTO runs VALUES (?, '', ?, '{}')", rusqlite::params![key, old.parse::<f64>().unwrap()])
            .unwrap();
    }
    c.conn.execute("INSERT INTO cve_scores VALUES ('CVE-2026-9', NULL, '', '', '', 0)", []).unwrap();
}

const FOUND: &[&str] = &[
    "YARA Forge rules",
    "signature-base IOCs",
    "Feodo Tracker",
    "PostgreSQL security",
    "CVE records",
    "Open VSX",
    "VS Code Marketplace",
    "CVE scores",
];

#[test]
fn a_sync_refreshes_what_a_scan_found_and_only_that() {
    let (_d, c) = cache();
    let got = run(&c, &Fake::new(feeds), false, &|_| {}).unwrap();
    for name in FOUND {
        let all: Vec<&String> = got.refreshed.iter().chain(got.failed.iter().map(|(n, _)| n)).collect();
        assert!(!all.iter().any(|n| n == name), "{name} was never used: {got:?}");
    }
    scanned(&c);
    let net = Fake::new(found);
    let got = run(&c, &net, false, &|_| {}).unwrap();
    for name in FOUND {
        assert!(got.refreshed.contains(&name.to_string()), "{name}: {got:?}");
    }
    let asked: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
    for want in [
        ASSET,
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "https://www.postgresql.org/support/security/",
        "https://vulnerability.circl.lu/api/browse/acme",
        "https://vulnerability.circl.lu/api/vulnerability/search/acme/server?page=1&per_page=100",
        "https://open-vsx.org/api/a/b/latest",
        "https://open-vsx.org/api/c/d/latest",
        "https://api.osv.dev/v1/vulns/CVE-2026-9",
        "https://cveawg.mitre.org/api/cve/CVE-2026-9",
    ] {
        assert!(asked.iter().any(|u| u == want), "{want} not asked: {asked:#?}");
    }
    let rules = crate::checks::malware::yara::rules_dir(&c);
    assert!(std::fs::read_to_string(rules.join("yara-forge-full.yar")).unwrap().contains("rule synced"));
    let compiled = std::fs::read_dir(&rules).unwrap().flatten().filter(|e| {
        let n = e.file_name().to_string_lossy().into_owned();
        n.starts_with("compiled-") && n.ends_with(".bundle")
    });
    assert_eq!(compiled.count(), 1, "compiled for the next scan");
    assert!(rules.join("iocs/feodo-ipblocklist.json").is_file(), "into the directory the scan reads");
    assert_eq!(crate::sources::releases::postgres(&c, &Fake::offline(), true).unwrap()[0].cve, "CVE-2026-1");
    let latest = extensions::latest_extensions(&c, &Fake::offline(), &["c.d".into(), "a.b".into()], true, true);
    assert_eq!(latest.unwrap()["a.b"], "2.0.0", "the same memo the scan reads");
    // Fresh now: nothing is asked again.
    let again = Fake::new(found);
    run(&c, &again, false, &|_| {}).unwrap();
    let urls: Vec<String> = again.requests().iter().map(|r| r.url.clone()).collect();
    assert!(!urls.iter().any(|u| u.contains("circl.lu") || u.contains("open-vsx") || u == ASSET), "{urls:#?}");
}

#[test]
fn a_source_a_scan_found_that_fails_is_named() {
    let (_d, c) = cache();
    scanned(&c);
    let down = Fake::new(|r| {
        let u = r.url.as_str();
        let theirs = [
            "https://api.github.com/repos/YARAHQ/",
            "https://api.github.com/repos/Neo23x0/",
            "https://feodotracker.abuse.ch/",
            "https://www.postgresql.org/",
            "https://vulnerability.circl.lu/",
            "https://open-vsx.org/",
            "https://marketplace.visualstudio.com/",
            "https://cveawg.mitre.org/",
        ];
        if theirs.iter().any(|h| u.starts_with(h)) {
            return Ok(Response { status: 503, body: Vec::new(), etag: None });
        }
        found(r)
    });
    let got = run(&c, &down, false, &|_| {}).unwrap();
    for name in FOUND {
        assert!(!got.refreshed.contains(&name.to_string()), "{name}: {got:?}");
        let why = got.failed.iter().find(|(n, _)| n == name).map(|(_, w)| w.as_str());
        assert!(why.is_some_and(|w| w.contains("HTTP 503")), "{name}: {why:?}");
    }
    // What was kept stays for the scan.
    assert_eq!(crate::sources::releases::postgres(&c, &Fake::offline(), true).unwrap(), Vec::new());
    assert!(crate::sources::cve_records::records(&c, "acme", "server").unwrap().is_some());
}

#[test]
fn a_sync_lists_the_tags_of_repos_asked_about_before() {
    let (d, c) = cache();
    let repo = d.path().join("upstream");
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
            ])
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    std::fs::create_dir_all(&repo).unwrap();
    git(&["init", "-q"]);
    git(&["commit", "-q", "--allow-empty", "-m", "a"]);
    git(&["tag", "v1.2.3"]);
    let url = repo.to_string_lossy().into_owned();
    let gone = d.path().join("gone").to_string_lossy().into_owned();
    let old = crate::utils::os::now() - 14.0 * 86_400.0;
    for r in [&url, &gone] {
        c.conn
            .execute("INSERT INTO runs VALUES (?, '', ?, '[]')", rusqlite::params![format!("tags:{r}"), old])
            .unwrap();
    }
    let got = run(&c, &Fake::new(feeds), false, &|_| {}).unwrap();
    assert_eq!(osv::tags(&c, &url, true).unwrap(), ["v1.2.3"]);
    let why = got.failed.iter().find(|(n, _)| n == "Git release tags").map(|(_, w)| w.as_str());
    assert!(why.is_some_and(|w| w.contains(&gone) && !w.contains(&format!("{url}:"))), "{got:?}");
    c.conn.execute("DELETE FROM runs WHERE source = ?", [format!("tags:{gone}")]).unwrap();
    let got = run(&c, &Fake::new(feeds), false, &|_| {}).unwrap();
    assert!(got.refreshed.iter().any(|n| n == "Git release tags"), "{got:?}");
}
