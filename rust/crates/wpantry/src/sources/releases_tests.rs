use super::*;
use crate::sources::testing::cache;
use crate::utils::dates::epoch;
use crate::utils::net::{Fake, Response};
use serde_json::json;

// The test vector the Python implementation had (`Parsers.test_postgres_table`).
#[test]
fn postgres_table() {
    let page = "<table><tr><th>Reference</th></tr><tr><td><a>CVE-2026-19385</a> <a>Announcement</a></td><td>18, 17, 16</td><td>18.6, 17.11, 16.15</td><td>core server<br>8.8<br>AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td><td>Heap overflow <a>more details</a></td></tr><tr><td>client</td><td>legend row</td></tr></table>";
    let got = parse_postgres(page);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].majors, ["18", "17", "16"]);
    assert_eq!(got[0].fixed, ["18.6", "17.11", "16.15"]);
    assert_eq!((got[0].component.as_str(), got[0].score), ("core server", 8.8));
    assert_eq!(got[0].summary, "Heap overflow");
    assert_eq!(severity_from_score(8.8), "HIGH");
    assert_eq!(unescape_html("a &amp; b &#39;c&#x27; &bogus;"), "a & b 'c' &bogus;");
}

#[test]
fn unreachable_postgres_is_offline_but_stale_beats_nothing() {
    let (_d, c) = cache();
    assert!(matches!(postgres(&c, &Fake::offline(), true), Err(Error::Offline(_))));
    c.put_run("postgres", "", &serde_json::json!([{"cve": "CVE-1"}])).unwrap();
    assert_eq!(postgres(&c, &Fake::offline(), true).unwrap()[0].cve, "CVE-1");
}

#[test]
fn cask_catalog_maps_app_bundles_to_tokens() {
    let (_d, c) = cache();
    assert!(matches!(casks(&c, &Fake::offline(), true), Err(Error::Offline(_))));
    assert!(matches!(casks(&c, &Fake::new(|_| Ok(Response::ok("{}"))), false), Err(Error::Offline(_))));
    let body = json!([
        {"token": "firefox", "version": "145.0", "artifacts": [{"app": ["Firefox.app"]}, {"zap": []}]},
        {"token": "dup", "version": "1", "artifacts": [{"app": ["Firefox.app"]}]},
        {"token": "nover", "artifacts": [{"app": ["X.app"]}]},
        {"token": "rolling", "version": "latest", "artifacts": [{"app": ["Y.app"]}]},
        {"token": "num", "version": 7, "artifacts": [{"app": ["Num.app"]}]},
        {"token": "nul", "version": null},
        {"token": "comma", "version": "1.2,345", "artifacts": [{"app": ["Comma.app", "not-an-app"]}]}
    ]);
    c.set("casks_at", "0").unwrap();
    let net = Fake::new(move |_| Ok(Response::ok(body.to_string())));
    let got = casks(&c, &net, false).unwrap();
    let rows: Vec<(&str, &str, &str)> = got.iter().map(|(a, (t, v))| (a.as_str(), t.as_str(), v.as_str())).collect();
    assert_eq!(rows, [("Comma.app", "comma", "1.2"), ("Firefox.app", "firefox", "145.0"), ("Num.app", "num", "7")]);
    assert_eq!(casks(&c, &Fake::new(|_| panic!("fresh")), false).unwrap().len(), 3);
}

#[test]
fn chrome_releases_carry_their_serving_date() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        assert!(r.url.contains("/platforms/mac/"), "{}", r.url);
        Ok(Response::ok(
            json!({"releases": [{"version": "142.0.1", "serving": {"startTime": "2026-10-01T00:00:00Z"}}, {"version": "141.0.0"}]})
                .to_string(),
        ))
    });
    let got = chrome(&c, &net, "mac", false).unwrap();
    assert_eq!(got, [("142.0.1".to_string(), epoch("2026-10-01")), ("141.0.0".to_string(), 0.0)]);
    assert!(epoch("2026-10-01") > 0.0 && epoch("soon") == 0.0);
    let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
    assert!(chrome(&c, &gone, "linux", false).is_err(), "a feed that is gone is unchecked, not empty");
}

#[test]
fn firefox_feed_joins_versions_and_release_dates() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        Ok(Response::ok(
            match r.url.rsplit('/').next().unwrap_or("") {
                "firefox_versions.json" => json!({"LATEST_FIREFOX_VERSION": "145.0", "FIREFOX_ESR": "140.4.0esr",
                "FIREFOX_ESR_NEXT": "", "FIREFOX_ESR115": "115.30.0esr", "FIREFOX_NIGHTLY": "147.0a1"}),
                "firefox_history_major_releases.json" => json!({"145.0": "2026-10-14"}),
                _ => json!({"145.0.1": "2026-10-21", "odd": 3}),
            }
            .to_string(),
        ))
    });
    let f = firefox(&c, &net, false).unwrap();
    let mut esr = f.esr.clone();
    esr.sort();
    assert_eq!((f.latest.as_str(), esr), ("145.0", vec!["115.30.0".to_string(), "140.4.0".into()]));
    assert_eq!(f.dates.get("145.0.1"), Some(&epoch("2026-10-21")));
    assert_eq!(f.dates.get("odd"), Some(&0.0));
    assert_eq!(net.requests().len(), 3);
    let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
    let (_d2, c2) = cache();
    assert!(firefox(&c2, &gone, false).is_err(), "a feed that is gone is unchecked, not empty");
}

#[test]
fn latest_release_drops_the_v_and_needs_a_tag() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        assert_eq!(r.header("Accept"), Some("application/vnd.github+json"));
        Ok(Response::ok(
            match r.url.as_str() {
                "https://api.github.com/repos/a/v/releases/latest" => json!({"tag_name": "v1.2.3"}),
                "https://api.github.com/repos/a/plain/releases/latest" => json!({"tag_name": "release-1"}),
                "https://api.github.com/repos/a/bare/releases/latest" => json!({"tag_name": "v"}),
                _ => json!({}),
            }
            .to_string(),
        ))
    });
    assert_eq!(github_latest(&c, &net, "a/v", false).unwrap(), "1.2.3");
    assert_eq!(github_latest(&c, &net, "a/plain", false).unwrap(), "release-1");
    assert_eq!(github_latest(&c, &net, "a/bare", false).unwrap(), "v");
    assert!(matches!(github_latest(&c, &net, "a/none", false), Err(Error::Offline(_))));
}

#[test]
fn postgres_table_is_fetched_as_html() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        assert_eq!(r.header("Accept"), Some("text/html"));
        Ok(Response::ok("<tr><td>CVE-2026-1</td><td>18</td><td>18.1</td><td>core 7.5 AV:N</td><td>Oops</td></tr>"))
    });
    let got = postgres(&c, &net, false).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].cve.as_str(), got[0].score, got[0].vector.as_str()), ("CVE-2026-1", 7.5, "AV:N"));
    assert_eq!(severity_from_score(9.5), "CRITICAL");
    assert_eq!(severity_from_score(5.0), "MODERATE");
    assert_eq!(severity_from_score(0.5), "LOW");
    assert_eq!(severity_from_score(0.0), "");
}
