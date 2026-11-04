//! `wpantry sync`: refresh what the cache already knows, so a later
//! `scan --offline` answers from it. Nothing is inventoried here: the
//! feeds (CISA KEV, the cask catalog, browser versions, the malicious
//! package index, the latest wpantry), the end-of-life pages of every
//! product on record, and OSV's answers for every package version that
//! has been asked about before. A scheduled run does this, then a check.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::net::Net;
use crate::system::Status;
use crate::{feeds, malicious, osv};

/// What a sync refreshed and what it couldn't.
#[derive(Debug, Default)]
pub struct Synced {
    pub refreshed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Package versions re-asked of OSV.
    pub packages: usize,
}

pub fn run(cache: &Cache, net: &dyn Net, refresh: bool, status: Status) -> Result<Synced> {
    let mut out = Synced::default();
    let note = |name: &str, r: Result<()>, out: &mut Synced| match r {
        Ok(()) => out.refreshed.push(name.to_string()),
        Err(e) if e.is_source() => out.failed.push((name.to_string(), e.to_string())),
        Err(e) => out.failed.push((name.to_string(), format!("internal: {e}"))),
    };
    status("Fetching CISA's known-exploited list");
    note("CISA KEV", feeds::kev(cache, net, false).map(|_| ()), &mut out);
    status("Fetching the malicious-package index");
    note("OpenSSF malicious packages", malicious::sync(cache, false).map(|_| ()), &mut out);
    if cfg!(target_os = "macos") {
        status("Fetching the Homebrew cask catalog");
        note("Homebrew casks", feeds::casks(cache, net, false).map(|_| ()), &mut out);
        status("Fetching Chrome's release list");
        note("Chrome releases", feeds::chrome(cache, net, "mac", false).map(|_| ()), &mut out);
    }
    status("Fetching Firefox's release list");
    note("Firefox releases", feeds::firefox(cache, net, false).map(|_| ()), &mut out);
    status("Fetching VS Code's extension lists");
    note("VS Code extension lists", feeds::vscode_lists(cache, net, false).map(|_| ()), &mut out);
    status("Checking the latest wpantry release");
    note("wpantry releases", feeds::github_latest(cache, net, "waffuruai/pantry", false).map(|_| ()), &mut out);
    let products = cache.eol_products()?;
    if !products.is_empty() {
        status(&format!("Fetching end-of-life dates for {} products", products.len()));
        let mut missed = Vec::new();
        for p in &products {
            match feeds::eol(cache, net, p, "", false) {
                Ok(_) => {}
                Err(e) if e.is_source() => missed.push(format!("{p}: {e}")),
                Err(e) => return Err(e),
            }
        }
        let r = if missed.is_empty() { Ok(()) } else { Err(Error::Offline(missed.join("; "))) };
        note("endoflife.date", r, &mut out);
    }
    let items: Vec<osv::Item> = cache.queried()?;
    if !items.is_empty() {
        status(&format!("Asking OSV about {} package versions", items.len()));
        let r = osv::lookup(cache, net, &items, refresh, false, &|_| {}, status).map(|a| {
            out.packages = items.len();
            if !a.gaps.is_empty() {
                return Err(Error::Offline(a.gaps.join("; ")));
            }
            Ok(())
        });
        note("OSV", r.and_then(|r| r), &mut out);
    }
    cache.commit()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Fake, Request, Response};
    use serde_json::json;

    fn cache() -> (crate::system::TempDir, Cache) {
        let d = crate::system::TempDir::new("sync").unwrap();
        let db = d.path().join("w.db");
        let c = Cache::open(Some(&db)).unwrap();
        // The malicious index fetches from a clone beside the cache: a local one here.
        crate::malicious::seed_clone(&db, &["osv/malicious/npm/evil/MAL-1.json"]);
        (d, c)
    }

    /// Every feed answers, except GitHub (down) and python's end-of-life
    /// page (gone, so nothing is cached for it).
    fn feeds(r: &Request) -> Result<Response> {
        let u = r.url.as_str();
        let ok = |v: serde_json::Value| Ok(Response::ok(v.to_string()));
        if u == feeds::KEV_URL {
            return ok(json!({"vulnerabilities": [{"cveID": "CVE-2026-1"}]}));
        }
        if u == feeds::CASKS_URL {
            return ok(json!([{"token": "firefox", "version": "145.0", "artifacts": [{"app": ["Firefox.app"]}]}]));
        }
        if u.starts_with("https://versionhistory.googleapis.com/") {
            return ok(json!({"releases": [{"version": "142.0.1"}]}));
        }
        if u.ends_with("firefox_versions.json") {
            return ok(json!({"LATEST_FIREFOX_VERSION": "145.0"}));
        }
        if u.starts_with(feeds::FIREFOX) {
            return ok(json!({}));
        }
        if u == feeds::VSCODE_LISTS {
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
        feeds::eol(&c, &net, "nodejs", "24", false).unwrap();
        c.conn.execute("INSERT INTO eol VALUES ('python', '3.9', 'true', '3.9.9')", []).unwrap();
        c.put_query("npm", "left-pad", "1.0.0", &[]).unwrap();
        let seen = std::sync::Mutex::new(Vec::new());
        let got = run(&c, &net, true, &|s| seen.lock().unwrap().push(s.to_string())).unwrap();
        let mut want =
            vec!["CISA KEV", "OpenSSF malicious packages", "Firefox releases", "VS Code extension lists", "OSV"];
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
            if r.url == feeds::KEV_URL {
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
}
