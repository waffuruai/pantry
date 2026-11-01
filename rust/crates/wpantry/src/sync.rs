//! `wpantry sync`: refresh what the cache already knows, so a later
//! `check --offline` answers from it. Nothing is inventoried here: the
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
