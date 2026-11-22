//! `wpantry sync`: refresh what the cache already knows, so a later
//! `scan --offline` answers from it. Nothing is inventoried here:
//!
//! - the feeds: CISA KEV, EPSS, the malicious-package index, the cask
//!   catalog, browser versions, VS Code's extension lists, the latest wpantry;
//! - once a malware scan has fetched them, YARA Forge's rules and the
//!   signature-base and Feodo Tracker indicator lists;
//! - Elastic's rules, once turned on, and the rules and lists of your
//!   sources file you said yes to (a rules file put in the rules directory
//!   by hand is named: nothing can update it);
//! - once PostgreSQL was found, its security page;
//! - what was asked before: end-of-life dates for every product on record,
//!   OSV for every package version, CIRCL's CVE records for every vendor and
//!   product, the latest versions of the extensions last checked (Open VSX,
//!   the Marketplace), upstream repos' release tags (`git ls-remote`), and
//!   the CVE scores (OSV, CVE.org).
//!
//! A source turned off in `sources.toml` is skipped, and nothing that needs
//! consent (breaches, hash lookups) is asked. A scheduled run does this,
//! then a check.

use crate::checks::malware::yara;
use crate::component::Status;
use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::endoflife;
use crate::sources::extensions;
use crate::sources::file::active;
use crate::sources::kev;
use crate::sources::malicious_packages;
use crate::sources::osv;
use crate::sources::releases;
use crate::sources::{cve_records, cve_scores, indicator_lists};
use crate::utils::net::{Net, Request, Response};
use std::sync::Mutex;

/// What a sync refreshed and what it couldn't.
#[derive(Debug, Default)]
pub struct Synced {
    pub refreshed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Package versions re-asked of OSV.
    pub packages: usize,
    /// Rules files put in the rules directory by hand: not kept up to date.
    pub hand_added: Vec<std::path::PathBuf>,
}

fn note(name: &str, r: Result<()>, out: &mut Synced) {
    match r {
        Ok(()) => out.refreshed.push(name.to_string()),
        Err(e) if e.is_source() => out.failed.push((name.to_string(), e.to_string())),
        Err(e) => out.failed.push((name.to_string(), format!("internal: {e}"))),
    }
}

/// A [`Net`] that keeps its first failed request.
struct Watch<'a> {
    net: &'a dyn Net,
    failed: Mutex<Option<String>>,
}

impl Net for Watch<'_> {
    fn send(&self, req: &Request) -> Result<Response> {
        let r = self.net.send(req);
        let why = match &r {
            Err(e) => Some(e.to_string()),
            Ok(resp) if !matches!(resp.status, 200..=299 | 304 | 404) => {
                Some(format!("{}: HTTP {}", req.url, resp.status))
            }
            Ok(_) => None,
        };
        if let Some(why) = why {
            self.failed.lock().expect("lock").get_or_insert(why);
        }
        r
    }
}

/// `f` over `net`, failed by its first unreachable request: a memo or a
/// prefetch keeps its last copy and carries on, but the source wasn't
/// refreshed.
fn watched(net: &dyn Net, f: impl FnOnce(&dyn Net) -> Result<()>) -> Result<()> {
    let w = Watch { net, failed: Mutex::new(None) };
    f(&w)?;
    match w.failed.into_inner().expect("lock") {
        Some(why) => Err(Error::Offline(why)),
        None => Ok(()),
    }
}

pub fn run(cache: &Cache, net: &dyn Net, refresh: bool, status: Status) -> Result<Synced> {
    let mut out = Synced::default();
    type Feed<'a> = Box<dyn FnOnce() -> Result<()> + 'a>;
    let mut feeds: Vec<(&str, &str, &str, Feed)> = vec![
        (
            "cisa-kev",
            "CISA KEV",
            "Fetching CISA's known-exploited list",
            Box::new(|| kev::kev(cache, net, false).map(|_| ())),
        ),
        (
            "epss",
            "EPSS",
            "Fetching EPSS's exploit predictions",
            Box::new(|| crate::sources::epss::refresh(cache, net, false).map(|_| ())),
        ),
        (
            "openssf-malicious-packages",
            "OpenSSF malicious packages",
            "Fetching the malicious-package index",
            Box::new(|| malicious_packages::sync(cache, false).map(|_| ())),
        ),
    ];
    if cfg!(target_os = "macos") {
        feeds.push((
            "homebrew-casks",
            "Homebrew casks",
            "Fetching the Homebrew cask catalog",
            Box::new(|| releases::casks(cache, net, false).map(|_| ())),
        ));
    }
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let platform = if cfg!(target_os = "macos") { "mac" } else { "linux" };
        feeds.push((
            "chrome-releases",
            "Chrome releases",
            "Fetching Chrome's release list",
            Box::new(move || releases::chrome(cache, net, platform, false).map(|_| ())),
        ));
    }
    feeds.extend([
        (
            "firefox-releases",
            "Firefox releases",
            "Fetching Firefox's release list",
            Box::new(|| releases::firefox(cache, net, false).map(|_| ())) as Feed,
        ),
        (
            "vscode-extension-lists",
            "VS Code extension lists",
            "Fetching VS Code's extension lists",
            Box::new(|| extensions::vscode_lists(cache, net, false).map(|_| ())),
        ),
        (
            "github-releases",
            "wpantry releases",
            "Checking the latest wpantry release",
            Box::new(|| releases::github_latest(cache, net, "waffuruai/pantry", false).map(|_| ())),
        ),
    ]);
    for (id, name, doing, f) in feeds {
        if active(id) {
            status(doing);
            note(name, f(), &mut out);
        }
    }
    malware(cache, net, refresh, status, &mut out)?;
    if active("postgresql-security") && releases::postgres_fetched(cache)? {
        status("Fetching PostgreSQL's security page");
        note("PostgreSQL security", watched(net, |n| releases::postgres(cache, n, false).map(|_| ())), &mut out);
    }
    let products = cache.eol_products()?;
    if active("endoflife") && !products.is_empty() {
        status(&format!("Fetching end-of-life dates for {} products", products.len()));
        let mut missed = Vec::new();
        for p in &products {
            match endoflife::eol(cache, net, p, "", false) {
                Ok(_) => {}
                Err(e) if e.is_source() => missed.push(format!("{p}: {e}")),
                Err(e) => return Err(e),
            }
        }
        let r = if missed.is_empty() { Ok(()) } else { Err(Error::Offline(missed.join("; "))) };
        note("endoflife.date", r, &mut out);
    }
    let items: Vec<osv::Item> = cache.queried()?;
    if active("osv") && !items.is_empty() {
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
    asked(cache, net, status, &mut out)?;
    cache.commit()?;
    Ok(out)
}

/// The malware rules and indicator lists, into the directories the scan
/// reads, once a malware scan has fetched them.
fn malware(cache: &Cache, net: &dyn Net, refresh: bool, status: Status, out: &mut Synced) -> Result<()> {
    if active("yara-forge-full") && yara::fetched(cache)? {
        status("Fetching YARA rules (YARA Forge)");
        note("YARA Forge rules", yara::update(cache, net, refresh).map(|_| ()), out);
    }
    let lists: Vec<(&str, &str)> = [("signature-base", "signature-base IOCs"), ("feodo", "Feodo Tracker")]
        .into_iter()
        .filter(|(id, _)| active(id))
        .collect();
    if active(yara::ELASTIC) {
        status("Fetching Elastic's YARA rules");
    }
    match yara::update_elastic(cache, net, refresh) {
        Ok(None) => {}
        r => note("Elastic's YARA rules", r.map(|_| ()), out),
    }
    yours(cache, net, status, out);
    out.hand_added = yara::hand_added(cache);
    if !lists.is_empty() && indicator_lists::fetched(cache)? {
        status("Fetching the indicator lists");
        let dir = yara::rules_dir(cache).join("iocs");
        let failed = indicator_lists::update(cache, net, &dir, refresh);
        for (id, name) in lists {
            let mine: Vec<String> = failed
                .iter()
                .filter(|(label, _)| indicator_lists::source_of(label) == id)
                .map(|(_, e)| e.to_string())
                .collect();
            note(name, if mine.is_empty() { Ok(()) } else { Err(Error::Offline(mine.join("; "))) }, out);
        }
    }
    Ok(())
}

/// The rules and lists of the user's sources file in use that they said
/// yes to (none is asked here): fetched as a scan fetches them.
fn yours(cache: &Cache, net: &dyn Net, status: Status, out: &mut Synced) {
    let effective = crate::sources::file::effective();
    let declared: Vec<crate::sources::file::Source> =
        effective.sources.iter().filter(|s| effective.user.contains(&s.id)).cloned().collect();
    yours_of(cache, net, &declared, &active, status, out);
}

/// [`yours`], for the user's sources `declared`, those `on` says are used.
fn yours_of(
    cache: &Cache,
    net: &dyn Net,
    declared: &[crate::sources::file::Source],
    on: &dyn Fn(&str) -> bool,
    status: Status,
    out: &mut Synced,
) {
    use crate::sources::{file, user};
    let mut mine = Vec::new();
    for s in declared.iter().filter(|s| on(&s.id)) {
        match user::consent(cache, None, s) {
            Ok(Ok(())) => {
                if let Some(h) = s.host() {
                    crate::utils::net::allow(&h);
                }
                mine.push(s.clone());
            }
            Ok(Err(why)) => out.failed.push((format!("the source {} (your sources file)", s.id), why)),
            Err(e) => out.failed.push((format!("the source {} (your sources file)", s.id), e.to_string())),
        }
    }
    let files: Vec<&file::Source> = mine.iter().filter(|s| user::is_file(s)).collect();
    if files.is_empty() {
        return;
    }
    status("Fetching the rules and lists of your sources file");
    let dir = yara::rules_dir(cache);
    let failed = user::fetch_files(cache, net, &dir, &mine, declared, false);
    for s in files {
        let name = format!("the source {} (your sources file)", s.id);
        match failed.iter().find(|(id, _)| *id == s.id) {
            Some((_, why)) => out.failed.push((name, why.clone())),
            None => out.refreshed.push(name),
        }
    }
}

/// What scans asked about before: CIRCL's CVE records, the latest versions
/// of the extensions last checked, upstream repos' release tags, and the
/// CVE scores.
fn asked(cache: &Cache, net: &dyn Net, status: Status, out: &mut Synced) -> Result<()> {
    let (vendors, pairs) = cve_records::on_record(cache)?;
    if active(cve_records::ID) && !(vendors.is_empty() && pairs.is_empty()) {
        status(&format!("Asking CVE records about {} vendors and {} products", vendors.len(), pairs.len()));
        let r = watched(net, |n| {
            cve_records::prefetch_products(cache, n, &vendors, false)?;
            cve_records::prefetch_records(cache, n, &pairs, false)
        });
        note("CVE records", r, out);
    }
    for (id, openvsx, name) in [("open-vsx", true, "Open VSX"), ("vscode-marketplace", false, "VS Code Marketplace")] {
        let ids = extensions::on_record(cache, openvsx)?;
        if active(id) && !ids.is_empty() {
            status(&format!("Fetching the latest versions of {} extensions ({name})", ids.len()));
            let r = watched(net, |n| extensions::latest_extensions(cache, n, &ids, openvsx, false).map(|_| ()));
            note(name, r, out);
        }
    }
    let repos = osv::tagged_repos(cache)?;
    if active("osv-git-tags") && !repos.is_empty() {
        status(&format!("Listing the release tags of {} repos", repos.len()));
        let mut missed = Vec::new();
        for r in &repos {
            match osv::refresh_tags(cache, r) {
                Ok(()) => {}
                Err(e) if e.is_source() => missed.push(e.to_string()),
                Err(e) => return Err(e),
            }
        }
        note("Git release tags", if missed.is_empty() { Ok(()) } else { Err(Error::Offline(missed.join("; "))) }, out);
    }
    let cves = cve_scores::on_record(cache)?;
    if (active("osv") || active("cve-org")) && !cves.is_empty() {
        status(&format!("Asking for the scores of {} CVEs", cves.len()));
        note("CVE scores", watched(net, |n| cve_scores::fill(cache, n, false, &cves)), out);
    }
    Ok(())
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
