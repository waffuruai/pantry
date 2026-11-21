//! Apps and browsers behind their latest release: apps against their
//! Homebrew cask and the Electron they bundle, browsers against their
//! vendor's release feed. On Linux only browsers are read (`browsers`):
//! Chrome and Chromium against Chrome's Linux feed, Firefox against
//! Mozilla's.

use crate::checks::ecosystems::versions;
use crate::checks::machine::GRACE;
use crate::checks::machine::apps as apps_mod;
use crate::checks::machine::browsers;
use crate::checks::machine::exploited::{Gap, escalate, superseded};
use crate::checks::{Scan, display_id, is_kev, is_malicious};
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv::Item;
use crate::sources::{osv, releases};
use crate::utils::homebrew;
use crate::utils::os::now;
use serde_json::Value;
use std::collections::BTreeMap;

// Apps and browsers -----------------------------------------------------------

pub fn apps(scan: &mut Scan) -> Result<()> {
    scan.status("Reading installed apps");
    if browsers::LINUX {
        return linux_browsers(scan, browsers::browsers());
    }
    apps_found(scan, apps_mod::apps(), homebrew::brew_casks)
}

/// The browser checks over what `browsers` found on Linux. All are
/// counted; a distro's own build is left to the OS update check (extra
/// `owner` = `os`), and Edge and Brave are not judged: no release feed is
/// read for them here.
///
/// TODO: Edge's and Brave's Linux release feeds (Brave's cask numbering
/// differs from its Linux builds).
fn linux_browsers(scan: &mut Scan, found: Vec<Component>) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    scan.count("browsers", found.len() as i64);
    for a in found.iter().filter(|a| a.extra.get("owner").is_none_or(|o| o != "os")) {
        if let "chrome" | "chromium" | "firefox" = a.extra.get("browser").map(String::as_str).unwrap_or("") {
            browser(scan, a, "linux", false, "")?;
        }
    }
    Ok(())
}

/// The app checks over the bundles found; `casks` lists what Homebrew
/// installed, read only when there are apps to check.
fn apps_found(
    scan: &mut Scan,
    mut found: Vec<Component>,
    casks: impl FnOnce() -> BTreeMap<String, String>,
) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    scan.count("apps", found.len() as i64);
    scan.status("Fetching the Homebrew cask catalog");
    let r = releases::casks(&scan.cache, scan.net, scan.opts.offline);
    let catalog = scan.guard("latest app versions (Homebrew cask catalog)", r, BTreeMap::new())?;
    let casks = casks();
    let items: Vec<Item> = found
        .iter()
        .filter_map(|a| a.extra.get("electron").map(|e| ("npm".to_string(), "electron".to_string(), e.clone())))
        .collect();
    let electron = scan.lookup(&items, "apps' bundled Electron against OSV")?;
    for a in &mut found {
        let (token, latest) =
            catalog.get(a.extra.get("bundle").map(String::as_str).unwrap_or("")).cloned().unwrap_or_default();
        (a.fix, a.auto) = if !token.is_empty() && casks.contains_key(&token) {
            (format!("brew upgrade --cask {token}"), true)
        } else {
            (format!("Update {} from its vendor (or its own updater)", a.name), false)
        };
        let behind = !latest.is_empty() && !versions::same_or_newer(&a.version, &latest);
        if a.kind == "browser" {
            browser(scan, a, "mac", behind, &latest)?;
            continue;
        }
        if let Some(ev) = a.extra.get("electron").cloned() {
            let recs = electron.get(&("npm".to_string(), "electron".to_string(), ev)).cloned().unwrap_or_default();
            if electron_finding(scan, a, &recs, behind, &latest) {
                continue;
            }
        }
        if behind {
            outdated(scan, a, &latest);
        }
    }
    Ok(())
}

/// Findings for an app's bundled Electron; false when it has none.
fn electron_finding(scan: &mut Scan, a: &Component, recs: &[Value], behind: bool, latest: &str) -> bool {
    let ev = a.extra.get("electron").cloned().unwrap_or_default();
    let bad: Vec<&Value> = recs
        .iter()
        .filter(|r| is_malicious(r) || !osv::fixed_versions(r, "npm", "electron", None).is_empty())
        .collect();
    if bad.is_empty() {
        return false;
    }
    let mut ids: Vec<String> = bad.iter().map(|r| display_id(r)).collect();
    ids.sort();
    ids.dedup();
    let kev = bad.iter().any(|r| is_kev(r, &scan.kev));
    let f = if behind {
        Finding {
            vuln_id: ids[0].clone(),
            status: "fail".into(),
            fixed: latest.into(),
            kev,
            note: format!("bundles Electron {ev} ({} fixed advisories); {latest} is out", ids.len()),
            fix_cmd: a.fix.clone(),
            fix_auto: a.auto,
            ..Finding::of(a)
        }
    } else {
        Finding {
            vuln_id: ids[0].clone(),
            status: "warn".into(),
            kev,
            note: format!("bundles Electron {ev} ({} fixed advisories); no newer app release yet", ids.len()),
            fix_cmd: format!("Ask the {} vendor to ship a newer Electron", a.name),
            ..Finding::of(a)
        }
    };
    scan.add(f);
    true
}

/// A browser against its vendor's feed; `platform` is the Chrome feed's
/// ("mac" or "linux"). Chromium shares Chrome's version numbers, so on
/// Linux it is held to Chrome's feed; on macOS it has only its cask.
fn browser(scan: &mut Scan, a: &Component, platform: &str, behind: bool, latest: &str) -> Result<()> {
    match a.extra.get("browser").map(String::as_str).unwrap_or("") {
        id if id == "chrome" || (id == "chromium" && platform == "linux") => {
            scan.status("Fetching Chrome's release feed");
            let r = releases::chrome(&scan.cache, scan.net, platform, scan.opts.offline);
            let releases = scan.guard("Chrome (Google's release feed)", r, Vec::new())?;
            let since = superseded(&a.version, &releases);
            let newest = releases
                .into_iter()
                .filter(|(v, _)| versions::lt(&a.version, v))
                .max_by(|x, y| versions::cmp(&x.0, &y.0));
            let (target, start) = newest.unwrap_or_default();
            browser_finding(scan, a, (&target, start), since, "Chrome menu → About Google Chrome, then Relaunch");
        }
        "firefox" => {
            scan.status("Fetching Firefox's release feed");
            let r = releases::firefox(&scan.cache, scan.net, scan.opts.offline).map(Some);
            if let Some(ff) = scan.guard("Firefox (Mozilla's release feed)", r, None)? {
                let major = a.version.split('.').next().unwrap_or("");
                let target =
                    ff.esr.iter().find(|e| e.split('.').next() == Some(major)).cloned().unwrap_or(ff.latest.clone());
                let start = ff.dates.get(&target).copied().unwrap_or(0.0);
                // On an ESR line only that line's releases supersede it: a
                // newer major can ship before the line's next patch.
                let esr = ff.esr.contains(&target);
                let dated: Vec<(String, f64)> =
                    ff.dates.into_iter().filter(|(v, _)| !esr || v.split('.').next() == Some(major)).collect();
                let since = superseded(&a.version, &dated);
                let how = "Firefox menu → About Firefox, then Restart to Update";
                browser_finding(scan, a, (&target, start), since, how);
            }
        }
        _ if behind => outdated(scan, a, latest),
        _ => {}
    }
    Ok(())
}

/// An app or browser behind its cask's latest: a warning, naming the
/// exploited CVEs listed in the last months (the cask catalog has no
/// release dates, so it can't fail on them).
fn outdated(scan: &mut Scan, a: &Component, latest: &str) {
    let mut f = Finding {
        vuln_id: "OUTDATED".into(),
        status: "warn".into(),
        fixed: latest.into(),
        note: format!("latest release is {latest}"),
        fix_cmd: a.fix.clone(),
        fix_auto: a.auto,
        ..Finding::of(a)
    };
    escalate(&mut f, a, &scan.kev_entries, Gap::default());
    scan.add(f);
}

/// A browser behind `target` (released at `start`, an epoch): fails once
/// the release is past the grace period, or once the first newer release
/// (`since`, when this version was superseded) is, when KEV lists
/// exploited CVEs for it since then.
fn browser_finding(scan: &mut Scan, a: &Component, (target, start): (&str, f64), since: Option<f64>, how: &str) {
    if !target.is_empty() && versions::lt(&a.version, target) {
        let old = start > 0.0 && start < now() - GRACE;
        let mut f = Finding {
            vuln_id: "BROWSER".into(),
            status: if old { "fail" } else { "warn" }.into(),
            fixed: target.into(),
            note: format!("{} {target} is out; its releases carry security fixes", a.name),
            // Linux browsers carry their source's fix: the menu path is macOS's.
            fix_cmd: if a.auto || a.extra.contains_key("install") { a.fix.clone() } else { how.into() },
            fix_auto: a.auto,
            ..Finding::of(a)
        };
        escalate(&mut f, a, &scan.kev_entries, Gap { superseded: since, ..Gap::default() });
        scan.add(f);
    }
}

#[cfg(test)]
#[path = "app_updates_tests.rs"]
mod tests;
