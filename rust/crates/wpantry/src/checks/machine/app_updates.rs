//! Apps and browsers behind their latest release: apps against their
//! Homebrew cask and the Electron they bundle, browsers against their
//! vendor's release feed.

use crate::checks::ecosystems::versions;
use crate::checks::machine::GRACE;
use crate::checks::machine::apps as apps_mod;
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
    apps_found(scan, apps_mod::apps(), homebrew::brew_casks)
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
            browser(scan, a, behind, &latest)?;
            continue;
        }
        if let Some(ev) = a.extra.get("electron").cloned() {
            let recs = electron.get(&("npm".to_string(), "electron".to_string(), ev)).cloned().unwrap_or_default();
            if electron_finding(scan, a, &recs, behind, &latest) {
                continue;
            }
        }
        if behind {
            scan.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: latest.clone(),
                note: format!("latest release is {latest}"),
                fix_cmd: a.fix.clone(),
                fix_auto: a.auto,
                ..Finding::of(a)
            });
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

fn browser(scan: &mut Scan, a: &Component, behind: bool, latest: &str) -> Result<()> {
    match a.extra.get("browser").map(String::as_str).unwrap_or("") {
        "chrome" => {
            scan.status("Fetching Chrome's release feed");
            let r = releases::chrome(&scan.cache, scan.net, "mac", scan.opts.offline);
            let releases = scan.guard("Chrome (Google's release feed)", r, Vec::new())?;
            let newest = releases
                .into_iter()
                .filter(|(v, _)| versions::lt(&a.version, v))
                .max_by(|x, y| versions::cmp(&x.0, &y.0));
            let (target, start) = newest.unwrap_or_default();
            browser_finding(scan, a, &target, start, "Chrome menu → About Google Chrome, then Relaunch");
        }
        "firefox" => {
            scan.status("Fetching Firefox's release feed");
            let r = releases::firefox(&scan.cache, scan.net, scan.opts.offline).map(Some);
            if let Some(ff) = scan.guard("Firefox (Mozilla's release feed)", r, None)? {
                let major = a.version.split('.').next().unwrap_or("");
                let target =
                    ff.esr.iter().find(|e| e.split('.').next() == Some(major)).cloned().unwrap_or(ff.latest.clone());
                let start = ff.dates.get(&target).copied().unwrap_or(0.0);
                browser_finding(scan, a, &target, start, "Firefox menu → About Firefox, then Restart to Update");
            }
        }
        _ if behind => scan.add(Finding {
            vuln_id: "OUTDATED".into(),
            status: "warn".into(),
            fixed: latest.into(),
            note: format!("latest release is {latest}"),
            fix_cmd: a.fix.clone(),
            fix_auto: a.auto,
            ..Finding::of(a)
        }),
        _ => {}
    }
    Ok(())
}

fn browser_finding(scan: &mut Scan, a: &Component, target: &str, start: f64, how: &str) {
    if !target.is_empty() && versions::lt(&a.version, target) {
        let old = start > 0.0 && start < now() - GRACE;
        scan.add(Finding {
            vuln_id: "BROWSER".into(),
            status: if old { "fail" } else { "warn" }.into(),
            fixed: target.into(),
            note: format!("{} {target} is out; its releases carry security fixes", a.name),
            fix_cmd: if a.auto { a.fix.clone() } else { how.into() },
            fix_auto: a.auto,
            ..Finding::of(a)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::machine::testing;
    use crate::error::Error;
    use crate::utils::net::Fake;

    #[test]
    fn apps_behind_their_cask_and_with_vulnerable_electron() {
        let d = crate::utils::temp::TempDir::new("apps").unwrap();
        let net = Fake::new(testing::app_net);
        let mut s = testing::scan(&net, &d);
        let found = vec![
            // Behind, with a fixed Electron advisory: fails, the cask upgrade is the fix.
            testing::app("Slack", "4.41.97", &[("electron", "33.4.11")]),
            // Up to date but its Electron has a fix: the vendor's turn.
            testing::app("Notion", "4.0.0", &[("electron", "34.0.0")]),
            // Electron advisory without a fix: not a finding; up to date.
            testing::app("Code", "1.95.0", &[("electron", "35.0.0")]),
            // Behind, no cask installed: update from the vendor.
            testing::app("zoom.us", "6.1.0", &[]),
            // A cask without a version ("latest") says nothing.
            testing::app("Unknown", "1.0", &[]),
        ];
        let casks: BTreeMap<String, String> = [("slack".to_string(), "4.41.97".to_string())].into();
        apps_found(&mut s, found, || casks).unwrap();
        assert_eq!(s.counts, [("apps".to_string(), 5)]);
        let slack = &s.findings[0];
        assert_eq!(
            (slack.component.as_str(), slack.vuln_id.as_str(), slack.status.as_str(), slack.fixed.as_str()),
            ("Slack", "CVE-2026-100", "fail", "4.41.100")
        );
        assert_eq!((slack.fix_cmd.as_str(), slack.fix_auto), ("brew upgrade --cask slack", true));
        assert_eq!(slack.note, "bundles Electron 33.4.11 (1 fixed advisories); 4.41.100 is out");
        let notion = &s.findings[1];
        assert_eq!(
            (notion.component.as_str(), notion.vuln_id.as_str(), notion.status.as_str()),
            ("Notion", "GHSA-e2", "warn")
        );
        assert_eq!(notion.fix_cmd, "Ask the Notion vendor to ship a newer Electron");
        let zoom = &s.findings[2];
        assert_eq!(
            (zoom.component.as_str(), zoom.vuln_id.as_str(), zoom.fixed.as_str()),
            ("zoom.us", "OUTDATED", "6.2.0")
        );
        assert_eq!(
            (zoom.fix_cmd.as_str(), zoom.fix_auto),
            ("Update zoom.us from its vendor (or its own updater)", false)
        );
        assert_eq!(s.findings.len(), 3, "{:?}", testing::kinds(&s));
    }

    #[test]
    fn browsers_follow_their_vendor_feeds() {
        let d = crate::utils::temp::TempDir::new("browsers").unwrap();
        let net = Fake::new(testing::app_net);
        let mut s = testing::scan(&net, &d);
        let found = vec![
            testing::app("Google Chrome", "129.0.6668.100", &[("browser", "chrome")]),
            testing::app("Firefox", "128.3.0", &[("browser", "firefox")]),
            testing::app("Brave Browser", "1.70.0", &[("browser", "brave")]),
            testing::app("Arc", "1.60.0", &[("browser", "arc")]),
        ];
        let casks: BTreeMap<String, String> = [("google-chrome".to_string(), "129.0.6668.100".to_string())].into();
        apps_found(&mut s, found, || casks).unwrap();
        // Chrome's fix has been out longer than the grace period: fail, by brew.
        let chrome = &s.findings[0];
        assert_eq!(
            (chrome.vuln_id.as_str(), chrome.status.as_str(), chrome.fixed.as_str()),
            ("BROWSER", "fail", "130.0.6723.117")
        );
        assert_eq!((chrome.fix_cmd.as_str(), chrome.fix_auto), ("brew upgrade --cask google-chrome", true));
        // Firefox ESR 128 moved to 128.5.0; its date is unknown, so a warning.
        let ff = &s.findings[1];
        assert_eq!((ff.vuln_id.as_str(), ff.status.as_str(), ff.fixed.as_str()), ("BROWSER", "warn", "128.5.0"));
        assert_eq!(ff.fix_cmd, "Firefox menu → About Firefox, then Restart to Update");
        assert_eq!(ff.note, "Firefox 128.5.0 is out; its releases carry security fixes");
        // Other browsers only compare with the cask catalog.
        let brave = &s.findings[2];
        assert_eq!(
            (brave.component.as_str(), brave.vuln_id.as_str(), brave.fixed.as_str()),
            ("Brave Browser", "OUTDATED", "1.71.0")
        );
        assert_eq!(s.findings.len(), 3, "{:?}", testing::kinds(&s));
    }

    #[test]
    fn browser_feeds_down_are_unchecked_and_no_apps_is_nothing() {
        let d = crate::utils::temp::TempDir::new("browsers").unwrap();
        let net = Fake::new(|r| {
            if r.url == releases::CASKS_URL {
                return Ok(crate::utils::net::Response::ok(testing::casks_body()));
            }
            Err(Error::Offline("down".into()))
        });
        let mut s = testing::scan(&net, &d);
        let found = vec![
            testing::app("Google Chrome", "129.0.6668.100", &[("browser", "chrome")]),
            testing::app("Firefox", "128.3.0", &[("browser", "firefox")]),
        ];
        apps_found(&mut s, found, BTreeMap::new).unwrap();
        testing::unchecked_note(&s, "Chrome (Google's release feed)");
        testing::unchecked_note(&s, "Firefox (Mozilla's release feed)");
        assert_eq!(s.findings.len(), 2, "{:?}", testing::kinds(&s));
        let mut s2 = testing::scan(&net, &d);
        apps_found(&mut s2, Vec::new(), || panic!("no apps, no casks")).unwrap();
        assert!(s2.findings.is_empty() && s2.counts.is_empty());
    }

    #[test]
    fn cask_catalog_down_still_checks_electron() {
        let d = crate::utils::temp::TempDir::new("casks").unwrap();
        let net = Fake::new(|r| {
            if r.url == releases::CASKS_URL {
                return Err(Error::Offline("down".into()));
            }
            testing::app_net(r)
        });
        let mut s = testing::scan(&net, &d);
        apps_found(&mut s, vec![testing::app("Slack", "4.41.97", &[("electron", "33.4.11")])], BTreeMap::new).unwrap();
        testing::unchecked_note(&s, "latest app versions (Homebrew cask catalog)");
        let slack = s.findings.iter().find(|f| f.component == "Slack").unwrap();
        assert_eq!(
            (slack.status.as_str(), slack.fix_cmd.as_str()),
            ("warn", "Ask the Slack vendor to ship a newer Electron")
        );
    }
}
