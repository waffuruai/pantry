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
    assert_eq!((zoom.component.as_str(), zoom.vuln_id.as_str(), zoom.fixed.as_str()), ("zoom.us", "OUTDATED", "6.2.0"));
    assert_eq!((zoom.fix_cmd.as_str(), zoom.fix_auto), ("Update zoom.us from its vendor (or its own updater)", false));
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
        if r.url == crate::sources::file::url("homebrew-casks") {
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
        if r.url == crate::sources::file::url("homebrew-casks") {
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
