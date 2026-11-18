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

fn kev_entry(cve: &str, added: &str, vendor: &str, product: &str) -> crate::sources::kev::Entry {
    crate::sources::kev::Entry { cve: cve.into(), added: added.into(), vendor: vendor.into(), product: product.into() }
}

#[test]
fn exploited_cves_since_a_browser_was_superseded_fail_and_an_apps_are_named() {
    let d = crate::utils::temp::TempDir::new("exploited").unwrap();
    let net = Fake::new(testing::app_net);
    let mut s = testing::scan(&net, &d);
    let today = crate::utils::dates::iso(crate::utils::dates::today());
    let year = &today[..4];
    s.kev_entries = vec![
        // After Chrome 130 superseded 129 (2024-01-01): named.
        kev_entry("CVE-2024-0519", "2024-01-17", "Google", "Chromium V8"),
        // Firefox 128.3.0 was superseded on 2024-10-29: this one came before.
        kev_entry("CVE-2024-9680", "2024-10-15", "Mozilla", "Firefox"),
        // The cask catalog has no dates: the last 180 days count, and the
        // finding stays a warning (the install may have the fix).
        kev_entry(&format!("CVE-{year}-7"), &today, "Adobe", "Acrobat and Reader"),
        kev_entry(&format!("CVE-{year}-8"), &today, "Google", "Chromium V8"),
    ];
    let found = vec![
        testing::app("Google Chrome", "129.0.6668.100", &[("browser", "chrome")]),
        testing::app("Firefox", "128.3.0", &[("browser", "firefox")]),
        testing::app("Brave Browser", "1.70.9", &[("browser", "brave")]),
        testing::app("Adobe Acrobat Reader", "24.001.20000", &[("id", "com.adobe.Reader")]),
    ];
    apps_found(&mut s, found, BTreeMap::new).unwrap();
    let chrome = &s.findings[0];
    assert_eq!((chrome.vuln_id.as_str(), chrome.status.as_str(), chrome.kev), ("BROWSER", "fail", true));
    assert_eq!(chrome.fixed, "130.0.6723.117");
    assert_eq!(
        chrome.note,
        format!(
            "Google Chrome 130.0.6723.117 is out; its releases carry security fixes; CISA lists actively exploited \
             Chromium CVEs added since this version was superseded on 2024-01-01: CVE-{year}-8, CVE-2024-0519. \
             Pantry knows this version is behind, not that each CVE affects this exact build"
        )
    );
    assert_eq!(chrome.fix_cmd, "Chrome menu → About Google Chrome, then Relaunch");
    // The KEV entry predates the gap: the warning stays as it was.
    let ff = &s.findings[1];
    assert_eq!((ff.status.as_str(), ff.kev), ("warn", false));
    assert_eq!(ff.note, "Firefox 128.5.0 is out; its releases carry security fixes");
    // One patch behind its cask (1.71.0), with a recent V8 entry it may
    // already have fixed: Brave warns and names it, without `kev`.
    let brave = &s.findings[2];
    assert_eq!((brave.vuln_id.as_str(), brave.status.as_str(), brave.kev), ("OUTDATED", "warn", false));
    let tail = format!(
        ": CVE-{year}-8. Pantry doesn't know when this version was superseded, so it may already have their fixes"
    );
    assert!(brave.note.ends_with(&tail), "{}", brave.note);
    let reader = &s.findings[3];
    assert_eq!((reader.vuln_id.as_str(), reader.status.as_str(), reader.kev), ("OUTDATED", "warn", false));
    assert!(reader.note.starts_with("latest release is 25.001.20000; CISA lists actively exploited Acrobat and Reader CVEs added in the last 180 days: CVE-"), "{}", reader.note);
    assert_eq!(reader.fix_cmd, "Update Adobe Acrobat Reader from its vendor (or its own updater)");
    assert_eq!(s.findings.len(), 4, "{:?}", testing::kinds(&s));
}

#[test]
fn an_up_to_date_browser_has_no_finding_whatever_kev_lists() {
    let d = crate::utils::temp::TempDir::new("current").unwrap();
    let net = Fake::new(testing::app_net);
    let mut s = testing::scan(&net, &d);
    let today = crate::utils::dates::iso(crate::utils::dates::today());
    s.kev_entries = vec![kev_entry(&format!("CVE-{}-1", &today[..4]), &today, "Google", "Chromium V8")];
    let found = vec![
        testing::app("Google Chrome", "130.0.6723.117", &[("browser", "chrome")]),
        testing::app("Adobe Acrobat Reader", "25.001.20000", &[("id", "com.adobe.Reader")]),
    ];
    apps_found(&mut s, found, BTreeMap::new).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
}

fn linux(id: &str, version: &str, install: &str, fix: &str) -> Component {
    let path = format!("/usr/bin/{id}");
    crate::checks::machine::browsers::component(id, version, &path, install, fix)
}

#[test]
fn linux_browsers_follow_chromes_linux_feed_and_mozillas() {
    let d = crate::utils::temp::TempDir::new("linux").unwrap();
    let net = Fake::new(testing::app_net);
    let mut s = testing::scan(&net, &d);
    let apt = "sudo apt-get update && sudo apt-get install --only-upgrade google-chrome-stable";
    let found = vec![
        linux("chrome", "129.0.6668.100", "package", apt),
        linux("chromium", "129.0.6668.100", "snap", "sudo snap refresh chromium"),
        linux("firefox", "128.3.0", "flatpak", "flatpak update org.mozilla.firefox"),
        linux("edge", "131.0.2903.70", "package", "sudo apt-get install --only-upgrade microsoft-edge-stable"),
        linux("brave", "131.1.73.97", "package", "sudo apt-get install --only-upgrade brave-browser"),
    ];
    linux_browsers(&mut s, found).unwrap();
    assert_eq!(s.counts, [("browsers".to_string(), 5)]);
    let urls: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
    assert!(urls.iter().any(|u| u.contains("/chrome/platforms/linux/")), "{urls:?}");
    assert!(!urls.iter().any(|u| u.contains("/platforms/mac/") || u.contains("cask")), "{urls:?}");
    let chrome = &s.findings[0];
    assert_eq!(
        (chrome.component.as_str(), chrome.vuln_id.as_str(), chrome.status.as_str(), chrome.fixed.as_str()),
        ("Google Chrome", "BROWSER", "fail", "130.0.6723.117")
    );
    // The package manager's command, printed: never run unattended.
    assert_eq!((chrome.fix_cmd.as_str(), chrome.fix_auto), (apt, false));
    // Chromium shares Chrome's version numbers and feed.
    let chromium = &s.findings[1];
    assert_eq!(
        (chromium.component.as_str(), chromium.vuln_id.as_str(), chromium.status.as_str()),
        ("Chromium", "BROWSER", "fail")
    );
    assert_eq!(chromium.fix_cmd, "sudo snap refresh chromium");
    let ff = &s.findings[2];
    assert_eq!((ff.vuln_id.as_str(), ff.status.as_str(), ff.fixed.as_str()), ("BROWSER", "warn", "128.5.0"));
    assert_eq!(ff.fix_cmd, "flatpak update org.mozilla.firefox");
    // No feed is read for Edge or Brave on Linux: said, not passed.
    assert_eq!(
        testing::unchecked_note(&s, "Microsoft Edge on Linux"),
        "no release feed for Microsoft Edge on Linux is read yet; 131.0.2903.70 is installed"
    );
    testing::unchecked_note(&s, "Brave Browser on Linux");
    assert_eq!(s.findings.len(), 5, "{:?}", testing::kinds(&s));
}

#[test]
fn exploited_chromium_cves_fail_a_linux_chrome_or_chromium_behind() {
    let d = crate::utils::temp::TempDir::new("linuxkev").unwrap();
    let net = Fake::new(testing::app_net);
    let mut s = testing::scan(&net, &d);
    s.kev_entries = vec![
        kev_entry("CVE-2024-0519", "2024-01-17", "Google", "Chromium V8"),
        // Before Chrome 130 superseded 129 on 2024-01-01: not named.
        kev_entry("CVE-2023-7024", "2023-12-21", "Google", "Chromium WebRTC"),
    ];
    let found = vec![
        linux("chrome", "129.0.6668.100", "package", "sudo dnf upgrade google-chrome-stable"),
        linux("chromium", "129.0.6668.100", "package", "sudo dnf upgrade chromium"),
    ];
    linux_browsers(&mut s, found).unwrap();
    for (f, name) in s.findings.iter().zip(["Google Chrome", "Chromium"]) {
        assert_eq!(
            (f.component.as_str(), f.vuln_id.as_str(), f.status.as_str(), f.kev),
            (name, "BROWSER", "fail", true)
        );
        assert!(
            f.note.ends_with(
                "CISA lists actively exploited Chromium CVEs added since this version was superseded on \
                 2024-01-01: CVE-2024-0519. Pantry knows this version is behind, not that each CVE affects this \
                 exact build"
            ),
            "{}",
            f.note
        );
    }
    assert_eq!(s.findings[0].fix_cmd, "sudo dnf upgrade google-chrome-stable");
    assert_eq!(s.findings.len(), 2, "{:?}", testing::kinds(&s));
}

#[test]
fn current_or_absent_linux_browsers_have_no_findings() {
    let d = crate::utils::temp::TempDir::new("linuxnone").unwrap();
    let net = Fake::new(testing::app_net);
    let mut s = testing::scan(&net, &d);
    let today = crate::utils::dates::iso(crate::utils::dates::today());
    s.kev_entries = vec![kev_entry(&format!("CVE-{}-1", &today[..4]), &today, "Google", "Chromium V8")];
    linux_browsers(&mut s, vec![linux("chrome", "130.0.6723.117", "package", "x")]).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
    let mut s2 = testing::scan(&net, &d);
    let before = net.requests().len();
    linux_browsers(&mut s2, Vec::new()).unwrap();
    assert!(s2.findings.is_empty() && s2.counts.is_empty());
    assert_eq!(net.requests().len(), before, "nothing installed, nothing fetched");
}
