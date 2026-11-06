use super::*;
use crate::utils::net::Fake;
use serde_json::json;

fn scan<'a>(net: &'a Fake, dir: &crate::utils::temp::TempDir) -> Scan<'a> {
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    Scan::new(Options::default(), cache, net, &|_| {}, &|_| {})
}

/// A fix version from a feed that isn't one version token never becomes
/// part of a command, let alone an unattended one.
#[test]
fn a_hostile_fix_version_never_reaches_a_command() {
    let mut c = Component::new("package", "npm:lodash", "4.17.20", "/usr/local/bin/npm");
    c.fix = "/usr/local/bin/npm install -g lodash@{safe}".into();
    c.auto = true;
    assert_eq!(fix_with(&c, "4.17.21"), ("/usr/local/bin/npm install -g lodash@4.17.21".to_string(), true));
    for bad in ["4.17.21 evil-pkg", "--registry=https://evil", "1' evil '", "4.17.21\nrm -rf /"] {
        let (cmd, auto) = fix_with(&c, bad);
        assert!(!auto, "{bad:?}");
        assert!(!cmd.contains("npm install"), "{cmd}");
    }
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    c.osv = Some(("npm".into(), "lodash".into(), "4.17.20".into()));
    let rec = json!({"id": "GHSA-h", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21 evil-pkg"}]}]}]});
    s.advisories(&c, &[rec], None, "fail", None);
    assert_eq!(s.findings.len(), 1);
    assert!(!s.findings[0].fix_auto);
    assert!(!s.findings[0].fix_cmd.contains("evil-pkg"), "{}", s.findings[0].fix_cmd);
}

#[test]
fn malicious_needs_no_fix_to_fail() {
    assert!(is_malicious(&json!({"id": "MAL-2026-1"})));
    assert!(is_malicious(&json!({"id": "GHSA-x", "aliases": ["MAL-2026-2"]})));
    assert!(!is_malicious(&json!({"id": "GHSA-x", "aliases": ["CVE-2026-1"]})));
}

#[test]
fn advisories_pick_the_closest_fix_and_dedupe_cves() {
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    s.kev.insert("CVE-2026-9".into());
    let mut c = Component::new("project", "rustls", "0.23.10", "/w/Cargo.lock");
    c.osv = Some(("crates.io".into(), "rustls".into(), "0.23.10".into()));
    c.fix = "cargo update -p rustls --precise {safe}".into();
    let fixed = |f: &str| json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": f}]}]);
    let recs = vec![
        json!({"id": "GHSA-1", "aliases": ["CVE-2026-9"], "summary": "bad", "database_specific": {"severity": "HIGH"},
               "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": fixed("0.23.18")}]}),
        json!({"id": "RUSTSEC-1", "aliases": ["CVE-2026-9"],
               "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": fixed("0.23.18")}]}),
        json!({"id": "GHSA-2", "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}),
        json!({"id": "MAL-1", "summary": "", "affected": []}),
    ];
    assert!(s.advisories(&c, &recs, None, "fail", Some(osv::group_by_alias(&recs))));
    assert_eq!(s.unfixed, 1);
    assert_eq!(s.findings.len(), 2);
    let f = &s.findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.fixed.as_str(), f.kev, f.severity.as_str()),
        ("CVE-2026-9", "0.23.18", true, "HIGH")
    );
    assert_eq!(f.fix_cmd, "cargo update -p rustls --precise 0.23.18");
    assert_eq!(f.affected_range, "<0.23.18", "introduced 0 reads as an open lower bound");
    assert_eq!((f.dep_scope.as_str(), f.dep_direct), ("", None), "a component says nothing about scope");
    let m = &s.findings[1];
    assert_eq!(
        (m.vuln_id.as_str(), m.severity.as_str(), m.note.as_str()),
        ("MAL-1", "MALICIOUS", "known malicious package")
    );
    assert_eq!(m.fix_cmd, "Remove rustls now, then rotate any credentials this machine holds");
}

/// Ubuntu's first tar update for CVE-2026-5704 (USN-8477-1, 0ubuntu0.1)
/// was incomplete; the CVE's own record, an alias, is fixed in 0ubuntu0.4.
/// The group's fix is the one that repairs both records.
#[test]
fn a_group_is_fixed_by_the_version_that_fixes_every_record() {
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    let (eco, installed) = ("Ubuntu:24.04:LTS", "1.35+dfsg-3build1");
    let mut c = Component::new("os", "tar", installed, "/var/lib/dpkg/status");
    c.osv = Some((eco.into(), "tar".into(), installed.into()));
    let rec = |id: &str, upstream: &str, fixed: &str| {
        json!({"id": id, "upstream": [upstream], "affected": [{"package": {"ecosystem": eco, "name": "tar"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})
    };
    let recs = vec![
        rec("USN-8477-1", "UBUNTU-CVE-2026-5704", "1.35+dfsg-3ubuntu0.1"),
        rec("UBUNTU-CVE-2026-5704", "CVE-2026-5704", "1.35+dfsg-3ubuntu0.4"),
    ];
    let groups = osv::group_by_alias(&recs);
    assert_eq!(groups.len(), 1);
    assert!(s.advisories(&c, &[], None, "fail", Some(groups)));
    assert_eq!(s.findings.len(), 1);
    assert_eq!(s.findings[0].fixed, "1.35+dfsg-3ubuntu0.4");
}

/// Installed 2.0.0, where an advisory was fixed in 1.5.0 and came back
/// in 2.0.0 with no fix yet: no downgrade is offered as the repair.
#[test]
fn a_reintroduced_interval_with_no_fix_is_unfixed() {
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    let mut c = Component::new("project", "x", "2.0.0", "/w/Cargo.lock");
    c.osv = Some(("crates.io".into(), "x".into(), "2.0.0".into()));
    let rec = json!({"id": "GHSA-3", "affected": [{"package": {"ecosystem": "crates.io", "name": "x"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}]}]}]});
    assert!(!s.advisories(&c, &[rec], None, "fail", None));
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert_eq!(s.unfixed, 1);
}

/// A Critical advisory with no fix anywhere still appears, as a warning
/// with the mitigation as its step; a Moderate one only counts.
#[test]
fn unfixed_high_impact_advisories_warn_with_a_mitigation() {
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    let mut c = Component::new("os", "linux-image", "6.8.0-45.45", "/var/lib/dpkg/status");
    c.osv = Some(("Ubuntu:24.04:LTS".into(), "linux-image".into(), "6.8.0-45.45".into()));
    let open = json!([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]);
    let recs = vec![
        json!({"id": "UBUNTU-CVE-2026-98432", "aliases": ["CVE-2026-98432"], "summary": "TCP use-after-free",
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
               "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "linux-image"}, "ranges": open}]}),
        json!({"id": "UBUNTU-CVE-2026-1", "aliases": ["CVE-2026-1"], "summary": "minor",
               "database_specific": {"severity": "MODERATE"},
               "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "linux-image"}, "ranges": open}]}),
    ];
    assert!(!s.advisories(&c, &recs, None, "fail", Some(osv::group_by_alias(&recs))), "a warning doesn't fail");
    assert_eq!(s.unfixed, 2);
    assert_eq!(s.findings.len(), 1);
    let f = &s.findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.status.as_str(), f.fixed.as_str(), f.severity.as_str()),
        ("CVE-2026-98432", "warn", "", "CRITICAL")
    );
    assert!(f.note.contains("no fix released"), "{}", f.note);
    assert!(f.fix_cmd.contains("hdrlength"), "{}", f.fix_cmd);
    assert!(!f.fix_auto);
}

#[test]
fn mitigations_are_looked_up_by_id() {
    assert!(mitigation("CVE-2026-98432").unwrap().contains("mptcp"));
    assert!(mitigation("cve-2026-98432").is_some());
    assert_eq!(mitigation("CVE-2000-1"), None);
    assert_eq!(mitigation_in("# c\n[mitigations]\n\"X-1\" = \"do this\"\n", "x-1").as_deref(), Some("do this"));
}

#[test]
fn unchecked_is_reported_once() {
    let net = Fake::offline();
    let dir = crate::utils::temp::TempDir::new("check").unwrap();
    let mut s = scan(&net, &dir);
    let r: Result<i32> = Err(Error::Offline("a: down\nmore".into()));
    assert_eq!(s.guard("feed", r, 7).unwrap(), 7);
    s.unchecked("feed", "again");
    assert_eq!(s.findings.len(), 1);
    assert_eq!((s.findings[0].note.as_str(), s.findings[0].status.as_str()), ("a: down", "warn"));
    let internal: Result<i32> = Err(Error::Io(std::io::Error::other("disk")));
    assert!(s.guard("x", internal, 0).is_err(), "internal errors pass through");
}

#[test]
fn listed_files_and_bundled_defaults() {
    assert!(listed(None, crate::defaults::INSTALL_SCRIPTS, "allow").iter().any(|l| l.starts_with("esbuild@")));
    assert!(listed(Some(Path::new("/nonexistent")), "x", "allow").is_empty());
    let d = crate::utils::temp::TempDir::new("policy").unwrap();
    let (toml, old) = (d.path().join("p.toml"), d.path().join("p.txt"));
    std::fs::write(&toml, "# mine\nallow = [\"MIT\"]\n").unwrap();
    std::fs::write(&old, "MIT\nApache-2.0\n").unwrap();
    assert_eq!(listed(Some(&toml), "", "allow"), ["MIT"]);
    assert_eq!(policy_error(&toml), None);
    assert!(policy_error(&old).unwrap().contains("not a TOML policy file"), "a list from before TOML is refused");
}
