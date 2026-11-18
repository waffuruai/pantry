use super::*;
use crate::checks::machine::catalog::MISE_FIX;
use crate::checks::machine::testing;
use crate::checks::machine::testing::FOO;
use crate::utils::net::Fake;

// The test vectors the Python implementation had (`Mise`).
#[test]
fn mise_behind_latest_release_warns_and_is_never_unattended() {
    let d = crate::utils::temp::TempDir::new("mise").unwrap();
    let net = Fake::new(|r| {
        assert_eq!(r.url, "https://api.github.com/repos/jdx/mise/releases/latest");
        Ok(crate::utils::net::Response::ok(r#"{"tag_name": "v2026.10.21"}"#))
    });
    let mut s = testing::scan(&net, &d);
    let mut c = Component::new("manager", "mise", "2026.10.19", "/h/.local/bin/mise");
    c.fix = MISE_FIX.into();
    mise(&mut s, &c).unwrap();
    let f = &s.findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.status.as_str(), f.fixed.as_str(), f.fix_cmd.as_str(), f.fix_auto),
        ("OUTDATED", "warn", "2026.10.21", MISE_FIX, false)
    );
    assert_eq!(
        f.note,
        "mise 2026.10.19 is behind 2026.10.21. mise is foundational infrastructure: update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it."
    );
    // Cached for a day: GitHub isn't asked again.
    let quiet = Fake::new(|_| panic!("cached"));
    let mut s2 = Scan::new(Default::default(), s.cache, &quiet, &|_| {}, &|_| {});
    mise(&mut s2, &c).unwrap();
}

#[test]
fn unreachable_github_is_unchecked_not_clean() {
    let d = crate::utils::temp::TempDir::new("mise").unwrap();
    let net = Fake::new(|_| Ok(crate::utils::net::Response { status: 403, body: vec![], etag: None }));
    let mut s = testing::scan(&net, &d);
    mise(&mut s, &Component::new("manager", "mise", "2026.10.19", "")).unwrap();
    assert_eq!(
        (s.findings[0].kind.as_str(), s.findings[0].component.as_str()),
        ("unchecked", "latest mise release (GitHub)")
    );
}

#[test]
fn postgres_advisories_by_major() {
    let d = crate::utils::temp::TempDir::new("pg").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    let mut c = Component::new("datastore", "postgres", "17.4", "/usr/bin/postgres");
    c.fix = "Upgrade postgres to {safe}".into();
    let adv = releases::PgAdvisory {
        cve: "CVE-2026-1".into(),
        majors: vec!["17".into(), "16".into()],
        fixed: vec!["17.6".into(), "16.10".into()],
        component: "core server".into(),
        score: 8.8,
        vector: String::new(),
        summary: "Heap overflow".into(),
    };
    assert!(postgres(&mut s, &c, &[adv]).unwrap());
    let f = &s.findings[0];
    assert_eq!(
        (f.fixed.as_str(), f.severity.as_str(), f.fix_cmd.as_str()),
        ("17.6", "HIGH", "Upgrade postgres to 17.6")
    );
}

#[test]
fn components_against_osv_eol_postgres_and_mise() {
    let d = crate::utils::temp::TempDir::new("components").unwrap();
    let net = Fake::new(|r| {
        use crate::utils::net::Response;
        let url = r.url.as_str();
        if url.ends_with("/querybatch") {
            let body = r.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|pkg, v| match (pkg, v) {
                ("left-pad", "1.0.0") => vec!["GHSA-lp"],
                (FOO, "v1.0.0" | "v1.0.1") => vec!["CVE-2026-9"],
                _ => vec![],
            }));
        }
        if url.contains("/vulns/") {
            let id = url.rsplit('/').next().unwrap_or("");
            let rec = if id == "GHSA-lp" {
                testing::npm_rec(id, "left-pad", Some("1.0.1"), &[])
            } else {
                serde_json::json!({"id": id, "modified": "m", "summary": "foo overflow",
                    "affected": [{"ranges": [{"type": "GIT", "repo": FOO, "events": [{"introduced": "abc"}]}]}]})
            };
            return Ok(Response::ok(rec.to_string()));
        }
        if url == "https://endoflife.date/api/nodejs.json" {
            return Ok(Response::ok(
                serde_json::json!([{"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
                                   {"cycle": "22", "eol": false, "latest": "22.11.0"}])
                .to_string(),
            ));
        }
        if url == "https://api.github.com/repos/jdx/mise/releases/latest" {
            return Ok(Response::ok(r#"{"tag_name": "v2026.10.21"}"#));
        }
        if url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        panic!("unexpected request {url}")
    });
    let mut s = testing::scan(&net, &d);
    // Release tags and PostgreSQL's table come from the cache: no git, no HTML.
    s.cache.put_run(&format!("tags:{FOO}"), "", &serde_json::json!(["v1.0.1", "v1.0.2"])).unwrap();
    s.cache
        .put_run(
            "postgres",
            "",
            &serde_json::json!([{"cve": "CVE-2026-1", "majors": ["17"], "fixed": ["17.6"], "component": "core",
                                 "score": 8.8, "vector": "", "summary": "Heap overflow"}]),
        )
        .unwrap();
    let mut pad = Component::new("package", "left-pad", "1.0.0", "/usr/local/lib/node_modules/left-pad");
    pad.osv = Some(("npm".into(), "left-pad".into(), "1.0.0".into()));
    pad.fix = "npm install -g left-pad@{safe}".into();
    let mut foo = Component::new("tool", "foo", "1.0.0", "/usr/local/bin/foo");
    foo.osv = Some(("GIT".into(), FOO.into(), "v1.0.0".into()));
    let mut node = Component::new("runtime", "node", "18.0.0", "/usr/local/bin/node");
    node.eol = Some(("nodejs".into(), "18".into()));
    let mut pg = Component::new("datastore", "postgres", "17.4", "/usr/local/bin/postgres");
    pg.fix = "Upgrade postgres to {safe}".into();
    let mise = Component::new("manager", "mise", "2026.10.19", "/h/.local/bin/mise");
    let foo_item = foo.osv.clone().unwrap();
    let answers = components(&mut s, &[pad, foo, node, pg, mise]).unwrap();
    // OSV's answers go back to the caller, for the checks that go on where OSV had nothing.
    assert_eq!(answers[&foo_item].len(), 1);
    let got = testing::kinds(&s);
    assert_eq!(
        got,
        [
            ("left-pad".to_string(), "GHSA-lp".to_string(), "fail".to_string()),
            ("foo".to_string(), "CVE-2026-9".to_string(), "fail".to_string()),
            ("node".to_string(), "EOL".to_string(), "fail".to_string()),
            ("postgres".to_string(), "CVE-2026-1".to_string(), "fail".to_string()),
            ("mise".to_string(), "OUTDATED".to_string(), "warn".to_string()),
        ],
        "{got:?}"
    );
    // The first later tag OSV stops reporting the advisory for is the fix.
    assert_eq!(s.findings[1].fixed, "v1.0.2");
    // Nothing found: nothing asked.
    let quiet = Fake::new(|_| panic!("nothing to ask about"));
    let mut s2 = Scan::new(Default::default(), s.cache, &quiet, &|_| {}, &|_| {});
    components(&mut s2, &[]).unwrap();
    assert!(s2.findings.is_empty());
    assert_eq!(s.findings[0].fixed, "1.0.1");
    assert_eq!(s.findings[2].note, "nodejs 18 reached end of life on 2025-04-30; supported: 22");
}

#[test]
fn postgres_skips_other_majors_and_known_cves() {
    let d = crate::utils::temp::TempDir::new("pg").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    let c = Component::new("datastore", "postgres", "17.4", "/usr/bin/postgres");
    let adv = |majors: &[&str], fixed: &[&str]| releases::PgAdvisory {
        cve: "CVE-2026-2".into(),
        majors: majors.iter().map(|m| m.to_string()).collect(),
        fixed: fixed.iter().map(|f| f.to_string()).collect(),
        component: "core".into(),
        score: 5.0,
        vector: String::new(),
        summary: "s".into(),
    };
    // Another major, a major without a fix, and an install already fixed.
    assert!(!postgres(&mut s, &c, &[adv(&["16"], &["16.10"]), adv(&["17"], &[]), adv(&["17"], &["17.4"])]).unwrap());
    assert!(s.findings.is_empty());
    assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
    assert!(s.cache.vuln("CVE-2026-2").unwrap().is_some());
    // Known to the cache already: not stored again.
    assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
    assert_eq!(s.findings.len(), 2);
}

/// An installed Go is checked as its toolchain too: a toolchain-only
/// advisory fails it, and one filed under both packages is one finding.
#[test]
fn installed_go_is_checked_as_its_toolchain_too() {
    let d = crate::utils::temp::TempDir::new("gotc").unwrap();
    let net = testing::go_osv();
    let mut s = testing::scan(&net, &d);
    let go = |v: &str| {
        let mut c = Component::new("runtime", "go", v, "/usr/local/go/bin/go");
        c.osv = Some(("Go".into(), "stdlib".into(), v.into()));
        c.osv_also = osv::also(c.osv.as_ref().unwrap());
        c.fix = "Update Go to {safe}".into();
        c
    };
    components(&mut s, &[go("1.26.10"), go("1.26.11")]).unwrap();
    let got = testing::kinds(&s);
    assert_eq!(
        got,
        [
            ("go".to_string(), "CVE-2026-0002".to_string(), "fail".to_string()),
            ("go".to_string(), "CVE-2026-0001".to_string(), "fail".to_string()),
        ],
        "{got:?}"
    );
    for f in &s.findings {
        assert_eq!(
            (f.version.as_str(), f.fixed.as_str(), f.affected_range.as_str()),
            ("1.26.10", "1.26.11", "<1.26.11")
        );
    }
}

#[test]
fn java_8_is_outdated_only_when_behind_temurins_latest_8() {
    let d = crate::utils::temp::TempDir::new("jdk8").unwrap();
    let net = Fake::new(|r| {
        assert_eq!(r.url, "https://endoflife.date/api/eclipse-temurin.json");
        Ok(crate::utils::net::Response::ok(r#"[{"cycle": "8", "eol": false, "latest": "8u472-b08"}]"#))
    });
    let mut s = testing::scan(&net, &d);
    for v in ["1.8.0_412", "1.8.0_472", "1.8.0_480"] {
        let mut c = Component::new("runtime", "java", v, "/j/bin/java");
        c.eol = Some(("eclipse-temurin".into(), "8".into()));
        s.eol(&c, false).unwrap();
    }
    let got: Vec<(&str, &str)> = s.findings.iter().map(|f| (f.version.as_str(), f.vuln_id.as_str())).collect();
    assert_eq!(got, [("1.8.0_412", "OUTDATED")]);
    assert_eq!(s.findings[0].fixed, "8u472-b08");
}

fn kev_entry(cve: &str, added: &str, vendor: &str, product: &str) -> crate::sources::kev::Entry {
    crate::sources::kev::Entry { cve: cve.into(), added: added.into(), vendor: vendor.into(), product: product.into() }
}

/// The feeds the self-hosted servers are judged by: endoflife.date for
/// Metabase and UnrealIRCd, GitHub's latest release for FreeSWITCH.
fn server_net(r: &crate::utils::net::Request) -> crate::error::Result<crate::utils::net::Response> {
    use crate::utils::net::Response;
    let url = r.url.as_str();
    if url.ends_with("/querybatch") {
        let body = r.body.clone().unwrap_or_default();
        return Ok(testing::querybatch(&body, &|_, _| vec![]));
    }
    if url == "https://endoflife.date/api/metabase.json" {
        return Ok(Response::ok(
            serde_json::json!([{"cycle": "0.64", "eol": "2099-12-01", "latest": "0.64.7"},
                               {"cycle": "0.61", "eol": "2026-09-01", "latest": "0.61.21.1"}])
            .to_string(),
        ));
    }
    if url == "https://endoflife.date/api/unrealircd.json" {
        return Ok(Response::ok(
            serde_json::json!([{"cycle": "6", "eol": false, "latest": "6.2.7.1"},
                               {"cycle": "5", "eol": "2023-07-01", "latest": "5.2.4"}])
            .to_string(),
        ));
    }
    if url == "https://api.github.com/repos/signalwire/freeswitch/releases/latest" {
        return Ok(Response::ok(r#"{"tag_name": "v1.11.3"}"#));
    }
    if url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
        return Ok(Response::not_found());
    }
    panic!("unexpected request {url}")
}

fn server(name: &str, version: &str, eol: Option<(&str, &str)>) -> Component {
    let mut c = Component::new("tool", name, version, &format!("/opt/{name}/bin/{name}"));
    c.eol = eol.map(|(p, cy)| (p.to_string(), cy.to_string()));
    c.fix = format!("Upgrade {name} to {{safe}}");
    c
}

#[test]
fn self_hosted_servers_behind_their_release_warn_and_name_exploited_cves() {
    let d = crate::utils::temp::TempDir::new("servers").unwrap();
    let net = Fake::new(server_net);
    let mut s = testing::scan(&net, &d);
    let today = crate::utils::dates::iso(crate::utils::dates::today());
    let year = &today[..4];
    s.kev_entries = vec![
        kev_entry(&format!("CVE-{year}-11"), &today, "SignalWire", "FreeSwitch"),
        kev_entry(&format!("CVE-{year}-12"), &today, "Metabase", "Metabase"),
        // Another vendor's product of the same name escalates nothing.
        kev_entry(&format!("CVE-{year}-13"), &today, "Someone", "UnrealIRCd"),
    ];
    let mut metabase = crate::checks::machine::servers::from_images(&["metabase/metabase:v0.64.2".to_string()]);
    assert_eq!(metabase.len(), 1);
    let found = vec![
        server("freeswitch", "1.10.12", None),
        metabase.remove(0),
        server("unrealircd", "6.1.8", Some(("unrealircd", "6"))),
        // Past its line's end of life: fails as EOL, as any catalog tool.
        server("unrealircd", "5.2.4", Some(("unrealircd", "5"))),
        // Up to date: nothing, whatever KEV lists.
        server("freeswitch", "1.11.3", None),
    ];
    components(&mut s, &found).unwrap();
    let got: Vec<(&str, &str, &str, &str, bool)> = s
        .findings
        .iter()
        .map(|f| (f.component.as_str(), f.version.as_str(), f.vuln_id.as_str(), f.status.as_str(), f.kev))
        .collect();
    assert_eq!(
        got,
        [
            ("freeswitch", "1.10.12", "OUTDATED", "warn", false),
            ("metabase", "0.64.2", "OUTDATED", "warn", false),
            ("unrealircd", "6.1.8", "OUTDATED", "warn", false),
            ("unrealircd", "5.2.4", "EOL", "fail", false),
        ],
        "{:?}",
        testing::kinds(&s)
    );
    let fs = &s.findings[0];
    assert_eq!((fs.fixed.as_str(), fs.fix_cmd.as_str()), ("1.11.3", "Upgrade freeswitch to 1.11.3"));
    assert_eq!(
        fs.note,
        format!(
            "behind 1.11.3, the latest freeswitch release; CISA lists actively exploited FreeSWITCH CVEs added in \
             the last 180 days: CVE-{year}-11. Pantry doesn't know when this version was superseded, so it may \
             already have their fixes"
        )
    );
    let mb = &s.findings[1];
    assert_eq!(
        (mb.fixed.as_str(), mb.fix_cmd.as_str()),
        ("0.64.7", "docker pull metabase/metabase:v0.64.7, then recreate its containers")
    );
    assert!(
        mb.note.contains(&format!("exploited Metabase CVEs added in the last 180 days: CVE-{year}-12")),
        "{}",
        mb.note
    );
    assert_eq!(s.findings[2].note, "behind 6.2.7.1, the latest unrealircd 6 release");
}

#[test]
fn the_latest_release_check_stays_quiet_when_an_advisory_fails_or_github_is_down() {
    let d = crate::utils::temp::TempDir::new("latest").unwrap();
    let net = Fake::new(server_net);
    let mut s = testing::scan(&net, &d);
    let c = server("freeswitch", "1.10.12", None);
    // An advisory already fails it: no second, weaker finding.
    latest(&mut s, &c, "signalwire/freeswitch", true).unwrap();
    assert!(s.findings.is_empty());
    let down = Fake::new(|_| Ok(crate::utils::net::Response { status: 403, body: vec![], etag: None }));
    let d2 = crate::utils::temp::TempDir::new("latest-down").unwrap();
    let mut s2 = testing::scan(&down, &d2);
    latest(&mut s2, &c, "signalwire/freeswitch", false).unwrap();
    assert_eq!(
        (s2.findings[0].kind.as_str(), s2.findings[0].component.as_str()),
        ("unchecked", "latest freeswitch release (GitHub)")
    );
}
