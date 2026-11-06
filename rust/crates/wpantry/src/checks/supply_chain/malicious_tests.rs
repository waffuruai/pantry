use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::error::Error;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use serde_json::json;

#[test]
fn every_ecosystem_has_a_directory_or_is_skipped() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let net = Fake::new(|_| panic!("an empty index asks nothing"));
    for eco in [
        "npm",
        "PyPI",
        "RubyGems",
        "crates.io",
        "Go",
        "NuGet",
        "Maven",
        "Packagist",
        "VSCode",
        "VSCode:https://open-vsx.org",
        "Hex",
    ] {
        assert_eq!(reports(&c, &net, eco, "x", "1.0.0", false).unwrap(), Reports::default(), "{eco}");
    }
    assert_eq!(openssf("Hex"), None);
    assert_eq!(normalize("PyPI", "trailing_"), "trailing-");
    assert_eq!(normalize("npm", "Trailing_"), "trailing_");
}

#[test]
fn a_cache_or_bug_error_is_not_an_unknown_report() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.conn.execute("INSERT INTO malicious VALUES ('npm', 'evil', 'MAL-1')", []).unwrap();
    let net = Fake::new(|_| Err(Error::Missing("not a source failure".into())));
    assert!(matches!(reports(&c, &net, "npm", "evil", "1.0.0", false), Err(Error::Missing(_))));
}

#[test]
fn an_open_interval_and_a_bare_package_cover_everything_after() {
    // An event that neither starts nor ends an interval is skipped; the
    // last `introduced` stays open.
    let open = json!({"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER",
        "events": [{"introduced": "1.0.0"}, {"note": "?"}]}]}]});
    assert!(!applies(&open, "0.9.0"));
    assert!(applies(&open, "1.0.0"));
    assert!(applies(&json!({"affected": [{"package": {"name": "x"}}]}), "1.0.0"), "no versions, no ranges");
}

#[test]
fn applies_to_versions_and_ranges() {
    let every = json!({"affected": [{"package": {"name": "x"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]});
    let some = json!({"affected": [{"package": {"name": "chalk"}, "versions": ["5.6.1"]}]});
    assert!(applies(&every, "1.0.0"));
    assert!(applies(&some, "5.6.1"));
    assert!(!applies(&some, "5.6.2"));
    assert!(applies(&json!({"affected": []}), "1.0.0"));
}

#[test]
fn index_lookup_normalises_names() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    for (e, n, i) in [("pypi", "evil-pkg", "MAL-1"), ("npm", "@bad/scope", "MAL-2")] {
        c.conn.execute("INSERT INTO malicious VALUES (?, ?, ?)", params![e, n, i]).unwrap();
    }
    c.put_vuln(&json!({"id": "MAL-1", "summary": "Malicious code in evil_pkg", "affected": []})).unwrap();
    c.put_vuln(&json!({"id": "MAL-2", "affected": [{"versions": ["1.0.0"]}]})).unwrap();
    let net = Fake::offline();
    let ids = |r: Reports| r.matched.iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(ids(reports(&c, &net, "PyPI", "Evil_Pkg", "", false).unwrap()), ["MAL-1"]);
    assert_eq!(ids(reports(&c, &net, "npm", "@bad/scope", "1.0.0", false).unwrap()), ["MAL-2"]);
    assert_eq!(reports(&c, &net, "npm", "@bad/scope", "2.0.0", false).unwrap(), Reports::default());
    assert_eq!(normalize("PyPI", "Foo__Bar.baz"), "foo-bar-baz");
}

#[test]
fn every_interval_counts() {
    let rec = json!({"affected": [{"package": {"ecosystem": "crates.io", "name": "x"}, "ranges": [{"type": "SEMVER",
        "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]}]});
    for (v, want) in [
        ("0.9.0", false),
        ("1.0.0", true),
        ("1.1.0", false),
        ("1.5.0", false),
        ("2.0.0", true),
        ("2.0.9", true),
        ("2.1.0", false),
    ] {
        assert_eq!(applies(&rec, v), want, "{v}");
    }
    let last = json!({"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER",
        "events": [{"introduced": "0"}, {"last_affected": "1.2.0"}, {"introduced": "3.0.0"}]}]}]});
    for (v, want) in [("1.2.0", true), ("1.2.1", false), ("2.9.9", false), ("3.0.0", true), ("9.0.0", true)] {
        assert_eq!(applies(&last, v), want, "{v}");
    }
    // The ecosystem's own order: PEP 440 puts 1.0rc1 before 1.0.
    let py = json!({"affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": [{"type": "ECOSYSTEM",
        "events": [{"introduced": "1.0"}]}]}]});
    assert!(!applies(&py, "1.0rc1"));
    assert!(applies(&py, "1.0.post1"));
}

#[test]
fn an_unread_report_is_unknown_never_assumed_and_never_cached() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.conn.execute("INSERT INTO malicious VALUES ('crates.io', 'evil', 'MAL-9')", []).unwrap();
    let unknown = Reports { matched: vec![], unknown: vec!["MAL-9".into()] };
    // Offline: no request at all.
    let no_calls = Fake::new(|_| panic!("offline must not fetch"));
    assert_eq!(reports(&c, &no_calls, "crates.io", "evil", "9.9.0", true).unwrap(), unknown);
    // Online, the fetch fails or OSV serves something that isn't the record.
    assert_eq!(reports(&c, &Fake::offline(), "crates.io", "evil", "9.9.0", false).unwrap(), unknown);
    let wrong = Fake::new(|_| Ok(crate::utils::net::Response::ok("{}")));
    assert_eq!(reports(&c, &wrong, "crates.io", "evil", "9.9.0", false).unwrap(), unknown);
    assert_eq!(c.vuln("MAL-9").unwrap(), None, "nothing invented was cached");
    // Once OSV answers, the real ranges decide.
    let rec = json!({"id": "MAL-9", "affected": [{"package": {"ecosystem": "crates.io", "name": "evil"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}]}]}]});
    let body = rec.to_string();
    let good = Fake::new(move |_| Ok(crate::utils::net::Response::ok(body.clone())));
    assert_eq!(reports(&c, &good, "crates.io", "evil", "9.9.0", false).unwrap(), Reports::default());
    assert_eq!(good.requests().len(), 1);
    assert_eq!(reports(&c, &no_calls, "crates.io", "evil", "1.0.5", true).unwrap().matched, [rec]);
}

/// Every package name against the index: a match fails (once per
/// component and report), a report that couldn't be read is unchecked
/// by name, and no index at all is unchecked.
#[test]
fn the_sweep_matches_the_malicious_index() {
    let d = TempDir::new("sweep").unwrap();
    testing::seed_index(&d, &[("npm", "evil", "MAL-0001"), ("npm", "evil", "MAL-0002"), ("pypi", "bad", "MAL-0003")]);
    let net = Fake::new(|r| {
        if r.url.ends_with("/MAL-0002") {
            return Err(Error::Offline("osv: down".into()));
        }
        testing::osv(r, &[]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
    });
    let mut s = testing::scan(&net, &d, Options::default());
    let mut evil = Component::new("npm", "evil", "1.0.0", "/n/evil");
    evil.osv = Some(("npm".into(), "evil".into(), "1.0.0".into()));
    let mut good = Component::new("npm", "good", "1.0.0", "/n/good");
    good.osv = Some(("npm".into(), "good".into(), "1.0.0".into()));
    let mut bad = Component::new("mcp", "bad (project: x)", "unpinned", "/r/.mcp.json");
    for (k, v) in [("eco", "PyPI"), ("pkg", "bad"), ("ver", "")] {
        bad.extra.insert(k.into(), v.into());
    }
    // Already reported under that id (by OSV, say): not again.
    s.add(Finding { vuln_id: "MAL-0001".into(), status: "fail".into(), ..Finding::of(&evil) });
    sweep(&mut s, &[evil, good], &[bad]).unwrap();
    assert_eq!(testing::by_id(&s, "MAL-0001").len(), 1, "{:?}", s.findings);
    let bad = testing::by_id(&s, "MAL-0003");
    assert_eq!(bad.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (bad[0].component.as_str(), bad[0].status.as_str(), bad[0].severity.as_str(), bad[0].note.as_str()),
        ("bad (project: x)", "fail", "MALICIOUS", "MAL-0003 is malicious")
    );
    assert!(bad[0].kev);
    assert_eq!(bad[0].fix_cmd, REMOVE.replace("{}", "bad"));
    assert_eq!(testing::unchecked(&s), ["packages named in the malicious-package index"]);
    let un = s.findings.iter().find(|f| f.kind == "unchecked").unwrap();
    assert!(un.note.ends_with("covered: evil 1.0.0 (MAL-0002)"), "{}", un.note);

    let d = TempDir::new("sweep-off").unwrap();
    let mut s = testing::scan(&net, &d, Options { offline: true, ..Default::default() });
    sweep(&mut s, &[], &[]).unwrap();
    assert_eq!(testing::unchecked(&s), ["malicious-package index (OpenSSF)"]);
}
