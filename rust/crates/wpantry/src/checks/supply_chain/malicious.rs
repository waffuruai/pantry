//! Known malicious packages: a package whose name is in the OpenSSF index
//! ([`crate::sources::malicious_packages`]) has just its reports fetched, to
//! check whether the version here is affected. This is what catches packages
//! known only by name (an unpinned `npx some-mcp-server`).

use crate::checks::ecosystems::{self, normalize, openssf};
use crate::checks::{REMOVE, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::malicious_packages;
use crate::utils::json::str_at;
use crate::utils::json::{self, arr_at};
use crate::utils::net::{self, Net};
use rusqlite::params;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashSet;

/// What the index says about one package: the reports that cover this
/// version, and the ids whose report couldn't be read (offline, or the fetch
/// failed), so whether they cover it is unknown.
#[derive(Debug, Default, PartialEq)]
pub struct Reports {
    pub matched: Vec<Value>,
    pub unknown: Vec<String>,
}

/// The malicious-package reports that cover this package at this version
/// (any version when `version` is ""), fetched and cached on first use. Only
/// a report OSV actually served is cached; one that couldn't be fetched is
/// `unknown`, and asked again next time.
pub fn reports(cache: &Cache, net: &dyn Net, eco: &str, name: &str, version: &str, offline: bool) -> Result<Reports> {
    let Some(dir) = openssf(eco) else { return Ok(Reports::default()) };
    let ids: Vec<String> = {
        let mut stmt = cache.conn.prepare("SELECT id FROM malicious WHERE ecosystem = ? AND name = ?")?;
        stmt.query_map(params![dir, normalize(eco, name)], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut out = Reports::default();
    for id in ids {
        let rec = match cache.vuln(&id)? {
            Some(r) => r,
            None if offline => {
                out.unknown.push(id);
                continue;
            }
            None => match net::get_json(net, &format!("https://api.osv.dev/v1/vulns/{id}"), &[]) {
                Ok(Some(r)) if json::str_at(&r, "id") == id => {
                    cache.put_vuln(&r)?;
                    r
                }
                Ok(_) => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) if e.is_source() => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        if version.is_empty() || applies(&rec, version) {
            out.matched.push(rec);
        }
    }
    Ok(out)
}

/// Whether `version` is among those a report covers: listed in `versions`,
/// or inside any of a range's intervals (each `introduced` up to the next
/// `fixed` or `limit`, exclusive, or `last_affected`, inclusive), compared
/// in the package's ecosystem's order. A report listing no ranges or
/// versions covers every version.
pub fn applies(rec: &Value, version: &str) -> bool {
    let affected = arr_at(rec, "affected");
    if affected.is_empty() {
        return true;
    }
    for a in affected {
        let versions = json::strs_at(a, "versions");
        if versions.iter().any(|v| v == version) {
            return true;
        }
        let eco = a.get("package").map(|p| json::str_at(p, "ecosystem")).unwrap_or("");
        let order = ecosystems::order(eco);
        let lt = |x: &str, y: &str| order.cmp(x, y) == Ordering::Less;
        for r in arr_at(a, "ranges") {
            let mut start: Option<&str> = None;
            for e in arr_at(r, "events") {
                let at = |k: &str| e.get(k).and_then(Value::as_str);
                if let Some(intro) = at("introduced") {
                    start = Some(intro);
                } else if let Some(intro) = start {
                    let from = intro == "0" || !lt(version, intro);
                    let inside = match (at("fixed").or(at("limit")), at("last_affected")) {
                        (Some(end), _) => lt(version, end),
                        (None, Some(last)) => !lt(last, version),
                        (None, None) => continue,
                    };
                    if from && inside {
                        return true;
                    }
                    start = None;
                }
            }
            if let Some(intro) = start
                && (intro == "0" || !lt(version, intro))
            {
                return true; // introduced, never fixed
            }
        }
        if versions.is_empty() && arr_at(a, "ranges").is_empty() {
            return true;
        }
    }
    false
}

/// Every package name we know against the local malicious-package index,
/// which also covers what OSV couldn't be asked about (offline, unpinned).
pub fn sweep(scan: &mut Scan, found: &[Component], refs: &[Component]) -> Result<()> {
    scan.status("Updating the malicious-package index (OpenSSF)");
    let synced = malicious_packages::sync(&scan.cache, scan.opts.offline);
    if scan.guard("malicious-package index (OpenSSF)", synced.map(Some), None)?.is_none() {
        return Ok(());
    }
    let mut flagged: HashSet<(String, String)> =
        scan.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone())).collect();
    let mut items: Vec<(&Component, String, String, String)> =
        found.iter().filter_map(|c| c.osv.as_ref().map(|(e, n, v)| (c, e.clone(), n.clone(), v.clone()))).collect();
    let extra = |c: &Component, k: &str| c.extra.get(k).cloned().unwrap_or_default();
    items.extend(refs.iter().map(|c| (c, extra(c, "eco"), extra(c, "pkg"), extra(c, "ver"))));
    let total = items.len();
    let mut unread = Vec::new();
    for (n, (c, eco, name, ver)) in items.into_iter().enumerate() {
        scan.status(&format!("Checking {name} against the malicious-package index ({}/{total})", n + 1));
        let found = reports(&scan.cache, scan.net, &eco, &name, &ver, scan.opts.offline)?;
        unread.extend(found.unknown.iter().map(|id| format!("{name} {ver} ({id})")));
        for rec in found.matched {
            let id = str_at(&rec, "id").to_string();
            if flagged.insert((c.name.clone(), id.clone())) {
                let summary = str_at(&rec, "summary");
                scan.add(Finding {
                    vuln_id: id,
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: if summary.is_empty() { format!("known malicious package {name}") } else { summary.into() },
                    fix_cmd: REMOVE.replace("{}", &name),
                    ..Finding::of(c)
                });
            }
        }
    }
    if !unread.is_empty() {
        unread.sort();
        unread.dedup();
        scan.unchecked(
            "packages named in the malicious-package index",
            &format!("couldn't read the report to tell whether these versions are covered: {}", unread.join(", ")),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
        testing::seed_index(
            &d,
            &[("npm", "evil", "MAL-0001"), ("npm", "evil", "MAL-0002"), ("pypi", "bad", "MAL-0003")],
        );
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
}
