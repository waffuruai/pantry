//! What the inventory found against OSV, end of life and (PostgreSQL) the
//! project's own table, and mise against its latest release.

use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::MISE_REPO;
use crate::checks::{Scan, fill};
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv::Item;
use crate::sources::{endoflife, osv, releases};
use std::collections::{BTreeMap, HashMap};

/// OSV, end of life and (PostgreSQL) the project's own table.
pub fn components(scan: &mut Scan, found: &[Component]) -> Result<()> {
    let items: Vec<Item> = found.iter().filter_map(|c| c.osv.clone()).collect();
    let answers = scan.lookup(&items, "tools, runtimes and packages against OSV")?;
    // For upstream repos, ask OSV about the newer release tags too: the first
    // one it stops reporting an advisory for is the fix.
    let mut candidates: Vec<(Item, Vec<String>)> = Vec::new();
    for c in found {
        if let Some(it) = &c.osv
            && it.0 == "GIT"
            && answers.get(it).is_some_and(|r| !r.is_empty())
            && !candidates.iter().any(|(k, _)| k == it)
        {
            scan.status(&format!("Listing {}'s release tags", it.1));
            candidates.push((it.clone(), osv::candidates(&scan.cache, &it.1, &it.2, scan.opts.offline)?));
        }
    }
    let later_items: Vec<Item> =
        candidates.iter().flat_map(|(k, ts)| ts.iter().map(|t| ("GIT".to_string(), k.1.clone(), t.clone()))).collect();
    let later = scan.lookup(&later_items, "which releases fix upstream-repo advisories")?;
    let newer: HashMap<Item, BTreeMap<String, Vec<String>>> = candidates
        .into_iter()
        .map(|(k, ts)| {
            let m = ts
                .into_iter()
                .filter_map(|t| {
                    later
                        .get(&("GIT".to_string(), k.1.clone(), t.clone()))
                        .map(|recs| (t, recs.iter().map(|r| crate::utils::json::str_at(r, "id").to_string()).collect()))
                })
                .collect();
            (k, m)
        })
        .collect();
    let pg = if found.iter().any(|c| c.name == "postgres") {
        scan.status("Fetching PostgreSQL's security table");
        let r = releases::postgres(&scan.cache, scan.net, scan.opts.offline);
        scan.guard("PostgreSQL (postgresql.org security table)", r, Vec::new())?
    } else {
        Vec::new()
    };
    // endoflife.date is one request per product: fetch the stale ones side
    // by side before the loop asks for each.
    let products: Vec<String> = found.iter().filter_map(|c| c.eol.as_ref().map(|(p, _)| p.clone())).collect();
    scan.status("Fetching end-of-life dates");
    endoflife::eol_prefetch(&scan.cache, scan.net, &products, scan.opts.offline)?;
    for c in found {
        let recs = c.osv.as_ref().and_then(|o| answers.get(o)).cloned().unwrap_or_default();
        let mut failing = scan.advisories(c, &recs, c.osv.as_ref().and_then(|o| newer.get(o)), "fail", None);
        if c.name == "postgres" {
            failing = postgres(scan, c, &pg)? || failing;
        }
        if c.name == "mise" {
            mise(scan, c)?;
        }
        if c.eol.is_some() {
            scan.eol(c, failing)?;
        }
    }
    Ok(())
}

/// A newer mise release only warns (OSV decides failures): a human bumps it
/// in ops, so the fix is never unattended.
pub fn mise(scan: &mut Scan, c: &Component) -> Result<()> {
    let r = releases::github_latest(&scan.cache, scan.net, MISE_REPO, scan.opts.offline);
    let latest = scan.guard("latest mise release (GitHub)", r, String::new())?;
    if !latest.is_empty() && !versions::same_or_newer(&c.version, &latest) {
        scan.add(Finding {
            vuln_id: "OUTDATED".into(),
            status: "warn".into(),
            fixed: latest.clone(),
            fix_cmd: c.fix.clone(),
            fix_auto: false,
            note: format!(
                "mise {} is behind {latest}. mise is foundational infrastructure: update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it.",
                c.version
            ),
            ..Finding::of(c)
        });
    }
    Ok(())
}

/// An advisory applies when the installed major is listed and the install
/// is older than that major's fixed release.
pub fn postgres(scan: &mut Scan, c: &Component, advisories: &[releases::PgAdvisory]) -> Result<bool> {
    let major = c.version.split('.').next().unwrap_or("").to_string();
    let mut failing = false;
    for a in advisories {
        let fixed = a.fixed.iter().find(|f| f.split('.').next() == Some(major.as_str())).cloned().unwrap_or_default();
        if !a.majors.contains(&major) || fixed.is_empty() || !versions::lt(&c.version, &fixed) {
            continue;
        }
        let sev = releases::severity_from_score(a.score);
        if scan.cache.vuln(&a.cve)?.is_none() {
            scan.cache.put_vuln(&serde_json::json!({"id": a.cve, "summary": a.summary, "database_specific": {"severity": sev},
                                                    "affected": [{"package": {"ecosystem": "PostgreSQL", "name": "postgresql"}}]}))?;
        }
        let kev = scan.kev.contains(&a.cve);
        scan.add(Finding {
            vuln_id: a.cve.clone(),
            status: "fail".into(),
            fixed: fixed.clone(),
            kev,
            severity: sev.into(),
            note: format!("{} ({})", a.summary, a.component),
            fix_cmd: fill(&c.fix, &fixed),
            fix_auto: c.auto,
            ..Finding::of(c)
        });
        failing = true;
    }
    Ok(failing)
}

#[cfg(test)]
mod tests {
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
        components(&mut s, &[pad, foo, node, pg, mise]).unwrap();
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
        assert!(
            !postgres(&mut s, &c, &[adv(&["16"], &["16.10"]), adv(&["17"], &[]), adv(&["17"], &["17.4"])]).unwrap()
        );
        assert!(s.findings.is_empty());
        assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
        assert!(s.cache.vuln("CVE-2026-2").unwrap().is_some());
        // Known to the cache already: not stored again.
        assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
        assert_eq!(s.findings.len(), 2);
    }
}
