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
        // PostgreSQL publishes a CVSS 3.x base score, not always the vector.
        let sev = if a.score > 0.0 { crate::utils::cvss::label(a.score) } else { "" };
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
            cvss: (a.score > 0.0).then_some(a.score),
            cvss_version: if a.score > 0.0 { "3.x".into() } else { String::new() },
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
#[path = "components_tests.rs"]
mod tests;
