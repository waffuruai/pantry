//! What the inventory found against OSV, end of life and (PostgreSQL) the
//! project's own table, and mise and the tools endoflife.date doesn't know
//! ([`GITHUB_LATEST`]) against their latest release.

use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::{GITHUB_LATEST, MISE_REPO};
use crate::checks::machine::erlang;
use crate::checks::machine::exploited::Gap;
use crate::checks::machine::packages;
use crate::checks::{Scan, fill, fix_with};
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv::Item;
use crate::sources::{endoflife, osv, releases};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// OSV, end of life and (PostgreSQL) the project's own table. Returns
/// OSV's answers, for the checks that go on where OSV had nothing
/// ([`crate::checks::machine::software_cves::tools`]).
pub fn components(scan: &mut Scan, found: &[Component]) -> Result<HashMap<Item, Vec<Value>>> {
    let items: Vec<Item> = found.iter().flat_map(|c| c.osv.iter().chain(&c.osv_also).cloned()).collect();
    let answers = scan.lookup(&items, "tools, runtimes and packages against OSV")?;
    // OTP's tags say which installs and fixes OSV's lists leave out.
    let otp_tags = if found.iter().any(|c| c.name == "erlang" && c.osv.is_some()) {
        scan.status("Listing Erlang/OTP's release tags");
        osv::tags(&scan.cache, &erlang::repo(), scan.opts.offline)?
    } else {
        Vec::new()
    };
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
            let mut ts = osv::candidates(&scan.cache, &it.1, &it.2, scan.opts.offline)?;
            if c.name == "erlang" {
                ts.retain(|t| erlang::side_branch(t, &otp_tags).is_none());
            }
            candidates.push((it.clone(), ts));
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
        let past = past_eol_pip(scan, c)?;
        let c = past.as_ref().unwrap_or(c);
        let recs = osv::records_for(&answers, c.osv.iter().chain(&c.osv_also));
        let mut failing = scan.advisories(c, &recs, c.osv.as_ref().and_then(|o| newer.get(o)), "fail", None);
        if c.name == "postgres" {
            failing = postgres(scan, c, &pg)? || failing;
        }
        if c.name == "mise" {
            mise(scan, c)?;
        }
        if c.name == "erlang"
            && let Some(why) = erlang::unlisted(c, c.osv.as_ref().and_then(|o| answers.get(o)), &otp_tags)
        {
            scan.unchecked(&format!("Erlang/OTP at {}", c.path), &why);
        }
        if let Some((_, repo)) = GITHUB_LATEST.iter().find(|(n, _)| *n == c.name) {
            latest(scan, c, repo, failing)?;
        }
        if c.eol.is_some() {
            scan.eol(c, failing)?;
        }
    }
    Ok(answers)
}

/// A pip package of a Python whose release line is past end of life, with
/// its fix turned into a suggestion, or None when it is not one, the line
/// still has support, or endoflife.date's answer for Python is not on hand.
///
/// The answer is read from the copy the scan already keeps for the Python
/// runtimes ([`endoflife::support_end`]); nothing is asked here. Releases
/// that fix a package often drop the interpreters that are past end of
/// life, so pip answers "No matching distribution found" for the fix
/// the scan would otherwise offer to run unattended.
///
/// Example: `requests` in a Python 3.9, 3.9 ended on 2025-10-31: not
/// unattended, "Python 3.9 is past end of life ... try it anyway: ...".
fn past_eol_pip(scan: &Scan, c: &Component) -> Result<Option<Component>> {
    let Some(line) = c.extra.get(packages::PY_LINE) else { return Ok(None) };
    if !c.auto || !c.fix.contains(" -m pip install") {
        return Ok(None);
    }
    let ended = match endoflife::support_end(&scan.cache, "python", line)? {
        Some(day) if !day.is_empty() => endoflife::past(&Value::String(day)),
        _ => false,
    };
    if !ended {
        return Ok(None);
    }
    let name = c.osv.as_ref().map_or(c.name.as_str(), |o| o.1.as_str());
    let mut adjusted = c.clone();
    adjusted.auto = false;
    adjusted.fix = format!(
        "Python {line} is past end of life, so releases that fix {name} may no longer support it: move the project to a supported Python. You may still try: {}",
        c.fix
    );
    Ok(Some(adjusted))
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

/// A tool behind its latest GitHub release warns (OUTDATED), unless an
/// advisory already fails it, naming the exploited CVEs CISA listed for
/// its product in the last months (GitHub gives no date for when this
/// version was superseded, so they can't fail it). An entry added after
/// the latest release was published isn't named: that release may not
/// fix it.
///
/// Example: FreeSWITCH 1.11.2, latest 1.11.3 published 2026-08-28, a KEV
/// entry added 2026-11-09: a plain OUTDATED warning naming no CVE.
pub fn latest(scan: &mut Scan, c: &Component, repo: &str, failing: bool) -> Result<()> {
    let r = releases::github_release(&scan.cache, scan.net, repo, scan.opts.offline);
    let (latest, published) = scan.guard(&format!("latest {} release (GitHub)", c.name), r, (String::new(), 0.0))?;
    if latest.is_empty() || failing || versions::same_or_newer(&c.version, &latest) {
        return Ok(());
    }
    let (fix_cmd, fix_auto) = fix_with(c, &latest);
    let mut f = Finding {
        vuln_id: "OUTDATED".into(),
        status: "warn".into(),
        fixed: latest.clone(),
        fix_cmd,
        fix_auto,
        note: format!("behind {latest}, the latest {} release", c.name),
        ..Finding::of(c)
    };
    let gap = Gap { latest_released: Some(published).filter(|t| *t > 0.0), ..Gap::default() };
    crate::checks::machine::exploited::escalate(&mut f, c, &scan.kev_entries, gap);
    scan.add(f);
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
