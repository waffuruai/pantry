//! Dependency licenses (`--licenses`): each locked package's
//! declared licenses, judged against an allowlist of SPDX ids. A package
//! passes when its license expression can be satisfied with allowed ids
//! (`MIT OR GPL-3.0-only` passes an allowlist holding MIT); one with no
//! identifiable license is only counted. deps.dev's `non-standard` (custom
//! terms, such as a license that needs a company licence) is a license no
//! allowlist holds, so it is reported, not counted as unknown.
//! The declared licenses come from [`crate::sources::package_licenses`].

use crate::checks::supply_chain::LICENSES;
use crate::checks::{Scan, lockfiles};
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv::Item;
use std::path::PathBuf;

/// Whether an SPDX license expression can be satisfied with `allowed` ids:
/// OR needs one side, AND both; `X WITH exception` is judged as X; ids
/// compare case-insensitively, and `X+` (or-later) as X.
pub fn satisfied(expr: &str, allowed: &[String]) -> Option<bool> {
    let spaced = expr.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut i = 0;
    let v = or(&tokens, &mut i, allowed)?;
    (i == tokens.len()).then_some(v)
}

fn or(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = and(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("OR")) {
        *i += 1;
        let rhs = and(t, i, allowed)?;
        v = v || rhs;
    }
    Some(v)
}

fn and(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = atom(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("AND")) {
        *i += 1;
        let rhs = atom(t, i, allowed)?;
        v = v && rhs;
    }
    Some(v)
}

fn atom(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let w = *t.get(*i)?;
    *i += 1;
    if w == "(" {
        let v = or(t, i, allowed)?;
        if t.get(*i) != Some(&")") {
            return None;
        }
        *i += 1;
        return Some(v);
    }
    if w == ")" || w.eq_ignore_ascii_case("AND") || w.eq_ignore_ascii_case("OR") {
        return None;
    }
    if t.get(*i).is_some_and(|x| x.eq_ignore_ascii_case("WITH")) {
        *i += 2; // the exception doesn't change which license it is
    }
    let id = w.trim_end_matches('+');
    Some(allowed.iter().any(|a| a.eq_ignore_ascii_case(id)))
}

/// One package's verdict: None passes, Some(["UNKNOWN"]) has no license we
/// can judge, Some(ids) are the licenses outside the allowlist.
pub fn judge(licenses: &[String], allowed: &[String]) -> Option<Vec<String>> {
    if licenses.is_empty() {
        return Some(vec!["UNKNOWN".into()]);
    }
    // deps.dev lists one expression per declared license; any one passing is enough.
    let mut verdicts = licenses.iter().map(|l| satisfied(l, allowed));
    if verdicts.any(|v| v == Some(true)) {
        return None;
    }
    if licenses.iter().all(|l| satisfied(l, allowed).is_none()) {
        return Some(vec!["UNKNOWN".into()]);
    }
    Some(licenses.to_vec())
}

/// Dependencies whose license isn't in the allowlist warn; ones with no
/// identifiable license are counted (`--licenses`).
pub(crate) fn licenses(scan: &mut Scan, read: &[(PathBuf, Vec<lockfiles::Package>)]) -> Result<()> {
    let allowed = scan.opts.policy.licenses();
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    scan.status(&format!("Checking {} dependencies' licenses", items.len()));
    let status = scan.status;
    let found = match crate::sources::package_licenses::lookup(&scan.cache, scan.net, &items, scan.opts.offline, status)
    {
        Ok(f) => f,
        Err(e) if e.is_source() => {
            scan.unchecked("dependency licenses (deps.dev)", &e.to_string());
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut i = 0;
    for (f, ps) in read {
        for p in ps {
            let verdict = crate::checks::supply_chain::licenses::judge(&found[i], &allowed);
            i += 1;
            match verdict {
                None => {}
                Some(v) if v == ["UNKNOWN"] => scan.unknown_licenses += 1,
                Some(v) => scan.add(Finding {
                    kind: "license".into(),
                    component: p.name.clone(),
                    version: p.version.clone(),
                    location: f.to_string_lossy().into_owned(),
                    vuln_id: "LICENSE".into(),
                    status: "warn".into(),
                    note: format!("license {} isn't in {LICENSES}", v.join(", ")),
                    fix_cmd: format!("Review {}: replace it, or approve its license in {LICENSES}", p.name),
                    ..Default::default()
                }),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "licenses_tests.rs"]
mod tests;
