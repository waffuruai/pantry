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
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing::CARGO_LOCK;
    use crate::checks::supply_chain::{projects, testing};
    use crate::error::Error;
    use crate::sources::testing::ids;
    use crate::utils::net::{Fake, Response};
    use crate::utils::temp::TempDir;
    use serde_json::json;

    #[test]
    fn spdx_expressions() {
        let allow = ids(&["MIT", "Apache-2.0", "BSD-3-Clause"]);
        assert_eq!(satisfied("MIT", &allow), Some(true));
        assert_eq!(satisfied("mit", &allow), Some(true));
        assert_eq!(satisfied("MIT OR GPL-3.0-only", &allow), Some(true));
        assert_eq!(satisfied("MIT AND GPL-3.0-only", &allow), Some(false));
        assert_eq!(satisfied("(Apache-2.0 OR MIT) AND BSD-3-Clause", &allow), Some(true));
        assert_eq!(satisfied("Apache-2.0 WITH LLVM-exception", &allow), Some(true));
        assert_eq!(satisfied("GPL-2.0+", &allow), Some(false));
        assert_eq!(satisfied("MIT AND", &allow), None);
        assert_eq!(judge(&[], &allow), Some(ids(&["UNKNOWN"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only"]), &allow), Some(ids(&["GPL-3.0-only"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only", "MIT"]), &allow), None);
        assert_eq!(judge(&ids(&["non-standard"]), &allow), Some(ids(&["non-standard"])), "custom terms need review");
    }

    /// `--licenses`: a license outside the allowlist warns, none at all is
    /// only counted, and deps.dev unreachable is unchecked.
    #[test]
    fn licenses_outside_the_allowlist_warn() {
        let d = TempDir::new("licenses").unwrap();
        let net = Fake::new(|r| {
            if let Some(rest) = r.url.strip_prefix("https://api.deps.dev/v3/systems/cargo/packages/") {
                let licenses = match rest.split('/').next().unwrap_or("") {
                    "serde" => json!(["GPL-3.0-only"]),
                    "sedre" => json!(["MIT OR Apache-2.0"]),
                    _ => json!([]),
                };
                return Ok(Response::ok(json!({"licenses": licenses}).to_string()));
            }
            testing::osv(r, &[]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
        });
        let mut s = testing::scan(&net, &d, Options { licenses: true, ..Default::default() });
        let (name, root) = testing::repo(&d, "app");
        testing::write(
            &root,
            "Cargo.lock",
            format!(
                "{CARGO_LOCK}\n[[package]]\nname = \"itoa\"\nversion = \"1.0.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ),
        );
        projects::projects(&mut s, &[(name, root.clone())]).unwrap();
        let lic = testing::by_id(&s, "LICENSE");
        assert_eq!(lic.len(), 1, "{:?}", s.findings);
        assert_eq!((lic[0].component.as_str(), lic[0].status.as_str()), ("serde", "warn"));
        assert_eq!(lic[0].note, format!("license GPL-3.0-only isn't in {LICENSES}"));
        assert_eq!(lic[0].location, root.join("Cargo.lock").to_string_lossy());
        assert_eq!(s.unknown_licenses, 1, "itoa has none; sedre's MIT passes");

        let d = TempDir::new("licenses-off").unwrap();
        let net = Fake::new(|r| {
            if r.url.starts_with("https://api.deps.dev/") {
                return Err(Error::Offline("deps.dev: down".into()));
            }
            testing::osv(r, &[]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
        });
        let mut s = testing::scan(&net, &d, Options { licenses: true, ..Default::default() });
        let (name, root) = testing::repo(&d, "app");
        testing::write(&root, "Cargo.lock", CARGO_LOCK);
        projects::projects(&mut s, &[(name, root)]).unwrap();
        assert_eq!(testing::unchecked(&s), ["dependency licenses (deps.dev)"]);
    }
}
