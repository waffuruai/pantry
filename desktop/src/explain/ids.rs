//! Public ids a finding can be looked up by, their notice addresses, and
//! the EPSS score as words.

use super::is_advisory;
use crate::data::Finding;
use serde::Serialize;

/// One public id for the finding, and where to read about it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Identifier {
    pub id: String,
    pub url: Option<String>,
}

/// An id safe to show and to put in a link: letters, digits and `-_.:`.
fn plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

/// Where to read an advisory: cve.org for CVE ids, GitHub's advisory
/// database for GHSA ids, osv.dev for the rest. None for demo and test
/// ids, which no database holds.
///
/// ```ignore
/// assert_eq!(advisory_url("CVE-2021-25900").unwrap(), "https://www.cve.org/CVERecord?id=CVE-2021-25900");
/// ```
pub fn advisory_url(id: &str) -> Option<String> {
    if !plain_id(id) || id.starts_with("DEMO-") || id.starts_with("TEST-") {
        return None;
    }
    Some(if id.starts_with("CVE-") {
        format!("https://www.cve.org/CVERecord?id={id}")
    } else if id.starts_with("GHSA-") {
        format!("https://github.com/advisories/{id}")
    } else {
        format!("https://osv.dev/vulnerability/{id}")
    })
}

/// The finding's public ids, CVE ids first, then its own id (when it is an
/// advisory or an OpenSSF malicious-package report, `MAL-2026-1`) and its
/// other aliases, each once.
pub fn identifiers(f: &Finding) -> Vec<Identifier> {
    let mut ids: Vec<&str> = Vec::new();
    if is_advisory(f) || (f.kind != "unchecked" && f.vuln_id.starts_with("MAL-")) {
        ids.push(&f.vuln_id);
    }
    let mut aliases: Vec<&str> = f.aliases.iter().map(String::as_str).collect();
    aliases.sort_by_key(|a| !a.starts_with("CVE-"));
    for alias in aliases {
        if !ids.contains(&alias) {
            ids.push(alias);
        }
    }
    // CVE ids lead: they are the ones people search for.
    ids.sort_by_key(|id| !id.starts_with("CVE-"));
    ids.into_iter()
        .filter(|id| plain_id(id))
        .map(|id| Identifier {
            id: id.to_owned(),
            url: advisory_url(id),
        })
        .collect()
}

/// The label for [`epss_text`] in the technical details.
pub const EPSS_LABEL: &str = "Estimated chance attackers will try this in the next 30 days";

/// EPSS as a person reads it, for [`EPSS_LABEL`]: "about 3 in 100 (EPSS)".
/// EPSS estimates attempts against flaws like this one anywhere, not the
/// chance that this computer is attacked, so it never says "you".
pub fn epss_text(epss: f64) -> String {
    let n = (epss.clamp(0.0, 1.0) * 100.0).round() as i64;
    if n < 1 {
        "less than 1 in 100 (EPSS)".into()
    } else {
        format!("about {n} in 100 (EPSS)")
    }
}

#[cfg(test)]
#[path = "ids_tests.rs"]
mod tests;
