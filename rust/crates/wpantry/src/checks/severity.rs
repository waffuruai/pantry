//! Every finding's severity, CVSS score and EPSS score, set once all the
//! checks have run, in CVSS's words (LOW, MEDIUM, HIGH, CRITICAL).
//!
//! An advisory's come from its record, or from the records it is an alias
//! of (an app's CVE is often filed as a GitHub advisory): the record's own
//! label (GitHub's MODERATE is MEDIUM, Red Hat's IMPORTANT is HIGH), else
//! the band its CVSS score falls in (3.x or 4.0, the newest it carries).
//! Its EPSS score is the highest of its CVE ids'. EPSS is likelihood, not
//! impact: it is shown beside the severity and never changes it.
//!
//! wpantry's own checks get a severity from [`own`], one table: what they
//! mean for this machine, not a CVSS score.

use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::cvss;
use serde_json::Value;
use std::collections::HashMap;

/// The severity of a finding of wpantry's own (not an advisory), when the
/// check didn't set one: by its marker, its kind, and whether it fails.
pub fn own(f: &Finding) -> &'static str {
    let fails = f.status == "fail";
    match (f.vuln_id.as_str(), f.kind.as_str()) {
        ("MALICIOUS", _) => "CRITICAL",
        ("EOL" | "BROWSER" | "OS-UPDATE" | "DISTRUSTED-CA", _) => {
            if fails {
                "HIGH"
            } else {
                "MEDIUM"
            }
        }
        ("OUTDATED" | "UNPINNED" | "MISSING" | "LICENSE" | "DEPRECATED" | "REPO-POLICY", _) => "LOW",
        ("INSTALL-SCRIPT" | "NPM-SCRIPTS", _) => {
            if fails {
                "MEDIUM"
            } else {
                "LOW"
            }
        }
        (_, "clipper" | "malware") => {
            if fails {
                "CRITICAL"
            } else {
                "MEDIUM"
            }
        }
        (_, "secret" | "repo-hook" | "persistence") => {
            if fails {
                "HIGH"
            } else {
                "MEDIUM"
            }
        }
        (_, "suspect-code" | "hidden-text" | "document") => {
            if fails {
                "HIGH"
            } else {
                "LOW"
            }
        }
        _ => {
            if fails {
                "HIGH"
            } else {
                "MEDIUM"
            }
        }
    }
}

/// Whether `id` names a public advisory (one OSV or a distro could hold a
/// record for), not one of wpantry's markers or rules.
pub fn is_advisory(id: &str) -> bool {
    let prefix = id.split('-').next().unwrap_or_default();
    id.contains('-')
        && prefix.len() >= 2
        && prefix.chars().all(|c| c.is_ascii_uppercase())
        && !id.starts_with("POSTURE-")
        && !matches!(
            prefix,
            "SUSPECT"
                | "HIDDEN"
                | "DOC"
                | "IMG"
                | "CLIPPER"
                | "PERSISTENCE"
                | "IOC"
                | "CONFUSABLE"
                | "AGENT"
                | "EXFIL"
                | "DANGEROUS"
                | "DISGUISED"
                | "REPO"
                | "OS"
                | "INSTALL"
                | "NPM"
                | "DISTRUSTED"
        )
}

/// What the cache knows of an advisory: every record that is it or names
/// it as an alias, its own first.
fn records(cache: &Cache, id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(Some(r)) = cache.vuln(id) {
        out.push(r);
    }
    let pattern = format!("% {id} %");
    if let Ok(mut stmt) =
        cache.conn.prepare("SELECT record FROM vulns WHERE id != ?1 AND (' ' || aliases || ' ') LIKE ?2")
    {
        let rows = stmt.query_map(rusqlite::params![id, pattern], |r| r.get::<_, Option<String>>(0));
        if let Ok(rows) = rows {
            for r in rows.flatten().flatten() {
                if let Ok(v) = serde_json::from_str::<Value>(&r) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The CVE ids among an advisory and its records' aliases.
fn cves(id: &str, recs: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: &str| {
        if s.starts_with("CVE-") && !out.iter().any(|o| o == s) {
            out.push(s.to_string());
        }
    };
    add(id);
    for r in recs {
        add(r.get("id").and_then(Value::as_str).unwrap_or_default());
        for a in crate::utils::json::arr_at(r, "aliases") {
            add(a.as_str().unwrap_or_default());
        }
    }
    out
}

/// What one advisory's records give: (severity, CVSS, EPSS).
type Scores = (String, Option<cvss::Score>, Option<(f64, f64)>);

fn scores(cache: &Cache, id: &str) -> Scores {
    let recs = records(cache, id);
    let score = recs.iter().find_map(cvss::of_record);
    let label = recs
        .iter()
        .map(crate::db::severity_of)
        .find(|s| !s.is_empty())
        .or_else(|| score.as_ref().map(|s| cvss::label(s.value).to_string()))
        .unwrap_or_default();
    let epss = cves(id, &recs)
        .iter()
        .filter_map(|c| crate::sources::epss::lookup(cache, c).ok().flatten())
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    (label, score, epss)
}

/// Set every finding's severity (in CVSS's words), CVSS and EPSS.
pub fn enrich(cache: &Cache, findings: &mut [Finding]) {
    let mut known: HashMap<String, Scores> = HashMap::new();
    for f in findings.iter_mut().filter(|f| f.kind != "unchecked") {
        if is_advisory(&f.vuln_id) {
            let (label, score, epss) =
                known.entry(f.vuln_id.clone()).or_insert_with(|| scores(cache, &f.vuln_id)).clone();
            if let Some(s) = score {
                f.cvss = Some(s.value);
                f.cvss_version = s.version;
            }
            if let Some((e, p)) = epss {
                f.epss = Some(e);
                f.epss_percentile = Some(p);
            }
            if cvss::word(&f.severity).is_empty() {
                f.severity = label;
            }
        }
        let word = cvss::word(&f.severity);
        f.severity =
            if word.is_empty() || word == "NONE" && f.status == "fail" { own(f).to_string() } else { word.to_string() };
    }
}

#[cfg(test)]
#[path = "severity_tests.rs"]
mod tests;
