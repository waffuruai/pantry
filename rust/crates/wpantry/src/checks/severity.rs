//! Every finding's severity, CVSS score and EPSS score, set once all the
//! checks have run, in CVSS's words (LOW, MEDIUM, HIGH, CRITICAL).
//!
//! An advisory's come from its record, or from the records it is an alias
//! of (an app's CVE is often filed as a GitHub advisory): the record's own
//! label (GitHub's MODERATE is MEDIUM, Red Hat's IMPORTANT is HIGH), else
//! the band its CVSS score falls in (3.x or 4.0, the newest it carries).
//! When none of them has a score, its CVE ids are asked about
//! ([`crate::sources::cve_scores`]: OSV's record for the CVE, then
//! CVE.org's). Its EPSS score is the highest of its CVE ids'. EPSS is likelihood, not
//! impact: it is shown beside the severity and never changes it.
//!
//! wpantry's own checks get a severity from [`own`], one table: what they
//! mean for this machine, not a CVSS score.

use crate::db::Cache;
use crate::finding::Finding;
use crate::utils::cvss;
use crate::utils::net::Net;
use serde_json::Value;
use std::collections::HashMap;

/// The severity of a finding of wpantry's own (not an advisory), when the
/// check didn't set one: by its marker, its kind, and whether it fails.
pub fn own(f: &Finding) -> &'static str {
    let fails = f.status == "fail";
    match (f.vuln_id.as_str(), f.kind.as_str()) {
        ("MALICIOUS" | "MODEL-KNOWN-BAD" | "MODEL-APPENDED-PROGRAM", _) => "CRITICAL",
        ("EOL" | "BROWSER" | "OS-UPDATE" | "DISTRUSTED-CA", _) => {
            if fails {
                "HIGH"
            } else {
                "MEDIUM"
            }
        }
        // Behind a release with exploited CVEs in the gap ([`crate::checks::machine::exploited`]).
        ("OUTDATED", _) if fails => "HIGH",
        ("OUTDATED" | "UNPINNED" | "MISSING" | "LICENSE" | "DEPRECATED" | "REPO-POLICY" | "IGNORE-FILE", _) => "LOW",
        // A repo's own file asking to skip a check that protects you from it.
        ("IGNORE-PROTECTED", _) => "MEDIUM",
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
        (_, "suspect-code" | "hidden-text" | "document" | "model") => {
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
                | "MODEL"
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
    #[cfg(test)]
    lookups::LOOKUPS.with(|n| n.set(n.get() + 1));
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

/// Counts the `records` scans of `vulns` (an unindexed `aliases LIKE`) on
/// this thread, so a test can prove how many a scan or a report makes.
#[cfg(test)]
pub(crate) mod lookups {
    thread_local! {
        pub static LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    pub fn reset() {
        LOOKUPS.with(|n| n.set(0));
    }
    pub fn taken() -> usize {
        LOOKUPS.with(std::cell::Cell::get)
    }
}

/// What one run has already asked the cache about advisories: each id's
/// records (one `aliases LIKE` scan of `vulns`) and text, kept so an id is
/// looked up once however many findings or exposures name it. Share one
/// across every step of a scan or a report.
#[derive(Default)]
pub struct Advisories {
    recs: HashMap<String, Vec<Value>>,
    texts: HashMap<String, AdvisoryText>,
}

impl Advisories {
    fn records(&mut self, cache: &Cache, id: &str) -> &[Value] {
        self.recs.entry(id.to_string()).or_insert_with(|| records(cache, id))
    }

    /// [`advisory_text`], remembered.
    pub fn text(&mut self, cache: &Cache, id: &str) -> AdvisoryText {
        if let Some(t) = self.texts.get(id) {
            return t.clone();
        }
        let t = text_of(cache, id, self.records(cache, id));
        self.texts.insert(id.to_string(), t.clone());
        t
    }
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

/// What one advisory's records give: (severity label, CVSS, EPSS), and its
/// CVE ids.
type Scores = (String, Option<cvss::Score>, Option<(f64, f64)>, Vec<String>);

fn scores(cache: &Cache, id: &str, recs: &[Value]) -> Scores {
    let score = recs.iter().find_map(cvss::of_record);
    let label = recs.iter().map(crate::db::severity_of).find(|s| !s.is_empty()).unwrap_or_default();
    let ids = cves(id, recs);
    let epss = ids
        .iter()
        .filter_map(|c| crate::sources::epss::lookup(cache, c).ok().flatten())
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    (label, score, epss, ids)
}

/// What identifies the local record a finding is rated from: its source, id
/// and component, which `for_finding` prefers when two records share an alias.
/// Two findings of one id and source but different packages may need two records.
fn local_key(f: &Finding) -> (String, String, String) {
    (f.local_source.clone(), f.vuln_id.clone(), f.component.clone())
}

/// Set every finding's severity (in CVSS's words), CVSS and EPSS. An
/// advisory with no score in the cache has its CVEs asked about (unless
/// `offline`); one that still has none keeps its record's label, or gets
/// wpantry's own rating.
pub fn enrich(cache: &Cache, net: &dyn Net, offline: bool, findings: &mut [Finding]) {
    // An OSV finding is rated from OSV's records, a finding of a source on this
    // machine from its own record and nothing else: a local record never
    // moves an OSV rating, and an OSV record that shares a local finding's id
    // never rates it. A local record with no score asks nobody for one.
    let mut local: HashMap<(String, String, String), (Scores, AdvisoryText)> = HashMap::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked" && !f.local_source.is_empty() && is_advisory(&f.vuln_id))
    {
        local.entry(local_key(f)).or_insert_with(|| {
            let own = crate::sources::osv_dir::for_finding(cache, &f.local_source, &f.vuln_id, &f.component);
            let recs: Vec<Value> = own.ok().flatten().map(|(r, _)| vec![r]).unwrap_or_default();
            (scores(cache, &f.vuln_id, &recs), text_of(cache, &f.vuln_id, &recs))
        });
    }
    let mut known: HashMap<String, Scores> = HashMap::new();
    // One memo for the scores and the text below: an id's records are read
    // from the cache once (the read scans `vulns`).
    let mut advisories = Advisories::default();
    for f in findings.iter().filter(|f| f.kind != "unchecked" && f.local_source.is_empty() && is_advisory(&f.vuln_id)) {
        if !known.contains_key(&f.vuln_id) {
            let s = scores(cache, &f.vuln_id, advisories.records(cache, &f.vuln_id));
            known.insert(f.vuln_id.clone(), s);
        }
    }
    let unscored: Vec<String> = known.values().filter(|s| s.1.is_none()).flat_map(|s| s.3.iter().cloned()).collect();
    if !unscored.is_empty() {
        // An unreachable source leaves the scores empty; the next scan asks again.
        let _ = crate::sources::cve_scores::fill(cache, net, offline, &unscored);
        for s in known.values_mut().filter(|s| s.1.is_none()) {
            s.1 =
                s.3.iter()
                    .filter_map(|c| crate::sources::cve_scores::lookup(cache, c).ok().flatten())
                    .max_by(|a, b| a.value.partial_cmp(&b.value).unwrap_or(std::cmp::Ordering::Equal));
        }
    }
    let (epss_date, epss_model) = crate::sources::epss::edition(cache).unwrap_or_default();
    for s in known.values_mut().chain(local.values_mut().map(|l| &mut l.0)).filter(|s| s.0.is_empty()) {
        s.0 = s.1.as_ref().map(|sc| cvss::label(sc.value).to_string()).unwrap_or_default();
    }
    for f in findings.iter_mut().filter(|f| f.kind != "unchecked" && is_advisory(&f.vuln_id)) {
        let text = match local.get(&local_key(f)) {
            Some(l) if !f.local_source.is_empty() => l.1.clone(),
            _ => advisories.text(cache, &f.vuln_id),
        };
        fill_text(f, &text);
    }
    for f in findings.iter_mut().filter(|f| f.kind != "unchecked") {
        let rated =
            if f.local_source.is_empty() { known.get(&f.vuln_id) } else { local.get(&local_key(f)).map(|l| &l.0) };
        if let Some((label, score, epss, _)) = rated.cloned() {
            if let Some(s) = score {
                f.cvss = Some(s.value);
                f.cvss_version = s.version;
            }
            if let Some((e, p)) = epss {
                f.epss = Some(e);
                f.epss_percentile = Some(p);
                f.epss_date = epss_date.clone();
                f.epss_model = epss_model.clone();
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

/// What the cache says an advisory is, for a reader: its summary, its
/// other ids and its weakness types (see [`Finding::summary`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdvisoryText {
    pub summary: String,
    pub aliases: Vec<String>,
    pub cwe: Vec<String>,
}

/// An advisory's text from the records the cache holds for it (it and the
/// records naming it as an alias, its own first), and CISA KEV's name for
/// one of its CVEs when no record has a summary. Nothing is fetched.
pub fn advisory_text(cache: &Cache, id: &str) -> AdvisoryText {
    Advisories::default().text(cache, id)
}

fn text_of(cache: &Cache, id: &str, recs: &[Value]) -> AdvisoryText {
    let summary = recs
        .iter()
        .map(|r| crate::finding::clean_summary(crate::utils::json::str_at(r, "summary")))
        .find(|s| !s.is_empty())
        .or_else(|| {
            cves(id, recs).iter().find_map(|c| {
                cache
                    .conn
                    .query_row("SELECT name FROM kev WHERE cve = ?", [c], |r| r.get::<_, Option<String>>(0))
                    .ok()
                    .flatten()
                    .map(|n| crate::finding::clean_summary(&n))
                    .filter(|n| !n.is_empty())
            })
        })
        .unwrap_or_default();
    let mut aliases: Vec<String> = Vec::new();
    for r in recs {
        for a in crate::sources::osv::ids_of(r) {
            if a != id && crate::finding::plain_id(&a) && !aliases.contains(&a) {
                aliases.push(a);
            }
        }
    }
    // CVE ids first, then GitHub's, then the rest, each in record order.
    aliases.sort_by_key(|a| {
        if a.starts_with("CVE-") {
            0
        } else if a.starts_with("GHSA-") {
            1
        } else {
            2
        }
    });
    aliases.truncate(12);
    let mut cwe: Vec<String> = Vec::new();
    for r in recs {
        let ids = r.get("database_specific").map(|d| crate::utils::json::strs_at(d, "cwe_ids")).unwrap_or_default();
        for c in ids.iter().filter_map(|c| crate::finding::cwe_id(c)) {
            if !cwe.contains(&c) {
                cwe.push(c);
            }
        }
    }
    cwe.truncate(8);
    AdvisoryText { summary, aliases, cwe }
}

/// Fill a finding's summary, aliases and weakness types from `text` where
/// the check left them empty.
pub fn fill_text(f: &mut Finding, text: &AdvisoryText) {
    if f.summary.is_empty() {
        f.summary = text.summary.clone();
    }
    if f.aliases.is_empty() {
        f.aliases = text.aliases.clone();
    }
    if f.cwe.is_empty() {
        f.cwe = text.cwe.clone();
    }
}

#[cfg(test)]
#[path = "severity_tests.rs"]
mod tests;
