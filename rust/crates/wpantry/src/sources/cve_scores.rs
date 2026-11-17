//! CVSS scores for the CVEs whose advisories carry none. An app's or a
//! language's advisory is often filed without a score (the Go project
//! publishes none); the CVE itself usually has one. They are asked for in
//! order, each answer kept in the cache's `cve_scores` table for the
//! source's `refresh` (a week), a CVE with no score included:
//!
//! 1. OSV's own record for the CVE (`api.osv.dev/v1/vulns/CVE-…`, the
//!    host every scan already asks), imported from the CVE list with NVD's
//!    score where there is one;
//! 2. the CVE record at CVE.org (`cveawg.mitre.org/api/cve/CVE-…`): the
//!    publisher's own score, else the one CISA adds when it reviews the
//!    CVE ("Vulnrichment").
//!
//! Only the CVE ids are sent, only for findings that apply here and have
//! no score, and only once a week each. A source that can't be reached
//! leaves the score empty; it is asked again next scan.

use crate::db::Cache;
use crate::error::Result;
use crate::sources::{fetch, file};
use crate::utils::cvss::{self, Score};
use crate::utils::net::Net;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cve_scores (\
  cve TEXT PRIMARY KEY, score REAL, version TEXT, vector TEXT, source TEXT, checked_at REAL);";

/// Requests in flight at once.
const PARALLEL: usize = 8;
/// The most CVEs asked about in one scan; the rest wait for the next.
pub const MAX_PER_SCAN: usize = 500;

/// A score and where it came from: `osv`, `cve.org`, `cve.org (CISA)`.
pub type Found = (Score, String, String);

/// The score a CVE record (CVE JSON 5) carries: the publisher's (the CNA
/// container's), else an added one's (ADP, CISA's first); the newest CVSS
/// version in the container that has one. With its vector, and who scored it.
pub fn of_cve_record(rec: &Value) -> Option<Found> {
    let containers = rec.get("containers")?;
    let mut scorers: Vec<(&Value, String)> = Vec::new();
    if let Some(cna) = containers.get("cna") {
        scorers.push((cna, "cve.org".into()));
    }
    let mut adp: Vec<&Value> =
        containers.get("adp").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    adp.sort_by_key(|a| short_name(a) != "CISA-ADP");
    for a in adp {
        scorers.push((a, format!("cve.org ({})", short_name(a).trim_end_matches("-ADP"))));
    }
    for (container, who) in scorers {
        let metrics = container.get("metrics").and_then(Value::as_array).cloned().unwrap_or_default();
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0"] {
            for m in &metrics {
                let Some(c) = m.get(key) else { continue };
                let vector = c.get("vectorString").and_then(Value::as_str).unwrap_or_default();
                let score = cvss::score(vector).or_else(|| {
                    let value = c.get("baseScore").and_then(Value::as_f64).filter(|v| (0.0..=10.0).contains(v))?;
                    let version = c.get("version").and_then(Value::as_str).unwrap_or("3.x").to_string();
                    Some(Score { value, version })
                });
                if let Some(s) = score {
                    return Some((s, vector.to_string(), who));
                }
            }
        }
    }
    None
}

fn short_name(container: &Value) -> &str {
    container.get("providerMetadata").and_then(|p| p.get("shortName")).and_then(Value::as_str).unwrap_or_default()
}

/// The score OSV's own record for the CVE carries.
fn from_osv(net: &dyn Net, cve: &str) -> Result<Option<Found>> {
    let url = format!("{}/vulns/{cve}", file::url("osv"));
    Ok(fetch::get_json(net, "osv", &url, &[])?.filter(|r| r.get("id").and_then(Value::as_str) == Some(cve)).and_then(
        |r| {
            let s = cvss::of_record(&r)?;
            let vector = r
                .get("severity")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter()
                        .filter_map(|e| e.get("score").and_then(Value::as_str))
                        .find(|v| cvss::score(v).as_ref() == Some(&s))
                })
                .unwrap_or_default()
                .to_string();
            Some((s, vector, "osv".to_string()))
        },
    ))
}

/// The score CVE.org's record carries.
fn from_cve_org(net: &dyn Net, cve: &str) -> Result<Option<Found>> {
    fetch::on("cve-org")?;
    let url = format!("{}{cve}", file::url("cve-org"));
    Ok(fetch::get_json(net, "cve-org", &url, &[])?.as_ref().and_then(of_cve_record))
}

/// Ask about every CVE in `cves` the cache has no fresh answer for (at most
/// [`MAX_PER_SCAN`]), OSV first, then CVE.org, and keep each answer.
pub fn fill(cache: &Cache, net: &dyn Net, offline: bool, cves: &[String]) -> Result<()> {
    if offline || cves.is_empty() {
        return Ok(());
    }
    let max_age = file::source("cve-org").refresh;
    let now = crate::utils::os::now();
    let mut due: Vec<&String> = Vec::new();
    for cve in cves {
        let checked: Option<f64> = cache
            .conn
            .query_row("SELECT checked_at FROM cve_scores WHERE cve = ?", [cve], |r| r.get(0))
            .optional()?
            .flatten();
        if checked.is_none_or(|t| now - t > max_age) && !due.contains(&cve) {
            due.push(cve);
        }
    }
    due.truncate(MAX_PER_SCAN);
    let answers = crate::utils::parallel::par_map(&due, PARALLEL, |cve| {
        let found = match from_osv(net, cve) {
            Ok(Some(f)) => Ok(Some(f)),
            Ok(None) => from_cve_org(net, cve),
            // OSV unreachable: CVE.org may still answer.
            Err(_) => from_cve_org(net, cve),
        };
        (cve.to_string(), found)
    });
    for (cve, found) in answers {
        match found {
            Ok(Some((s, vector, source))) => {
                cache.conn.execute(
                    "INSERT OR REPLACE INTO cve_scores VALUES (?, ?, ?, ?, ?, ?)",
                    params![cve, s.value, s.version, vector, source, now],
                )?;
            }
            // Asked, and neither has a score: don't ask again this week.
            Ok(None) => {
                cache
                    .conn
                    .execute("INSERT OR REPLACE INTO cve_scores VALUES (?, NULL, '', '', '', ?)", params![cve, now])?;
            }
            // Unreachable: nothing kept, so the next scan asks again.
            Err(_) => {}
        }
    }
    Ok(())
}

/// A CVE's score from the cache, when one was found.
pub fn lookup(cache: &Cache, cve: &str) -> Result<Option<Score>> {
    Ok(cache
        .conn
        .query_row("SELECT score, version FROM cve_scores WHERE cve = ? AND score IS NOT NULL", [cve], |r| {
            Ok(Score { value: r.get(0)?, version: r.get(1)? })
        })
        .optional()?)
}

#[cfg(test)]
#[path = "cve_scores_tests.rs"]
mod tests;
