//! Homebrew's advisory database (`github.com/Homebrew/advisory-database`,
//! CC0): OSV records `BREW-<formula>-<CVE>` for the CVEs a homebrew-core
//! formula's `patch` resolves, each with the Homebrew version and revision
//! that ships the patch (`{"introduced": "0"}, {"fixed": "0.12.20_1"}`).
//! Regenerated daily; read from CIRCL's Vulnerability-Lookup, which
//! mirrors it as source `osv_homebrew`, one request per formula (paged),
//! sending its name only.
//!
//! The repo has no per-formula index (some 17,000 files), and CIRCL allows
//! 20 anonymous requests a minute, so a formula is asked about only when
//! its CVE records name a CVE for it ([`crate::checks::machine::brew_cves`]).
//!
//! Example:
//!
//! ```text
//! vulnerability/?source=osv_homebrew&product=lrzsz&per_page=100&page=1
//!     -> [{"id": "BREW-lrzsz-CVE-2018-10195", "upstream": ["CVE-2018-10195"],
//!          "affected": [{"package": {"ecosystem": "Homebrew", "name": "lrzsz"},
//!                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.20_1"}]}]}]}]
//! ```

use crate::checks::ecosystems::versions;
use crate::db::Cache;
use crate::error::Result;
use crate::sources::cve_records::segment;
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::json::{arr_at, str_at, strs_at};
use crate::utils::net::Net;
use serde_json::{Value, json};
use std::cmp::Ordering;

/// The source's id in `sources.toml`.
pub const ID: &str = "homebrew-advisories";
/// Requests in flight at once: CIRCL allows 20 a minute.
const PARALLEL: usize = 2;
const PER_PAGE: usize = 100;
/// Pages read per formula; a formula with more is read in part.
pub const MAX_PAGES: usize = 10;

/// One `BREW-` record, as much as the check needs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Advisory {
    pub id: String,
    /// The CVEs (or other ids) it is the Homebrew side of.
    pub upstream: Vec<String>,
    /// Its intervals for the formula: introduced, and the fixed version (or
    /// the last affected one, `true`), None when open.
    pub intervals: Vec<(String, Option<(bool, String)>)>,
}

impl Advisory {
    /// Whether this record is about `id` (a CVE): its upstream names it.
    pub fn about(&self, id: &str) -> bool {
        self.upstream.iter().any(|u| u == id)
    }

    /// Whether `installed` (a Cellar version, revision and all) is in one
    /// of its intervals: Some(the fixed version, "" when the interval names
    /// none), None when it isn't.
    pub fn affects(&self, installed: &str) -> Option<String> {
        self.intervals.iter().find_map(|(from, to)| {
            let after = from == "0" || cmp(installed, from) != Ordering::Less;
            let before = match to {
                None => true,
                Some((true, last)) => cmp(installed, last) != Ordering::Greater,
                Some((false, fixed)) => cmp(installed, fixed) == Ordering::Less,
            };
            (after && before).then(|| match to {
                Some((false, fixed)) => fixed.clone(),
                _ => String::new(),
            })
        })
    }
}

/// A formula's records, and whether every page of them was read.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Advisories {
    pub records: Vec<Advisory>,
    pub complete: bool,
}

/// A Homebrew version as its upstream version and revision: `6.0_8` is
/// (`6.0`, 8), `2.10.0` is (`2.10.0`, 0).
pub fn split(v: &str) -> (&str, u64) {
    match v.rsplit_once('_') {
        Some((base, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => {
            (base, rev.parse().unwrap_or(0))
        }
        _ => (v, 0),
    }
}

/// Homebrew's order: by upstream version, then revision, so `1.81.6_5` <
/// `1.81.6_6` < `1.82.0`.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let ((va, ra), (vb, rb)) = (split(a), split(b));
    versions::cmp(va, vb).then(ra.cmp(&rb))
}

fn key(formula: &str) -> String {
    format!("homebrew_advisories:{formula}")
}

/// What is kept of a record, for `formula`; None when it doesn't name it.
pub fn trim(rec: &Value, formula: &str) -> Option<Value> {
    let mut intervals: Vec<Value> = Vec::new();
    for a in arr_at(rec, "affected").iter().filter(|a| str_at(&a["package"], "name") == formula) {
        for r in arr_at(a, "ranges").iter().filter(|r| str_at(r, "type") == "ECOSYSTEM") {
            let mut start: Option<String> = None;
            for e in arr_at(r, "events") {
                if let Some(v) = e.get("introduced").and_then(Value::as_str) {
                    if let Some(s) = start.replace(v.to_string()) {
                        intervals.push(json!({"introduced": s}));
                    }
                } else if let Some(v) = e.get("fixed").and_then(Value::as_str) {
                    intervals.push(json!({"introduced": start.take().unwrap_or_else(|| "0".into()), "fixed": v}));
                } else if let Some(v) = e.get("last_affected").and_then(Value::as_str) {
                    intervals
                        .push(json!({"introduced": start.take().unwrap_or_else(|| "0".into()), "last_affected": v}));
                }
            }
            if let Some(s) = start {
                intervals.push(json!({"introduced": s}));
            }
        }
    }
    let id = str_at(rec, "id");
    (!id.is_empty() && !intervals.is_empty())
        .then(|| json!({"id": id, "upstream": strs_at(rec, "upstream"), "intervals": intervals}))
}

/// `formula`'s records from the cache; None when they were never fetched.
pub fn advisories(cache: &Cache, formula: &str) -> Result<Option<Advisories>> {
    let Some(text) = cache.get(&key(formula))? else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let records = arr_at(&v, "records")
        .iter()
        .map(|r| Advisory {
            id: str_at(r, "id").to_string(),
            upstream: strs_at(r, "upstream"),
            intervals: arr_at(r, "intervals")
                .iter()
                .map(|i| {
                    let to = match (
                        i.get("fixed").and_then(Value::as_str),
                        i.get("last_affected").and_then(Value::as_str),
                    ) {
                        (Some(f), _) => Some((false, f.to_string())),
                        (None, Some(l)) => Some((true, l.to_string())),
                        _ => None,
                    };
                    (str_at(i, "introduced").to_string(), to)
                })
                .collect(),
        })
        .collect();
    Ok(Some(Advisories { records, complete: v["complete"].as_bool().unwrap_or(false) }))
}

/// Fetch the records of the `formulae` whose copy isn't fresh and keep them.
pub fn prefetch(cache: &Cache, net: &dyn Net, formulae: &[String], offline: bool) -> Result<()> {
    let keys: Vec<(String, String)> = formulae.iter().map(|f| (key(f), f.clone())).collect();
    fetch::prefetch(cache, ID, &keys, PARALLEL, offline, |formula| fetch_records(net, formula))
}

fn fetch_records(net: &dyn Net, formula: &str) -> Result<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut complete = false;
    for page in 1..=MAX_PAGES {
        let u = format!("{}&per_page={PER_PAGE}&page={page}", url(ID).replace("{}", &segment(formula)));
        let list = match fetch::get_json(net, ID, &u, &[])? {
            None => Vec::new(),
            Some(Value::Array(a)) => a,
            Some(_) => return Err(fetch::invalid(ID, &format!("{formula}: not a list of records"))),
        };
        out.extend(list.iter().filter_map(|r| trim(r, formula)));
        if list.len() < PER_PAGE {
            complete = true;
            break;
        }
    }
    Ok(json!({"complete": complete, "records": out}))
}

#[cfg(test)]
#[path = "homebrew_advisories_tests.rs"]
pub(crate) mod tests;
