//! CVE records by vendor and product, from CIRCL's Vulnerability-Lookup
//! (`vulnerability.circl.lu`): the CVE Program's records (CVE JSON 5) as
//! their publishers wrote them, indexed by the `vendor` and `product` of
//! each `affected[]` entry. It covers what OSV doesn't: desktop and
//! industrial software sold outside any package ecosystem.
//!
//! Two kinds of request, each answer kept in the cache for the source's
//! `refresh`:
//!
//! - `browse/<vendor>`: the product names the index knows for a vendor,
//!   one request per vendor of the installed programs;
//! - `vulnerability/search/<vendor>/<product>`: that product's records,
//!   paged, asked only for a product name that matches an installed
//!   program's.
//!
//! What is kept of a record is what the judgement needs: its id, title,
//! CVSS score and `affected[]` entries. A copy that can't be refreshed
//! stays in use; a vendor or product never fetched is missing, and the
//! check that needs it reports it not checked.
//!
//! Example (what the check does for one program):
//!
//! ```text
//! browse/circutor                                  -> ["powerstudio scada wave", ...]
//! vulnerability/search/circutor/powerstudio%20scada%20wave?page=1&per_page=100
//!                                                  -> {"total_count": 2, "results": {"cvelistv5": [[id, record]], ...}}
//! ```

use crate::db::Cache;
use crate::error::Result;
use crate::sources::cve_scores;
use crate::sources::fetch;
use crate::sources::file::{source, url};
use crate::utils::json::arr_at;
use crate::utils::net::Net;
use serde_json::{Value, json};

/// The source's id in `sources.toml`.
pub const ID: &str = "cve-records";
/// Requests in flight at once: the index is a public service, kept polite.
const PARALLEL: usize = 4;
/// Pages of 100 read per product; a product with more is read in part, and
/// says so ([`Records::complete`]). MySQL Server, the largest Pantry asks
/// about, had 23 on 2026-11-18 (2246 entries across the index's sources).
pub const MAX_PAGES: u64 = 30;

/// One CVE record, as much of it as the judgement needs.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub id: String,
    pub title: String,
    /// The best CVSS base score the record carries (the publisher's, else an
    /// added one's), and its CVSS version.
    pub score: Option<(f64, String)>,
    /// The record's `affected[]` entries: vendor, product, versions,
    /// defaultStatus.
    pub affected: Vec<Value>,
}

/// A product's records, and whether every page of them was read.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Records {
    pub records: Vec<Record>,
    pub complete: bool,
}

/// A path segment, percent-encoded: every byte but the unreserved ones.
pub fn segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn products_key(vendor: &str) -> String {
    format!("cve_records_products:{vendor}")
}

fn records_key(vendor: &str, product: &str) -> String {
    format!("cve_records:{vendor}\u{1f}{product}")
}

/// The product names the index knows for `vendor`, from the cache; None
/// when they were never fetched.
pub fn products(cache: &Cache, vendor: &str) -> Result<Option<Vec<String>>> {
    let Some(text) = cache.get(&products_key(vendor))? else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(Some(v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()))
}

/// `product`'s records from the cache; None when they were never fetched.
pub fn records(cache: &Cache, vendor: &str, product: &str) -> Result<Option<Records>> {
    let Some(text) = cache.get(&records_key(vendor, product))? else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let records = arr_at(&v, "records")
        .iter()
        .map(|r| Record {
            id: r["id"].as_str().unwrap_or_default().to_string(),
            title: r["title"].as_str().unwrap_or_default().to_string(),
            score: r["score"].as_f64().map(|s| (s, r["cvss_version"].as_str().unwrap_or_default().to_string())),
            affected: arr_at(r, "affected").to_vec(),
        })
        .collect();
    Ok(Some(Records { records, complete: v["complete"].as_bool().unwrap_or(false) }))
}

/// Fetch the product lists of the `vendors` whose copy isn't fresh, side
/// by side, and keep them; one that can't be fetched keeps its last copy.
pub fn prefetch_products(cache: &Cache, net: &dyn Net, vendors: &[String], offline: bool) -> Result<()> {
    let keys: Vec<(String, String)> = vendors.iter().map(|v| (products_key(v), v.clone())).collect();
    prefetch(cache, &keys, offline, |vendor| fetch_products(net, vendor))
}

/// Fetch the records of the (vendor, product) pairs whose copy isn't
/// fresh, side by side, and keep them.
pub fn prefetch_records(cache: &Cache, net: &dyn Net, pairs: &[(String, String)], offline: bool) -> Result<()> {
    let keys: Vec<(String, String)> = pairs.iter().map(|(v, p)| (records_key(v, p), format!("{v}\u{1f}{p}"))).collect();
    prefetch(cache, &keys, offline, |arg| {
        let (vendor, product) = arg.split_once('\u{1f}').unwrap_or((arg, ""));
        fetch_records(net, vendor, product)
    })
}

/// `get` for every (cache key, argument) not fresh, at most [`PARALLEL`]
/// at once; each answer is stored under its key, and one that failed as a
/// source leaves the key as it was.
fn prefetch(
    cache: &Cache,
    keys: &[(String, String)],
    offline: bool,
    get: impl Fn(&str) -> Result<Value> + Sync,
) -> Result<()> {
    if offline || fetch::on(ID).is_err() {
        return Ok(());
    }
    let refresh = source(ID).refresh;
    let mut stale: Vec<&(String, String)> = Vec::new();
    for k in keys {
        if !stale.iter().any(|s| s.0 == k.0) && !cache.fresh(&format!("{}_at", k.0), refresh)? {
            stale.push(k);
        }
    }
    let fetched = crate::utils::parallel::par_map(&stale, PARALLEL, |(_, arg)| get(arg));
    for ((key, _), r) in stale.iter().zip(fetched) {
        match r {
            Ok(v) => {
                cache.set(key, &v.to_string())?;
                cache.touch(&format!("{key}_at"))?;
            }
            Err(e) if e.is_source() => {}
            Err(e) => return Err(e),
        }
    }
    cache.commit()
}

fn fetch_products(net: &dyn Net, vendor: &str) -> Result<Value> {
    let u = url("cve-records").replace("{}", &format!("browse/{}", segment(vendor)));
    match fetch::get_json(net, ID, &u, &[])? {
        None => Ok(json!([])),
        Some(v @ Value::Array(_)) => Ok(v),
        Some(_) => Err(fetch::invalid(ID, &format!("browse/{vendor}: not a list of products"))),
    }
}

fn fetch_records(net: &dyn Net, vendor: &str, product: &str) -> Result<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut complete = false;
    for page in 1..=MAX_PAGES {
        let u = url("cve-records").replace(
            "{}",
            &format!("vulnerability/search/{}/{}?page={page}&per_page=100", segment(vendor), segment(product)),
        );
        let Some(v) = fetch::get_json(net, ID, &u, &[])? else {
            complete = true;
            break;
        };
        let Some(results) = v.get("results").filter(|r| r.is_object()) else {
            return Err(fetch::invalid(ID, &format!("search/{vendor}/{product}: no results")));
        };
        // Each source's page is a list of [id, record]; the CVE list's are
        // the publishers' own records, the shape the judgement reads.
        let mut n = 0;
        for (_, list) in results.as_object().into_iter().flatten() {
            n += list.as_array().map_or(0, Vec::len);
        }
        out.extend(arr_at(results, "cvelistv5").iter().filter_map(|pair| trim(pair.get(1)?)));
        let total = v["total_count"].as_u64().unwrap_or(0);
        let size = v["page_size"].as_u64().unwrap_or(100).max(1);
        if n == 0 || page * size >= total {
            complete = true;
            break;
        }
    }
    Ok(json!({"complete": complete, "records": out}))
}

/// What is kept of a published CVE JSON 5 record; None for a rejected or
/// reserved one, or one without an id.
pub fn trim(rec: &Value) -> Option<Value> {
    let meta = rec.get("cveMetadata")?;
    if meta.get("state").and_then(Value::as_str) != Some("PUBLISHED") {
        return None;
    }
    let id = meta.get("cveId").and_then(Value::as_str).filter(|s| !s.is_empty())?.to_ascii_uppercase();
    let cna = rec.get("containers").and_then(|c| c.get("cna")).cloned().unwrap_or(Value::Null);
    let title = cna.get("title").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| {
        let desc =
            arr_at(&cna, "descriptions").iter().find(|d| d["lang"].as_str().is_some_and(|l| l.starts_with("en")));
        desc.and_then(|d| d["value"].as_str()).unwrap_or_default().chars().take(200).collect()
    });
    let affected: Vec<Value> = arr_at(&cna, "affected")
        .iter()
        .map(|a| {
            json!({
                "vendor": a.get("vendor").cloned().unwrap_or(Value::Null),
                "product": a.get("product").cloned().unwrap_or(Value::Null),
                "versions": a.get("versions").cloned().unwrap_or(json!([])),
                "defaultStatus": a.get("defaultStatus").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let score = cve_scores::of_cve_record(rec).map(|(s, _, _)| s);
    Some(json!({
        "id": id,
        "title": title,
        "score": score.as_ref().map(|s| s.value),
        "cvss_version": score.as_ref().map(|s| s.version.clone()),
        "affected": affected,
    }))
}

#[cfg(test)]
#[path = "cve_records_tests.rs"]
pub(crate) mod tests;
