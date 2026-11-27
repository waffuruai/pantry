//! endoflife.date: each product's release cycles and when each one's
//! support ends, fetched side by side and cached.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::source;
use crate::sources::file::url;
use crate::utils::dates::{epoch, parse_date, today};
use crate::utils::net::Net;
use rusqlite::params;
use serde_json::Value;

/// What endoflife.date says about one release cycle.
#[derive(Debug, PartialEq)]
pub struct Eol {
    pub cycle: String,
    /// The end-of-life date when it has passed ("True" for a bare `true`).
    pub ended: Option<String>,
    pub latest: String,
    /// When the cycle's first release came out (its `releaseDate`, an
    /// epoch), when the page gives one.
    pub released: Option<f64>,
    /// Cycles still supported.
    pub supported: Vec<String>,
}

/// Fetch every product's endoflife.date page that isn't fresh, side by
/// side, and store them; a product that can't be fetched is left for
/// [`eol`] to report.
pub fn eol_prefetch(cache: &Cache, net: &dyn Net, products: &[String], offline: bool) -> Result<()> {
    if offline {
        return Ok(());
    }
    let mut stale: Vec<String> = Vec::new();
    for p in products {
        if !stale.contains(p) && stale_page(cache, p)? {
            stale.push(p.clone());
        }
    }
    let fetched = crate::utils::parallel::par_map(&stale, 8, |p| {
        fetch::get_json(net, "endoflife", &url("endoflife").replace("{}", p), &[])
    });
    for (p, r) in stale.iter().zip(fetched) {
        match r {
            Ok(data) => eol_store(cache, p, data.as_ref())?,
            Err(e) if e.is_source() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Whether `product`'s stored page needs fetching: not fresh, or stored
/// before release dates were kept (`released` NULL; a page without one
/// stores "").
fn stale_page(cache: &Cache, product: &str) -> Result<bool> {
    let old: bool = cache.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM eol WHERE product = ? AND released IS NULL)",
        [product],
        |r| r.get(0),
    )?;
    Ok(old || !cache.fresh(&format!("eol_at:{product}"), source("endoflife").refresh)?)
}

fn eol_store(cache: &Cache, product: &str, data: Option<&Value>) -> Result<()> {
    // One transaction: the product's old cycles or its new ones, never part of them.
    cache.atomically(|| eol_store_now(cache, product, data))
}

fn eol_store_now(cache: &Cache, product: &str, data: Option<&Value>) -> Result<()> {
    cache.conn.execute("DELETE FROM eol WHERE product = ?", [product])?;
    let rows = data.and_then(Value::as_array).cloned().unwrap_or_default();
    let mut released = serde_json::Map::new();
    for c in rows {
        let cyc = match &c["cycle"] {
            Value::String(s) => s.clone(),
            Value::Null => continue,
            other => other.to_string(),
        };
        if let Some(day) = c.get("releaseDate").and_then(Value::as_str).filter(|d| parse_date(d).is_some()) {
            released.insert(cyc.clone(), day.into());
        }
        let latest = match c.get("latest") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        let end = c.get("eol").cloned().unwrap_or(Value::Null).to_string();
        let released = c.get("releaseDate").and_then(Value::as_str).unwrap_or("");
        cache.conn.execute(
            "INSERT OR REPLACE INTO eol (product, cycle, eol, latest, released) VALUES (?, ?, ?, ?, ?)",
            params![product, cyc, end, latest, released],
        )?;
    }
    cache.set(&released_key(product), &Value::Object(released).to_string())?;
    cache.touch(&format!("eol_at:{product}"))
}

fn released_key(product: &str) -> String {
    format!("eol_released:{product}")
}

/// When `cycle` of `product` was first released (`2024-11-21` for PHP
/// 8.4), from the copy [`eol`] and [`eol_prefetch`] keep; None when it was
/// never fetched or the page names no date. Nothing is asked.
pub fn released(cache: &Cache, product: &str, cycle: &str) -> Result<Option<String>> {
    let Some(text) = cache.get(&released_key(product))? else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(v.get(cycle).and_then(Value::as_str).map(str::to_string))
}

/// When support for `cycle` of `product` ends or ended, from the copy
/// [`eol`] and [`eol_prefetch`] keep: `""` while it has no end date,
/// `"1970-01-01"` when it ended on a day the page doesn't name; None when
/// the cycle was never fetched. Nothing is asked.
pub fn support_end(cache: &Cache, product: &str, cycle: &str) -> Result<Option<String>> {
    let mut stmt = cache.conn.prepare("SELECT eol FROM eol WHERE product = ? AND cycle = ?")?;
    let end: Option<Option<String>> =
        stmt.query_map([product, cycle], |r| r.get::<_, Option<String>>(0))?.next().transpose()?;
    let Some(end) = end else { return Ok(None) };
    Ok(Some(match serde_json::from_str::<Value>(&end.unwrap_or_default()).unwrap_or(Value::Null) {
        Value::String(day) => day,
        Value::Bool(true) => "1970-01-01".into(),
        _ => String::new(),
    }))
}

/// Keep `data` as endoflife.date's page for `product`, as a fetch does.
#[cfg(test)]
pub fn store_for_tests(cache: &Cache, product: &str, data: &Value) {
    eol_store(cache, product, Some(data)).unwrap();
}

/// endoflife.date's view of `cycle` of `product`, or None when it doesn't
/// know the cycle.
pub fn eol(cache: &Cache, net: &dyn Net, product: &str, cycle: &str, offline: bool) -> Result<Option<Eol>> {
    if !offline && stale_page(cache, product)? {
        match fetch::get_json(net, "endoflife", &url("endoflife").replace("{}", product), &[]) {
            Ok(data) => eol_store(cache, product, data.as_ref())?,
            Err(e) if e.is_source() => {}
            Err(e) => return Err(e),
        }
    }
    let mut stmt = cache.conn.prepare("SELECT cycle, eol, latest, released FROM eol WHERE product = ?")?;
    let text = |r: &rusqlite::Row, i: usize| r.get::<_, Option<String>>(i).map(Option::unwrap_or_default);
    let rows: Vec<(String, String, String, String)> = stmt
        .query_map([product], |r| Ok((text(r, 0)?, text(r, 1)?, text(r, 2)?, text(r, 3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        return Err(Error::Offline(format!("endoflife.date ({product}) unreachable and not cached")));
    }
    let end_of = |e: &str| serde_json::from_str::<Value>(e).unwrap_or(Value::Null);
    let supported: Vec<String> =
        rows.iter().filter(|(_, e, _, _)| !past(&end_of(e))).map(|(c, _, _, _)| c.clone()).collect();
    for (c, e, latest, released) in &rows {
        if c == cycle {
            let end = end_of(e);
            let ended = past(&end).then(|| match &end {
                Value::String(s) => s.clone(),
                _ => "True".to_string(), // as Python prints it
            });
            let released = Some(epoch(released)).filter(|t| *t > 0.0);
            return Ok(Some(Eol { cycle: c.clone(), ended, latest: latest.clone(), released, supported }));
        }
    }
    Ok(None)
}

/// Whether an endoflife.date `eol` value (a date, or true/false) has passed.
pub fn past(end: &Value) -> bool {
    match end {
        Value::Bool(b) => *b,
        Value::String(s) => parse_date(s).is_some_and(|d| d <= today()),
        _ => false,
    }
}

#[cfg(test)]
#[path = "endoflife_tests.rs"]
mod tests;
