//! endoflife.date: each product's release cycles and when each one's
//! support ends, fetched side by side and cached.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::source;
use crate::sources::file::url;
use crate::utils::dates::{parse_date, today};
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
        if !stale.contains(p) && !cache.fresh(&format!("eol_at:{p}"), source("endoflife").refresh)? {
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

fn eol_store(cache: &Cache, product: &str, data: Option<&Value>) -> Result<()> {
    cache.conn.execute("DELETE FROM eol WHERE product = ?", [product])?;
    let rows = data.and_then(Value::as_array).cloned().unwrap_or_default();
    for c in rows {
        let cyc = match &c["cycle"] {
            Value::String(s) => s.clone(),
            Value::Null => continue,
            other => other.to_string(),
        };
        let latest = match c.get("latest") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        let end = c.get("eol").cloned().unwrap_or(Value::Null).to_string();
        cache.conn.execute("INSERT OR REPLACE INTO eol VALUES (?, ?, ?, ?)", params![product, cyc, end, latest])?;
    }
    cache.touch(&format!("eol_at:{product}"))
}

/// endoflife.date's view of `cycle` of `product`, or None when it doesn't
/// know the cycle.
pub fn eol(cache: &Cache, net: &dyn Net, product: &str, cycle: &str, offline: bool) -> Result<Option<Eol>> {
    if !(offline || cache.fresh(&format!("eol_at:{product}"), source("endoflife").refresh)?) {
        match fetch::get_json(net, "endoflife", &url("endoflife").replace("{}", product), &[]) {
            Ok(data) => eol_store(cache, product, data.as_ref())?,
            Err(e) if e.is_source() => {}
            Err(e) => return Err(e),
        }
    }
    let mut stmt = cache.conn.prepare("SELECT cycle, eol, latest FROM eol WHERE product = ?")?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map([product], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        return Err(Error::Offline(format!("endoflife.date ({product}) unreachable and not cached")));
    }
    let end_of = |e: &str| serde_json::from_str::<Value>(e).unwrap_or(Value::Null);
    let supported: Vec<String> = rows.iter().filter(|(_, e, _)| !past(&end_of(e))).map(|(c, _, _)| c.clone()).collect();
    for (c, e, latest) in &rows {
        if c == cycle {
            let end = end_of(e);
            let ended = past(&end).then(|| match &end {
                Value::String(s) => s.clone(),
                _ => "True".to_string(), // as Python prints it
            });
            return Ok(Some(Eol { cycle: c.clone(), ended, latest: latest.clone(), supported }));
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
