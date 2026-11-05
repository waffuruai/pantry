//! endoflife.date: each product's release cycles and when each one's
//! support ends, fetched side by side and cached.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::sources::file::url;
use crate::utils::dates::{parse_date, today};
use crate::utils::net::{self, Net};
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
        if !stale.contains(p) && !cache.fresh(&format!("eol_at:{p}"), 7.0 * DAY)? {
            stale.push(p.clone());
        }
    }
    let fetched =
        crate::utils::parallel::par_map(&stale, 8, |p| net::get_json(net, &url("endoflife").replace("{}", p), &[]));
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
    if !(offline || cache.fresh(&format!("eol_at:{product}"), 7.0 * DAY)?) {
        match net::get_json(net, &url("endoflife").replace("{}", product), &[]) {
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
mod tests {
    use super::*;
    use crate::sources::testing::cache;
    use crate::utils::dates::{days_from_civil, parse_date};
    use crate::utils::net::{Fake, Response};
    use serde_json::json;

    #[test]
    fn civil_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_date("2000-03-01"), Some(11017));
        assert_eq!(parse_date("2026-10-27"), Some(20753));
        assert_eq!(parse_date("2026-13-01"), None);
        assert!(
            past(&json!(true)) && !past(&json!(false)) && past(&json!("2000-01-01")) && !past(&json!("2999-01-01"))
        );
    }

    #[test]
    fn eol_cycles() {
        let (_d, c) = cache();
        let net = Fake::new(|_| {
            Ok(Response::ok(
                json!([{"cycle": "24", "eol": "2999-04-30", "latest": "24.11.0"},
                                   {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
                                   {"cycle": 16, "eol": true, "latest": "16.20.2"}])
                .to_string(),
            ))
        });
        let e = eol(&c, &net, "nodejs", "18", false).unwrap().unwrap();
        assert_eq!(
            (e.ended.as_deref(), e.latest.as_str(), e.supported.clone()),
            (Some("2025-04-30"), "18.20.8", vec!["24".to_string()])
        );
        assert_eq!(eol(&c, &net, "nodejs", "16", true).unwrap().unwrap().ended.as_deref(), Some("True"));
        assert_eq!(eol(&c, &net, "nodejs", "24", true).unwrap().unwrap().ended, None);
        assert_eq!(eol(&c, &net, "nodejs", "99", true).unwrap(), None);
    }

    /// The prefetch asks once per stale product, side by side, and the loop
    /// after it finds everything cached; a product that fails is left for
    /// `eol` to report.
    #[test]
    fn eol_prefetch_asks_once_per_product() {
        let (_d, c) = cache();
        let net = Fake::new(|req| {
            if req.url.ends_with("/down.json") {
                return Err(Error::Offline("down".into()));
            }
            Ok(Response::ok(json!([{"cycle": "1", "eol": false, "latest": "1.2.3"}]).to_string()))
        });
        let products: Vec<String> = ["a", "b", "a", "down"].iter().map(|s| s.to_string()).collect();
        eol_prefetch(&c, &net, &products, false).unwrap();
        let asked: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(asked.len(), 3, "{asked:?}");
        assert_eq!(eol(&c, &net, "a", "1", false).unwrap().unwrap().latest, "1.2.3");
        assert_eq!(net.requests().len(), 3, "a was cached by the prefetch");
        assert!(matches!(eol(&c, &net, "down", "1", true), Err(Error::Offline(_))));
        eol_prefetch(&c, &net, &products, true).unwrap();
        assert_eq!(net.requests().len(), 3, "offline asks nothing");
        eol_prefetch(&c, &net, &products, false).unwrap();
        assert_eq!(net.requests().len(), 4, "only the product that failed is asked again");
    }

    #[test]
    fn odd_cycles_and_stale_pages() {
        let (_d, c) = cache();
        let net = Fake::new(|_| {
            Ok(Response::ok(
                json!([{"cycle": null}, {"cycle": "1", "latest": null}, {"cycle": "2", "latest": 7, "eol": false}, {"cycle": "3"}])
                    .to_string(),
            ))
        });
        assert_eq!(eol(&c, &net, "p", "2", false).unwrap().unwrap().latest, "7");
        assert_eq!(eol(&c, &net, "p", "1", true).unwrap().unwrap().latest, "");
        assert_eq!(eol(&c, &net, "p", "3", true).unwrap().unwrap().latest, "");
        assert_eq!(eol(&c, &net, "p", "null", true).unwrap(), None);
        // Stale and unreachable, the stored page is served; a bug is not.
        c.set("eol_at:p", "0").unwrap();
        assert_eq!(eol(&c, &Fake::offline(), "p", "2", false).unwrap().unwrap().latest, "7");
        let bug = Fake::new(|_| Err(Error::Missing("not a source failure".into())));
        assert!(matches!(eol(&c, &bug, "p", "2", false), Err(Error::Missing(_))));
        assert!(!past(&json!(null)));
        assert_eq!(parse_date("2026-1-1"), None);
        assert_eq!(parse_date("2026-01"), None);
    }
}
