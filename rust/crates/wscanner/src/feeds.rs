//! Side feeds: CISA KEV, endoflife.date and the Arch security tracker. Each
//! is cached and refetched only when stale (with an ETag where the server
//! supports one). A feed that can't be reached and has nothing cached is
//! `Offline`, so the caller reports it unchecked instead of clean. The
//! other Python feeds (casks, browsers, PostgreSQL, extensions, GitHub
//! releases) arrive with the machine inventory (phase 2).

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::net::{self, Net};
use rusqlite::params;
use serde_json::Value;
use std::collections::HashSet;

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";

/// Body bytes when a refetch returned new data, else None.
fn etag_fetch(
    cache: &Cache,
    net: &dyn Net,
    url: &str,
    key: &str,
    max_age: f64,
    offline: bool,
) -> Result<Option<Vec<u8>>> {
    if offline || cache.fresh(&format!("{key}_at"), max_age)? {
        return Ok(None);
    }
    let etag = cache.get(&format!("{key}_etag"))?;
    let resp = match net::request(net, url, None, &[], etag.as_deref()) {
        Ok(r) => r,
        Err(e) if e.is_source() => return Ok(None),
        Err(e) => return Err(e),
    };
    cache.touch(&format!("{key}_at"))?;
    if resp.status != 200 {
        return Ok(None);
    }
    if let Some(e) = &resp.etag {
        cache.set(&format!("{key}_etag"), e)?;
    }
    Ok(Some(resp.body))
}

/// The CVE ids in CISA's Known Exploited Vulnerabilities list.
pub fn kev(cache: &Cache, net: &dyn Net, offline: bool) -> Result<HashSet<String>> {
    if let Some(body) = etag_fetch(cache, net, KEV_URL, "kev", DAY, offline)? {
        let data = json::parse(&body, json::MAX_DOCUMENT)?;
        cache.conn.execute("DELETE FROM kev", [])?;
        let mut stmt = cache.conn.prepare("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)")?;
        for v in json::arr_at(&data, "vulnerabilities") {
            let id = str_at(v, "cveID");
            if !id.is_empty() {
                stmt.execute(params![id, str_at(v, "dateAdded"), str_at(v, "vulnerabilityName")])?;
            }
        }
        drop(stmt);
        cache.commit()?;
    }
    let ids = cache.kev_ids()?;
    if ids.is_empty() {
        return Err(Error::Offline("CISA KEV list unreachable and not cached".into()));
    }
    Ok(ids)
}

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

/// endoflife.date's view of `cycle` of `product`, or None when it doesn't
/// know the cycle.
pub fn eol(cache: &Cache, net: &dyn Net, product: &str, cycle: &str, offline: bool) -> Result<Option<Eol>> {
    if !(offline || cache.fresh(&format!("eol_at:{product}"), 7.0 * DAY)?) {
        match net::get_json(net, &format!("https://endoflife.date/api/{product}.json"), &[]) {
            Ok(data) => {
                cache.conn.execute("DELETE FROM eol WHERE product = ?", [product])?;
                let rows = data.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
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
                    cache.conn.execute(
                        "INSERT OR REPLACE INTO eol VALUES (?, ?, ?, ?)",
                        params![product, cyc, end, latest],
                    )?;
                }
                cache.touch(&format!("eol_at:{product}"))?;
            }
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

/// Days since 1970-01-01 for an ISO date (YYYY-MM-DD).
pub fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant's days_from_civil.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Today (UTC), in days since 1970-01-01.
pub fn today() -> i64 {
    (crate::system::now() / 86400.0).floor() as i64
}

/// The Arch Linux security tracker's advisory groups.
pub fn arch(cache: &Cache, net: &dyn Net, offline: bool) -> Result<Value> {
    let fetch = || match net::get_json(net, ARCH_URL, &[])? {
        Some(Value::Array(groups)) if !groups.is_empty() => Ok(Value::Array(groups)),
        _ => Err(Error::Offline("the Arch security tracker returned nothing".into())),
    };
    cache.memo("arch-tracker", fetch, DAY, "", false, offline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Fake, Response};
    use serde_json::json;

    fn cache() -> (crate::system::TempDir, Cache) {
        let d = crate::system::TempDir::new("feeds").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        (d, c)
    }

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
    fn unreachable_feed_raises_instead_of_reporting_clean() {
        let (_d, c) = cache();
        assert!(matches!(kev(&c, &Fake::offline(), true), Err(Error::Offline(_))));
        assert!(matches!(eol(&c, &Fake::offline(), "nodejs", "24", true), Err(Error::Offline(_))));
        assert!(matches!(kev(&c, &Fake::offline(), false), Err(Error::Offline(_))));
    }

    #[test]
    fn kev_fetch_with_etag() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert!(r.header("If-None-Match").is_none());
            Ok(Response {
                status: 200,
                body: json!({"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-01-01"}]})
                    .to_string()
                    .into_bytes(),
                etag: Some("\"k1\"".into()),
            })
        });
        assert_eq!(kev(&c, &net, false).unwrap(), HashSet::from(["CVE-2026-1".to_string()]));
        assert_eq!(c.get("kev_etag").unwrap().as_deref(), Some("\"k1\""));
        // Fresh: no request at all.
        assert!(kev(&c, &Fake::new(|_| panic!("fresh")), false).is_ok());
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
}
