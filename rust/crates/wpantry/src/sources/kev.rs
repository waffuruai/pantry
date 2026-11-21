//! CISA's Known Exploited Vulnerabilities list, refetched daily with an
//! ETag. Unreachable with nothing cached is `Offline`, never clean.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::utils::json::{self, str_at};
use crate::utils::net::Net;
use rusqlite::params;
use std::collections::HashSet;

/// One entry of the list as the cache keeps it: the CVE, the day CISA
/// added it (YYYY-MM-DD), and the vendor and product CISA names it under
/// (`vendorProject`, `product`; empty in a cache from before they were kept).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub cve: String,
    pub added: String,
    pub vendor: String,
    pub product: String,
}

/// The CVE ids in CISA's Known Exploited Vulnerabilities list.
pub fn kev(cache: &Cache, net: &dyn Net, offline: bool) -> Result<HashSet<String>> {
    // A cache from before the vendor and product were kept has them NULL:
    // forget its ETag and age, so the next fetch downloads the whole list
    // rather than getting a 304 that leaves them empty.
    let old: bool = cache.conn.query_row("SELECT EXISTS (SELECT 1 FROM kev WHERE vendor IS NULL)", [], |r| r.get(0))?;
    if old && !offline {
        cache.unset("kev_etag")?;
        cache.unset("kev_at")?;
    }
    if let Some(body) = fetch::file(cache, net, "cisa-kev", "kev", offline)? {
        // A copy with nothing in it is refused: the last good list stays.
        let rows: Vec<(Entry, String)> = match json::parse(&body, json::MAX_DOCUMENT) {
            Ok(data) => json::arr_at(&data, "vulnerabilities")
                .iter()
                .map(|v| {
                    let entry = Entry {
                        cve: str_at(v, "cveID").to_string(),
                        added: str_at(v, "dateAdded").to_string(),
                        vendor: str_at(v, "vendorProject").to_string(),
                        product: str_at(v, "product").to_string(),
                    };
                    (entry, str_at(v, "vulnerabilityName").to_string())
                })
                .filter(|(e, _)| !e.cve.is_empty())
                .collect(),
            Err(e) => {
                fetch::rejected("cisa-kev", &e.to_string());
                Vec::new()
            }
        };
        if rows.is_empty() {
            fetch::rejected("cisa-kev", "no vulnerabilities in the catalog");
        } else {
            cache.conn.execute("DELETE FROM kev", [])?;
            let mut stmt = cache
                .conn
                .prepare("INSERT OR REPLACE INTO kev (cve, added, name, vendor, product) VALUES (?, ?, ?, ?, ?)")?;
            for (e, name) in &rows {
                stmt.execute(params![e.cve, e.added, name, e.vendor, e.product])?;
            }
            drop(stmt);
            cache.commit()?;
        }
    }
    let ids = cache.kev_ids()?;
    if ids.is_empty() {
        return Err(Error::Offline("CISA KEV list unreachable and not cached".into()));
    }
    Ok(ids)
}

/// Every entry the cache holds, with its vendor and product ("" where a
/// cache from before kept none).
pub fn entries(cache: &Cache) -> Result<Vec<Entry>> {
    let mut stmt = cache.conn.prepare("SELECT cve, added, vendor, product FROM kev")?;
    let text = |r: &rusqlite::Row, i: usize| r.get::<_, Option<String>>(i).map(Option::unwrap_or_default);
    let rows = stmt.query_map([], |r| {
        Ok(Entry { cve: text(r, 0)?, added: text(r, 1)?, vendor: text(r, 2)?, product: text(r, 3)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
#[path = "kev_tests.rs"]
mod tests;
