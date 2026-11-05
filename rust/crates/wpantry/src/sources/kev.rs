//! CISA's Known Exploited Vulnerabilities list, refetched daily with an
//! ETag. Unreachable with nothing cached is `Offline`, never clean.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::utils::json::{self, str_at};
use crate::utils::net::Net;
use rusqlite::params;
use std::collections::HashSet;

/// The CVE ids in CISA's Known Exploited Vulnerabilities list.
pub fn kev(cache: &Cache, net: &dyn Net, offline: bool) -> Result<HashSet<String>> {
    if let Some(body) = fetch::file(cache, net, "cisa-kev", "kev", offline)? {
        // A copy with nothing in it is refused: the last good list stays.
        let rows: Vec<(String, String, String)> = match json::parse(&body, json::MAX_DOCUMENT) {
            Ok(data) => json::arr_at(&data, "vulnerabilities")
                .iter()
                .map(|v| {
                    (
                        str_at(v, "cveID").to_string(),
                        str_at(v, "dateAdded").to_string(),
                        str_at(v, "vulnerabilityName").to_string(),
                    )
                })
                .filter(|(id, _, _)| !id.is_empty())
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
            let mut stmt = cache.conn.prepare("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)")?;
            for (id, added, name) in &rows {
                stmt.execute(params![id, added, name])?;
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

#[cfg(test)]
#[path = "kev_tests.rs"]
mod tests;
