//! EPSS, the Exploit Prediction Scoring System (FIRST; scores by Empirical
//! Security, published freely every day): for every CVE, the probability
//! that it is exploited in the next 30 days, and its percentile. The whole
//! file is downloaded (about 3 MB, gzip) at most daily, so no CVE list from
//! this machine is sent anywhere, and kept in the cache's `epss` table.
//!
//! A copy that isn't EPSS's CSV, or has too few rows to be the whole set,
//! is refused: the last good one stays.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::utils::net::Net;
use rusqlite::{OptionalExtension, params};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL);";

/// Fewer rows than this is not the whole set (it has over 300,000).
const MIN_ROWS: usize = 1000;
/// The most a copy may hold once inflated.
const MAX_TEXT: usize = 256 << 20;

/// One CVE's row: its id, score and percentile.
pub type Row = (String, f64, f64);

/// What a copy holds: the score date and model version from its comment
/// line, and the rows.
#[derive(Debug, Default, PartialEq)]
pub struct Daily {
    pub date: String,
    pub model: String,
    pub rows: Vec<Row>,
}

/// EPSS's CSV: the score date and model version from its comment line
/// (`#model_version:v2026.06.15,score_date:2026-11-05T12:03:04Z`), and each
/// `cve,epss,percentile` row; None when it isn't that.
pub fn parse(text: &str) -> Option<Daily> {
    let mut copy = Daily::default();
    let mut header = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(meta) = line.strip_prefix('#') {
            for part in meta.split(',').map(str::trim) {
                if let Some(d) = part.strip_prefix("score_date:") {
                    copy.date = d.to_string();
                } else if let Some(m) = part.strip_prefix("model_version:") {
                    copy.model = m.to_string();
                }
            }
            continue;
        }
        if !header {
            if line != "cve,epss,percentile" {
                return None;
            }
            header = true;
            continue;
        }
        let mut f = line.split(',');
        let (Some(cve), Some(score), Some(pct)) = (f.next(), f.next(), f.next()) else { continue };
        let (Ok(score), Ok(pct)) = (score.parse::<f64>(), pct.parse::<f64>()) else { continue };
        if cve.starts_with("CVE-") && (0.0..=1.0).contains(&score) && (0.0..=1.0).contains(&pct) {
            copy.rows.push((cve.to_string(), score, pct));
        }
    }
    header.then_some(copy)
}

/// Refresh the scores when due (or unless `offline`); the number kept.
/// Unreachable with none kept is `Offline`.
pub fn refresh(cache: &Cache, net: &dyn Net, offline: bool) -> Result<usize> {
    if let Some(body) = fetch::file(cache, net, "epss", "epss", offline)? {
        let text = if crate::utils::archive::gzip::is_gzip(&body) {
            crate::utils::archive::gzip::gunzip(&body, MAX_TEXT).map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            Some(String::from_utf8_lossy(&body).into_owned())
        };
        match text.as_deref().and_then(parse) {
            Some(copy) if copy.rows.len() >= MIN_ROWS => {
                cache.conn.execute("DELETE FROM epss", [])?;
                let mut stmt = cache.conn.prepare("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)")?;
                for (cve, score, pct) in &copy.rows {
                    stmt.execute(params![cve, score, pct])?;
                }
                drop(stmt);
                cache.set("epss_date", &copy.date)?;
                cache.set("epss_model", &copy.model)?;
                cache.commit()?;
            }
            Some(copy) => fetch::rejected("epss", &format!("only {} scores: not the whole set", copy.rows.len())),
            None => fetch::rejected("epss", "not EPSS's CSV (cve,epss,percentile)"),
        }
    }
    let n: i64 = cache.conn.query_row("SELECT COUNT(*) FROM epss", [], |r| r.get(0))?;
    if n == 0 {
        return Err(Error::Offline("EPSS scores unreachable and not cached".into()));
    }
    Ok(n as usize)
}

/// The kept copy's score date and model version ("" when not kept).
pub fn edition(cache: &Cache) -> Result<(String, String)> {
    Ok((cache.get("epss_date")?.unwrap_or_default(), cache.get("epss_model")?.unwrap_or_default()))
}

/// A CVE's EPSS score and percentile, when the cache has it.
pub fn lookup(cache: &Cache, cve: &str) -> Result<Option<(f64, f64)>> {
    Ok(cache
        .conn
        .query_row("SELECT score, percentile FROM epss WHERE cve = ?", [cve], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?)
}

#[cfg(test)]
#[path = "epss_tests.rs"]
mod tests;
