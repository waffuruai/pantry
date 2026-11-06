//! CSV: the latest findings, one row per finding with its aliases and
//! link, or with `--history` the exposure log, one row per exposure.

use crate::db::Cache;
use crate::error::Result;
use crate::history::Exposure;
use rusqlite::types::ValueRef;

/// One CSV field, quoted when it must be.
pub fn field(s: &str) -> String {
    if s.contains([',', '"', '\r', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

fn line(fields: &[&str]) -> String {
    let mut t = fields.iter().map(|f| field(f)).collect::<Vec<_>>().join(",");
    t.push_str("\r\n");
    t
}

/// The latest findings, each joined with its OSV record's aliases and URL.
pub fn findings(cache: &Cache) -> Result<String> {
    let mut stmt = cache.conn.prepare(
        "SELECT f.vuln_id, v.aliases, v.url, f.component, f.kind, f.version, f.fixed, f.severity, f.kev, f.status, f.location \
         FROM findings f LEFT JOIN vulns v ON v.id = f.vuln_id OR (' ' || v.aliases || ' ') LIKE ('% ' || f.vuln_id || ' %') \
         GROUP BY f.vuln_id, f.component, f.version, f.location",
    )?;
    let rows: Vec<Vec<String>> = stmt
        .query_map([], |r| {
            (0..11)
                .map(|i| {
                    Ok(match r.get_ref(i)? {
                        ValueRef::Null => String::new(),
                        ValueRef::Integer(n) => n.to_string(),
                        ValueRef::Real(x) => x.to_string(),
                        ValueRef::Text(t) | ValueRef::Blob(t) => String::from_utf8_lossy(t).into_owned(),
                    })
                })
                .collect()
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut text =
        String::from("id,aliases,url,component,kind,affected_version,safe_version,severity,kev,status,location\r\n");
    for mut r in rows {
        if r[2].is_empty() && r[0].starts_with("CVE-") {
            r[2] = format!("https://www.cve.org/CVERecord?id={}", r[0]);
        }
        text.push_str(&line(&r.iter().map(String::as_str).collect::<Vec<_>>()));
    }
    Ok(text)
}

/// The exposure log: what applied, from first seen to resolved, in the
/// columns every format shares ([`super::EXPOSURE_COLUMNS`]).
pub fn exposures(exposures: &[Exposure]) -> String {
    let names: Vec<&str> = super::EXPOSURE_COLUMNS.iter().map(|(n, _)| *n).collect();
    let mut t = line(&names);
    for e in exposures {
        let cells = super::exposure_cells(e);
        t.push_str(&line(&cells.iter().map(String::as_str).collect::<Vec<_>>()));
    }
    t
}
