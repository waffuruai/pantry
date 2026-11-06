//! CSV: the latest findings, one row per finding with its aliases and
//! link, or with `--history` the exposure log, one row per exposure.

use crate::db::Cache;
use crate::error::Result;
use crate::history::{Exposure, Fix, ScanRow, stamp};
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
        "SELECT f.vuln_id, v.aliases, v.url, f.component, f.kind, f.version, f.fixed, f.severity, f.kev, f.status, f.location, \
         f.cvss, f.cvss_version, f.epss, f.epss_percentile \
         FROM findings f LEFT JOIN vulns v ON v.id = f.vuln_id OR (' ' || v.aliases || ' ') LIKE ('% ' || f.vuln_id || ' %') \
         GROUP BY f.vuln_id, f.component, f.version, f.location",
    )?;
    let rows: Vec<Vec<String>> = stmt
        .query_map([], |r| {
            (0..15)
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
    let mut text = String::from(
        "id,aliases,url,component,kind,affected_version,safe_version,severity,kev,status,location,cvss,cvss_version,epss,epss_percentile\r\n",
    );
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

/// The remediation log: each fix, when, who ran it, its result and the
/// scan that verified it.
pub fn fixes(fixes: &[Fix]) -> String {
    let mut t = line(&["when", "user", "host", "command", "mode", "ok", "verified_scan"]);
    for f in fixes {
        let verified = f.verified_scan.map(|v| v.to_string()).unwrap_or_default();
        t.push_str(&line(&[
            &stamp(f.at),
            &f.user,
            &f.host,
            &f.command,
            &f.mode,
            if f.ok { "true" } else { "false" },
            &verified,
        ]));
    }
    t
}

/// The audit log's scans.
pub fn scans(scans: &[ScanRow]) -> String {
    let mut t = line(&["scan", "finished", "host", "user", "version", "scope", "fails", "warns", "unchecked"]);
    for s in scans {
        t.push_str(&line(&[
            &s.id.to_string(),
            &stamp(s.finished_at),
            &s.host,
            &s.user,
            &s.version,
            &s.scope,
            &s.fails.to_string(),
            &s.warns.to_string(),
            &s.unchecked.to_string(),
        ]));
    }
    t
}

/// The summary's figures, `metric,value`.
pub fn summary(report: &super::Report) -> String {
    super::summary::csv(&super::summary::summary(report))
}
