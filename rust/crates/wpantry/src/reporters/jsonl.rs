//! `wpantry report --jsonl`: one JSON object per finding, joining what the
//! cache knows about it (the finding, the full OSV record, the exposure's
//! lifecycle across scans and the outcome of the fix `wpantry fix` ran), so a
//! consumer (wsentinel's triage-verdict corpus) reads one record and never
//! the cache tables. Additive to `scan --json`'s finding: the same keys,
//! plus `aliases`, `url`, `record`, `first_seen`, `last_seen`, `resolved_at`,
//! `days_exposed` and `fix`.
//!
//! With `all`, the resolved exposures the latest scan no longer lists are
//! rows too (their `status` is the last one seen, `resolved_at` is set):
//! that is where "fixed, N days later" comes from.

use crate::checks::severity::{Advisories, fill_text, is_advisory};
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::history::{self, Exposure};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

/// One row of the export, before the record and lifecycle are joined.
struct Row {
    finding: Finding,
    key: String,
}

fn from_finding(f: Finding) -> Row {
    let key = history::key_of(&f);
    Row { finding: f, key }
}

fn from_exposure(e: &Exposure) -> Row {
    let f = Finding {
        kind: e.kind.clone(),
        component: e.component.clone(),
        version: e.version.clone(),
        location: e.location.clone(),
        vuln_id: e.vuln_id.clone(),
        status: e.status.clone(),
        fixed: e.fixed.clone(),
        kev: e.kev,
        severity: e.severity.clone(),
        note: e.note.clone(),
        fix_cmd: e.fix_cmd.clone(),
        fix_auto: false,
        dep_scope: e.dep_scope.clone(),
        dep_direct: e.dep_direct,
        affected_range: e.affected_range.clone(),
        cvss: e.cvss,
        cvss_version: e.cvss_version.clone(),
        epss: e.epss,
        epss_percentile: e.epss_percentile,
        epss_date: String::new(),
        epss_model: String::new(),
        // Exposures never hold `unchecked` findings.
        excluded: false,
        ..Default::default()
    };
    from_finding(f)
}

/// The latest scan's findings, as saved.
pub fn findings(cache: &Cache) -> Result<Vec<Finding>> {
    findings_in(cache, &mut Advisories::default())
}

/// [`findings`], asking the cache about each advisory through `advisories`.
fn findings_in(cache: &Cache, advisories: &mut Advisories) -> Result<Vec<Finding>> {
    let mut stmt = cache.conn.prepare(
        "SELECT kind, component, version, location, vuln_id, status, fixed, kev, severity, note, fix_cmd, fix_auto, \
         dep_scope, dep_direct, affected_range, cvss, cvss_version, epss, epss_percentile, epss_date, epss_model, \
         excluded, summary, aliases, cwe, local_source, local_link FROM findings",
    )?;
    let rows = stmt.query_map([], |r| {
        let s = |i: usize| r.get::<_, Option<String>>(i).map(Option::unwrap_or_default);
        Ok(Finding {
            kind: s(0)?,
            component: s(1)?,
            version: s(2)?,
            location: s(3)?,
            vuln_id: s(4)?,
            status: s(5)?,
            fixed: s(6)?,
            kev: r.get::<_, Option<i64>>(7)?.unwrap_or(0) != 0,
            severity: s(8)?,
            note: s(9)?,
            fix_cmd: s(10)?,
            fix_auto: r.get::<_, Option<i64>>(11)?.unwrap_or(0) != 0,
            dep_scope: s(12)?,
            dep_direct: r.get::<_, Option<i64>>(13)?.map(|d| d != 0),
            affected_range: s(14)?,
            cvss: r.get(15)?,
            cvss_version: s(16)?,
            epss: r.get(17)?,
            epss_percentile: r.get(18)?,
            epss_date: s(19)?,
            epss_model: s(20)?,
            excluded: r.get::<_, Option<i64>>(21)?.unwrap_or(0) != 0,
            summary: s(22)?,
            aliases: s(23)?.split_whitespace().map(str::to_string).collect(),
            cwe: s(24)?.split_whitespace().map(str::to_string).collect(),
            local_source: s(25)?,
            local_link: s(26)?,
        })
    })?;
    let mut out: Vec<Finding> = rows.collect::<rusqlite::Result<_>>()?;
    with_text_in(cache, advisories, &mut out);
    Ok(out)
}

/// Fill the summary, aliases and weakness types of findings saved without
/// them (a scan from before they were kept) from the advisory records the
/// cache still holds. Nothing is fetched.
pub fn with_text(cache: &Cache, findings: &mut [Finding]) {
    with_text_in(cache, &mut Advisories::default(), findings);
}

/// [`with_text`] through a memo shared with the caller's other lookups.
fn with_text_in(cache: &Cache, advisories: &mut Advisories, findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let bare = f.summary.is_empty() && f.aliases.is_empty() && f.cwe.is_empty();
        if bare && f.kind != "unchecked" && is_advisory(&f.vuln_id) {
            let text = advisories.text(cache, &f.vuln_id);
            fill_text(f, &text);
        }
    }
}

/// The OSV record for a finding, and where it came from: from OSV's cached
/// records first (the one with the finding's id, else the one that lists it
/// as an alias), and only when OSV has none, from the user's folder of OSV
/// records ([`crate::sources::osv_dir`]) the finding came from, whose link
/// (`Some`, "" for none) is the record's own.
///
/// A local record is used only for a finding that names its source
/// (`local_source`: it was produced from a source of the user's in use that
/// scan) and only a record of that source, found by source and id; the
/// component name only picks between records that share an alias (it is not
/// the OSV package name for a runtime or tool, so it is never a filter),
/// so an OSV finding that shares a CVE id with some local record, or one of a
/// source that is off, never takes its record, aliases or url.
fn record(cache: &Cache, f: &Finding) -> Result<Option<(Value, Option<String>)>> {
    let vuln_id = f.vuln_id.as_str();
    if vuln_id.is_empty() {
        return Ok(None);
    }
    if let Some(r) = cache.vuln(vuln_id)? {
        return Ok(Some((r, None)));
    }
    let found: Option<String> = cache
        .conn
        .query_row(
            "SELECT record FROM vulns WHERE (' ' || aliases || ' ') LIKE ('% ' || ? || ' %') LIMIT 1",
            [vuln_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(r) = found.and_then(|t| serde_json::from_str(&t).ok()) {
        return Ok(Some((r, None)));
    }
    if f.local_source.is_empty() {
        return Ok(None);
    }
    Ok(crate::sources::osv_dir::for_finding(cache, &f.local_source, vuln_id, &f.component)?
        .map(|(r, url)| (r, Some(url))))
}

/// The exposure row for a finding's key, if scans have been recorded.
/// An exposure's first seen, last seen and resolved times, and its first
/// EPSS score and percentile.
type Life = (f64, f64, Option<f64>, Option<f64>, Option<f64>);

fn exposure(cache: &Cache, key: &str) -> Result<Option<Life>> {
    Ok(cache
        .conn
        .query_row(
            "SELECT first_at, last_at, resolved_at, first_epss, first_epss_percentile FROM exposures WHERE key = ?",
            [key],
            |r| {
                Ok((
                    r.get::<_, Option<f64>>(0)?.unwrap_or(0.0),
                    r.get::<_, Option<f64>>(1)?.unwrap_or(0.0),
                    r.get::<_, Option<f64>>(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            },
        )
        .optional()?)
}

/// The latest fix `wpantry fix` ran for this command, and whether a later scan
/// verified it (the exposure resolved in that scan).
fn fix(cache: &Cache, command: &str, resolved_scan: Option<i64>) -> Result<Option<Value>> {
    if command.is_empty() {
        return Ok(None);
    }
    let row: Option<(f64, String, i64, Option<i64>)> = cache
        .conn
        .query_row(
            "SELECT at, mode, ok, verified_scan FROM fixes WHERE command = ? ORDER BY at DESC LIMIT 1",
            [command],
            |r| Ok((r.get::<_, Option<f64>>(0)?.unwrap_or(0.0), r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    Ok(row.map(|(at, mode, ok, verified)| {
        let verified = verified.is_some() && (resolved_scan.is_none() || resolved_scan == verified);
        json!({"attempted_at": history::stamp(at), "mode": mode, "ok": ok != 0, "verified": verified,
               "succeeded": ok != 0 && verified})
    }))
}

fn resolved_scan(cache: &Cache, key: &str) -> Result<Option<i64>> {
    Ok(cache
        .conn
        .query_row("SELECT resolved_scan FROM exposures WHERE key = ?", [key], |r| r.get::<_, Option<i64>>(0))
        .optional()?
        .flatten())
}

fn row_json(cache: &Cache, row: &Row) -> Result<Value> {
    let f = &row.finding;
    let found = record(cache, f)?;
    let wordfence = crate::sources::wordfence::link_in(&f.note).filter(|_| f.kind == crate::sources::wordfence::KIND);
    let cve = || format!("https://www.cve.org/CVERecord?id={}", f.vuln_id);
    let (aliases, url) = match &found {
        _ if wordfence.is_some() => (Vec::new(), wordfence.unwrap_or_default().to_string()),
        Some((r, local)) => {
            let mut ids = crate::sources::osv::ids_of(r);
            ids.retain(|i| i != &f.vuln_id);
            for a in &f.aliases {
                if !ids.contains(a) {
                    ids.push(a.clone());
                }
            }
            let url = match local {
                // A record of the user's own: its own link, never OSV.dev's.
                Some(u) if u.is_empty() && f.vuln_id.starts_with("CVE-") => cve(),
                Some(u) => u.clone(),
                None => format!("https://osv.dev/vulnerability/{}", crate::utils::json::str_at(r, "id")),
            };
            (ids, url)
        }
        None if f.vuln_id.starts_with("CVE-") => (f.aliases.clone(), cve()),
        None => (f.aliases.clone(), String::new()),
    };
    let life = exposure(cache, &row.key)?;
    let now = crate::utils::os::now();
    let (first_seen, last_seen, resolved_at, days) = match life {
        Some((first, last, resolved, ..)) => (
            Some(history::stamp(first)),
            Some(history::stamp(last)),
            resolved.map(history::stamp),
            Some(((resolved.unwrap_or(now) - first) / 86400.0 * 10.0).round() / 10.0),
        ),
        None => (None, None, None, None),
    };
    let (first_epss, first_epss_percentile) = life.map(|l| (l.3, l.4)).unwrap_or_default();
    let fix = fix(cache, &f.fix_cmd, resolved_scan(cache, &row.key)?)?;
    Ok(json!({
        "schema": crate::SCHEMA, "id": f.id(),
        "kind": f.kind, "component": f.component, "version": f.version, "location": f.location,
        "vuln_id": f.vuln_id, "status": f.status, "fixed": f.fixed, "kev": f.kev, "severity": f.severity,
        "cvss": f.cvss, "cvss_version": f.cvss_version, "epss": f.epss, "epss_percentile": f.epss_percentile,
        "epss_date": f.epss_date, "epss_model": f.epss_model,
        "note": f.note, "fix_cmd": f.fix_cmd, "fix_auto": f.fix_auto,
        "dep_scope": f.dep_scope_name(), "dep_direct": f.dep_direct, "affected_range": f.affected_range,
        "excluded": f.excluded, "summary": f.summary, "cwe": f.cwe,
        "local_source": f.local_source, "local_link": f.local_link,
        "aliases": aliases, "url": url, "record": found.map(|(r, _)| r),
        "first_seen": first_seen, "last_seen": last_seen, "resolved_at": resolved_at, "days_exposed": days,
        "first_epss": first_epss, "first_epss_percentile": first_epss_percentile,
        "fix": fix,
    }))
}

/// The export as JSON Lines: the latest findings, plus (with `all`) the
/// resolved exposures no longer among them. Returns the text and the row count.
pub fn jsonl(cache: &Cache, all: bool) -> Result<(String, usize)> {
    // One memo for the whole export: an advisory's records are read once,
    // however many rows name it.
    let mut advisories = Advisories::default();
    let mut rows: Vec<Row> = findings_in(cache, &mut advisories)?.into_iter().map(from_finding).collect();
    if all {
        let have: Vec<String> = rows.iter().map(|r| r.key.clone()).collect();
        for e in history::exposures(cache, 0.0)? {
            let mut r = from_exposure(&e);
            // The filter first: an exposure that is still open, or that
            // the latest scan lists, is not a row and costs no lookup.
            if e.resolved_at.is_some() && !have.contains(&r.key) {
                with_text_in(cache, &mut advisories, std::slice::from_mut(&mut r.finding));
                rows.push(r);
            }
        }
    }
    rows.sort_by(|a, b| {
        (&a.finding.kind, &a.finding.component, &a.finding.location, &a.finding.vuln_id).cmp(&(
            &b.finding.kind,
            &b.finding.component,
            &b.finding.location,
            &b.finding.vuln_id,
        ))
    });
    let mut text = String::new();
    for r in &rows {
        text.push_str(&row_json(cache, r)?.to_string());
        text.push('\n');
    }
    Ok((text, rows.len()))
}

#[cfg(test)]
#[path = "jsonl_tests.rs"]
mod tests;
