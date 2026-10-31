//! `wpantry export --jsonl`: one JSON object per finding, joining what the
//! cache knows about it (the finding, the full OSV record, the exposure's
//! lifecycle across scans and the outcome of the fix `--update` ran), so a
//! consumer (wsentinel's triage-verdict corpus) reads one record and never
//! the cache tables. Additive to `check --json`'s finding: the same keys,
//! plus `aliases`, `url`, `record`, `first_seen`, `last_seen`, `resolved_at`,
//! `days_exposed` and `fix`.
//!
//! With `all`, the resolved exposures the latest scan no longer lists are
//! rows too (their `status` is the last one seen, `resolved_at` is set):
//! that is where "fixed, N days later" comes from.

use crate::check::Finding;
use crate::db::Cache;
use crate::error::Result;
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
    };
    from_finding(f)
}

/// The latest scan's findings, as saved.
pub fn findings(cache: &Cache) -> Result<Vec<Finding>> {
    let mut stmt = cache.conn.prepare(
        "SELECT kind, component, version, location, vuln_id, status, fixed, kev, severity, note, fix_cmd, fix_auto, \
         dep_scope, dep_direct, affected_range FROM findings",
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
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The OSV record for a finding's id: the record with that id, or the one
/// that lists it as an alias.
fn record(cache: &Cache, vuln_id: &str) -> Result<Option<Value>> {
    if vuln_id.is_empty() {
        return Ok(None);
    }
    if let Some(r) = cache.vuln(vuln_id)? {
        return Ok(Some(r));
    }
    let found: Option<String> = cache
        .conn
        .query_row(
            "SELECT record FROM vulns WHERE (' ' || aliases || ' ') LIKE ('% ' || ? || ' %') LIMIT 1",
            [vuln_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.and_then(|t| serde_json::from_str(&t).ok()))
}

/// The exposure row for a finding's key, if scans have been recorded.
fn exposure(cache: &Cache, key: &str) -> Result<Option<(f64, f64, Option<f64>)>> {
    Ok(cache
        .conn
        .query_row("SELECT first_at, last_at, resolved_at FROM exposures WHERE key = ?", [key], |r| {
            Ok((
                r.get::<_, Option<f64>>(0)?.unwrap_or(0.0),
                r.get::<_, Option<f64>>(1)?.unwrap_or(0.0),
                r.get::<_, Option<f64>>(2)?,
            ))
        })
        .optional()?)
}

/// The latest fix `--update` ran for this command, and whether a later scan
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
    let rec = record(cache, &f.vuln_id)?;
    let (aliases, url) = match &rec {
        Some(r) => {
            let mut ids = crate::osv::ids_of(r);
            ids.retain(|i| i != &f.vuln_id);
            (ids, format!("https://osv.dev/vulnerability/{}", crate::json::str_at(r, "id")))
        }
        None if f.vuln_id.starts_with("CVE-") => {
            (Vec::new(), format!("https://www.cve.org/CVERecord?id={}", f.vuln_id))
        }
        None => (Vec::new(), String::new()),
    };
    let life = exposure(cache, &row.key)?;
    let now = crate::system::now();
    let (first_seen, last_seen, resolved_at, days) = match life {
        Some((first, last, resolved)) => (
            Some(history::stamp(first)),
            Some(history::stamp(last)),
            resolved.map(history::stamp),
            Some(((resolved.unwrap_or(now) - first) / 86400.0 * 10.0).round() / 10.0),
        ),
        None => (None, None, None, None),
    };
    let fix = fix(cache, &f.fix_cmd, resolved_scan(cache, &row.key)?)?;
    Ok(json!({
        "schema": crate::SCHEMA,
        "kind": f.kind, "component": f.component, "version": f.version, "location": f.location,
        "vuln_id": f.vuln_id, "status": f.status, "fixed": f.fixed, "kev": f.kev, "severity": f.severity,
        "note": f.note, "fix_cmd": f.fix_cmd, "fix_auto": f.fix_auto,
        "dep_scope": f.dep_scope_name(), "dep_direct": f.dep_direct, "affected_range": f.affected_range,
        "aliases": aliases, "url": url, "record": rec,
        "first_seen": first_seen, "last_seen": last_seen, "resolved_at": resolved_at, "days_exposed": days,
        "fix": fix,
    }))
}

/// The export as JSON Lines: the latest findings, plus (with `all`) the
/// resolved exposures no longer among them. Returns the text and the row count.
pub fn jsonl(cache: &Cache, all: bool) -> Result<(String, usize)> {
    let mut rows: Vec<Row> = findings(cache)?.into_iter().map(from_finding).collect();
    if all {
        let have: Vec<String> = rows.iter().map(|r| r.key.clone()).collect();
        for e in history::exposures(cache, 0.0)? {
            let r = from_exposure(&e);
            if e.resolved_at.is_some() && !have.contains(&r.key) {
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
mod tests {
    use super::*;
    use crate::check::Options;

    fn finding(id: &str, fix_cmd: &str) -> Finding {
        Finding {
            kind: "project".into(),
            component: "zip".into(),
            version: "8.6.0".into(),
            location: "/w/Cargo.lock".into(),
            vuln_id: id.into(),
            status: "fail".into(),
            fixed: "9.0.0".into(),
            severity: "HIGH".into(),
            fix_cmd: fix_cmd.into(),
            fix_auto: true,
            dep_scope: "runtime".into(),
            dep_direct: Some(true),
            affected_range: ">=7.2.0, <9.0.0".into(),
            ..Default::default()
        }
    }

    #[test]
    fn rows_join_the_record_the_lifecycle_and_the_fix() {
        let d = crate::system::TempDir::new("export").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        c.put_vuln(&json!({"id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "zip bomb",
            "affected": [{"package": {"ecosystem": "crates.io", "name": "zip"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "7.2.0"}, {"fixed": "9.0.0"}]}]}]}))
            .unwrap();
        let opts = Options { machine: false, paths: Some(vec!["/w".into()]), ..Default::default() };
        let cmd = "cd /w && cargo update -p zip --precise 9.0.0";
        let f = finding("CVE-2026-1", cmd);
        c.replace_findings(std::slice::from_ref(&f)).unwrap();
        let s1 =
            history::record_scan(&c, crate::system::now() - 86400.0, std::slice::from_ref(&f), &[], &opts).unwrap();
        let (text, n) = jsonl(&c, false).unwrap();
        assert_eq!(n, 1);
        let row: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(row["vuln_id"], "CVE-2026-1");
        assert_eq!(row["aliases"], json!(["GHSA-1"]));
        assert_eq!(row["record"]["summary"], "zip bomb");
        assert_eq!(row["dep_scope"], "runtime");
        assert_eq!(row["dep_direct"], true);
        assert_eq!(row["affected_range"], ">=7.2.0, <9.0.0");
        assert_eq!(row["url"], "https://osv.dev/vulnerability/GHSA-1");
        assert!(row["first_seen"].is_string() && row["resolved_at"].is_null());
        assert_eq!(row["fix"], Value::Null, "nothing ran yet");
        // The fix runs; the next scan no longer lists the finding: resolved and verified.
        let targets: Vec<String> = c
            .conn
            .prepare("SELECT key FROM exposures")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        history::record_fix(&c, Some(s1), cmd, "auto", true, &targets).unwrap();
        c.replace_findings(&[]).unwrap();
        let s2 = history::record_scan(&c, crate::system::now(), &[], &[], &opts).unwrap();
        history::verify_fixes(&c, s1, s2).unwrap();
        let (text, n) = jsonl(&c, false).unwrap();
        assert_eq!((n, text.as_str()), (0, ""), "the latest scan has no findings");
        let (text, n) = jsonl(&c, true).unwrap();
        assert_eq!(n, 1);
        let row: Value = serde_json::from_str(text.trim()).unwrap();
        assert!(row["resolved_at"].is_string(), "{row}");
        assert_eq!(row["fix"]["succeeded"], true, "{row}");
        assert_eq!(row["fix"]["mode"], "auto");
        assert_eq!(row["fix_cmd"], cmd, "the exposure keeps the command");
        c.close().unwrap();
    }
}
