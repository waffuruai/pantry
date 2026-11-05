//! Known malicious packages: a package whose name is in the OpenSSF index
//! ([`crate::sources::malicious_packages`]) has just its reports fetched, to
//! check whether the version here is affected. This is what catches packages
//! known only by name (an unpinned `npx some-mcp-server`).

use crate::checks::ecosystems::{self, normalize, openssf};
use crate::checks::{REMOVE, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::malicious_packages;
use crate::utils::json::str_at;
use crate::utils::json::{self, arr_at};
use crate::utils::net::Net;
use rusqlite::params;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashSet;

/// What the index says about one package: the reports that cover this
/// version, and the ids whose report couldn't be read (offline, or the fetch
/// failed), so whether they cover it is unknown.
#[derive(Debug, Default, PartialEq)]
pub struct Reports {
    pub matched: Vec<Value>,
    pub unknown: Vec<String>,
}

/// The malicious-package reports that cover this package at this version
/// (any version when `version` is ""), fetched and cached on first use. Only
/// a report OSV actually served is cached; one that couldn't be fetched is
/// `unknown`, and asked again next time.
pub fn reports(cache: &Cache, net: &dyn Net, eco: &str, name: &str, version: &str, offline: bool) -> Result<Reports> {
    let Some(dir) = openssf(eco) else { return Ok(Reports::default()) };
    let ids: Vec<String> = {
        let mut stmt = cache.conn.prepare("SELECT id FROM malicious WHERE ecosystem = ? AND name = ?")?;
        stmt.query_map(params![dir, normalize(eco, name)], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut out = Reports::default();
    for id in ids {
        let rec = match cache.vuln(&id)? {
            Some(r) => r,
            None if offline => {
                out.unknown.push(id);
                continue;
            }
            None => match crate::sources::fetch::get_json(
                net,
                "osv",
                &format!("{}/vulns/{id}", crate::sources::file::url("osv")),
                &[],
            ) {
                Ok(Some(r)) if json::str_at(&r, "id") == id => {
                    cache.put_vuln(&r)?;
                    r
                }
                Ok(_) => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) if e.is_source() => {
                    out.unknown.push(id);
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        if version.is_empty() || applies(&rec, version) {
            out.matched.push(rec);
        }
    }
    Ok(out)
}

/// Whether `version` is among those a report covers: listed in `versions`,
/// or inside any of a range's intervals (each `introduced` up to the next
/// `fixed` or `limit`, exclusive, or `last_affected`, inclusive), compared
/// in the package's ecosystem's order. A report listing no ranges or
/// versions covers every version.
pub fn applies(rec: &Value, version: &str) -> bool {
    let affected = arr_at(rec, "affected");
    if affected.is_empty() {
        return true;
    }
    for a in affected {
        let versions = json::strs_at(a, "versions");
        if versions.iter().any(|v| v == version) {
            return true;
        }
        let eco = a.get("package").map(|p| json::str_at(p, "ecosystem")).unwrap_or("");
        let order = ecosystems::order(eco);
        let lt = |x: &str, y: &str| order.cmp(x, y) == Ordering::Less;
        for r in arr_at(a, "ranges") {
            let mut start: Option<&str> = None;
            for e in arr_at(r, "events") {
                let at = |k: &str| e.get(k).and_then(Value::as_str);
                if let Some(intro) = at("introduced") {
                    start = Some(intro);
                } else if let Some(intro) = start {
                    let from = intro == "0" || !lt(version, intro);
                    let inside = match (at("fixed").or(at("limit")), at("last_affected")) {
                        (Some(end), _) => lt(version, end),
                        (None, Some(last)) => !lt(last, version),
                        (None, None) => continue,
                    };
                    if from && inside {
                        return true;
                    }
                    start = None;
                }
            }
            if let Some(intro) = start
                && (intro == "0" || !lt(version, intro))
            {
                return true; // introduced, never fixed
            }
        }
        if versions.is_empty() && arr_at(a, "ranges").is_empty() {
            return true;
        }
    }
    false
}

/// Every package name we know against the local malicious-package index,
/// which also covers what OSV couldn't be asked about (offline, unpinned).
pub fn sweep(scan: &mut Scan, found: &[Component], refs: &[Component]) -> Result<()> {
    scan.status("Updating the malicious-package index (OpenSSF)");
    let synced = malicious_packages::sync(&scan.cache, scan.opts.offline);
    if scan.guard("malicious-package index (OpenSSF)", synced.map(Some), None)?.is_none() {
        return Ok(());
    }
    let mut flagged: HashSet<(String, String)> =
        scan.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone())).collect();
    let mut items: Vec<(&Component, String, String, String)> =
        found.iter().filter_map(|c| c.osv.as_ref().map(|(e, n, v)| (c, e.clone(), n.clone(), v.clone()))).collect();
    let extra = |c: &Component, k: &str| c.extra.get(k).cloned().unwrap_or_default();
    items.extend(refs.iter().map(|c| (c, extra(c, "eco"), extra(c, "pkg"), extra(c, "ver"))));
    let total = items.len();
    let mut unread = Vec::new();
    for (n, (c, eco, name, ver)) in items.into_iter().enumerate() {
        scan.status(&format!("Checking {name} against the malicious-package index ({}/{total})", n + 1));
        let found = reports(&scan.cache, scan.net, &eco, &name, &ver, scan.opts.offline)?;
        unread.extend(found.unknown.iter().map(|id| format!("{name} {ver} ({id})")));
        for rec in found.matched {
            let id = str_at(&rec, "id").to_string();
            if flagged.insert((c.name.clone(), id.clone())) {
                let summary = str_at(&rec, "summary");
                scan.add(Finding {
                    vuln_id: id,
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: if summary.is_empty() { format!("known malicious package {name}") } else { summary.into() },
                    fix_cmd: REMOVE.replace("{}", &name),
                    ..Finding::of(c)
                });
            }
        }
    }
    if !unread.is_empty() {
        unread.sort();
        unread.dedup();
        scan.unchecked(
            "packages named in the malicious-package index",
            &format!("couldn't read the report to tell whether these versions are covered: {}", unread.join(", ")),
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "malicious_tests.rs"]
mod tests;
