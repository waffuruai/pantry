//! `wpantry watch`: the advisories the last scan found with no fix
//! released, asked about again now, bypassing the daily cache, so the hour
//! a fix lands you hear about it. The items come from the cache's own
//! record of what was asked (`queries`): every package version whose
//! answer named the advisory is asked again and the record is re-read.

use crate::check::{display_id, mitigation};
use crate::compare::Comparator;
use crate::db::Cache;
use crate::error::Result;
use crate::net::Net;
use crate::system::Status;
use crate::{osv, versions};
use serde_json::Value;
use std::collections::BTreeMap;

/// One watched advisory's state now.
#[derive(Clone, Debug, PartialEq)]
pub struct Watched {
    pub id: String,
    pub severity: String,
    pub summary: String,
    /// (ecosystem, package, installed version)
    pub item: osv::Item,
    /// The version that fixes it, now that one exists.
    pub fixed: Option<String>,
    pub mitigation: Option<String>,
}

/// The unfixed Critical/High/KEV advisories of the last scan.
pub fn watched_ids(cache: &Cache) -> Result<Vec<String>> {
    let mut stmt = cache.conn.prepare(
        "SELECT DISTINCT vuln_id FROM findings WHERE fixed = '' AND status = 'warn' AND (vuln_id LIKE 'CVE-%' OR vuln_id LIKE 'GHSA-%' OR vuln_id LIKE 'USN-%' OR vuln_id LIKE 'RUSTSEC-%' OR vuln_id LIKE 'PYSEC-%' OR vuln_id LIKE 'DSA-%' OR vuln_id LIKE 'ALSA-%') ORDER BY 1",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows.into_iter().flatten().collect())
}

/// Every (ecosystem, package, version) whose cached answer named `id`.
fn items_for(cache: &Cache, id: &str) -> Result<Vec<osv::Item>> {
    let mut stmt = cache.conn.prepare("SELECT ecosystem, package, version, vuln_ids FROM queries")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Vec::new();
    for (e, p, v, ids) in rows {
        let ids = ids.unwrap_or_default();
        let names: Vec<&str> = ids.split_whitespace().collect();
        let hit = names.contains(&id)
            || names
                .iter()
                .any(|n| cache.vuln(n).ok().flatten().is_some_and(|rec| osv::ids_of(&rec).iter().any(|a| a == id)));
        if hit {
            out.push((e.unwrap_or_default(), p.unwrap_or_default(), v.unwrap_or_default()));
        }
    }
    Ok(out)
}

/// Ask again about everything the watched advisories touch; what each
/// looks like now.
pub fn run(cache: &Cache, net: &dyn Net, offline: bool, status: Status) -> Result<Vec<Watched>> {
    let ids = watched_ids(cache)?;
    let mut items: Vec<osv::Item> = Vec::new();
    let mut by_id: BTreeMap<String, Vec<osv::Item>> = BTreeMap::new();
    for id in &ids {
        let mine = items_for(cache, id)?;
        for it in &mine {
            if !items.contains(it) {
                items.push(it.clone());
            }
        }
        by_id.insert(id.clone(), mine);
    }
    if items.is_empty() {
        return Ok(Vec::new());
    }
    status(&format!("Asking OSV again about {} package versions behind {} unfixed advisories", items.len(), ids.len()));
    let answers = osv::lookup(cache, net, &items, !offline, offline, &|_| {}, status)?;
    let mut out = Vec::new();
    for (id, mine) in by_id {
        for item in mine {
            let recs = answers.found.get(&item).cloned().unwrap_or_default();
            let Some(rec) = recs.iter().find(|r| osv::ids_of(r).contains(&id) || display_id(r) == id) else {
                continue;
            };
            let order = Comparator::for_ecosystem(&item.0);
            let fixes = osv::fixed_versions(rec, &item.0, &item.1, None);
            let fixed = versions::pick_safe_by(&item.2, &fixes, |a, b| order.cmp(a, b));
            out.push(Watched {
                id: id.clone(),
                severity: crate::db::severity_of(rec),
                summary: crate::json::str_at(rec, "summary").to_string(),
                item: item.clone(),
                fixed,
                mitigation: mitigation(&id),
            });
        }
    }
    cache.commit()?;
    Ok(out)
}

pub fn to_json(w: &Watched) -> Value {
    serde_json::json!({"id": w.id, "severity": w.severity, "summary": w.summary, "ecosystem": w.item.0, "package": w.item.1,
                       "version": w.item.2, "fixed": w.fixed, "mitigation": w.mitigation})
}

/// `watch --json`: the envelope other subcommands print, with `watched`.
pub fn report_json(watched: &[Watched]) -> String {
    serde_json::json!({"schema": crate::SCHEMA, "impl": crate::IMPL, "version": crate::VERSION,
                       "watched": watched.iter().map(to_json).collect::<Vec<_>>()})
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Finding;
    use crate::net::Fake;
    use serde_json::json;

    fn record(fixed: Option<&str>) -> Value {
        let mut events = vec![json!({"introduced": "0"})];
        if let Some(f) = fixed {
            events.push(json!({"fixed": f}));
        }
        json!({"id": "GHSA-k", "aliases": ["CVE-2026-98432"], "summary": "TCP use-after-free",
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
               "affected": [{"package": {"ecosystem": "npm", "name": "kern"}, "ranges": [{"type": "SEMVER", "events": events}]}]})
    }

    #[test]
    fn a_fix_landing_is_noticed_offline_from_the_cache() {
        let dir = crate::system::TempDir::new("watch").unwrap();
        let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
        cache.put_vuln(&record(None)).unwrap();
        cache.put_query("npm", "kern", "1.0.0", &["GHSA-k".into()]).unwrap();
        cache
            .replace_findings(&[Finding {
                kind: "project".into(),
                component: "kern".into(),
                version: "1.0.0".into(),
                location: "/w/package-lock.json".into(),
                vuln_id: "CVE-2026-98432".into(),
                status: "warn".into(),
                severity: "CRITICAL".into(),
                ..Default::default()
            }])
            .unwrap();
        cache.commit().unwrap();
        assert_eq!(watched_ids(&cache).unwrap(), ["CVE-2026-98432"]);
        let net = Fake::offline();
        let w = run(&cache, &net, true, &|_| {}).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(
            (w[0].id.as_str(), w[0].severity.as_str(), w[0].fixed.as_deref()),
            ("CVE-2026-98432", "CRITICAL", None)
        );
        assert!(w[0].mitigation.as_deref().unwrap_or("").contains("hdrlength"));
        assert!(net.requests().is_empty(), "offline asks nothing");
        cache.put_vuln(&record(Some("1.0.1"))).unwrap();
        let w = run(&cache, &net, true, &|_| {}).unwrap();
        assert_eq!(w[0].fixed.as_deref(), Some("1.0.1"));
        let j: Value = serde_json::from_str(&report_json(&w)).unwrap();
        assert_eq!(j["watched"][0]["fixed"], "1.0.1");
        assert_eq!(j["schema"], crate::SCHEMA);
    }
}
