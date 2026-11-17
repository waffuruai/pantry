use super::*;
use crate::finding::Finding;
use crate::utils::net::Fake;
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
    let dir = crate::utils::temp::TempDir::new("watch").unwrap();
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
    assert_eq!((w[0].id.as_str(), w[0].severity.as_str(), w[0].fixed.as_deref()), ("CVE-2026-98432", "CRITICAL", None));
    assert!(w[0].mitigation.as_deref().unwrap_or("").contains("hdrlength"));
    assert!(net.requests().is_empty(), "offline asks nothing");
    cache.put_vuln(&record(Some("1.0.1"))).unwrap();
    let w = run(&cache, &net, true, &|_| {}).unwrap();
    assert_eq!(w[0].fixed.as_deref(), Some("1.0.1"));
    let j: Value = serde_json::from_str(&report_json(&w)).unwrap();
    assert_eq!(j["watched"][0]["fixed"], "1.0.1");
    assert_eq!(j["schema"], crate::SCHEMA);
}
