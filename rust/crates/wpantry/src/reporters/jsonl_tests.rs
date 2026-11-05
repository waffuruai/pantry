use super::*;
use crate::checks::Options;

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
    let d = crate::utils::temp::TempDir::new("export").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.put_vuln(&json!({"id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "zip bomb",
        "affected": [{"package": {"ecosystem": "crates.io", "name": "zip"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "7.2.0"}, {"fixed": "9.0.0"}]}]}]}))
        .unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/w".into()]), ..Default::default() };
    let cmd = "cd /w && cargo update -p zip --precise 9.0.0";
    let f = finding("CVE-2026-1", cmd);
    c.replace_findings(std::slice::from_ref(&f)).unwrap();
    let s1 = history::record_scan(&c, crate::utils::os::now() - 86400.0, std::slice::from_ref(&f), &[], &opts).unwrap();
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
    let s2 = history::record_scan(&c, crate::utils::os::now(), &[], &[], &opts).unwrap();
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
