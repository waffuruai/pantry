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

/// A hostile advisory summary: markup, control and bidi characters, and
/// 10 KB of text.
fn hostile_summary() -> String {
    format!(
        "<script>alert(1)</script>Heap\u{7} overflow\r\n in <b>parse()</b>\u{202e} for versions <1.2 {}",
        "A".repeat(10 * 1024)
    )
}

#[test]
fn a_finding_carries_its_advisory_text_into_scan_and_report_json() {
    let d = crate::utils::temp::TempDir::new("text").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.put_vuln(&json!({"id": "GHSA-1", "aliases": ["CVE-2026-1", "bad id <x>"], "summary": hostile_summary(),
        "database_specific": {"cwe_ids": ["CWE-787", "cwe-0416", "NVD-CWE-Other"]}}))
        .unwrap();
    let mut fs = vec![finding("CVE-2026-1", "")];
    crate::checks::severity::enrich(&c, &crate::utils::net::Fake::new(|_| panic!("no fetch")), true, &mut fs);
    let f = &fs[0];
    // Oracle: the fixture's text, with the tags, control and bidi
    // characters gone and the length capped.
    assert!(f.summary.starts_with("Heap overflow in parse() for versions <1.2 AAAA"), "{}", &f.summary[..80]);
    assert_eq!(f.summary.chars().count(), crate::finding::SUMMARY_MAX);
    assert!(f.summary.ends_with('…'));
    assert!(!f.summary.chars().any(|c| c.is_control() || c == '\u{202e}'), "{}", f.summary);
    assert!(!f.summary.contains("script") && !f.summary.contains("<b>"));
    assert_eq!(f.aliases, ["GHSA-1"], "the vuln_id itself and an unsafe id are left out");
    assert_eq!(f.cwe, ["CWE-787", "CWE-416"]);
    // scan --json
    let scan: Value = serde_json::from_str(&f.to_json().dumps()).unwrap();
    assert_eq!(
        (&scan["summary"], &scan["aliases"], &scan["cwe"]),
        (&json!(f.summary), &json!(["GHSA-1"]), &json!(["CWE-787", "CWE-416"]))
    );
    // report --json and report --jsonl, from what the cache keeps.
    c.replace_findings(&fs).unwrap();
    let saved = findings(&c).unwrap();
    assert_eq!((&saved[0].summary, &saved[0].aliases, &saved[0].cwe), (&f.summary, &f.aliases, &f.cwe));
    let (text, _) = jsonl(&c, false).unwrap();
    let row: Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!((&row["summary"], &row["cwe"]), (&json!(f.summary), &json!(["CWE-787", "CWE-416"])));
    c.close().unwrap();
}

#[test]
fn a_scan_saved_before_the_text_was_kept_gets_it_from_the_cached_record() {
    let d = crate::utils::temp::TempDir::new("old").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.put_vuln(&json!({"id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "zip bomb",
        "database_specific": {"cwe_ids": ["CWE-400"]}}))
        .unwrap();
    // A row as an older wpantry wrote it: no summary, aliases or cwe.
    c.conn
        .execute(
            "INSERT INTO findings (kind, component, version, location, vuln_id, status) \
             VALUES ('project', 'zip', '8.6.0', '/w/Cargo.lock', 'CVE-2026-1', 'fail')",
            [],
        )
        .unwrap();
    let saved = findings(&c).unwrap();
    assert_eq!(
        (saved[0].summary.as_str(), saved[0].aliases.clone(), saved[0].cwe.clone()),
        ("zip bomb", vec!["GHSA-1".to_string()], vec!["CWE-400".to_string()])
    );
    // Without a record, nothing is made up.
    c.conn.execute("DELETE FROM vulns", []).unwrap();
    let bare = findings(&c).unwrap();
    assert_eq!((bare[0].summary.as_str(), bare[0].aliases.len(), bare[0].cwe.len()), ("", 0, 0));
    c.close().unwrap();
}

#[test]
fn kev_names_the_vulnerability_when_no_record_summarises_it() {
    let d = crate::utils::temp::TempDir::new("kev").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.conn
        .execute(
            "INSERT INTO kev (cve, added, name) VALUES ('CVE-2026-1', '2026-11-01', 'Zip Remote Code Execution Vulnerability')",
            [],
        )
        .unwrap();
    let text = crate::checks::severity::advisory_text(&c, "CVE-2026-1");
    assert_eq!(text.summary, "Zip Remote Code Execution Vulnerability");
    c.close().unwrap();
}
