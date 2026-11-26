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

/// Risk: the export reads the cache's advisory records (an unindexed
/// `aliases LIKE` scan of `vulns`) once per exposure, and for exposures it
/// then drops, which cost seconds on a real cache. Oracle: the count of
/// those scans, which the test counts at the one function that makes them:
/// at most one per distinct advisory id across the whole export, and none
/// when the export asks for no resolved rows. Known bad: give each step its
/// own memo, or fill the text before the resolved filter, and the count
/// passes M.
#[test]
fn the_export_reads_each_advisorys_records_once_and_only_for_rows_it_keeps() {
    let d = crate::utils::temp::TempDir::new("lookups").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/w".into()]), ..Default::default() };
    let on = |id: &str, component: &str| Finding { component: component.into(), ..finding(id, "") };
    // An open exposure the latest scan does not list: another scope's scan
    // found it (the findings table holds only the latest scan). It is no
    // row, so its id (Z) must cost no read at all.
    let elsewhere = Options { paths: Some(vec!["/elsewhere".into()]), ..opts.clone() };
    let z = [on("CVE-2026-4", "z1")];
    history::record_scan(&c, crate::utils::os::now() - 2.0 * 86400.0, &z, &[], &elsewhere).unwrap();
    // Latest scan: ids A and B, four findings. The next scan drops the three
    // that name R and one more naming A: four resolved exposures.
    let first = vec![
        on("CVE-2026-1", "a1"),
        on("CVE-2026-1", "a2"),
        on("CVE-2026-1", "a3"),
        on("CVE-2026-2", "b1"),
        on("CVE-2026-2", "b2"),
        on("CVE-2026-3", "r1"),
        on("CVE-2026-3", "r2"),
        on("CVE-2026-3", "r3"),
    ];
    c.replace_findings(&first).unwrap();
    history::record_scan(&c, crate::utils::os::now() - 86400.0, &first, &[], &opts).unwrap();
    let second = vec![on("CVE-2026-1", "a1"), on("CVE-2026-1", "a2"), on("CVE-2026-2", "b1"), on("CVE-2026-2", "b2")];
    c.replace_findings(&second).unwrap();
    history::record_scan(&c, crate::utils::os::now(), &second, &[], &opts).unwrap();
    // The latest scan lists A and B (M = 2 ids); the export with `all` adds
    // the resolved a3 (id A, already read) and r1..r3 (id R): M = 3 ids.
    crate::checks::severity::lookups::reset();
    let (_, n) = jsonl(&c, false).unwrap();
    assert_eq!(n, 4);
    assert_eq!(crate::checks::severity::lookups::taken(), 2, "one read per advisory of the latest scan");
    crate::checks::severity::lookups::reset();
    let (_, n) = jsonl(&c, true).unwrap();
    assert_eq!(n, 8, "four findings and four resolved exposures");
    let taken = crate::checks::severity::lookups::taken();
    assert_eq!(taken, 3, "one read per distinct advisory id (3), not per row (8) or per exposure");
    c.close().unwrap();
}

/// A record of a folder on this machine as a load of it leaves it: the row
/// and the package name it is found by.
fn local_row(c: &Cache, source: &str, id: &str, aliases: &[&str], package: &str, url: &str) {
    use rusqlite::params;
    let rec = json!({"id": id, "aliases": aliases, "summary": format!("{id} from {source}"),
        "affected": [{"package": {"ecosystem": "npm", "name": package}}]});
    c.conn
        .execute(
            "INSERT INTO local_vulns VALUES (?, ?, ?, ?, ?, ?)",
            params![source, id, format!("{id}.json"), aliases.join(" "), url, rec.to_string()],
        )
        .unwrap();
    c.conn
        .execute("INSERT INTO local_vuln_names VALUES (?, ?, ?)", params![source, id, package.to_lowercase()])
        .unwrap();
}

/// The export row of one finding, from a cache holding it.
fn row_of(c: &Cache, f: &Finding) -> Value {
    c.replace_findings(std::slice::from_ref(f)).unwrap();
    let (text, n) = jsonl(c, false).unwrap();
    assert_eq!(n, 1);
    serde_json::from_str(text.trim()).unwrap()
}

fn cache_for(label: &str) -> (crate::utils::temp::TempDir, Cache) {
    let d = crate::utils::temp::TempDir::new(label).unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    (d, c)
}

/// Risk: an upstream finding shown as `CVE-X` (promoted from an OSV record's
/// alias) takes `record`, `aliases` and `url` from a local record whose id is
/// `CVE-X`, because the local table was tried first. Oracle: the row is
/// OSV's cached record and its osv.dev link, whether or not the finding
/// names a local source; the local record is only for what OSV has none for.
#[test]
fn an_upstream_finding_keeps_osvs_record_when_a_local_record_has_its_cve_id() {
    let (_d, c) = cache_for("export-order");
    c.put_vuln(&json!({"id": "GHSA-1", "aliases": ["CVE-2026-9999"], "summary": "upstream zip bomb",
        "affected": [{"package": {"ecosystem": "npm", "name": "zip"}}]}))
        .unwrap();
    local_row(&c, "t-src", "CVE-2026-9999", &[], "zip", "https://internal.example/CVE-2026-9999");
    for source in ["", "t-src"] {
        let f = Finding { local_source: source.into(), ..finding("CVE-2026-9999", "") };
        let row = row_of(&c, &f);
        assert_eq!(row["record"]["id"], "GHSA-1", "source {source:?}: {row}");
        assert_eq!(row["url"], "https://osv.dev/vulnerability/GHSA-1", "source {source:?}");
        assert_eq!(row["aliases"], json!(["GHSA-1"]), "source {source:?}");
    }
}

/// Risk: a local record in a source the finding didn't come from (one turned
/// off, whose rows stay, or another local source) supplies
/// the record and link of an unrelated finding that merely shares its id.
/// Oracle: with no OSV record, such a finding has no record and the CVE
/// page's link; one matching the source and the id has the
/// record and its own link, by id first and then by alias.
#[test]
fn a_local_record_is_used_only_for_its_source_and_id() {
    let (_d, c) = cache_for("export-local");
    local_row(&c, "t-off", "CVE-2026-1", &[], "zip", "https://off.example/CVE-2026-1");
    let cve = "https://www.cve.org/CVERecord?id=CVE-2026-1";
    // No local source: an upstream-style finding never reads a local table.
    let row = row_of(&c, &finding("CVE-2026-1", ""));
    assert_eq!((row["record"].is_null(), row["url"].as_str()), (true, Some(cve)), "{row}");
    // From a source that holds nothing of the id (the id is in a source that is off).
    let f = Finding { local_source: "t-other".into(), ..finding("CVE-2026-1", "") };
    let row = row_of(&c, &f);
    assert_eq!((row["record"].is_null(), row["url"].as_str()), (true, Some(cve)), "another source: {row}");
    // The match: this source, by id first; then by alias.
    let from = |source: &str, id: &str| Finding { local_source: source.into(), ..finding(id, "") };
    local_row(&c, "t-src", "CVE-2026-2", &[], "zip", "https://advisories.example/CVE-2026-2");
    local_row(&c, "t-off", "CVE-2026-2", &[], "zip", "https://off.example/CVE-2026-2");
    let row = row_of(&c, &from("t-src", "CVE-2026-2"));
    assert_eq!(
        (row["record"]["summary"].as_str(), row["url"].as_str()),
        (Some("CVE-2026-2 from t-src"), Some("https://advisories.example/CVE-2026-2")),
        "the finding's own source, not the other that holds the id: {row}"
    );
    local_row(&c, "t-src", "TEAM-7", &["CVE-2026-7"], "Zip", "https://advisories.example/TEAM-7");
    let row = row_of(&c, &from("t-src", "CVE-2026-7"));
    assert_eq!(
        (row["record"]["id"].as_str(), row["url"].as_str()),
        (Some("TEAM-7"), Some("https://advisories.example/TEAM-7")),
        "{row}"
    );
}

/// Risk: a local advisory on a runtime or tool exports with `record: null`
/// and no aliases because the lookup compared the finding's component name
/// (`go`, `node`) with the OSV package name the record is filed under
/// (`stdlib`, the repository URL). Oracle: the row of such a finding carries
/// the record, its alias and its own link, as a project dependency whose name
/// equals the package does; a record that names two packages is still one
/// record for each of them, found by id or by alias.
#[test]
fn a_local_advisory_on_a_runtime_or_tool_exports_with_its_record() {
    let (_d, c) = cache_for("export-runtime");
    local_row(&c, "t-src", "TEAM-GO", &["CVE-2026-31"], "stdlib", "https://advisories.example/TEAM-GO");
    // The same record also covers the Go toolchain package.
    c.conn.execute("INSERT INTO local_vuln_names VALUES ('t-src', 'TEAM-GO', 'toolchain')", []).unwrap();
    let node = "https://github.com/nodejs/node";
    local_row(&c, "t-src", "TEAM-NODE", &["CVE-2026-32"], node, "https://advisories.example/TEAM-NODE");
    local_row(&c, "t-src", "TEAM-TOOL", &["CVE-2026-33"], "curl", "https://advisories.example/TEAM-TOOL");
    // (kind, component, id the finding shows, record id, the alias exported)
    let cases = [
        ("runtime", "go", "TEAM-GO", "TEAM-GO", "CVE-2026-31"),
        ("runtime", "go", "CVE-2026-31", "TEAM-GO", "TEAM-GO"),
        ("runtime", "node", "TEAM-NODE", "TEAM-NODE", "CVE-2026-32"),
        ("runtime", "node", "CVE-2026-32", "TEAM-NODE", "TEAM-NODE"),
        ("tool", "libcurl-cli", "TEAM-TOOL", "TEAM-TOOL", "CVE-2026-33"),
        ("project", "curl", "TEAM-TOOL", "TEAM-TOOL", "CVE-2026-33"),
    ];
    for (kind, component, id, record_id, alias) in cases {
        let f =
            Finding { kind: kind.into(), component: component.into(), local_source: "t-src".into(), ..finding(id, "") };
        let row = row_of(&c, &f);
        let at = format!("{kind} {component} {id}: {row}");
        assert_eq!(row["record"]["id"], record_id, "{at}");
        assert_eq!(row["url"], format!("https://advisories.example/{record_id}"), "{at}");
        assert_eq!(row["aliases"], json!([alias]), "{at}");
    }
}
