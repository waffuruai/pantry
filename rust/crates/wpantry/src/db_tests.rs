use super::*;
use serde_json::json;

/// A cached run stamped in the future (an edited cache) is stale, not
/// fresh forever.
#[test]
fn a_future_timestamp_is_not_fresh() {
    let dir = crate::utils::temp::TempDir::new("db").unwrap();
    let c = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    c.conn
        .execute("INSERT INTO runs(source, fingerprint, ran_at, result) VALUES (?, ?, ?, ?)", ("k", "fp", 1e12, "[1]"))
        .unwrap();
    let v = c.memo("k", || Ok(json!([2])), DAY, "fp", false, false).unwrap();
    assert_eq!(v, json!([2]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("w.db")), 0o600);
    }
}

/// A cache from before the dependency columns existed gains them on
/// open, and keeps its rows.
#[test]
fn older_caches_gain_the_added_columns() {
    let d = crate::utils::temp::TempDir::new("migrate").unwrap();
    let file = d.path().join("old.db");
    let conn = Connection::open(&file).unwrap();
    conn.execute_batch(
        "CREATE TABLE findings (kind TEXT, component TEXT, version TEXT, location TEXT, vuln_id TEXT, status TEXT, \
             fixed TEXT, kev INTEGER, severity TEXT, note TEXT, fix_cmd TEXT, fix_auto INTEGER); \
             INSERT INTO findings VALUES ('project', 'x', '1', '/l', 'CVE-1', 'fail', '2', 0, 'HIGH', '', 'cmd', 1); \
             CREATE TABLE fixes (id INTEGER PRIMARY KEY, scan_id INTEGER, at REAL, command TEXT, mode TEXT, ok INTEGER, \
             verified_scan INTEGER); \
             INSERT INTO fixes VALUES (1, 1, 1.0, 'brew upgrade x', 'auto', 1, NULL); \
             CREATE TABLE scans (id INTEGER PRIMARY KEY, started_at REAL, finished_at REAL, host TEXT, user TEXT, \
             version TEXT, scope TEXT, counts TEXT, fails INTEGER, warns INTEGER);",
    )
    .unwrap();
    conn.close().unwrap();
    let c = Cache::open(Some(&file)).unwrap();
    // A cache from before fixes kept their targets (v0.2.0) still reads its remediation log.
    let fixes = crate::history::fixes(&c, 0.0).expect("the fixes table gained its targets column");
    assert_eq!((fixes.len(), fixes[0].targets.len()), (1, 0));
    // A cache from before scans counted their unchecked sources (v0.2.0) still records a scan.
    let scan_cols: Vec<String> = c
        .conn
        .prepare("PRAGMA table_info(scans)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(scan_cols.iter().any(|c| c == "unchecked"), "{scan_cols:?}");
    crate::history::record_scan(&c, 1.0, &[], &[], &crate::checks::Options::default())
        .expect("a scan records on the migrated table");
    let cols: Vec<String> = c
        .conn
        .prepare("PRAGMA table_info(findings)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        &cols[12..],
        ["dep_scope", "dep_direct", "affected_range", "cvss", "cvss_version", "epss", "epss_percentile"]
    );
    let kept: i64 = c.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0)).unwrap();
    assert_eq!(kept, 1);
    let f = crate::reporters::jsonl::findings(&c).unwrap();
    assert_eq!((f[0].dep_scope.as_str(), f[0].dep_direct, f[0].affected_range.as_str()), ("", None, ""));
    c.close().unwrap();
    // Opening again is a no-op.
    Cache::open(Some(&file)).unwrap().close().unwrap();
}

pub fn temp_cache() -> (crate::utils::temp::TempDir, Cache) {
    let dir = crate::utils::temp::TempDir::new("db").unwrap();
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    (dir, cache)
}

#[test]
fn cvss_vectors_score_like_the_calculator() {
    let rec = |sev: serde_json::Value| serde_json::json!({"severity": sev});
    assert_eq!(
        severity_of(&rec(
            serde_json::json!([{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        )),
        "CRITICAL"
    );
    assert_eq!(
        severity_of(&rec(
            serde_json::json!([{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"}])
        )),
        "MEDIUM"
    );
    assert_eq!(
        severity_of(&serde_json::json!({"database_specific": {"severity": "MODERATE"}})),
        "MEDIUM",
        "GitHub's word, as CVSS says it"
    );
    assert_eq!(severity_of(&serde_json::json!({})), "");
    let labelled = json!({"database_specific": {"severity": "low"}, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]});
    assert_eq!(severity_of(&labelled), "LOW", "a label wins over the vector");
    let vector_only =
        json!({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]});
    assert_eq!(severity_of(&vector_only), "CRITICAL");
    assert_eq!(severity_of(&json!({})), "");
}

#[test]
fn schema_matches_the_contract() {
    let (_d, c) = temp_cache();
    assert!(c.fts, "the bundled SQLite has FTS5");
    let cols = |t: &str| -> Vec<String> {
        let mut s = c.conn.prepare(&format!("PRAGMA table_info({t})")).unwrap();
        s.query_map([], |r| r.get::<_, String>(1)).unwrap().map(|r| r.unwrap()).collect()
    };
    assert_eq!(cols("queries"), ["ecosystem", "package", "version", "checked_at", "vuln_ids"]);
    assert_eq!(
        cols("findings"),
        [
            "kind",
            "component",
            "version",
            "location",
            "vuln_id",
            "status",
            "fixed",
            "kev",
            "severity",
            "note",
            "fix_cmd",
            "fix_auto",
            "dep_scope",
            "dep_direct",
            "affected_range",
            "cvss",
            "cvss_version",
            "epss",
            "epss_percentile"
        ]
    );
}

#[test]
fn records_queries_and_search() {
    let (_d, c) = temp_cache();
    c.put_vuln(&json!({"id": "GHSA-b", "aliases": ["CVE-1"], "summary": "vite dev server path traversal",
                        "modified": "2026-10-01T00:00:00Z", "database_specific": {"severity": "high"},
                        "affected": [{"package": {"ecosystem": "npm", "name": "vite"}}]}))
        .unwrap();
    assert_eq!(c.modified("GHSA-b").unwrap().as_deref(), Some("2026-10-01T00:00:00Z"));
    assert_eq!(c.vuln("GHSA-b").unwrap().unwrap()["summary"], "vite dev server path traversal");
    let sev: String = c.conn.query_row("SELECT severity FROM vulns", [], |r| r.get(0)).unwrap();
    assert_eq!(sev, "HIGH");
    let hit: String =
        c.conn.query_row("SELECT id FROM vulns_fts WHERE vulns_fts MATCH 'traversal'", [], |r| r.get(0)).unwrap();
    assert_eq!(hit, "GHSA-b");
    c.put_query("npm", "zod", "4.4.3", &[]).unwrap();
    let (at, ids) = c.query("npm", "zod", "4.4.3").unwrap().unwrap();
    assert!(at > now() - 5.0 && ids.is_empty());
}

#[test]
fn memo_reuses_fresh_falls_back_stale_and_never_caches_failures() {
    let (_d, c) = temp_cache();
    let off = || Err(Error::Offline("down".into()));
    assert!(matches!(c.memo("k", off, DAY, "", false, true), Err(Error::Offline(_))));
    assert!(matches!(c.memo("k", off, DAY, "", false, false), Err(Error::Offline(_))));
    assert_eq!(c.memo("k", || Ok(json!([1])), DAY, "fp", false, false).unwrap(), json!([1]));
    assert_eq!(c.memo("k", || panic!("fresh"), DAY, "fp", false, false).unwrap(), json!([1]));
    c.conn.execute("UPDATE runs SET ran_at = 0", []).unwrap();
    assert_eq!(c.memo("k", off, DAY, "fp", false, false).unwrap(), json!([1]), "stale beats nothing");
    assert_eq!(c.memo("k", || panic!("offline"), DAY, "fp", false, true).unwrap(), json!([1]));
    // A result for other input is never reused, offline or not.
    assert!(matches!(c.memo("k", || panic!("offline"), DAY, "other", false, true), Err(Error::Offline(_))));
    assert!(matches!(c.memo("k", off, DAY, "other", false, false), Err(Error::Offline(_))));
    assert_eq!(c.memo("k", || Ok(json!([2])), DAY, "fp", true, false).unwrap(), json!([2]));
}

#[test]
fn cache_location() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| std::ffi::OsString::from(v))
    };
    assert_eq!(path_from(&env(&[("WPANTRY_DB", "/x/w.db"), ("HOME", "/h")])), PathBuf::from("/x/w.db"));
    assert_eq!(path_from(&env(&[("XDG_CACHE_HOME", "/x"), ("HOME", "/h")])), PathBuf::from("/x/wpantry/wpantry.db"));
    assert_eq!(
        path_from(&env(&[("XDG_CACHE_HOME", ""), ("HOME", "/h")])),
        PathBuf::from("/h/.cache/wpantry/wpantry.db")
    );
}
