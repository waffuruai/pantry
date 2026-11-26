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
    // No scan had run on that cache: its findings belong to none, and are kept by none.
    let kept: i64 = c.conn.query_row("SELECT COUNT(*) FROM run_findings WHERE scan_id != 1", [], |r| r.get(0)).unwrap();
    assert_eq!(kept, 0);
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
        [
            "dep_scope",
            "dep_direct",
            "affected_range",
            "cvss",
            "cvss_version",
            "epss",
            "epss_percentile",
            "epss_date",
            "epss_model",
            "excluded",
            "summary",
            "aliases",
            "cwe",
            "local_source",
            "local_link"
        ]
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
            "epss_percentile",
            "epss_date",
            "epss_model",
            "excluded",
            "summary",
            "aliases",
            "cwe",
            "local_source",
            "local_link"
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
    // Windows: LOCALAPPDATA when neither XDG_CACHE_HOME nor HOME is set; HOME still wins.
    let local = path_from(&env(&[("LOCALAPPDATA", "/l"), ("USERPROFILE", "/u")]));
    let want = if cfg!(windows) { "/l" } else { ".cache" };
    assert_eq!(local, PathBuf::from(want).join("wpantry").join("wpantry.db"));
    assert_eq!(
        path_from(&env(&[("LOCALAPPDATA", "/l"), ("HOME", "/h")])),
        PathBuf::from("/h/.cache/wpantry/wpantry.db")
    );
    assert_eq!(path_from(&env(&[("XDG_CACHE_HOME", "/x"), ("HOME", "/h")])), PathBuf::from("/x/wpantry/wpantry.db"));
    assert_eq!(
        path_from(&env(&[("XDG_CACHE_HOME", ""), ("HOME", "/h")])),
        PathBuf::from("/h/.cache/wpantry/wpantry.db")
    );
}

/// A cache from before each scan kept its findings (0.8.0): the latest
/// scan's are in `findings`, and become the one kept scan's.
#[test]
fn an_older_caches_latest_scan_becomes_the_one_kept() {
    let d = crate::utils::temp::TempDir::new("migrate").unwrap();
    let file = d.path().join("old.db");
    let conn = Connection::open(&file).unwrap();
    conn.execute_batch(
        "CREATE TABLE findings (kind TEXT, component TEXT, version TEXT, location TEXT, vuln_id TEXT, status TEXT, \
             fixed TEXT, kev INTEGER, severity TEXT, note TEXT, fix_cmd TEXT, fix_auto INTEGER); \
             INSERT INTO findings VALUES ('project', 'x', '1', '/l', 'CVE-1', 'fail', '2', 0, 'HIGH', '', 'cmd', 1); \
             CREATE TABLE scans (id INTEGER PRIMARY KEY, started_at REAL, finished_at REAL, host TEXT, user TEXT, \
             version TEXT, scope TEXT, counts TEXT, fails INTEGER, warns INTEGER); \
             INSERT INTO scans VALUES (6, 1.0, 2.0, 'h', 'u', '0.8.0', 'machine:~', '{}', 0, 0); \
             INSERT INTO scans VALUES (7, 3.0, 4.0, 'h', 'u', '0.8.0', 'repos:/r', '{}', 1, 0);",
    )
    .unwrap();
    conn.close().unwrap();
    let c = Cache::open(Some(&file)).unwrap();
    let runs = crate::history::runs(&c).unwrap();
    assert_eq!(runs.iter().map(|r| (r.row.id, r.findings, r.latest)).collect::<Vec<_>>(), [(7, 1, true)]);
    assert_eq!(crate::history::latest_scan(&c).unwrap(), Some(7));
    c.close().unwrap();
    // A scan an older wpantry records afterwards is adopted the same way, with what it left in `findings`.
    let c = Cache::open(Some(&file)).unwrap();
    c.conn.execute("DELETE FROM findings", []).unwrap();
    c.conn.execute("INSERT INTO scans (started_at, finished_at, scope) VALUES (5.0, 6.0, 'machine:~')", []).unwrap();
    c.close().unwrap();
    let c = Cache::open(Some(&file)).unwrap();
    let runs = crate::history::runs(&c).unwrap();
    assert_eq!(
        runs.iter().map(|r| (r.row.id, r.findings, r.latest)).collect::<Vec<_>>(),
        [(8, 0, true), (7, 1, false)]
    );
    // One that was pruned stays pruned.
    crate::history::prune_run(&c, 8).unwrap().unwrap();
    c.close().unwrap();
    // Opened again, nothing is kept twice.
    let c = Cache::open(Some(&file)).unwrap();
    assert_eq!(crate::history::runs(&c).unwrap()[0].findings, 1);
    // That scan reads back through the view as it does from the table.
    c.show_findings_of(7).unwrap();
    assert_eq!(crate::reporters::jsonl::findings(&c).unwrap()[0].vuln_id, "CVE-1");
    c.show_findings_of(6).unwrap();
    assert!(crate::reporters::jsonl::findings(&c).unwrap().is_empty());
}

/// A kept scan's findings are the findings, whole: a column added to
/// `findings` and not to `run_findings` would drop it from `report --run`.
#[test]
fn a_kept_scans_findings_have_every_findings_column() {
    let d = crate::utils::temp::TempDir::new("columns").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let columns = |table: &str| -> Vec<String> {
        c.conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    let mut findings = columns("findings");
    let mut kept: Vec<String> = columns("run_findings").into_iter().filter(|c| c != "scan_id").collect();
    let mut listed: Vec<String> = FINDING_COLUMNS.split(',').map(|c| c.trim().to_string()).collect();
    findings.sort();
    kept.sort();
    listed.sort();
    assert_eq!(kept, findings);
    assert_eq!(listed, findings);
}

/// A wpantry that stopped between copying an older cache's findings and
/// marking the scan kept left rows under a scan that still says nothing:
/// the next open replaces them, so nothing is kept twice.
#[test]
fn an_adoption_cut_short_is_done_again_whole() {
    let d = crate::utils::temp::TempDir::new("migrate").unwrap();
    let file = d.path().join("w.db");
    let c = Cache::open(Some(&file)).unwrap();
    let f = crate::finding::Finding { kind: "project".into(), vuln_id: "CVE-1".into(), ..Default::default() };
    c.replace_findings(std::slice::from_ref(&f)).unwrap();
    let id = crate::history::record_scan(&c, 1.0, std::slice::from_ref(&f), &[], &Default::default()).unwrap();
    // As the interrupted process left it: the copy made, the mark not.
    c.conn.execute("UPDATE scans SET kept = NULL WHERE id = ?", [id]).unwrap();
    c.close().unwrap();
    for _ in 0..2 {
        let c = Cache::open(Some(&file)).unwrap();
        let rows: i64 =
            c.conn.query_row("SELECT COUNT(*) FROM run_findings WHERE scan_id = ?", [id], |r| r.get(0)).unwrap();
        assert_eq!(rows, 1, "one copy, however many times it is opened");
        assert!(crate::history::is_kept(&c, id).unwrap());
        c.close().unwrap();
    }
}

/// `cache prune` keeps the advisory a kept scan's finding names, even when
/// the latest scan and every cached answer have moved on: `report --run`
/// exports its record.
#[test]
fn prune_keeps_an_advisory_only_an_older_kept_scan_refers_to() {
    let d = crate::utils::temp::TempDir::new("prune-runs").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    for id in ["CVE-2026-0001", "CVE-2026-0002"] {
        c.put_vuln(&serde_json::json!({"id": id, "summary": "s"})).unwrap();
    }
    let f = crate::finding::Finding { kind: "project".into(), vuln_id: "CVE-2026-0001".into(), ..Default::default() };
    c.replace_findings(std::slice::from_ref(&f)).unwrap();
    crate::history::record_scan(&c, 1.0, std::slice::from_ref(&f), &[], &Default::default()).unwrap();
    // A later scan finds nothing: the latest findings no longer name it.
    c.replace_findings(&[]).unwrap();
    crate::history::record_scan(&c, 2.0, &[], &[], &Default::default()).unwrap();
    let (_, gone, _) = c.prune(0.0).unwrap();
    assert_eq!(gone, 1, "the advisory nothing refers to");
    assert!(c.vuln("CVE-2026-0001").unwrap().is_some(), "the older kept scan's");
    assert!(c.vuln("CVE-2026-0002").unwrap().is_none());
}

/// Risk: a scan holds the cache's write lock for the length of its run
/// (network time included), so a program that runs `report`, `ignore` or
/// `cache prune` while a scan is in flight waits the busy timeout (60 s) and
/// fails, where it used to slip in between the scan's writes; or two scans
/// run at once and one removes what the other loaded (a scan with other
/// sources forgets a source of the first), or fail with "database is locked".
/// Oracle: with a scan's cache open and having written, another command's
/// cache writes at once and a read sees the scan's committed write; a second
/// scan does not get the cache until the first lets go, and then it does.
#[test]
fn a_scan_does_not_hold_the_database_lock_and_scans_take_turns() {
    use std::sync::mpsc;
    let dir = crate::utils::temp::TempDir::new("db").unwrap();
    let file = dir.path().join("w.db");
    let scan = Cache::open_for_scan(Some(&file)).unwrap();
    scan.set("a", "1").unwrap();
    // Another command's write is not held up by the scan, and sees its write.
    let other = Cache::open(Some(&file)).unwrap();
    let started = std::time::Instant::now();
    other.set("b", "2").unwrap();
    other.commit().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "a write waited for the scan");
    assert_eq!(other.get("a").unwrap().as_deref(), Some("1"), "the scan's write is committed");
    drop(other);
    // A second scan waits for the first.
    let (tx, rx) = mpsc::channel();
    let f2 = file.clone();
    let second = std::thread::spawn(move || {
        let c = Cache::open_for_scan(Some(&f2)).unwrap();
        tx.send(()).unwrap();
        c
    });
    assert!(rx.recv_timeout(std::time::Duration::from_millis(700)).is_err(), "the second scan got the cache early");
    scan.close().unwrap();
    rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the second scan gets the cache when the first ends");
    let c = second.join().unwrap();
    assert_eq!(c.get("a").unwrap().as_deref(), Some("1"));
}

/// Risk: a scan that waits for another longer than the database busy timeout
/// (60 s in production) fails with "database is locked", or gets the cache
/// and loses what it writes. Production waits are shortened here (busy 1 s)
/// and the first scan keeps the cache for 3 s while it and another command
/// keep writing; the wait is a lock file's, so the busy timeout is not the
/// limit. Oracle: the second scan, queued well past the busy timeout, gets
/// the cache without error, its writes land and the first scan's stay.
#[test]
fn a_scan_that_waits_longer_than_the_busy_timeout_still_runs() {
    use std::time::{Duration, Instant};
    let dir = crate::utils::temp::TempDir::new("db").unwrap();
    let file = dir.path().join("w.db");
    let limits = Limits { queue: Duration::from_secs(60), busy: Duration::from_secs(1) };
    let first = Cache::open_for_scan_within(Some(&file), limits).unwrap();
    first.set("first", "1").unwrap();
    let f2 = file.clone();
    let waited = std::thread::spawn(move || {
        let t = Instant::now();
        let c = Cache::open_for_scan_within(Some(&f2), limits).unwrap();
        let took = t.elapsed();
        c.set("second", "2").unwrap();
        c.close().unwrap();
        took
    });
    for i in 0..6 {
        std::thread::sleep(Duration::from_millis(500));
        first.set("tick", &i.to_string()).unwrap();
    }
    first.close().unwrap();
    let took = waited.join().unwrap();
    assert!(took > limits.busy * 2, "it waited {took:?}, not past the busy timeout");
    let c = Cache::open(Some(&file)).unwrap();
    assert_eq!(c.get("first").unwrap().as_deref(), Some("1"));
    assert_eq!(c.get("second").unwrap().as_deref(), Some("2"));
    assert_eq!(c.get("tick").unwrap().as_deref(), Some("5"));
}

/// Risk: a scan that has waited its whole queue time goes on without the
/// cache and reports an empty or `unchecked` result with exit 0, or fails
/// with a bare "database is locked". Oracle: it returns an error that names
/// the other scan (the CLI turns any error from opening the cache into exit
/// 3), after about the queue time and not much more, and it wrote nothing.
#[test]
fn a_scan_that_waits_out_the_queue_fails_and_says_why() {
    use std::time::{Duration, Instant};
    let dir = crate::utils::temp::TempDir::new("db").unwrap();
    let file = dir.path().join("w.db");
    let first = Cache::open_for_scan(Some(&file)).unwrap();
    first.set("first", "1").unwrap();
    let limits = Limits { queue: Duration::from_secs(1), busy: Duration::from_secs(1) };
    let t = Instant::now();
    let err = match Cache::open_for_scan_within(Some(&file), limits) {
        Ok(_) => panic!("the second scan got the cache while the first had it"),
        Err(e) => e,
    };
    let took = t.elapsed();
    assert!(matches!(err, crate::Error::Failed(_)), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("another scan has had the cache for 1 s"), "{text}");
    assert!(!text.contains("database is locked"), "{text}");
    assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(5), "{took:?}");
    first.close().unwrap();
    let c = Cache::open(Some(&file)).unwrap();
    assert_eq!(c.get("first").unwrap().as_deref(), Some("1"));
}
