use super::*;

#[test]
fn the_index_is_fetched_from_the_clone_beside_the_cache() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let db = d.path().join("w.db");
    let c = Cache::open(Some(&db)).unwrap();
    seed_clone(
        &db,
        &[
            "osv/malicious/npm/evil/MAL-2026-1.json",
            "osv/malicious/npm/@scope/Pkg/MAL-2026-2.json",
            "osv/malicious/pypi/evil-pkg/MAL-2026-3.json",
            "osv/malicious/npm/README.md",
            "osv/malicious/npm/evil/notes.txt",
        ],
    );
    assert_eq!(sync(&c, false).unwrap(), 3);
    let rows = |c: &Cache| -> Vec<(String, String, String)> {
        let mut st = c.conn.prepare("SELECT ecosystem, name, id FROM malicious ORDER BY 3").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
    };
    assert_eq!(
        rows(&c),
        [
            ("npm".to_string(), "evil".to_string(), "MAL-2026-1".to_string()),
            ("npm".into(), "@scope/pkg".into(), "MAL-2026-2".into()),
            ("pypi".into(), "evil-pkg".into(), "MAL-2026-3".into()),
        ]
    );
    // Fresh, or offline: the index is reused without a fetch.
    assert_eq!(sync(&c, false).unwrap(), 3);
    assert_eq!(sync(&c, true).unwrap(), 3);
    // Stale and the fetch fails: the old index stands.
    c.set("malicious_at", "0").unwrap();
    std::fs::remove_dir_all(d.path().join("origin")).unwrap();
    assert_eq!(sync(&c, false).unwrap(), 3);
    c.conn.execute("DELETE FROM malicious", []).unwrap();
    assert!(matches!(sync(&c, false), Err(Error::Offline(m)) if m.contains(url("openssf-malicious-packages"))));
}

#[test]
fn offline_without_an_index_is_unchecked() {
    let d = crate::utils::temp::TempDir::new("mal").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    assert!(matches!(sync(&c, true), Err(Error::Offline(_))));
}

/// Risk: a scan's cache is in autocommit, so an index load that fails
/// part-way has committed the delete and leaves the malicious-package check
/// with part of the index for every later scan. Oracle: an insert that fails
/// part-way (a trigger stands in for the error) leaves the old index whole.
/// Known bad: the delete and the inserts committed one by one.
#[test]
fn an_index_load_that_fails_part_way_leaves_the_old_index() {
    let d = crate::utils::temp::TempDir::new("mal-load").unwrap();
    let db = d.path().join("w.db");
    let c = Cache::open_for_scan(Some(&db), &|_| {}).unwrap();
    seed_clone(&db, &["osv/malicious/npm/evil/MAL-2026-1.json"]);
    assert_eq!(sync(&c, false).unwrap(), 1);
    std::fs::remove_dir_all(d.path().join("origin")).unwrap();
    let _ = std::fs::remove_dir_all(d.path().join("malicious-packages"));
    seed_clone(&db, &["osv/malicious/npm/a/MAL-2026-2.json", "osv/malicious/npm/b/MAL-2026-3.json"]);
    c.conn
        .execute_batch(
            "CREATE TRIGGER fail_part_way BEFORE INSERT ON malicious WHEN NEW.id = 'MAL-2026-3'
             BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        )
        .unwrap();
    c.set("malicious_at", "0").unwrap();
    let _ = sync(&c, false);
    let ids: Vec<String> = c
        .conn
        .prepare("SELECT id FROM malicious")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ids, ["MAL-2026-1"]);
}
