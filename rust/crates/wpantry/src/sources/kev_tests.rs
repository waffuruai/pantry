use super::*;
use crate::sources::endoflife::{eol, eol_prefetch};
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};
use serde_json::json;

#[test]
fn unreachable_feed_raises_instead_of_reporting_clean() {
    let (_d, c) = cache();
    assert!(matches!(kev(&c, &Fake::offline(), true), Err(Error::Offline(_))));
    assert!(matches!(eol(&c, &Fake::offline(), "nodejs", "24", true), Err(Error::Offline(_))));
    assert!(matches!(kev(&c, &Fake::offline(), false), Err(Error::Offline(_))));
}

#[test]
fn kev_fetch_with_etag() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        assert!(r.header("If-None-Match").is_none());
        Ok(Response {
            status: 200,
            body: json!({"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-01-01"}]})
                .to_string()
                .into_bytes(),
            etag: Some("\"k1\"".into()),
        })
    });
    assert_eq!(kev(&c, &net, false).unwrap(), HashSet::from(["CVE-2026-1".to_string()]));
    assert_eq!(c.get("kev_etag").unwrap().as_deref(), Some("\"k1\""));
    // Fresh: no request at all.
    assert!(kev(&c, &Fake::new(|_| panic!("fresh")), false).is_ok());
}

#[test]
fn a_not_modified_answer_keeps_the_list_and_a_bug_is_not_offline() {
    let (_d, c) = cache();
    let body = json!({"vulnerabilities": [{"cveID": "CVE-2026-1"}, {"cveID": "", "vulnerabilityName": "unnamed"}]});
    let net = Fake::new(move |r| {
        Ok(match r.header("If-None-Match") {
            Some("\"k1\"") => Response { status: 304, body: Vec::new(), etag: None },
            _ => Response { status: 200, body: body.to_string().into_bytes(), etag: Some("\"k1\"".into()) },
        })
    });
    assert_eq!(kev(&c, &net, false).unwrap().len(), 1, "a row without an id is skipped");
    c.set("kev_at", "0").unwrap();
    assert_eq!(kev(&c, &net, false).unwrap().len(), 1);
    assert_eq!(net.requests().len(), 2);
    assert!(c.fresh("kev_at", crate::db::DAY).unwrap(), "a 304 counts as a refresh");
    c.set("kev_at", "0").unwrap();
    let bug = Fake::new(|_| Err(Error::Missing("not a source failure".into())));
    assert!(matches!(kev(&c, &bug, false), Err(Error::Missing(_))));
    assert!(matches!(eol_prefetch(&c, &bug, &["p".to_string()], false), Err(Error::Missing(_))));
}

#[test]
fn entries_keep_the_vendor_and_product() {
    let (_d, c) = cache();
    let body = json!({"vulnerabilities": [
        {"cveID": "CVE-2026-1", "dateAdded": "2026-01-02", "vendorProject": "Google", "product": "Chromium V8",
         "vulnerabilityName": "Google Chromium V8 Type Confusion"},
        {"cveID": "CVE-2026-2", "dateAdded": "2026-01-03"}
    ]});
    let net = Fake::new(move |_| Ok(Response::ok(body.to_string())));
    kev(&c, &net, false).unwrap();
    let mut got = entries(&c).unwrap();
    got.sort_by(|a, b| a.cve.cmp(&b.cve));
    assert_eq!(
        got,
        [
            Entry {
                cve: "CVE-2026-1".into(),
                added: "2026-01-02".into(),
                vendor: "Google".into(),
                product: "Chromium V8".into()
            },
            Entry { cve: "CVE-2026-2".into(), added: "2026-01-03".into(), ..Default::default() },
        ]
    );
}

/// A cache from before the vendor and product were kept still loads (its
/// rows with them empty, offline too), and the next fetch skips the ETag so
/// the whole list comes back with them.
#[test]
fn an_old_cache_loads_and_its_next_fetch_downloads_the_whole_list() {
    let d = crate::utils::temp::TempDir::new("kev-old").unwrap();
    let file = d.path().join("w.db");
    let conn = rusqlite::Connection::open(&file).unwrap();
    conn.execute_batch(
        "CREATE TABLE kev (cve TEXT PRIMARY KEY, added TEXT, name TEXT); \
         INSERT INTO kev VALUES ('CVE-2026-1', '2026-01-02', 'old'); \
         CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
         INSERT INTO meta VALUES ('kev_etag', '\"k0\"');",
    )
    .unwrap();
    conn.close().unwrap();
    let c = Cache::open(Some(&file)).unwrap();
    assert_eq!(
        entries(&c).unwrap(),
        [Entry { cve: "CVE-2026-1".into(), added: "2026-01-02".into(), ..Default::default() }]
    );
    c.touch("kev_at").unwrap();
    // Offline: the old rows serve, and nothing is forgotten.
    assert_eq!(kev(&c, &Fake::offline(), true).unwrap().len(), 1);
    assert_eq!(c.get("kev_etag").unwrap().as_deref(), Some("\"k0\""));
    let body = json!({"vulnerabilities": [
        {"cveID": "CVE-2026-1", "dateAdded": "2026-01-02", "vendorProject": "Oracle", "product": "Java SE"}
    ]});
    let net = Fake::new(move |r| {
        Ok(match r.header("If-None-Match") {
            Some(_) => Response { status: 304, body: Vec::new(), etag: None },
            None => Response { status: 200, body: body.to_string().into_bytes(), etag: Some("\"k1\"".into()) },
        })
    });
    // Fresh by its age, but refetched without the ETag all the same.
    kev(&c, &net, false).unwrap();
    assert_eq!(net.requests().len(), 1);
    assert_eq!(entries(&c).unwrap()[0].vendor, "Oracle");
    assert_eq!(c.get("kev_etag").unwrap().as_deref(), Some("\"k1\""));
    // Migrated: the next run is the usual fresh no-request one.
    assert!(kev(&c, &Fake::new(|_| panic!("fresh")), false).is_ok());
}

/// Risk: a scan's cache is in autocommit, so a KEV load that fails part-way
/// (an error, a killed scan) has already committed the delete and leaves a
/// partial list for every later command. Oracle: an insert that fails
/// part-way (a trigger stands in for the error) leaves the old list whole.
/// Known bad: the delete and the inserts committed one by one.
#[test]
fn a_kev_load_that_fails_part_way_leaves_the_old_list() {
    let d = crate::utils::temp::TempDir::new("kev-load").unwrap();
    let c = Cache::open_for_scan(Some(&d.path().join("w.db")), &|_| {}).unwrap();
    let list = |ids: &[&str]| {
        let v: Vec<_> = ids.iter().map(|i| json!({"cveID": i, "dateAdded": "2026-01-01"})).collect();
        json!({ "vulnerabilities": v }).to_string()
    };
    let old = list(&["CVE-2026-1", "CVE-2026-2"]);
    kev(&c, &Fake::new(move |_| Ok(Response::ok(old.clone()))), false).unwrap();
    c.conn
        .execute_batch(
            "CREATE TRIGGER fail_part_way BEFORE INSERT ON kev WHEN NEW.cve = 'CVE-2026-12'
             BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        )
        .unwrap();
    c.unset("kev_at").unwrap();
    let new = list(&["CVE-2026-10", "CVE-2026-11", "CVE-2026-12"]);
    assert!(kev(&c, &Fake::new(move |_| Ok(Response::ok(new.clone()))), false).is_err());
    assert_eq!(c.kev_ids().unwrap(), HashSet::from(["CVE-2026-1".to_string(), "CVE-2026-2".to_string()]));
}

/// Risk: the same for one product's end-of-life page: a store that fails
/// part-way leaves the product with some cycles or none. Oracle: the old
/// cycles stay whole.
#[test]
fn an_eol_store_that_fails_part_way_leaves_the_old_cycles() {
    let d = crate::utils::temp::TempDir::new("eol-load").unwrap();
    let c = Cache::open_for_scan(Some(&d.path().join("w.db")), &|_| {}).unwrap();
    crate::sources::endoflife::store_for_tests(&c, "php", &json!([{"cycle": "8.3"}, {"cycle": "8.2"}]));
    c.conn
        .execute_batch(
            "CREATE TRIGGER fail_part_way BEFORE INSERT ON eol WHEN NEW.cycle = '8.5'
             BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        )
        .unwrap();
    let new = json!([{"cycle": "8.4"}, {"cycle": "8.5"}]);
    let stored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::sources::endoflife::store_for_tests(&c, "php", &new)
    }));
    assert!(stored.is_err(), "the trigger did not fire");
    let mut cycles: Vec<String> = c
        .conn
        .prepare("SELECT cycle FROM eol WHERE product = 'php'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    cycles.sort();
    assert_eq!(cycles, ["8.2", "8.3"]);
}
