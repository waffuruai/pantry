use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Request, Response};
use serde_json::json;
use std::sync::{Arc, Mutex};

const LIST: &str = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/modified_id.csv";

/// A storage server: honours `Range`, 404 for what it doesn't hold.
fn serve(r: &Request, body: &str) -> Response {
    let range = r.headers.iter().find(|(k, _)| k == "Range").map(|(_, v)| v.clone());
    let Some(range) = range else { return Response::ok(body) };
    let (from, to) = range.trim_start_matches("bytes=").split_once('-').unwrap();
    let (from, to): (usize, usize) = (from.parse().unwrap(), to.parse().unwrap());
    let bytes = body.as_bytes();
    let part = &bytes[from.min(bytes.len())..(to + 1).min(bytes.len())];
    Response { status: 206, body: part.to_vec(), etag: None }
}

fn list(lines: &[(&str, &str)]) -> String {
    lines.iter().map(|(t, id)| format!("{t},{id}\n")).collect()
}

fn smallvec(id: &str, fixed: &str) -> Value {
    json!({"id": id, "modified": "2026-11-06T00:00:00Z", "affected": [{"package": {"ecosystem": "crates.io", "name": "smallvec"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})
}

#[test]
fn times_and_directories() {
    assert_eq!(seconds("1970-01-02T00:00:01.5Z"), Some(86401.0));
    assert_eq!(seconds("2026-11-05T09:00:02.642244274Z"), Some(seconds("2026-11-05T09:00:02Z").unwrap()));
    assert_eq!(seconds("yesterday"), None);
    assert_eq!(directory("Debian:12").as_deref(), Some("Debian"));
    assert_eq!(directory("crates.io").as_deref(), Some("crates.io"));
    assert_eq!(directory("GIT"), None);
}

#[test]
fn a_list_is_read_from_the_top_down_to_a_time() {
    let body = list(&[
        ("2026-11-06T10:00:00Z", "RUSTSEC-3"),
        ("2026-11-06T09:00:00Z", "RUSTSEC-2"),
        ("2026-11-01T00:00:00Z", "RUSTSEC-1"),
    ]);
    let b = body.clone();
    let net = Fake::new(move |r| Ok(serve(r, &b)));
    let after = seconds("2026-11-05T00:00:00Z").unwrap();
    assert_eq!(
        changes(&net, LIST, after).unwrap(),
        Listed::Changes(
            vec![
                ("2026-11-06T10:00:00Z".into(), "RUSTSEC-3".into()),
                ("2026-11-06T09:00:00Z".into(), "RUSTSEC-2".into())
            ],
            "2026-11-06T10:00:00Z".into()
        )
    );
    assert_eq!(
        changes(&net, LIST, f64::INFINITY).unwrap(),
        Listed::Changes(Vec::new(), "2026-11-06T10:00:00Z".into()),
        "no chain yet: only the newest time"
    );
    let Listed::Changes(all, _) = changes(&net, LIST, 0.0).unwrap() else { panic!() };
    assert_eq!(all.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(), ["RUSTSEC-3", "RUSTSEC-2", "RUSTSEC-1"]);
    // A server that ignores the range sends it all: still read right.
    let whole = Fake::new(move |_| Ok(Response::ok(body.clone())));
    assert!(matches!(changes(&whole, LIST, after).unwrap(), Listed::Changes(ids, _) if ids.len() == 2));
    let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
    assert_eq!(changes(&gone, LIST, after).unwrap(), Listed::NoList);
    let html = Fake::new(|_| Ok(Response::ok("<html>maintenance</html>\n")));
    assert!(changes(&html, LIST, after).is_err(), "not a change list");
}

#[test]
fn a_long_list_is_read_in_chunks_and_too_many_changes_say_so() {
    // Lines cross the chunk boundaries; every id comes back whole.
    let n = 3000;
    let lines: Vec<(String, String)> =
        (0..n).map(|i| ("2026-11-06T10:00:00Z".to_string(), format!("GHSA-{i:05}-long-enough-id"))).collect();
    let body: String =
        lines.iter().map(|(t, id)| format!("{t},{id}\n")).collect::<String>() + "2026-01-01T00:00:00Z,OLD\n";
    assert!(body.len() as u64 > 2 * CHUNK);
    let seen = Arc::new(Mutex::new(0));
    let (b, s) = (body.clone(), seen.clone());
    let net = Fake::new(move |r| {
        *s.lock().unwrap() += 1;
        Ok(serve(r, &b))
    });
    let Listed::Changes(ids, _) = changes(&net, LIST, seconds("2026-11-01T00:00:00Z").unwrap()).unwrap() else {
        panic!()
    };
    assert_eq!(ids.len(), n);
    assert!(ids.iter().all(|(t, id)| id.ends_with("-long-enough-id") && t.len() == 20), "no line cut in two");
    assert!(*seen.lock().unwrap() >= 3);
    let many: String = (0..MAX_CHANGES + 2).map(|i| format!("2026-11-06T10:00:00Z,MAL-{i}\n")).collect();
    let net = Fake::new(move |r| Ok(serve(r, &many)));
    assert_eq!(changes(&net, LIST, 0.0).unwrap(), Listed::TooMany("2026-11-06T10:00:00Z".into()));
}

#[test]
fn a_record_is_matched_here_or_left_to_osv() {
    let rec = smallvec("RUSTSEC-1", "1.6.1");
    assert_eq!(affects(&rec, "crates.io", "smallvec", "1.6.0"), Some(true));
    assert_eq!(affects(&rec, "crates.io", "smallvec", "1.6.1"), Some(false));
    assert_eq!(affects(&rec, "crates.io", "serde", "1.0.0"), Some(false), "another package");
    let mut withdrawn = rec.clone();
    withdrawn["withdrawn"] = json!("2026-11-06T00:00:00Z");
    assert_eq!(affects(&withdrawn, "crates.io", "smallvec", "1.6.0"), Some(false));
    let git = json!({"affected": [{"package": {"ecosystem": "crates.io", "name": "smallvec"},
        "ranges": [{"type": "GIT", "repo": "https://github.com/servo/rust-smallvec", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]}]});
    assert_eq!(affects(&git, "crates.io", "smallvec", "1.6.0"), None, "commits: only OSV can tell");
    let listed = json!({"affected": [{"package": {"ecosystem": "npm", "name": "evil"}, "versions": ["1.0.0"]}]});
    assert_eq!(affects(&listed, "npm", "evil", "1.0.0"), Some(true));
    assert_eq!(affects(&listed, "npm", "evil", "1.0.1"), Some(false));
    let every = json!({"affected": [{"package": {"ecosystem": "npm", "name": "evil"}}]});
    assert_eq!(affects(&every, "npm", "evil", "9.9.9"), Some(true), "a malicious package names no versions");
    let unknown = json!({"affected": [{"package": {"ecosystem": "Nowhere", "name": "x"}, "versions": ["1"]}]});
    assert_eq!(affects(&unknown, "Nowhere", "x", "1"), None, "no known order");
}

#[test]
fn a_chain_keeps_answers_current_from_the_changes() {
    let (_d, c) = cache();
    let item: Item = ("crates.io".into(), "smallvec".into(), "1.6.0".into());
    let other: Item = ("crates.io".into(), "anyhow".into(), "1.0.0".into());
    c.put_query_at(&item.0, &item.1, &item.2, &[], 1000.0).unwrap();
    c.put_query_at(&other.0, &other.1, &other.2, &[], 1000.0).unwrap();
    let items: BTreeSet<&Item> = [&item, &other].into_iter().collect();
    let body = Arc::new(Mutex::new(list(&[("2026-11-05T00:00:00Z", "RUSTSEC-0")])));
    let records: Arc<Mutex<BTreeMap<String, Value>>> = Arc::default();
    let (b, recs) = (body.clone(), records.clone());
    let net = Fake::new(move |r| {
        if r.url.starts_with("https://osv-vulnerabilities") {
            return Ok(serve(r, &b.lock().unwrap()));
        }
        let id = r.url.rsplit('/').next().unwrap().to_string();
        Ok(match recs.lock().unwrap().get(&id) {
            Some(v) => Response::ok(v.to_string()),
            None => Response { status: 404, body: Vec::new(), etag: None },
        })
    });
    let quiet = |_: &str| {};
    // The first read starts the chain: what was answered before it isn't current.
    let s = sync(&c, &net, &items, false, &quiet).unwrap();
    // Read moments ago: not read again.
    let before = net.requests().len();
    sync(&c, &net, &items, false, &quiet).unwrap();
    assert_eq!(net.requests().len(), before, "a list read in the last 15 minutes isn't read again");
    let since = s.since["crates.io"];
    assert!(!current(&c, "crates.io", 1000.0, 86400.0).unwrap(), "answered before the chain");
    assert!(current(&c, "crates.io", since, 86400.0).unwrap());
    // Answered again (as the lookup does), then three changes are listed.
    c.put_query(&item.0, &item.1, &item.2, &[]).unwrap();
    c.put_query(&other.0, &other.1, &other.2, &[]).unwrap();
    let at = c.query(&item.0, &item.1, &item.2).unwrap().unwrap().0;
    records.lock().unwrap().insert("RUSTSEC-NEW".into(), smallvec("RUSTSEC-NEW", "1.6.1"));
    records.lock().unwrap().insert(
        "RUSTSEC-GIT".into(),
        json!({"id": "RUSTSEC-GIT", "affected": [{"package": {"ecosystem": "crates.io", "name": "anyhow"},
            "ranges": [{"type": "GIT", "repo": "x", "events": [{"introduced": "0"}]}]}]}),
    );
    records.lock().unwrap().insert(
        "RUSTSEC-ELSE".into(),
        json!({"id": "RUSTSEC-ELSE", "affected": [{"package": {"ecosystem": "crates.io", "name": "tokio"}, "versions": ["1.0.0"]}]}),
    );
    *body.lock().unwrap() = list(&[
        ("2026-11-07T00:00:00Z", "RUSTSEC-NEW"),
        ("2026-11-06T12:00:00Z", "RUSTSEC-GIT"),
        ("2026-11-06T06:00:00Z", "RUSTSEC-ELSE"),
        ("2026-11-05T00:00:00Z", "RUSTSEC-0"),
    ]);
    c.set("osv_read:crates.io", "0").unwrap();
    let s = sync(&c, &net, &items, false, &quiet).unwrap();
    let (got_at, ids) = c.query(&item.0, &item.1, &item.2).unwrap().unwrap();
    assert_eq!((ids.as_str(), got_at), ("RUSTSEC-NEW", at), "applied here, the answer's age kept");
    assert!(c.vuln("RUSTSEC-NEW").unwrap().is_some());
    assert!(c.vuln("RUSTSEC-ELSE").unwrap().is_none(), "about no package here: not kept");
    assert_eq!(s.reask.into_iter().collect::<Vec<_>>(), std::slice::from_ref(&other), "a git range goes back to OSV");
    assert_eq!(c.get("osv_cursor:crates.io").unwrap().as_deref(), Some("2026-11-07T00:00:00Z"));
    // Fixed later: the next change takes the advisory off.
    records.lock().unwrap().insert("RUSTSEC-NEW".into(), smallvec("RUSTSEC-NEW", "1.5.0"));
    body.lock().unwrap().insert_str(0, "2026-11-08T00:00:00Z,RUSTSEC-NEW\n");
    c.set("osv_read:crates.io", "0").unwrap();
    sync(&c, &net, &items, false, &quiet).unwrap();
    assert_eq!(c.query(&item.0, &item.1, &item.2).unwrap().unwrap().1, "");
    // The same list again: what was applied is skipped, nothing downloaded.
    let before = net.requests().len();
    c.set("osv_read:crates.io", "0").unwrap();
    sync(&c, &net, &items, false, &quiet).unwrap();
    let after: Vec<String> = net.requests()[before..].iter().map(|r| r.url.clone()).collect();
    assert!(after.iter().all(|u| u.ends_with("modified_id.csv")), "{after:?}");
    // --refresh starts the chain again.
    let s = sync(&c, &net, &items, true, &quiet).unwrap();
    assert!(s.since["crates.io"] > since);
    assert!(!current(&c, "crates.io", at, 86400.0).unwrap());
    // Unreachable: noted, nothing changed.
    c.set("osv_read:crates.io", "0").unwrap();
    let s = sync(&c, &Fake::offline(), &items, false, &quiet).unwrap();
    assert_eq!(s.failed.len(), 1);
}
