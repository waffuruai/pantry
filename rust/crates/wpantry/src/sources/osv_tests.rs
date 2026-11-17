use super::*;

#[test]
fn another_osv_compatible_api_is_asked_the_same_way() {
    let net = Fake::new(|r| {
        assert!(r.url.starts_with("https://mirror.example/v1/"), "{}", r.url);
        Ok(Response::ok(
            json!({"results": [{"vulns": [{"id": "MIRROR-1", "modified": "2026-01-01T00:00:00Z"}]}]}).to_string(),
        ))
    });
    let items = [("npm".to_string(), "x".to_string(), "1.0.0".to_string())];
    let got = refresh_from(&net, "osv", "https://mirror.example/v1", &items).unwrap();
    assert_eq!(got, vec![vec![("MIRROR-1".to_string(), "2026-01-01T00:00:00Z".to_string())]]);
    assert!(net.requests()[0].url.ends_with("/querybatch"));
}
use crate::utils::net::{Fake, Response};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const GIT: &str = "https://github.com/python/cpython.git";

fn rec(id: &str, ranges: Value, aliases: &[&str], pkg: Option<(&str, &str)>) -> Value {
    let mut affected = json!({"ranges": ranges, "versions": []});
    if let Some((e, n)) = pkg {
        affected["package"] = json!({"ecosystem": e, "name": n});
    }
    json!({"id": id, "aliases": aliases, "summary": format!("{id} summary"),
           "modified": "2026-10-01T00:00:00Z", "affected": [affected]})
}

fn cache() -> (crate::utils::temp::TempDir, Cache) {
    let d = crate::utils::temp::TempDir::new("osv").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    (d, c)
}

fn item(e: &str, n: &str, v: &str) -> Item {
    (e.into(), n.into(), v.into())
}

// The test vectors the Python implementation had (`Fixes`).
#[test]
fn semver_fix() {
    let r = rec(
        "RUSTSEC-1",
        json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.10"}]}]),
        &[],
        Some(("crates.io", "webpki-roots")),
    );
    assert_eq!(fixed_versions(&r, "crates.io", "webpki-roots", None), ["1.0.10"]);
    assert!(fixed_versions(&r, "crates.io", "other", None).is_empty());
}

#[test]
fn distro_release_only_takes_its_own_fix() {
    let r = json!({"id": "DEBIAN-CVE-1", "upstream": ["CVE-1"], "affected": [
        {"package": {"ecosystem": "Debian:13", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
        {"package": {"ecosystem": "Debian:14", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.0-1"}]}]}]});
    assert!(fixed_versions(&r, "Debian:13", "acl", None).is_empty());
    assert_eq!(fixed_versions(&r, "Debian:14", "acl", None), ["2.4.0-1"]);
    assert!(ids_of(&r).contains(&"CVE-1".to_string()));
}

#[test]
fn ubuntu_release_suffix_matches_but_pro_does_not() {
    let r = json!({"id": "USN-1", "affected": [
        {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "glibc"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9"}]}]},
        {"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "glibc"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9+esm1"}]}]}]});
    assert_eq!(fixed_versions(&r, "Ubuntu:24.04", "glibc", None), ["2.39-0ubuntu8.9"]);
}

#[test]
fn commit_hash_is_not_a_release() {
    let r = rec(
        "OSV-1",
        json!([{"type": "ECOSYSTEM", "events": [{"fixed": "76b7feab363d547e06151c8a8aa0ca72ade0594a"}]}]),
        &[],
        Some(("npm", "x")),
    );
    assert!(fixed_versions(&r, "npm", "x", None).is_empty());
    assert!(!released("76b7feab363d547e06151c8a8aa0ca72ade0594a"));
    assert!(released("1.2.3"));
}

#[test]
fn git_fix_is_the_tag_osv_stops_reporting() {
    let r = rec("CVE-2026-1", json!([{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}]), &[], None);
    let newer: BTreeMap<String, Vec<String>> = [
        ("v3.12.14".to_string(), vec!["CVE-2026-1".to_string()]),
        ("v3.12.15".to_string(), vec![]),
        ("v3.13.9".to_string(), vec!["OTHER".to_string()]),
    ]
    .into();
    assert_eq!(fixed_versions(&r, "GIT", GIT, Some(&newer)), ["v3.12.15", "v3.13.9"]);
    let only: BTreeMap<_, _> = [("v3.12.14".to_string(), vec!["CVE-2026-1".to_string()])].into();
    assert!(fixed_versions(&r, "GIT", GIT, Some(&only)).is_empty());
    let r =
        rec("PSF-1", json!([{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}]), &["CVE-2026-2"], None);
    let aliased: BTreeMap<_, _> = [("v3.14.5".to_string(), vec!["CVE-2026-2".to_string()])].into();
    assert!(fixed_versions(&r, "GIT", GIT, Some(&aliased)).is_empty(), "matches aliases");
}

#[test]
fn candidates_from_cached_tags() {
    let (_d, c) = cache();
    let tags = json!(["v3.12.12", "v3.12.13", "v3.12.14", "v3.12.15", "v3.13.0", "v3.13.9", "v3.14.0rc1", "v3.14.5"]);
    c.put_run(&format!("tags:{GIT}"), "", &tags).unwrap();
    assert_eq!(candidates(&c, GIT, "v3.12.13", true).unwrap(), ["v3.12.14", "v3.12.15", "v3.13.9", "v3.14.5"]);
}

#[test]
fn groups_aliases_transitively() {
    let a = json!({"id": "GHSA-1", "aliases": ["CVE-1"]});
    let b = json!({"id": "RUSTSEC-1", "aliases": ["CVE-1"]});
    let c = json!({"id": "DEBIAN-CVE-2", "upstream": ["CVE-2"]});
    let d = json!({"id": "CVE-2"});
    let g = group_by_alias(&[a, b, c, d]);
    let ids: Vec<Vec<&str>> = g.iter().map(|g| g.iter().map(|r| r["id"].as_str().unwrap()).collect()).collect();
    assert_eq!(ids, [vec!["GHSA-1", "RUSTSEC-1"], vec!["DEBIAN-CVE-2", "CVE-2"]]);
}

#[test]
fn lookup_offline_uses_cached_answers() {
    let (_d, c) = cache();
    c.put_vuln(&rec("CVE-2026-3", json!([]), &[], Some(("PyPI", "pip")))).unwrap();
    c.put_query("PyPI", "pip", "26.0.1", &["CVE-2026-3".into()]).unwrap();
    let net = Fake::new(|_| panic!("offline lookups make no requests"));
    let got =
        lookup(&c, &net, &[item("PyPI", "pip", "26.0.1"), item("PyPI", "uv", "0.1.0")], false, true, &|_| {}, &|_| {})
            .unwrap();
    assert_eq!(got.found[&item("PyPI", "pip", "26.0.1")][0]["id"], "CVE-2026-3");
    assert!(!got.found.contains_key(&item("PyPI", "uv", "0.1.0")), "never answered: unknown, not clean");
    assert!(got.gaps.is_empty(), "today's answer is complete: {:?}", got.gaps);
}

#[test]
fn lookup_batches_pages_fetches_changed_records_and_caches() {
    let (_d, c) = cache();
    // GHSA-old is cached with the modified time OSV still reports: not refetched.
    c.put_vuln(&json!({"id": "GHSA-old", "modified": "2026-01-01T00:00:00Z", "affected": []})).unwrap();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let batches = Arc::new(AtomicUsize::new(0));
    let (f, b) = (fetched.clone(), batches.clone());
    let net = Fake::new(move |r| {
        let body: Value = r.body.as_ref().map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(Value::Null);
        if r.url.ends_with("/querybatch") {
            b.fetch_add(1, Ordering::SeqCst);
            let qs = body["queries"].as_array().unwrap();
            let results: Vec<Value> = qs
                .iter()
                .map(|q| match q["package"]["name"].as_str().unwrap() {
                    "vite" => json!({"vulns": [{"id": "GHSA-new", "modified": "2026-10-01T00:00:00Z"},
                                               {"id": "GHSA-old", "modified": "2026-01-01T00:00:00Z"}],
                                     "next_page_token": "p2"}),
                    _ => json!({}),
                })
                .collect();
            return Ok(Response::ok(json!({"results": results}).to_string()));
        }
        if r.url.ends_with("/v1/query") {
            assert_eq!(body["page_token"], "p2");
            return Ok(Response::ok(
                json!({"vulns": [{"id": "MAL-1", "modified": "2026-10-02T00:00:00Z"}]}).to_string(),
            ));
        }
        let id = r.url.rsplit('/').next().unwrap().to_string();
        f.lock().unwrap().push(id.clone());
        Ok(Response {
            status: 200,
            body: json!({"id": id, "modified": "x", "affected": []}).to_string().into_bytes(),
            etag: Some(format!("\"{id}\"")),
        })
    });
    let mut items: Vec<Item> = (0..1500).map(|i| item("npm", &format!("pkg{i}"), "1.0.0")).collect();
    items.push(item("npm", "vite", "8.0.0"));
    let got = lookup(&c, &net, &items, false, false, &|_| {}, &|_| {}).unwrap();
    assert!(got.gaps.is_empty());
    let got = got.found;
    assert_eq!(batches.load(Ordering::SeqCst), 2, "1501 queries take two batches");
    let mut ids: Vec<&str> = got[&item("npm", "vite", "8.0.0")].iter().map(|r| r["id"].as_str().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, ["GHSA-new", "GHSA-old", "MAL-1"]);
    let mut f = fetched.lock().unwrap().clone();
    f.retain(|id| id != "modified_id.csv");
    f.sort();
    assert_eq!(f, ["GHSA-new", "MAL-1"]);
    assert_eq!(c.get("vuln_etag:GHSA-new").unwrap().as_deref(), Some("\"GHSA-new\""));
    assert!(got[&item("npm", "pkg7", "1.0.0")].is_empty(), "answered clean");
    // A second lookup the same day asks nothing.
    let quiet = Fake::new(|r| {
        assert!(r.url.contains("modified_id.csv"), "fresh answers are not refetched: {}", r.url);
        Ok(Response::not_found())
    });
    assert_eq!(lookup(&c, &quiet, &items, false, false, &|_| {}, &|_| {}).unwrap().found.len(), items.len());
}

#[test]
fn unreachable_osv_leaves_items_unanswered() {
    let (_d, c) = cache();
    let logged = Mutex::new(Vec::new());
    let got = lookup(
        &c,
        &Fake::offline(),
        &[item("npm", "a", "1")],
        false,
        false,
        &|m| logged.lock().unwrap().push(m.to_string()),
        &|_| {},
    )
    .unwrap();
    assert!(got.found.is_empty());
    assert!(logged.lock().unwrap().iter().any(|l| l.contains("OSV unreachable")));
}

/// An answer cached clean two days ago, then OSV fails: the old answer is
/// used, and the gap is reported, so the scan can't call it a clean check.
#[test]
fn a_stale_answer_after_a_failed_refresh_is_a_gap() {
    let (_d, c) = cache();
    c.put_query("crates.io", "x", "2.0.0", &[]).unwrap();
    c.conn.execute("UPDATE queries SET checked_at = ?", [now() - 2.0 * QUERY_TTL]).unwrap();
    let it = item("crates.io", "x", "2.0.0");
    let got = lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
    assert!(got.found[&it].is_empty());
    assert_eq!(got.gaps.len(), 1);
    assert!(
        got.gaps[0].contains("more than a day out of date") && got.gaps[0].contains("OSV unreachable"),
        "{:?}",
        got.gaps
    );
    let off = lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
    assert!(off.gaps[0].contains("--offline"), "{:?}", off.gaps);
}

/// OSV names an advisory but can't serve it (404, `{}`, another id): the
/// item keeps its other records, nothing is cached for the missing one,
/// the gap is reported, and the next online run asks again.
#[test]
fn an_advisory_osv_cannot_serve_is_a_gap_and_is_asked_again() {
    for body in ["", "{}", r#"{"id": "OTHER-1"}"#] {
        let (_d, c) = cache();
        let serve = Arc::new(Mutex::new(false));
        let s = serve.clone();
        let net = Fake::new(move |r| {
            if r.url.ends_with("/querybatch") {
                return Ok(Response::ok(
                    json!({"results": [{"vulns": [{"id": "TEST-1", "modified": "m"}]}]}).to_string(),
                ));
            }
            Ok(if *s.lock().unwrap() {
                Response::ok(json!({"id": "TEST-1", "modified": "m", "affected": []}).to_string())
            } else if body.is_empty() {
                Response { status: 404, body: vec![], etag: None }
            } else {
                Response::ok(body)
            })
        });
        let it = item("crates.io", "x", "2.0.0");
        let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
        assert!(got.found[&it].is_empty());
        assert_eq!(got.gaps, ["OSV lists advisories it couldn't serve here: TEST-1"], "body {body:?}");
        assert_eq!(c.vuln("TEST-1").unwrap(), None);
        // Offline the gap stays visible; online again the record arrives.
        let off = lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
        assert_eq!(off.gaps.len(), 1);
        *serve.lock().unwrap() = true;
        let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
        assert_eq!(got.found[&it][0]["id"], "TEST-1");
        assert!(got.gaps.is_empty());
    }
}

/// A batch answer that isn't an object (`null`), or whose `vulns` isn't a
/// list of advisories with ids, is not "no advisories".
#[test]
fn a_malformed_batch_answer_is_not_clean() {
    for answer in [
        json!([null]),
        json!([[]]),
        json!([]),
        json!([{"vulns": {}}]),
        json!([{"vulns": [{}]}]),
        json!([{"vulns": [{"id": ""}]}]),
        json!([{"vulns": [{"id": 7}]}]),
        json!([{"vulns": "none"}]),
    ] {
        let (_d, c) = cache();
        let body = json!({"results": answer}).to_string();
        let net = Fake::new(move |_| Ok(Response::ok(body.clone())));
        let it = item("npm", "a", "1.0.0");
        let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
        assert!(!got.found.contains_key(&it), "{answer}: unanswered, so reported unchecked");
        assert_eq!(c.query("npm", "a", "1.0.0").unwrap(), None, "{answer}: nothing cached");
    }
}

/// Invalid evidence never replaces an earlier answer: the stale answer
/// (its findings included) stands and the failed refresh is a gap, in a
/// batch and in a page of one.
#[test]
fn invalid_evidence_does_not_replace_a_previous_answer() {
    for (page, body) in [(false, json!({"vulns": {}})), (true, json!({"vulns": [{"modified": "m"}]}))] {
        let (_d, c) = cache();
        c.put_vuln(&rec("CVE-2026-9", json!([]), &[], Some(("npm", "a")))).unwrap();
        c.put_query("npm", "a", "1.0.0", &["CVE-2026-9".into()]).unwrap();
        c.conn.execute("UPDATE queries SET checked_at = ?", [now() - 2.0 * QUERY_TTL]).unwrap();
        let net = Fake::new(move |r| {
            if r.url.ends_with("/querybatch") && page {
                let first =
                    json!({"results": [{"vulns": [{"id": "CVE-2026-9", "modified": "m"}], "next_page_token": "p2"}]});
                return Ok(Response::ok(first.to_string()));
            }
            Ok(Response::ok(if page { body.to_string() } else { json!({"results": [body]}).to_string() }))
        });
        let it = item("npm", "a", "1.0.0");
        let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
        assert_eq!(got.found[&it][0]["id"], "CVE-2026-9", "page {page}: the earlier answer stands");
        assert_eq!(got.gaps.len(), 1, "page {page}: {:?}", got.gaps);
        assert!(
            got.gaps[0].contains("more than a day out of date") && got.gaps[0].contains("OSV answered"),
            "{:?}",
            got.gaps
        );
        let (at, ids) = c.query("npm", "a", "1.0.0").unwrap().unwrap();
        assert!(at < now() - QUERY_TTL && ids == "CVE-2026-9", "page {page}: the stale answer wasn't restamped");
    }
}

/// OSV reports a changed revision of a cached advisory but can't serve
/// it: the old record stays (its finding still stands), the gap is
/// reported until the revision arrives, and the next run asks again.
#[test]
fn a_changed_advisory_osv_cannot_serve_is_a_gap_and_the_old_record_stands() {
    let (_d, c) = cache();
    let mut old = rec("GHSA-chg", json!([]), &[], Some(("npm", "a")));
    old["modified"] = json!("2026-01-01T00:00:00Z");
    c.put_vuln(&old).unwrap();
    let serve = Arc::new(Mutex::new(false));
    let s = serve.clone();
    let net = Fake::new(move |r| {
        if r.url.ends_with("/querybatch") {
            let res = json!({"results": [{"vulns": [{"id": "GHSA-chg", "modified": "2026-06-01T00:00:00Z"}]}]});
            return Ok(Response::ok(res.to_string()));
        }
        Ok(if *s.lock().unwrap() {
            Response::ok(json!({"id": "GHSA-chg", "modified": "2026-06-01T00:00:00Z", "affected": []}).to_string())
        } else {
            Response { status: 404, body: vec![], etag: None }
        })
    });
    let it = item("npm", "a", "1.0.0");
    let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
    assert_eq!(got.found[&it][0]["id"], "GHSA-chg", "the old revision still counts");
    assert_eq!(got.gaps, ["OSV changed advisories whose new revision couldn't be downloaded: GHSA-chg"]);
    assert_eq!(c.modified("GHSA-chg").unwrap().as_deref(), Some("2026-01-01T00:00:00Z"));
    // Offline the gap stays visible; the same day, online, it is asked
    // again without a new querybatch, and clears when the revision arrives.
    let off = lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
    assert_eq!(off.gaps.len(), 1, "{:?}", off.gaps);
    let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
    assert_eq!(got.gaps.len(), 1, "still unavailable: {:?}", got.gaps);
    *serve.lock().unwrap() = true;
    let got = lookup(&c, &net, std::slice::from_ref(&it), false, false, &|_| {}, &|_| {}).unwrap();
    assert!(got.gaps.is_empty(), "{:?}", got.gaps);
    assert_eq!(c.modified("GHSA-chg").unwrap().as_deref(), Some("2026-06-01T00:00:00Z"));
    assert_eq!(c.get(&want_key("GHSA-chg")).unwrap(), None);
}

#[test]
fn batch_microseconds_match_full_record_nanoseconds() {
    assert!(same_revision(Some("2026-10-17T13:00:02.715376292Z"), "2026-10-17T13:00:02.715376Z"));
    assert!(same_revision(Some("2026-10-17T13:00:02Z"), "2026-10-17T13:00:02.000000Z"));
    assert!(!same_revision(Some("2026-10-17T13:00:02.715376292Z"), "2026-10-17T13:00:02.715377Z"));
    assert!(!same_revision(None, "2026-10-17T13:00:02Z"));
    let (_d, c) = cache();
    c.put_vuln(&json!({"id":"CVE-cached", "modified":"2026-10-17T13:00:02.715376292Z", "affected":[]})).unwrap();
    let net = Fake::new(|r| {
        if r.url.ends_with("modified_id.csv") {
            return Ok(Response::not_found());
        }
        assert!(r.url.ends_with("/querybatch"), "unchanged advisory must not be downloaded again");
        Ok(Response::ok(
            json!({"results":[{"vulns":[{"id":"CVE-cached", "modified":"2026-10-17T13:00:02.715376Z"}]}]}).to_string(),
        ))
    });
    let it = item("npm", "pkg", "1");
    lookup(&c, &net, &[it], false, false, &|_| {}, &|_| {}).unwrap();
    assert_eq!(net.requests().iter().filter(|r| r.url.ends_with("/querybatch")).count(), 1);
    assert_eq!(c.modified("CVE-cached").unwrap().as_deref(), Some("2026-10-17T13:00:02.715376292Z"));
    assert!(!same_revision(Some("invalid"), "2026-10-17T13:00:02Z"));
    assert!(!same_revision(Some("2026-10-17T13:00:02.1234567890Z"), "2026-10-17T13:00:02.123456Z"));
}
