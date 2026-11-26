use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};
use serde_json::json;

/// A feed of the records given, as Wordfence's v3 production feed writes them.
pub(crate) fn feed(records: &[Value]) -> String {
    let mut m = serde_json::Map::new();
    for r in records {
        m.insert(r["id"].as_str().unwrap().to_string(), r.clone());
    }
    Value::Object(m).to_string()
}

/// A record for one piece of software: `ranges` as (from, from_inclusive,
/// to, to_inclusive), `patched` its patched versions.
pub(crate) fn record(id: &str, kind: &str, slug: &str, ranges: &[(&str, bool, &str, bool)], patched: &[&str]) -> Value {
    let mut affected = serde_json::Map::new();
    for (from, fi, to, ti) in ranges {
        affected.insert(
            format!("{from} - {to}"),
            json!({"from_version": from, "from_inclusive": fi, "to_version": to, "to_inclusive": ti}),
        );
    }
    json!({
        "id": id,
        "title": format!("{slug} <= x - Cross-Site Scripting"),
        "software": [{"type": kind, "name": slug, "slug": slug, "affected_versions": affected,
                      "patched": !patched.is_empty(), "patched_versions": patched,
                      "remediation": "Update to version 1.2.4, or a newer patched version"}],
        "informational": false,
        "description": "…", "references": [record_url(id)], "cwe": null,
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1, "rating": "Medium"},
        "cve": "CVE-2026-1001", "cve_link": "https://www.cve.org/CVERecord?id=CVE-2026-1001",
        "researchers": [], "published": "2026-06-02 00:00:00", "updated": "2026-07-05 17:46:13",
        "copyrights": {"message": "This record contains material that is subject to copyright",
                       "defiant": {"notice": "Copyright 2012-2026 Defiant Inc.", "license": DEFIANT_LICENSE, "license_url": DEFIANT_LICENSE_URL},
                       "mitre": {"notice": "Copyright 1999-2026 The MITRE Corporation", "license": MITRE_LICENSE, "license_url": MITRE_LICENSE_URL}}
    })
}

const A: &str = "61c39f5f-3b17-4e4d-824e-241159a73400";

/// What a fetch came to is kept for the process under the source's id
/// ([`fetch::last_error`]), and every test here fetches as `wordfence`: one
/// that succeeds while another has just been refused clears the reason the
/// second is about to read. The tests that fetch take turns, the WordPress
/// check's among them.
static FETCHES: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    FETCHES.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn a_record_gives_a_row_per_software_and_informational_ones_none() {
    let rec = record(A, "plugin", "Akismet", &[("*", true, "1.2.3", true)], &["1.2.4"]);
    let rows = rows_of(&rec);
    assert_eq!(rows.len(), 1);
    let v = &rows[0];
    assert_eq!((v.kind.as_str(), v.slug.as_str(), v.cve.as_str()), ("plugin", "akismet", "CVE-2026-1001"));
    assert_eq!(v.score, Some(6.1));
    assert_eq!(v.rating, "Medium");
    assert_eq!(v.patched, vec!["1.2.4"]);
    assert_eq!(
        v.ranges,
        vec![Range { from: "*".into(), from_inclusive: true, to: "1.2.3".into(), to_inclusive: true }]
    );
    assert_eq!(v.url(), format!("https://www.wordfence.com/threat-intel/vulnerabilities/id/{A}"));

    let mut info = rec.clone();
    info["informational"] = json!(true);
    assert!(rows_of(&info).is_empty(), "informational records aren't vulnerabilities");
    let mut odd = rec.clone();
    odd["id"] = json!("<script>");
    assert!(rows_of(&odd).is_empty(), "an id that isn't a record id never reaches a link");
    let mut other = rec.clone();
    other["software"][0]["type"] = json!("library");
    assert!(rows_of(&other).is_empty());
    let mut none = rec;
    none["cve"] = Value::Null;
    none["cvss"] = Value::Null;
    let v = &rows_of(&none)[0];
    assert_eq!((v.cve.as_str(), v.score), ("", None));
}

#[test]
fn the_feed_is_read_gzip_or_not_and_refused_when_it_isnt_the_feed() {
    let text = feed(&[
        record(A, "plugin", "akismet", &[("*", true, "1.2.3", true)], &["1.2.4"]),
        record("0b0b0b0b-0000-0000-0000-000000000002", "theme", "astra", &[("2.0", true, "2.1", false)], &[]),
    ]);
    let (rows, n) = parse(text.as_bytes()).unwrap();
    assert_eq!((rows.len(), n), (2, 2));
    let gz = crate::utils::archive::gzip::tests::stored(text.as_bytes(), None);
    assert_eq!(parse(&gz).unwrap().0, rows);
    assert!(parse(b"[1, 2]").is_err(), "not an object of records");
    assert!(parse(b"{\"a\": {\"id\": ").is_err(), "cut short");
    assert!(parse(b"{} trailing").is_err());
    assert_eq!(parse(b"{}").unwrap().1, 0);
}

#[test]
fn only_the_key_is_sent_and_the_feed_is_kept_daily_with_its_etag() {
    let _turn = one_at_a_time();
    let (_d, c) = cache();
    let body = feed(&[record(A, "plugin", "akismet", &[("*", true, "1.2.3", true)], &["1.2.4"])]);
    let net = Fake::new(move |r| {
        assert_eq!(r.url, "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production");
        assert_eq!(r.header("Authorization"), Some("Bearer k-123"));
        assert_eq!(r.header("Accept-Encoding"), Some("gzip"));
        assert!(r.body.is_none());
        Ok(match r.header("If-None-Match") {
            Some("\"w1\"") => Response { status: 304, body: Vec::new(), etag: None },
            _ => Response { status: 200, body: body.clone().into_bytes(), etag: Some("\"w1\"".into()) },
        })
    });
    assert_eq!(refresh(&c, &net, "k-123", false).unwrap(), 1);
    assert_eq!(refresh(&c, &net, "k-123", false).unwrap(), 1, "fresh: not asked again");
    assert_eq!(net.requests().len(), 1);
    c.set("wordfence_at", "0").unwrap();
    assert_eq!(refresh(&c, &net, "k-123", false).unwrap(), 1, "a 304 keeps the copy");
    assert_eq!(net.requests().len(), 2);
    let got = for_software(&c, "plugin", "Akismet").unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ranges[0].to, "1.2.3");
    assert_eq!(got[0].patched, vec!["1.2.4"]);
    assert!(for_software(&c, "theme", "akismet").unwrap().is_empty());
}

#[test]
fn a_refused_key_or_a_bad_copy_is_not_checked_never_clean() {
    let _turn = one_at_a_time();
    let (_d, c) = cache();
    let denied =
        Fake::new(|_| Ok(Response { status: 401, body: b"{\"message\":\"unauthorized\"}".to_vec(), etag: None }));
    let e = refresh(&c, &denied, "wrong", false).unwrap_err();
    assert!(matches!(&e, Error::Offline(m) if m.contains("HTTP 401")), "{e}");
    let empty = Fake::new(|_| Ok(Response::ok("{}")));
    assert!(refresh(&c, &empty, "k", false).is_err(), "no records is refused");
    c.set("wordfence_at", "0").unwrap();
    let junk = Fake::new(|_| Ok(Response::ok("<html>")));
    assert!(refresh(&c, &junk, "k", false).is_err());
    assert!(matches!(refresh(&c, &Fake::offline(), "k", true), Err(Error::Offline(_))), "offline, nothing cached");
}

#[test]
fn the_notices_come_with_wordfence_findings_only() {
    let wf = Finding {
        kind: KIND.into(),
        vuln_id: "CVE-2026-1001".into(),
        note: format!("XSS (Wordfence: {})", record_url(A)),
        ..Default::default()
    };
    let n = notices(std::slice::from_ref(&wf));
    assert_eq!(n.len(), 2);
    assert!(n[0].contains("Defiant Inc.") && n[0].contains(DEFIANT_LICENSE) && n[0].contains(DEFIANT_LICENSE_URL));
    assert!(n[1].contains("The MITRE Corporation") && n[1].contains(MITRE_LICENSE));
    let bare = Finding { vuln_id: A.into(), ..wf.clone() };
    assert_eq!(notices(&[bare]).len(), 1, "no CVE id: Defiant's alone");
    let gap = Finding { kind: KIND.into(), vuln_id: "UNCHECKED".into(), ..Default::default() };
    assert!(notices(&[gap]).is_empty());
    assert!(notices(&[]).is_empty());
}

#[test]
fn a_note_s_link_is_found() {
    let note = format!("XSS (Wordfence: {})", record_url(A));
    assert_eq!(link_in(&note), Some(record_url(A).as_str()));
    assert_eq!(link_in("no link"), None);
}
