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
