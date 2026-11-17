use super::*;
use crate::sources::testing::cache_in;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;

#[test]
fn lookups_ask_once_cache_a_day_and_read_each_source() {
    let d = TempDir::new("iocs").unwrap();
    let cache = cache_in(&d);
    assert_eq!(consent(&cache, None, 2).unwrap(), None, "undecided, nobody to ask");
    assert_eq!(consent(&cache, Some(&|q| Some(q.contains("Only the hash is sent"))), 2).unwrap(), Some(true));
    assert_eq!(consent(&cache, Some(&|_| panic!("asked once")), 2).unwrap(), Some(true));
    let net = Fake::new(|r| {
        if r.url == url("yaraify") {
            let body: serde_json::Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
            return Ok(Response::ok(match body["search_term"].as_str() {
                Some("aa") => {
                    r#"{"query_status": "ok", "data": {"tasks": [{"clamav_results": ["Win.Coinminer.Generic-1", "Win.Coinminer.Generic-1"], "static_results": [{"rule_name": "DebuggerCheck"}]}]}}"#
                }
                // Known to YARAify, but only as a vulnerable driver: no verdict.
                Some("dd") => {
                    r#"{"query_status": "ok", "data": {"tasks": [{"clamav_results": ["SecuriteInfo.com.HackTool.VulnDriver.x64"]}, {"clamav_results": []}]}}"#
                }
                _ => r#"{"query_status": "no_results"}"#,
            }));
        }
        if r.url == format!("{}bb", url("circl-hashlookup")) {
            return Ok(Response::ok(r#"{"FileName": "ls"}"#));
        }
        Ok(Response { status: 404, body: br#"{"message": "Non existing SHA-256"}"#.to_vec(), etag: None })
    });
    let (v, failed) = verify(&cache, &net, "aa");
    assert!(failed.is_empty());
    assert_eq!(
        v,
        [("YARAify", Verdict::Malware("Win.Coinminer.Generic-1".into())), ("CIRCL hashlookup", Verdict::Unknown)]
    );
    let (v, _) = verify(&cache, &net, "dd");
    assert_eq!(v[0], ("YARAify", Verdict::Unknown), "a hacking tool's signature isn't a malware verdict");
    let (v, _) = verify(&cache, &net, "bb");
    assert_eq!(v, [("YARAify", Verdict::Unknown), ("CIRCL hashlookup", Verdict::KnownGood)]);
    let asked = net.requests().len();
    verify(&cache, &net, "aa");
    assert_eq!(net.requests().len(), asked, "answers are cached a day");
    let down = Fake::offline();
    let (v, failed) = verify(&cache, &down, "cc");
    assert!(v.is_empty());
    assert_eq!(failed.len(), 2);
    cache.set("online_hash_consent", "no").unwrap();
    assert_eq!(consent(&cache, Some(&|_| panic!("decided")), 1).unwrap(), Some(false));
}

#[test]
fn malwarebazaar_needs_the_users_key() {
    let net = Fake::new(|r| {
        assert_eq!(r.header("auth-key"), Some("k"));
        assert_eq!(r.body.as_deref(), Some(&b"query=get_info&hash=aa"[..]));
        Ok(Response::ok(r#"{"query_status": "ok", "data": [{"signature": "XMRig"}]}"#))
    });
    assert_eq!(malwarebazaar(&net, "aa", "k").unwrap(), Verdict::Malware("XMRig".into()));
    let missing = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "hash_not_found"}"#)));
    assert_eq!(malwarebazaar(&missing, "aa", "k").unwrap(), Verdict::Unknown);
    let refused = Fake::new(|_| Ok(Response { status: 401, body: vec![], etag: None }));
    assert!(malwarebazaar(&refused, "aa", "k").is_err());
    let odd = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "illegal_hash"}"#)));
    assert!(malwarebazaar(&odd, "aa", "k").is_err());
    let odd = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "unknown_auth_key"}"#)));
    assert!(yaraify(&odd, "yaraify", url("yaraify"), "aa").is_err());
}
