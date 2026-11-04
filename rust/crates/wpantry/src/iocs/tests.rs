use super::*;
use crate::net::{Fake, Response};
use crate::system::TempDir;

fn cache_in(d: &TempDir) -> Cache {
    Cache::open(Some(&d.path().join("w.db"))).unwrap()
}

/// A network serving small versions of every list.
fn lists() -> Fake {
    Fake::new(|r| {
        Ok(Response::ok(match r.url.as_str() {
            u if u.ends_with("hash-iocs.txt") => {
                assert_eq!(r.header("accept"), Some("application/vnd.github.raw"));
                format!("# comment\n{};Test Malware\nnot-a-hash;x\n", crate::sha256::hex(b"evil bytes"))
            }
            u if u.ends_with("filename-iocs.txt") => {
                "(?i)\\\\evilsvc\\.exe;90\n/\\.hidden-miner$;60\nbroken;nan\n[bad;70\n".into()
            }
            u if u.ends_with("c2-iocs.txt") => "# c2\nbad-c2.example\n203.0.113.66\nx.y\n".into(),
            FEODO => r#"[{"ip_address": "198.51.100.7", "malware": "Emotet"}]"#.into(),
            other => panic!("unexpected {other}"),
        }))
    })
}

#[test]
fn fetches_and_loads_every_list() {
    let d = TempDir::new("iocs").unwrap();
    let cache = cache_in(&d);
    let dir = d.path().join("iocs");
    let net = lists();
    assert!(update(&cache, &net, &dir, false).is_empty());
    assert_eq!(net.requests().len(), 4);
    assert!(update(&cache, &net, &dir, false).is_empty());
    assert_eq!(net.requests().len(), 4, "fresh lists aren't fetched again");
    let iocs = load(&dir);
    assert_eq!(iocs.hash_match(b"evil bytes"), Some("Test Malware"));
    assert_eq!(iocs.hash_match(b"other"), None);
    assert_eq!(iocs.filenames.len(), 2, "unparseable lines are skipped");
    assert_eq!(iocs.filename_match(Path::new("C:\\Windows\\EvilSvc.exe")), Some((90, "\\\\evilsvc\\.exe")));
    assert_eq!(iocs.filename_match(Path::new("/tmp/.hidden-miner")).map(|m| m.0), Some(60));
    assert_eq!(iocs.filename_match(Path::new("/tmp/fine")), None);
    let hosts: Vec<&str> = iocs.c2.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(hosts, ["198.51.100.7", "203.0.113.66", "bad-c2.example"]);
    let rules = iocs.c2_rules();
    assert!(rules.contains("IOC_C2_Host_SignatureBase") && rules.contains("IOC_C2_Host_FeodoTracker"));
    let mut c = wpantry_yara::Compiler::new();
    assert_eq!(c.add_source("ioc", &rules, wpantry_yara::Syntax::Relaxed), 2);
    let compiled = c.build();
    let hits = compiled.scan(b"pool = bad-c2.example:443", &Default::default()).matches;
    assert_eq!(hits.len(), 1);
    assert!(compiled.scan(b"notbad-c2.example", &Default::default()).matches.is_empty(), "whole words only");
    assert_eq!((filename_category(90), filename_category(60)), ("malware", "suspicious"));
}

#[test]
fn md5_and_sha1_lists_are_checked_too() {
    let d = TempDir::new("iocs").unwrap();
    std::fs::write(
        d.path().join("hash-iocs.txt"),
        format!(
            "{};md5 one\n{};sha1 one\n",
            wpantry_yara::modules::hex(&wpantry_yara::modules::hash::md5(b"m")),
            wpantry_yara::modules::hex(&wpantry_yara::modules::hash::sha1(b"s"))
        ),
    )
    .unwrap();
    let iocs = load(d.path());
    assert_eq!(iocs.hash_match(b"m"), Some("md5 one"));
    assert_eq!(iocs.hash_match(b"s"), Some("sha1 one"));
    assert!(Iocs::default().hash_match(b"m").is_none());
    assert!(Iocs::default().c2_rules().is_empty());
}

#[test]
fn a_failing_source_is_reported_and_the_rest_still_update() {
    let d = TempDir::new("iocs").unwrap();
    let cache = cache_in(&d);
    let net = Fake::new(|r| {
        if r.url == FEODO {
            return Ok(Response { status: 500, body: vec![], etag: None });
        }
        if r.url.ends_with("c2-iocs.txt") {
            return Ok(Response { status: 404, body: vec![], etag: None });
        }
        Ok(Response::ok("x"))
    });
    let failed = update(&cache, &net, &d.path().join("iocs"), false);
    let names: Vec<&str> = failed.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["signature-base IOCs", "Feodo Tracker"]);
    assert!(d.path().join("iocs/hash-iocs.txt").is_file());
}

#[test]
fn lookups_ask_once_cache_a_day_and_read_each_source() {
    let d = TempDir::new("iocs").unwrap();
    let cache = cache_in(&d);
    assert_eq!(consent(&cache, None, 2).unwrap(), None, "undecided, nobody to ask");
    assert_eq!(consent(&cache, Some(&|q| Some(q.contains("Only the hash is sent"))), 2).unwrap(), Some(true));
    assert_eq!(consent(&cache, Some(&|_| panic!("asked once")), 2).unwrap(), Some(true));
    let net = Fake::new(|r| {
        if r.url == YARAIFY {
            let body: serde_json::Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
            return Ok(Response::ok(if body["search_term"] == "aa" {
                r#"{"query_status": "ok", "data": {"tasks": [{"static_results": [{"rule_name": "MAL_XMRig"}, {"rule_name": "MAL_XMRig"}]}]}}"#
            } else {
                r#"{"query_status": "no_results"}"#
            }));
        }
        if r.url == format!("{CIRCL}bb") {
            return Ok(Response::ok(r#"{"FileName": "ls"}"#));
        }
        Ok(Response { status: 404, body: br#"{"message": "Non existing SHA-256"}"#.to_vec(), etag: None })
    });
    let (v, failed) = verify(&cache, &net, "aa");
    assert!(failed.is_empty());
    assert_eq!(v, [("YARAify", Verdict::Malware("MAL_XMRig".into())), ("CIRCL hashlookup", Verdict::Unknown)]);
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
    assert!(yaraify(&odd, "aa").is_err());
}
