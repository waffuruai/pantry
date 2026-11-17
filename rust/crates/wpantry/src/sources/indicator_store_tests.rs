use super::*;

fn keys(token: &str) -> Vec<u64> {
    let mut out = Vec::new();
    lookups(token, &mut out);
    out
}

#[test]
fn entries_normalize_to_one_form() {
    let n = |s: &str| normalize(s);
    assert_eq!(n("Bad-C2.Example."), Some((Kind::Host, "bad-c2.example".into())));
    assert_eq!(n("https://user@Evil.example:8443/a/b.php?x=1#y"), Some((Kind::Url, "evil.example/a/b.php".into())));
    assert_eq!(n("52.196.149.49/"), Some((Kind::Ip, "52.196.149.49".into())), "a bare address with a slash");
    assert_eq!(n("198.51.100.7:443"), Some((Kind::Ip, "198.51.100.7".into())));
    assert_eq!(n("198.51.100.7/gate.php"), Some((Kind::Url, "198.51.100.7/gate.php".into())));
    assert_eq!(n(&"AB".repeat(32)), Some((Kind::Hash, "ab".repeat(32))));
    assert_eq!(n("xn--80ak6aa92e.com"), Some((Kind::Host, "xn--80ak6aa92e.com".into())));
    for bad in ["", "localhost", "999.1.1.1", "1.2.3", "a.b", "evil.c0m", "(?i)evil\\.exe", "10.0.0.0/8x", "-"] {
        assert_eq!(n(bad).map(|(k, _)| k).filter(|k| *k != Kind::Url), None, "{bad}");
    }
}

#[test]
fn a_token_is_looked_up_by_its_host_its_parents_and_its_path() {
    assert_eq!(
        keys("a.b.evil.example"),
        [key(Kind::Host, "a.b.evil.example"), key(Kind::Host, "b.evil.example"), key(Kind::Host, "evil.example")]
    );
    assert_eq!(
        keys("http://evil.example:80/x/y/"),
        [key(Kind::Host, "evil.example"), key(Kind::Url, "evil.example/x"), key(Kind::Url, "evil.example/x/y")]
    );
    assert_eq!(keys("bad-c2.example:443"), [key(Kind::Host, "bad-c2.example")]);
    assert_eq!(keys("203.0.113.66"), [key(Kind::Ip, "203.0.113.66")]);
    assert!(keys(&"ab".repeat(32)).is_empty(), "a hash in a file is not looked up as that file's hash");
    assert!(keys("notatoken").is_empty());
    let deep = format!("evil.example/{}", "s/".repeat(20));
    assert_eq!(keys(&deep).len(), 1 + 8, "at most eight path segments");
}

#[test]
fn the_store_finds_what_was_added_first_and_nothing_else() {
    let mut s = Store::new();
    let ours = s.origin("IOC_C2_Host_SignatureBase", "signature-base");
    let theirs = s.origin("IOC_Host_User_trails", "trails");
    assert!(s.add("bad-c2.example", "", ours));
    assert!(s.add("BAD-C2.example.", "interlock (malware)", theirs), "the same host from another list");
    assert!(s.add("evil.example/gate.php", "a gate", theirs));
    assert!(s.add(&"0f".repeat(32), "Test Kit", ours));
    assert!(!s.add("not an indicator", "", ours));
    s.seal();
    assert_eq!(s.len(), 3, "a key added twice is kept once");
    let f = s.get(key(Kind::Host, "bad-c2.example")).unwrap();
    assert_eq!((f.value, f.what, f.origin.rule.as_str()), ("bad-c2.example", "", "IOC_C2_Host_SignatureBase"));
    assert_eq!(s.get(key(Kind::Url, "evil.example/gate.php")).unwrap().what, "a gate");
    assert_eq!(s.get(key(Kind::Hash, &"0f".repeat(32))).unwrap().kind, Kind::Hash);
    assert!(s.get(key(Kind::Host, "evil.example")).is_none());
    assert!(Store::new().get(1).is_none(), "an empty store finds nothing");
    assert_eq!(s.counts(), [("signature-base".to_string(), 2), ("trails".to_string(), 1)]);
}

#[test]
fn a_full_store_still_finds_every_key() {
    let mut s = Store::new();
    let o = s.origin("r", "s");
    for i in 0..50_000u32 {
        s.add(&format!("h{i}.example"), "", o);
    }
    s.seal();
    assert_eq!(s.len(), 50_000);
    assert!((0..50_000u32).all(|i| s.get(key(Kind::Host, &format!("h{i}.example"))).is_some()));
    assert!((0..1000u32).all(|i| s.get(key(Kind::Host, &format!("nope{i}.example"))).is_none()));
}

#[test]
fn a_saved_store_reads_back_for_its_digest_only() {
    let d = crate::utils::temp::TempDir::new("store").unwrap();
    let path = d.path().join("store.bin");
    let mut s = Store::new();
    let o = s.origin("IOC_Host_User_trails", "trails");
    s.add("evil.example", "interlock (malware)", o);
    s.add("évil.example", "not a domain", o);
    let feodo = s.origin("IOC_C2_Host_FeodoTracker", "Feodo Tracker");
    s.add("198.51.100.7:443", "", feodo);
    s.seal();
    s.save(&path, "d1").unwrap();
    let back = Store::load(&path, "d1").expect("read back");
    assert_eq!(back.len(), s.len());
    let f = back.get(key(Kind::Host, "evil.example")).unwrap();
    assert_eq!((f.what, f.origin.source.as_str()), ("interlock (malware)", "trails"));
    assert_eq!(back.get(key(Kind::Ip, "198.51.100.7")).unwrap().origin.rule, "IOC_C2_Host_FeodoTracker");
    assert_eq!(back.counts(), s.counts());
    assert!(Store::load(&path, "d2").is_none(), "built from other lists");
    assert!(Store::load(&d.path().join("missing"), "d1").is_none());
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, &bytes).unwrap();
    assert!(Store::load(&path, "d1").is_none(), "trailing bytes");
}
