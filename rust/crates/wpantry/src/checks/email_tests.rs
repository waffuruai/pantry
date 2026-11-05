use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;

use crate::sources::breaches::quote;

#[test]
fn quoting_and_consent() {
    assert_eq!(quote("a.b+c@example.com"), "a.b%2Bc%40example.com");
    let d = crate::utils::temp::TempDir::new("breach").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    assert_eq!(consent(&c, None).unwrap(), None, "undecided, and nobody to ask");
    assert_eq!(consent(&c, Some(&|_| None)).unwrap(), None);
    assert_eq!(consent(&c, Some(&|q| Some(q.contains("against breach data")))).unwrap(), Some(true));
    assert_eq!(consent(&c, Some(&|_| panic!("asked once"))).unwrap(), Some(true));
}

#[test]
fn a_no_is_remembered_too() {
    let d = crate::utils::temp::TempDir::new("breach").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.set("breach_consent", "no").unwrap();
    assert_eq!(consent(&c, Some(&|_| panic!("decided"))).unwrap(), Some(false));
}

#[test]
fn addresses_are_distinct_lowercased_and_never_noreply() {
    let found = [
        "Dev@Example.com\n".to_string(),
        "dev@example.com\n123+dev@users.noreply.github.com\nother@x.io\nnot-an-email".into(),
    ];
    assert_eq!(emails_from(&found), ["dev@example.com", "other@x.io"]);
    assert!(emails_from(&[]).is_empty());
}

/// Nothing is sent anywhere without consent: undecided and nobody to
/// ask is nothing; asked and declined is remembered.
#[test]
fn the_breach_check_needs_consent() {
    let d = TempDir::new("breach").unwrap();
    let net = Fake::new(|r| panic!("asked {} without consent", r.url));
    let mut s = testing::scan(&net, &d, Options::default());
    breach(&mut s).unwrap();
    assert!(s.findings.is_empty());
    let asked = std::sync::Mutex::new(Vec::new());
    let ask = |q: &str| {
        asked.lock().unwrap().push(q.to_string());
        Some(false)
    };
    let mut s = testing::scan(&net, &d, Options { ask: true, ..Default::default() }).with_ask(&ask);
    breach(&mut s).unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(s.cache.get("breach_consent").unwrap().as_deref(), Some("no"));
    breach(&mut s).unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1, "remembered");
    assert!(s.findings.is_empty());
}
