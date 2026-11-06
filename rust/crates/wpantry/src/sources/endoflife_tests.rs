use super::*;
use crate::sources::testing::cache;
use crate::utils::dates::{days_from_civil, parse_date};
use crate::utils::net::{Fake, Response};
use serde_json::json;

#[test]
fn civil_dates() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(parse_date("2000-03-01"), Some(11017));
    assert_eq!(parse_date("2026-10-27"), Some(20753));
    assert_eq!(parse_date("2026-13-01"), None);
    assert!(past(&json!(true)) && !past(&json!(false)) && past(&json!("2000-01-01")) && !past(&json!("2999-01-01")));
}

#[test]
fn eol_cycles() {
    let (_d, c) = cache();
    let net = Fake::new(|_| {
        Ok(Response::ok(
            json!([{"cycle": "24", "eol": "2999-04-30", "latest": "24.11.0"},
                               {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
                               {"cycle": 16, "eol": true, "latest": "16.20.2"}])
            .to_string(),
        ))
    });
    let e = eol(&c, &net, "nodejs", "18", false).unwrap().unwrap();
    assert_eq!(
        (e.ended.as_deref(), e.latest.as_str(), e.supported.clone()),
        (Some("2025-04-30"), "18.20.8", vec!["24".to_string()])
    );
    assert_eq!(eol(&c, &net, "nodejs", "16", true).unwrap().unwrap().ended.as_deref(), Some("True"));
    assert_eq!(eol(&c, &net, "nodejs", "24", true).unwrap().unwrap().ended, None);
    assert_eq!(eol(&c, &net, "nodejs", "99", true).unwrap(), None);
}

/// The prefetch asks once per stale product, side by side, and the loop
/// after it finds everything cached; a product that fails is left for
/// `eol` to report.
#[test]
fn eol_prefetch_asks_once_per_product() {
    let (_d, c) = cache();
    let net = Fake::new(|req| {
        if req.url.ends_with("/down.json") {
            return Err(Error::Offline("down".into()));
        }
        Ok(Response::ok(json!([{"cycle": "1", "eol": false, "latest": "1.2.3"}]).to_string()))
    });
    let products: Vec<String> = ["a", "b", "a", "down"].iter().map(|s| s.to_string()).collect();
    eol_prefetch(&c, &net, &products, false).unwrap();
    let asked: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert_eq!(eol(&c, &net, "a", "1", false).unwrap().unwrap().latest, "1.2.3");
    assert_eq!(net.requests().len(), 3, "a was cached by the prefetch");
    assert!(matches!(eol(&c, &net, "down", "1", true), Err(Error::Offline(_))));
    eol_prefetch(&c, &net, &products, true).unwrap();
    assert_eq!(net.requests().len(), 3, "offline asks nothing");
    eol_prefetch(&c, &net, &products, false).unwrap();
    assert_eq!(net.requests().len(), 4, "only the product that failed is asked again");
}

#[test]
fn odd_cycles_and_stale_pages() {
    let (_d, c) = cache();
    let net = Fake::new(|_| {
        Ok(Response::ok(
            json!([{"cycle": null}, {"cycle": "1", "latest": null}, {"cycle": "2", "latest": 7, "eol": false}, {"cycle": "3"}])
                .to_string(),
        ))
    });
    assert_eq!(eol(&c, &net, "p", "2", false).unwrap().unwrap().latest, "7");
    assert_eq!(eol(&c, &net, "p", "1", true).unwrap().unwrap().latest, "");
    assert_eq!(eol(&c, &net, "p", "3", true).unwrap().unwrap().latest, "");
    assert_eq!(eol(&c, &net, "p", "null", true).unwrap(), None);
    // Stale and unreachable, the stored page is served; a bug is not.
    c.set("eol_at:p", "0").unwrap();
    assert_eq!(eol(&c, &Fake::offline(), "p", "2", false).unwrap().unwrap().latest, "7");
    let bug = Fake::new(|_| Err(Error::Missing("not a source failure".into())));
    assert!(matches!(eol(&c, &bug, "p", "2", false), Err(Error::Missing(_))));
    assert!(!past(&json!(null)));
    assert_eq!(parse_date("2026-1-1"), None);
    assert_eq!(parse_date("2026-01"), None);
}
