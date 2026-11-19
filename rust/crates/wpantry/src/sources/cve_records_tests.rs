use super::*;
use crate::error::Error;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};
use serde_json::json;

/// A CVE JSON 5 record of the CIRCUTOR shape, trimmed to what is read.
pub(crate) fn circutor_record() -> Value {
    json!({
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": "CVE-2026-120387", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "title": "CIRCUTOR PowerStudio SCADA WAVE JWT Signature Validation Authentication Bypass",
                "affected": [{
                    "vendor": "Circutor",
                    "product": "PowerStudio SCADA Wave",
                    "platforms": ["Windows", "64 bit"],
                    "versions": [
                        {"status": "affected", "version": "24.8.0", "lessThan": "24.11.17.0", "versionType": "custom"},
                        {"status": "unaffected", "version": "24.11.17.0", "versionType": "custom"}
                    ],
                    "defaultStatus": "unaffected"
                }],
                "metrics": [{"cvssV4_0": {"version": "4.0", "baseScore": 10,
                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}}]
            }
        }
    })
}

/// A search page as the index answers it: the CVE list's records and
/// NVD's copies side by side.
pub(crate) fn page(records: &[Value], total: u64) -> String {
    let pairs: Vec<Value> = records.iter().map(|r| json!([r["cveMetadata"]["cveId"], r])).collect();
    json!({"total_count": total, "page_size": 100, "page": 1,
           "results": {"nvd": [["cve-x", {"id": "x"}]], "cvelistv5": pairs}})
    .to_string()
}

#[test]
fn segments_are_percent_encoded() {
    assert_eq!(segment("powerstudio scada wave"), "powerstudio%20scada%20wave");
    assert_eq!(segment("tcp2rs\\+/x"), "tcp2rs%5C%2B%2Fx");
    assert_eq!(segment("a-b_c.d~e"), "a-b_c.d~e");
}

#[test]
fn a_record_is_trimmed_to_what_is_judged() {
    let t = trim(&circutor_record()).unwrap();
    assert_eq!(t["id"], "CVE-2026-120387");
    assert_eq!(t["score"], 10.0);
    assert_eq!(t["cvss_version"], "4.0");
    assert_eq!(t["affected"][0]["product"], "PowerStudio SCADA Wave");
    assert_eq!(t["affected"][0]["versions"][0]["lessThan"], "24.11.17.0");
    assert!(t["affected"][0].get("platforms").is_none());
    // The day it was published, when it says; "" otherwise.
    assert_eq!(t["published"], "");
    let mut dated = circutor_record();
    dated["cveMetadata"]["datePublished"] = json!("2024-11-22T06:03:29.764Z");
    assert_eq!(trim(&dated).unwrap()["published"], "2024-11-22");
    // Rejected, or without metadata or an id: nothing.
    let mut rejected = circutor_record();
    rejected["cveMetadata"]["state"] = json!("REJECTED");
    assert_eq!(trim(&rejected), None);
    assert_eq!(trim(&json!({})), None);
    assert_eq!(trim(&json!({"cveMetadata": {"state": "PUBLISHED", "cveId": ""}})), None);
    // No title: the English description, cut short; no score, no affected.
    let bare = json!({"cveMetadata": {"state": "PUBLISHED", "cveId": "cve-2026-1"},
        "containers": {"cna": {"descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Overflow in a viewer."}]}}});
    let t = trim(&bare).unwrap();
    assert_eq!((t["id"].as_str(), t["title"].as_str()), (Some("CVE-2026-1"), Some("Overflow in a viewer.")));
    assert!(t["score"].is_null() && t["affected"].as_array().unwrap().is_empty());
    let none = json!({"cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-2026-2"}});
    assert_eq!(trim(&none).unwrap()["title"], "");
}

#[test]
fn products_and_records_are_fetched_once_and_kept() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        Ok(if r.url.ends_with("/api/browse/circutor") {
            Response::ok(json!(["powerstudio scada wave", "lineeds"]).to_string())
        } else if r.url.ends_with("/api/browse/nobody") {
            Response::ok("[]")
        } else if r.url.contains("search/circutor/powerstudio%20scada%20wave?page=1&per_page=100") {
            Response::ok(page(&[circutor_record()], 2))
        } else {
            Response::not_found()
        })
    });
    assert_eq!(products(&c, "circutor").unwrap(), None);
    let vendors = vec!["circutor".to_string(), "nobody".to_string(), "missing".to_string(), "circutor".to_string()];
    prefetch_products(&c, &net, &vendors, false).unwrap();
    assert_eq!(net.requests().len(), 3, "each vendor once");
    assert_eq!(products(&c, "circutor").unwrap().unwrap(), ["powerstudio scada wave", "lineeds"]);
    assert_eq!(products(&c, "nobody").unwrap().unwrap(), Vec::<String>::new());
    // A vendor the index doesn't know (404) is an empty list, not a gap.
    assert_eq!(products(&c, "missing").unwrap().unwrap(), Vec::<String>::new());
    // Fresh: not asked again.
    prefetch_products(&c, &net, &vendors, false).unwrap();
    assert_eq!(net.requests().len(), 3);

    let pairs = vec![("circutor".to_string(), "powerstudio scada wave".to_string())];
    prefetch_records(&c, &net, &pairs, false).unwrap();
    let got = records(&c, "circutor", "powerstudio scada wave").unwrap().unwrap();
    assert!(got.complete);
    assert_eq!(got.records.len(), 1, "NVD's copies aren't kept");
    let r = &got.records[0];
    assert_eq!((r.id.as_str(), r.score.clone()), ("CVE-2026-120387", Some((10.0, "4.0".to_string()))));
    assert_eq!((r.affected.len(), r.published.as_str()), (1, ""));
    assert_eq!(records(&c, "circutor", "lineeds").unwrap(), None);
}

#[test]
fn records_are_paged_and_a_long_list_is_read_in_part() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        let n: u64 = r.url.split("page=").nth(1).and_then(|p| p.split('&').next()).unwrap().parse().unwrap();
        let mut rec = circutor_record();
        rec["cveMetadata"]["cveId"] = json!(format!("CVE-2026-{n}"));
        let total = if r.url.contains("/few") { 150 } else { 100_000 };
        Ok(Response::ok(page(&[rec], total)))
    });
    let pairs = vec![("v".to_string(), "few".to_string()), ("v".to_string(), "many".to_string())];
    prefetch_records(&c, &net, &pairs, false).unwrap();
    let few = records(&c, "v", "few").unwrap().unwrap();
    assert_eq!((few.records.len(), few.complete), (2, true));
    let many = records(&c, "v", "many").unwrap().unwrap();
    assert_eq!((many.records.len() as u64, many.complete), (MAX_PAGES, false));
    // A page with nothing on it ends the list too.
    let (_d, c) = cache();
    let net = Fake::new(|_| Ok(Response::ok(json!({"total_count": 9, "page_size": 100, "results": {}}).to_string())));
    prefetch_records(&c, &net, &[("v".into(), "p".into())], false).unwrap();
    assert_eq!(records(&c, "v", "p").unwrap().unwrap(), Records { records: vec![], complete: true });
}

#[test]
fn a_failed_or_refused_answer_keeps_the_last_copy() {
    let (_d, c) = cache();
    let good = Fake::new(|r| {
        Ok(if r.url.contains("browse") {
            Response::ok(json!(["p"]).to_string())
        } else {
            Response::ok(page(&[circutor_record()], 1))
        })
    });
    let pairs = vec![("v".to_string(), "p".to_string())];
    prefetch_products(&c, &good, &["v".into()], false).unwrap();
    prefetch_records(&c, &good, &pairs, false).unwrap();
    // Stale now; the index answers nonsense, then nothing.
    c.set("cve_records_products:v_at", "0").unwrap();
    c.set("cve_records:v\u{1f}p_at", "0").unwrap();
    let odd = Fake::new(|r| {
        Ok(if r.url.contains("browse") { Response::ok("{\"not\": \"a list\"}") } else { Response::ok("{\"x\": 1}") })
    });
    prefetch_products(&c, &odd, &["v".into()], false).unwrap();
    prefetch_records(&c, &odd, &pairs, false).unwrap();
    assert_eq!(products(&c, "v").unwrap().unwrap(), ["p"]);
    assert_eq!(records(&c, "v", "p").unwrap().unwrap().records.len(), 1);
    let down = Fake::offline();
    prefetch_records(&c, &down, &pairs, false).unwrap();
    assert_eq!(records(&c, "v", "p").unwrap().unwrap().records.len(), 1);
    // Offline: nothing is asked.
    let (_d, c) = cache();
    prefetch_products(&c, &good, &["v".into()], true).unwrap();
    assert!(good.requests().len() == 2 && products(&c, "v").unwrap().is_none());
}

#[test]
fn an_internal_error_passes_through() {
    let (_d, c) = cache();
    let net = Fake::new(|_| Err(Error::Io(std::io::Error::other("disk"))));
    assert!(prefetch_products(&c, &net, &["v".into()], false).is_err());
}
