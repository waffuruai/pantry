use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};

/// A `BREW-` record as the database writes it.
pub(crate) fn brew_record(formula: &str, cve: &str, fixed: &str) -> Value {
    json!({
        "schema_version": "1.7.3",
        "id": format!("BREW-{formula}-{cve}"),
        "upstream": [cve],
        "affected": [{
            "package": {"ecosystem": "Homebrew", "name": formula, "purl": format!("pkg:brew/{formula}")},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            "ecosystem_specific": {"fix": "patch", "patches": [{"url": "https://example.org/fix.patch"}]}
        }],
        "database_specific": {"source": "generated"}
    })
}

#[test]
fn homebrew_versions_order_by_version_then_revision() {
    assert_eq!(split("6.0_8"), ("6.0", 8));
    assert_eq!(split("2.10.0"), ("2.10.0", 0));
    assert_eq!(split("1.0_rc1"), ("1.0_rc1", 0));
    assert_eq!(cmp("1.81.6_5", "1.81.6_6"), Ordering::Less);
    assert_eq!(cmp("1.81.6_6", "1.82.0"), Ordering::Less);
    assert_eq!(cmp("0.12.20", "0.12.20_1"), Ordering::Less);
    assert_eq!(cmp("2.10.0", "2.9.0_3"), Ordering::Greater);
    assert_eq!(cmp("6.0_8", "6.0_8"), Ordering::Equal);
}

#[test]
fn a_record_says_which_revisions_its_patch_fixes() {
    let t = trim(&brew_record("lrzsz", "CVE-2018-10195", "0.12.20_1"), "lrzsz").unwrap();
    assert_eq!(
        t,
        json!({"id": "BREW-lrzsz-CVE-2018-10195", "upstream": ["CVE-2018-10195"],
               "intervals": [{"introduced": "0", "fixed": "0.12.20_1"}]})
    );
    // Another formula's record, or one with no ECOSYSTEM range, isn't kept.
    assert_eq!(trim(&brew_record("lrzsz", "CVE-2018-10195", "0.12.20_1"), "zip"), None);
    let open = json!({"id": "BREW-x-CVE-1", "affected": [{"package": {"name": "x"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"introduced": "2.0"}, {"last_affected": "2.1"}, {"introduced": "3.0"}]}]}]});
    assert_eq!(
        trim(&open, "x").unwrap()["intervals"],
        json!([{"introduced": "1.0"}, {"introduced": "2.0", "last_affected": "2.1"}, {"introduced": "3.0"}])
    );
    let (_d, c) = cache();
    c.set(&key("x"), &json!({"complete": true, "records": [trim(&open, "x").unwrap()]}).to_string()).unwrap();
    let a = &advisories(&c, "x").unwrap().unwrap().records[0];
    assert!(!a.about("CVE-1"), "no upstream named");
    assert_eq!(a.affects("1.5"), Some(String::new()), "open from 1.0");
    assert_eq!(a.affects("2.1_2"), Some(String::new()), "an open interval from 1.0 covers it");
    assert_eq!(a.affects("0.9"), None);
    let p = Advisory {
        id: "BREW-lrzsz-CVE-2018-10195".into(),
        upstream: vec!["CVE-2018-10195".into()],
        intervals: vec![("0".into(), Some((false, "0.12.20_1".into())))],
    };
    assert!(p.about("CVE-2018-10195") && !p.about("CVE-2018-1"));
    assert_eq!(p.affects("0.12.20"), Some("0.12.20_1".into()));
    assert_eq!(p.affects("0.12.20_1"), None);
    assert_eq!(p.affects("0.12.21"), None);
}

#[test]
fn records_are_fetched_by_formula_paged_and_kept() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        let u = r.url.as_str();
        assert!(u.starts_with("https://vulnerability.circl.lu/api/vulnerability/?source=osv_homebrew&product="), "{u}");
        if u.contains("product=aider&") {
            // Two full pages and a short one.
            let page: usize = u.rsplit("page=").next().unwrap().parse().unwrap();
            let n = if page < 3 { PER_PAGE } else { 3 };
            let list: Vec<Value> =
                (0..n).map(|i| brew_record("aider", &format!("CVE-2026-{page}{i:03}"), "0.86.0_1")).collect();
            return Ok(Response::ok(Value::Array(list).to_string()));
        }
        if u.contains("product=lrzsz&") {
            return Ok(Response::ok(json!([brew_record("lrzsz", "CVE-2018-10195", "0.12.20_1")]).to_string()));
        }
        Ok(Response::ok("[]"))
    });
    let names = vec!["aider".to_string(), "lrzsz".to_string(), "expat".to_string()];
    prefetch(&c, &net, &names, false).unwrap();
    prefetch(&c, &net, &names, false).unwrap();
    assert_eq!(net.requests().len(), 5, "three pages, then one each; fresh copies aren't asked again");
    let aider = advisories(&c, "aider").unwrap().unwrap();
    assert!(aider.complete);
    assert_eq!(aider.records.len(), 2 * PER_PAGE + 3);
    let lrzsz = advisories(&c, "lrzsz").unwrap().unwrap();
    assert_eq!(lrzsz.records[0].affects("0.12.20"), Some("0.12.20_1".into()));
    assert_eq!(advisories(&c, "expat").unwrap().unwrap(), Advisories { records: vec![], complete: true });
    assert_eq!(advisories(&c, "zip").unwrap(), None, "never asked");
}

#[test]
fn a_long_list_is_read_in_part_and_an_odd_answer_is_refused() {
    let (_d, c) = cache();
    let full = Fake::new(|_| {
        let list: Vec<Value> = (0..PER_PAGE).map(|i| brew_record("big", &format!("CVE-1-{i}"), "1.0_1")).collect();
        Ok(Response::ok(Value::Array(list).to_string()))
    });
    prefetch(&c, &full, &["big".into()], false).unwrap();
    assert_eq!(full.requests().len(), MAX_PAGES);
    assert!(!advisories(&c, "big").unwrap().unwrap().complete);
    let odd = Fake::new(|_| Ok(Response::ok(json!({"results": {}}).to_string())));
    prefetch(&c, &odd, &["odd".into()], false).unwrap();
    assert_eq!(advisories(&c, "odd").unwrap(), None);
    prefetch(&c, &Fake::offline(), &["gone".into()], false).unwrap();
    assert_eq!(advisories(&c, "gone").unwrap(), None);
}
