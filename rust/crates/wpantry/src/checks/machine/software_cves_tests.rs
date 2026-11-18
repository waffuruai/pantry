use super::*;
use crate::checks::machine::testing;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::json;

const W: &str = "installed programs against CVE records";

fn program(name: &str, version: &str, publisher: &str) -> Subject {
    Subject {
        kind: "app".into(),
        name: name.into(),
        version: version.into(),
        location: format!(r"HKLM\x\{name}"),
        vendors: vendors_for(publisher),
        product: None,
    }
}

fn parts(v: &str) -> Vec<String> {
    dotted(v, false).unwrap()
}

fn entry(versions: Value) -> Value {
    json!({"vendor": "Circutor", "product": "PowerStudio SCADA Wave", "versions": versions, "defaultStatus": "unaffected"})
}

/// The CIRCUTOR record's own `affected[]` entry.
fn circutor() -> Value {
    entry(json!([
        {"status": "affected", "version": "24.8.0", "lessThan": "24.11.17.0", "versionType": "custom"},
        {"status": "unaffected", "version": "24.11.17.0", "versionType": "custom"}
    ]))
}

#[test]
fn vendors_compare_without_case_punctuation_or_company_suffix() {
    assert_eq!(vendor_key("CIRCUTOR, SA"), "circutor");
    assert_eq!(vendor_key("Circutor"), "circutor");
    assert_eq!(vendor_key("Example Software, Inc."), "example software");
    assert_eq!(vendor_key("Exemple S.A."), "exemple");
    assert_eq!(vendor_key("Notepad++ Team"), "notepad++ team");
    // A suffix alone is still a name.
    assert_eq!(vendor_key("Corp"), "corp");
    assert_eq!(vendor_key(""), "");
    // The alias's names, or the key; then the whole name, as the index may keep it.
    assert_eq!(vendors_for("Broadcom Inc."), ["vmware", "broadcom", "broadcom inc"]);
    assert_eq!(vendors_for("Adobe Systems Incorporated"), ["adobe", "adobe systems incorporated"]);
    assert_eq!(vendors_for("Circutor"), ["circutor"]);
    assert_eq!(vendors_for("Oracle Corporation"), ["oracle", "oracle corporation"]);
    assert_eq!(vendors_for("Example Software, Inc."), ["example software", "example software inc"]);
    assert!(vendors_for("").is_empty() && vendors_for(" , ").is_empty());
}

#[test]
fn products_compare_without_version_build_or_vendor_words() {
    assert_eq!(product_key("PowerStudio SCADA Wave", "circutor", ""), "powerstudio scada wave");
    assert_eq!(
        product_key("PowerStudio SCADA Wave 24.11.17.0 (x64)", "circutor", "24.11.17.0"),
        "powerstudio scada wave"
    );
    assert_eq!(product_key("Circutor PowerStudio SCADA Wave v24.10", "circutor", ""), "powerstudio scada wave");
    assert_eq!(product_key("Example Viewer (64-bit)", "example", ""), "viewer");
    assert_eq!(product_key("Example Viewer 32 bit arm64", "", ""), "example viewer");
    assert_eq!(product_key("Viewer 2024", "", "7"), "viewer 2024", "a year is part of the name");
    assert_eq!(product_key("Viewer 7", "", "7"), "viewer", "the program's own version");
    assert_eq!(product_key("acrobat_reader", "adobe", ""), "acrobat reader");
    // The vendor's name alone stays.
    assert_eq!(product_key("Circutor", "circutor", ""), "circutor");
}

#[test]
fn dotted_versions_and_their_order() {
    assert_eq!(dotted("v24.11.17.0", false), Some(parts("24.11.17.0")));
    assert_eq!(dotted("17.x", true), Some(parts("17")));
    assert_eq!(dotted("17.x.X", true), Some(parts("17")));
    assert_eq!(dotted("17.x", false), None);
    for bad in ["", "25H2", "1..2", "https://example.com", "1.0-beta"] {
        assert_eq!(dotted(bad, false), None, "{bad}");
    }
    assert_eq!(cmp_parts(&parts("24.11.17"), &parts("24.11.17.0")), Ordering::Equal);
    assert_eq!(cmp_parts(&parts("24.10.3.0"), &parts("24.11.17.0")), Ordering::Less);
    assert_eq!(cmp_parts(&parts("26.002.21900"), &parts("26.2.21899")), Ordering::Greater);
}

#[test]
fn the_record_ranges_judge_the_installed_version() {
    let affected = |range: &str, fixed: &str| Verdict::Affected { range: range.into(), fixed: fixed.into() };
    // The CIRCUTOR shape: in range fails with its fix; the fix and older than the range don't.
    assert_eq!(judge(&parts("24.10.3.0"), &circutor()), affected(">=24.8.0, <24.11.17.0", "24.11.17.0"));
    assert_eq!(judge(&parts("24.11.17.0"), &circutor()), Verdict::Unaffected);
    assert_eq!(judge(&parts("24.7"), &circutor()), Verdict::Unaffected);
    // From the start, up to and including: the next unaffected version is the fix.
    let le = entry(json!([
        {"status": "affected", "version": "0", "lessThanOrEqual": "26.002.21900"},
        {"status": "unaffected", "version": "26.002.21901"},
        {"status": "unaffected", "version": "25.0"},
        {"status": "unaffected", "version": "later"}
    ]));
    assert_eq!(judge(&parts("26.002.21900"), &le), affected("<=26.002.21900", "26.002.21901"));
    let le_only = entry(json!([{"status": "affected", "version": "*", "lessThanOrEqual": "3.0"}]));
    assert_eq!(judge(&parts("3.0"), &le_only), affected("<=3.0", ""));
    let le_bad = entry(
        json!([{"status": "affected", "version": "1.0", "lessThanOrEqual": "3.0"}, {"status": "unaffected", "version": "next"}]),
    );
    assert_eq!(judge(&parts("2"), &le_bad), affected(">=1.0, <=3.0", ""));
    // One version; every version from one on; a wildcard start.
    let one = entry(json!([{"status": "affected", "version": "2.4.1"}]));
    assert_eq!(judge(&parts("2.4.1"), &one), affected("=2.4.1", ""));
    assert_eq!(judge(&parts("2.4.2"), &one), Verdict::Unaffected);
    let open = entry(json!([{"status": "affected", "version": "5.0", "lessThan": "*"}]));
    assert_eq!(judge(&parts("9"), &open), affected(">=5.0", ""));
    let wild = entry(json!([{"status": "affected", "version": "17.x", "lessThan": "17.5.1"}]));
    assert_eq!(judge(&parts("17.0.2"), &wild), affected(">=17.x, <17.5.1", "17.5.1"));
    assert_eq!(judge(&parts("16.2"), &wild), Verdict::Unaffected);
    // An unaffected match wins, wherever it is listed.
    let both = entry(json!([
        {"status": "affected", "version": "1.0", "lessThan": "3.0"},
        {"status": "unaffected", "version": "2.0"}
    ]));
    assert_eq!(judge(&parts("2.0"), &both), Verdict::Unaffected);
    // Versions that aren't numbers can't be judged; nor a default of affected with no match.
    let named = entry(json!([{"status": "affected", "version": "25H2", "lessThan": "26H1"}]));
    assert_eq!(judge(&parts("25.0.0"), &named), Verdict::Unknown);
    let url = entry(json!([{"status": "affected", "version": "16.0.1", "lessThan": "https://example.com/releases"}]));
    assert_eq!(judge(&parts("16.0.1"), &url), Verdict::Unknown);
    let word = entry(json!([{"status": "affected", "version": "all"}]));
    assert_eq!(judge(&parts("1"), &word), Verdict::Unknown);
    let default = json!({"versions": [], "defaultStatus": "affected"});
    assert_eq!(judge(&parts("1"), &default), Verdict::Unknown);
    // A known range that misses wins over nothing: unaffected.
    assert_eq!(judge(&parts("1"), &json!({})), Verdict::Unaffected);
    // A status that is neither (an unknown one) says nothing.
    let unknown_status = entry(json!([{"status": "unknown", "version": "1"}]));
    assert_eq!(judge(&parts("1"), &unknown_status), Verdict::Unaffected);
}

fn record(id: &str, affected: Value, score: Option<f64>) -> Record {
    Record {
        id: id.into(),
        title: "JWT signature validation bypass".into(),
        score: score.map(|s| (s, "4.0".to_string())),
        affected: vec![affected],
    }
}

#[test]
fn a_matching_record_is_a_finding_that_names_it() {
    let p = program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA");
    let recs = vec![
        record("CVE-2026-120387", circutor(), Some(10.0)),
        // The same CVE again (asked under two product names): once.
        record("CVE-2026-120387", circutor(), Some(10.0)),
        // Same vendor, another product: not this program's.
        record(
            "CVE-2026-2",
            json!({"vendor": "Circutor", "product": "PowerStudio Deluxe", "versions": [{"status": "affected", "version": "0", "lessThan": "99"}]}),
            None,
        ),
        // Same product name, another vendor: not this program's.
        record(
            "CVE-2026-3",
            json!({"vendor": "Someone Else", "product": "PowerStudio SCADA Wave", "versions": [{"status": "affected", "version": "0", "lessThan": "99"}]}),
            None,
        ),
    ];
    let (found, unknown) = assess(&p, "circutor", &recs, &|id| id == "CVE-2026-120387");
    assert!(!unknown);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(
        (f.kind.as_str(), f.vuln_id.as_str(), f.status.as_str(), f.fixed.as_str(), f.severity.as_str()),
        ("app", "CVE-2026-120387", "fail", "24.11.17.0", "CRITICAL")
    );
    assert!(f.kev);
    assert_eq!((f.cvss, f.cvss_version.as_str()), (Some(10.0), "4.0"));
    assert_eq!(f.affected_range, ">=24.8.0, <24.11.17.0");
    assert_eq!(
        f.note,
        "JWT signature validation bypass (CVE record for vendor \"Circutor\", product \"PowerStudio SCADA Wave\")"
    );
    assert_eq!(f.fix_cmd, "Update PowerStudio SCADA Wave to 24.11.17.0 or later from its vendor");
    assert_eq!((f.component.as_str(), f.version.as_str()), ("PowerStudio SCADA Wave", "24.10.3.0"));
    assert_eq!(f.location, r"HKLM\x\PowerStudio SCADA Wave");
    // The fixed version itself: nothing.
    let fixed = program("PowerStudio SCADA Wave", "24.11.17.0", "CIRCUTOR, SA");
    assert_eq!(assess(&fixed, "circutor", &recs, &|_| false), (vec![], false));
}

#[test]
fn no_fix_named_warns_and_unreadable_versions_are_not_clean() {
    let p = program("Example Viewer", "3.0", "Example Software, Inc.");
    let open = json!({"vendor": "Example Software", "product": "Example Viewer", "versions": [{"status": "affected", "version": "0", "lessThanOrEqual": "3.0"}]});
    let (found, unknown) = assess(&p, "example software", &[record("CVE-2026-4", open, None)], &|_| false);
    assert!(!unknown);
    assert_eq!((found[0].status.as_str(), found[0].fixed.as_str(), found[0].severity.as_str()), ("warn", "", ""));
    assert!(found[0].fix_cmd.starts_with("No fixed version named in the CVE record"), "{}", found[0].fix_cmd);
    let named = json!({"vendor": "Example Software", "product": "Example Viewer", "versions": [{"status": "affected", "version": "25H2", "lessThan": "26H1"}]});
    assert_eq!(
        assess(&p, "example software", &[record("CVE-2026-5", named.clone(), None)], &|_| false),
        (vec![], true)
    );
    // An installed version that isn't a dotted number can't be judged by any record.
    let odd = program("Example Viewer", "2024 R2", "Example Software, Inc.");
    assert_eq!(assess(&odd, "example software", &[record("CVE-2026-5", named, None)], &|_| false), (vec![], true));
    assert_eq!(assess(&odd, "example software", &[], &|_| false), (vec![], false));
}

#[test]
fn products_are_matched_by_name_not_by_likeness() {
    let p = program("VMware Workstation", "17.5.1.23298084", "Broadcom Inc.");
    let listed: Vec<String> =
        ["workstation", "vmware workstation", "vmware_workstation", "workstation pro", "workstation, fusion"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    assert_eq!(matching_products(&p, "vmware", &listed), ["vmware workstation", "vmware_workstation", "workstation"]);
    assert!(matching_products(&program("1.2", "1.2", "x"), "x", &listed).is_empty(), "a name that is only a version");
}

/// The index, for the scan tests: Circutor's products and records, one
/// vendor it doesn't know, and every request kept.
fn index() -> Fake {
    Fake::new(|r| {
        let rec = crate::sources::cve_records::tests::circutor_record();
        Ok(if r.url.ends_with("/browse/circutor") {
            Response::ok(json!(["powerstudio scada wave", "lineeds"]).to_string())
        } else if r.url.contains("/browse/") {
            Response::ok("[]")
        } else if r.url.contains("search/circutor/powerstudio%20scada%20wave") {
            Response::ok(crate::sources::cve_records::tests::page(&[rec], 1))
        } else {
            Response::not_found()
        })
    })
}

#[test]
fn the_scan_finds_the_circutor_record_and_nothing_else() {
    let d = TempDir::new("programs").unwrap();
    let net = index();
    let mut s = testing::scan(&net, &d);
    s.kev.insert("CVE-2026-120387".into());
    let programs = vec![
        program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA"),
        // A product of the same vendor the index doesn't list: never asked about.
        program("PowerStudio Deluxe", "1.0", "CIRCUTOR, SA"),
        program("Example Viewer", "2.4.1", "Example Software, Inc."),
        // No publisher: no vendor to match.
        program("Portable Tool", "1.0", ""),
    ];
    check(&mut s, &programs, W).unwrap();
    assert_eq!(testing::kinds(&s), [("PowerStudio SCADA Wave".into(), "CVE-2026-120387".into(), "fail".into())]);
    assert!(s.findings[0].kev);
    let urls: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
    // circutor, circutor sa, example software, example software inc; one product.
    assert_eq!(urls.len(), 5, "{urls:?}");
    assert!(urls.iter().all(|u| u.starts_with("https://vulnerability.circl.lu/api/")));
    assert!(!urls.iter().any(|u| u.contains("deluxe") || u.contains("portable")), "{urls:?}");

    // The fixed version: clean, from the cache, nothing asked.
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[program("PowerStudio SCADA Wave", "24.11.17.0", "CIRCUTOR, SA")], W).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
    assert_eq!(net.requests().len(), 5);

    // Offline with the cache: the same answer.
    let mut s = testing::scan(&net, &d);
    s.opts.offline = true;
    check(&mut s, &[program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA")], W).unwrap();
    assert_eq!(s.findings.len(), 1);
}

#[test]
fn the_index_offline_without_a_cache_is_not_checked_not_clean() {
    let d = TempDir::new("programs-offline").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA")], W).unwrap();
    assert_eq!(testing::unchecked_note(&s, &unreached(W)), "PowerStudio SCADA Wave");
    assert_eq!(s.findings.len(), 1);
    // Products known, records never fetched: not checked either.
    let d = TempDir::new("programs-half").unwrap();
    let half = Fake::new(|r| {
        if r.url.contains("/browse/") {
            Ok(Response::ok(json!(["powerstudio scada wave"]).to_string()))
        } else {
            Err(crate::error::Error::Offline("down".into()))
        }
    });
    let mut s = testing::scan(&half, &d);
    check(&mut s, &[program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA")], W).unwrap();
    assert_eq!(testing::unchecked_note(&s, &unreached(W)), "PowerStudio SCADA Wave");
    // Nothing installed: nothing asked, nothing said.
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[], W).unwrap();
    assert!(s.findings.is_empty() && s.counts.is_empty());
}

#[test]
fn unjudged_and_partly_read_records_are_reported() {
    let d = TempDir::new("programs-odd").unwrap();
    let net = Fake::new(|r| {
        let mut rec = crate::sources::cve_records::tests::circutor_record();
        rec["containers"]["cna"]["affected"][0]["product"] = json!("Viewer");
        rec["containers"]["cna"]["affected"][0]["vendor"] = json!("Example");
        rec["containers"]["cna"]["affected"][0]["versions"] =
            json!([{"status": "affected", "version": "25H2", "lessThan": "26H1"}]);
        Ok(if r.url.contains("/browse/") {
            Response::ok(json!(["viewer"]).to_string())
        } else {
            Response::ok(crate::sources::cve_records::tests::page(&[rec], 1_000_000))
        })
    });
    let mut s = testing::scan(&net, &d);
    let many: Vec<Subject> = (1..=6).map(|i| program("Viewer", &format!("{i}.0"), "Example Ltd")).collect();
    check(&mut s, &many, W).unwrap();
    assert_eq!(testing::unchecked_note(&s, &unjudged(W)), "Viewer", "one name, however many versions are installed");
    assert_eq!(testing::unchecked_note(&s, &partial(W)), "Viewer");
}

#[test]
fn a_long_list_of_names_is_cut_short() {
    let d = TempDir::new("programs-many").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    let many: Vec<Subject> = ["A", "B", "C", "D", "E", "F"].iter().map(|n| program(n, "1.0", "Example")).collect();
    check(&mut s, &many, W).unwrap();
    assert_eq!(testing::unchecked_note(&s, &unreached(W)), "A, B, C, D and 2 more");
}

/// Oracle's MySQL Server entry (CVE-2026-114952's shape): `a-b` is an
/// inclusive range, a bare version that version only.
fn mysql_entry() -> Value {
    json!({"vendor": "Oracle Corporation", "product": "MySQL Server", "versions": [
        {"version": "8.4.0-8.4.13", "status": "affected"},
        {"version": "9.7.0-9.7.4", "status": "affected"},
        {"version": "26.10", "status": "affected"}
    ]})
}

/// Oracle's Java SE entry (CVE-2026-114938's shape): the last affected
/// version of each train.
fn java_entry() -> Value {
    json!({"vendor": "Oracle Corporation", "product": "Oracle Java SE", "versions": [
        {"version": "8u511b33-perf", "status": "affected"},
        {"version": "17.0.21.0.3", "status": "affected"},
        {"version": "21.0.13.0.3", "status": "affected"},
        {"version": "25.0.5.0.3", "status": "affected"},
        {"version": "27.0.1.0.3", "status": "affected"}
    ]})
}

#[test]
fn oracle_mysql_ranges_are_inclusive_and_a_bare_version_is_that_version() {
    let affected = |range: &str| Verdict::Affected { range: range.into(), fixed: String::new() };
    assert_eq!(judge(&parts("8.4.13"), &mysql_entry()), affected(">=8.4.0, <=8.4.13"));
    assert_eq!(judge(&parts("8.4.0"), &mysql_entry()), affected(">=8.4.0, <=8.4.13"));
    assert_eq!(judge(&parts("9.7.2"), &mysql_entry()), affected(">=9.7.0, <=9.7.4"));
    assert_eq!(judge(&parts("26.10"), &mysql_entry()), affected("=26.10"));
    for clean in ["8.4.14", "8.0.40", "9.7.5", "26.11", "9.6.9"] {
        assert_eq!(judge(&parts(clean), &mysql_entry()), Verdict::Unaffected, "{clean}");
    }
    // A backwards or half-numeric span is not a range.
    assert_eq!(inclusive_span("8.4.13-8.4.0"), None);
    assert_eq!(inclusive_span("8.4.0-beta"), None);
    let backwards = entry(json!([{"status": "affected", "version": "2.0-1.0"}]));
    assert_eq!(judge(&parts("1.5"), &backwards), Verdict::Unknown);
}

#[test]
fn java_versions_are_read_by_train() {
    assert_eq!(java_parts("17.0.21.0.3"), Some(parts("17.0.21.0.3")));
    assert_eq!(java_parts("8u511b33-perf"), Some(parts("8.0.511")));
    assert_eq!(java_parts("1.8.0_412"), Some(parts("8.0.412")));
    for none in ["1.8.0", "1.7.0", "8u", "1.8.0_", "openjdk"] {
        assert_eq!(java_parts(none), None, "{none}");
    }
    let affected = |range: &str| Verdict::Affected { range: range.into(), fixed: String::new() };
    let i = |v: &str| java_parts(v).unwrap();
    assert_eq!(judge_trains(&i("17.0.12"), &java_entry()), affected("<=17.0.21.0.3 (the 17 train)"));
    assert_eq!(judge_trains(&i("17.0.21"), &java_entry()), affected("<=17.0.21.0.3 (the 17 train)"));
    assert_eq!(judge_trains(&i("17.0.22"), &java_entry()), Verdict::Unaffected);
    // Java 8 as `java -version` reports it, `1.8.0_N`, against Oracle's `8u511b33-perf`.
    assert_eq!(judge_trains(&i("1.8.0_412"), &java_entry()), affected("<=8u511b33-perf (the 8 train)"));
    assert_eq!(judge_trains(&i("1.8.0_511"), &java_entry()), affected("<=8u511b33-perf (the 8 train)"));
    assert_eq!(judge_trains(&i("1.8.0_512"), &java_entry()), Verdict::Unaffected);
    assert_eq!(java_parts("1.8.0_512-b08"), Some(parts("8.0.512")), "a build suffix is not the update");
    assert_eq!(judge_trains(&i("8u521"), &java_entry()), Verdict::Unaffected);
    assert_eq!(judge_trains(&i("21"), &java_entry()), affected("<=21.0.13.0.3 (the 21 train)"));
    // A train the record doesn't list can't be judged; unread versions are skipped.
    assert_eq!(judge_trains(&i("11.0.25"), &java_entry()), Verdict::Unknown);
    let odd =
        json!({"versions": [{"version": "next", "status": "affected"}, {"version": "17.0.1", "status": "unaffected"}]});
    assert_eq!(judge_trains(&i("17.0.1"), &odd), Verdict::Unknown);
}

#[test]
fn catalog_tools_are_matched_by_the_table_only() {
    let tool = |name: &str, version: &str| crate::component::Component {
        kind: if name == "java" { "runtime" } else { "datastore" }.into(),
        name: name.into(),
        version: version.into(),
        path: format!("/opt/{name}/bin/{name}"),
        ..Default::default()
    };
    let subjects = tool_subjects(&[tool("java", "17.0.12"), tool("mysql", "8.4.3"), tool("node", "22.0.0")]);
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0].vendors, ["oracle", "oracle corporation"]);
    assert_eq!(subjects[0].product.as_deref(), Some("Oracle Java SE"));
    let recs = |e: Value| vec![record("CVE-2026-114938", e, Some(7.5))];
    let (java, unknown) = assess(&subjects[0], "oracle corporation", &recs(java_entry()), &|_| false);
    assert!(!unknown);
    assert_eq!(
        (java[0].kind.as_str(), java[0].component.as_str(), java[0].status.as_str(), java[0].severity.as_str()),
        ("runtime", "java", "warn", "HIGH")
    );
    assert_eq!(java[0].affected_range, "<=17.0.21.0.3 (the 17 train)");
    assert_eq!(
        java[0].note,
        "JWT signature validation bypass (CVE record for vendor \"Oracle Corporation\", product \"Oracle Java SE\")"
    );
    let (mysql, _) = assess(&subjects[1], "oracle corporation", &recs(mysql_entry()), &|_| false);
    assert_eq!((mysql[0].component.as_str(), mysql[0].affected_range.as_str()), ("mysql", ">=8.4.0, <=8.4.13"));
    // The index's names for Java SE: Oracle's own and the bare one, not Oracle's other Java products.
    let listed: Vec<String> = ["oracle java se", "java se", "java", "oracle javafx", "java se jdk and jre"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(matching_products(&subjects[0], "oracle corporation", &listed), ["java se", "oracle java se"]);
    // A Java 8 with its update is judged by it; one without can't be judged.
    let eight = tool_subjects(&[tool("java", "1.8.0_412"), tool("java", "1.8.0_512"), tool("java", "1.8.0")]);
    let (affected, unknown) = assess(&eight[0], "oracle corporation", &recs(java_entry()), &|_| false);
    assert!(!unknown);
    assert_eq!(
        (affected[0].version.as_str(), affected[0].status.as_str(), affected[0].affected_range.as_str()),
        ("1.8.0_412", "warn", "<=8u511b33-perf (the 8 train)")
    );
    assert_eq!(assess(&eight[1], "oracle corporation", &recs(java_entry()), &|_| false), (vec![], false));
    assert_eq!(assess(&eight[2], "oracle", &recs(java_entry()), &|_| false), (vec![], true));
}

#[test]
fn the_tool_check_asks_for_oracle_records() {
    let d = TempDir::new("tools-cve").unwrap();
    let net = Fake::new(|r| {
        let rec = json!({"cveMetadata": {"cveId": "CVE-2026-114952", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "MySQL Server optimizer flaw", "affected": [mysql_entry()]}}});
        Ok(if r.url.ends_with("/browse/oracle%20corporation") {
            Response::ok(json!(["mysql server", "mysql cluster", "oracle java se"]).to_string())
        } else if r.url.contains("/browse/") {
            Response::ok("[]")
        } else if r.url.contains("search/oracle%20corporation/mysql%20server") {
            Response::ok(crate::sources::cve_records::tests::page(&[rec], 1))
        } else {
            Response::ok(crate::sources::cve_records::tests::page(&[], 0))
        })
    });
    let mut s = testing::scan(&net, &d);
    let mysql = crate::component::Component {
        kind: "datastore".into(),
        name: "mysql".into(),
        version: "8.4.3".into(),
        path: "/usr/sbin/mysqld".into(),
        ..Default::default()
    };
    let java = crate::component::Component { name: "java".into(), version: "17.0.22".into(), ..mysql.clone() };
    tools(&mut s, &[mysql, java]).unwrap();
    assert_eq!(testing::kinds(&s), [("mysql".into(), "CVE-2026-114952".into(), "warn".into())]);
    assert_eq!(s.findings[0].location, "/usr/sbin/mysqld");
    // No tool the table names: nothing asked.
    let before = net.requests().len();
    tools(&mut s, &[]).unwrap();
    assert_eq!(net.requests().len(), before);
}
