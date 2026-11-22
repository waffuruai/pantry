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
        released: None,
        support_end: None,
        nvd: false,
        system: String::new(),
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
        published: String::new(),
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
    assert!(unknown.is_none(), "{unknown:?}");
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
    assert_eq!(assess(&fixed, "circutor", &recs, &|_| false), (vec![], None));
}

#[test]
fn no_fix_named_warns_and_unreadable_versions_are_not_clean() {
    let p = program("Example Viewer", "3.0", "Example Software, Inc.");
    let open = json!({"vendor": "Example Software", "product": "Example Viewer", "versions": [{"status": "affected", "version": "0", "lessThanOrEqual": "3.0"}]});
    let (found, unknown) = assess(&p, "example software", &[record("CVE-2026-4", open, None)], &|_| false);
    assert!(unknown.is_none(), "{unknown:?}");
    assert_eq!((found[0].status.as_str(), found[0].fixed.as_str(), found[0].severity.as_str()), ("warn", "", ""));
    assert!(found[0].fix_cmd.starts_with("No fixed version named in the CVE record"), "{}", found[0].fix_cmd);
    let named = json!({"vendor": "Example Software", "product": "Example Viewer", "versions": [{"status": "affected", "version": "25H2", "lessThan": "26H1"}]});
    {
        let (f, why) = assess(&p, "example software", &[record("CVE-2026-5", named.clone(), None)], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // An installed version that isn't a dotted number can't be judged by any record.
    let odd = program("Example Viewer", "2024 R2", "Example Software, Inc.");
    {
        let (f, why) = assess(&odd, "example software", &[record("CVE-2026-5", named, None)], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    assert_eq!(assess(&odd, "example software", &[], &|_| false), (vec![], None));
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
    assert_eq!(
        testing::unchecked_note(&s, &unjudged_label(W)),
        "Viewer 1.0, Viewer 2.0, Viewer 3.0 and 3 more: CVE-2026-120387 writes some versions in a form Pantry can't read.",
        "the installs that share a reason share a line"
    );
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
    // `and prior` / `and earlier`: up to that version, included.
    for words in ["8.0.30 and prior", "8.0.30 and earlier"] {
        let prior = entry(json!([{"status": "affected", "version": words}]));
        assert_eq!(
            judge(&parts("8.0.30"), &prior),
            Verdict::Affected { range: "<=8.0.30".into(), fixed: String::new() },
            "{words}"
        );
        assert_eq!(
            judge(&parts("5.7.44"), &prior),
            Verdict::Affected { range: "<=8.0.30".into(), fixed: String::new() }
        );
        assert_eq!(judge(&parts("8.0.31"), &prior), Verdict::Unaffected);
    }
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
    // A record naming Java 8 only as Performance Pack (`8u511b33-perf`)
    // doesn't affect a plain Java 8.
    assert_eq!(judge_trains(&i("1.8.0_412"), &java_entry()), Verdict::Unaffected);
    // With a plain 8 entry too, that one decides. Java 8 as `java -version`
    // reports it, `1.8.0_N`, by quarterly update: OpenJDK's 8u512 is Oracle's
    // 8u511, so it's affected; 8u521 and OpenJDK's 8u522 are the next quarter.
    let eight = json!({"versions": [
        {"version": "8u511-perf", "status": "affected"},
        {"version": "8u511b33", "status": "affected"},
        {"version": "17.0.21.0.3", "status": "affected"}
    ]});
    assert_eq!(judge_trains(&i("1.8.0_412"), &eight), affected("<=8u511b33 (the 8 train)"));
    assert_eq!(judge_trains(&i("1.8.0_511"), &eight), affected("<=8u511b33 (the 8 train)"));
    assert_eq!(judge_trains(&i("1.8.0_512"), &eight), affected("<=8u511b33 (the 8 train)"));
    assert_eq!(judge_trains(&i("8u521"), &eight), Verdict::Unaffected);
    assert_eq!(judge_trains(&i("1.8.0_522"), &eight), Verdict::Unaffected);
    assert_eq!(java_parts("1.8.0_512-b08"), Some(parts("8.0.512")), "a build suffix is not the update");
    // An entry that names the product first.
    let named = json!({"versions": [{"version": "Oracle Java SE:17.0.13", "status": "affected"}]});
    assert_eq!(judge_trains(&i("17.0.12"), &named), affected("<=17.0.13 (the 17 train)"));
    assert_eq!(judge_trains(&i("17.0.14"), &named), Verdict::Unaffected);
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
    let subjects =
        tool_subjects(&[tool("java", "17.0.12"), tool("mysql", "8.4.3"), tool("node", "22.0.0")], &|_| false);
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0].vendors, ["oracle", "oracle corporation"]);
    assert_eq!(subjects[0].product.as_deref(), Some("Oracle Java SE"));
    let recs = |e: Value| vec![record("CVE-2026-114938", e, Some(7.5))];
    let (java, unknown) = assess(&subjects[0], "oracle corporation", &recs(java_entry()), &|_| false);
    assert!(unknown.is_none(), "{unknown:?}");
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
    let eight =
        tool_subjects(&[tool("java", "1.8.0_412"), tool("java", "1.8.0_522"), tool("java", "1.8.0")], &|_| false);
    let plain = json!({"vendor": "Oracle Corporation", "product": "Oracle Java SE", "versions": [
        {"version": "8u511b33-perf", "status": "affected"},
        {"version": "8u511b33", "status": "affected"}
    ]});
    let (affected, unknown) = assess(&eight[0], "oracle corporation", &recs(plain.clone()), &|_| false);
    assert!(unknown.is_none(), "{unknown:?}");
    assert_eq!(
        (affected[0].version.as_str(), affected[0].status.as_str(), affected[0].affected_range.as_str()),
        ("1.8.0_412", "warn", "<=8u511b33 (the 8 train)")
    );
    assert_eq!(assess(&eight[1], "oracle corporation", &recs(plain.clone()), &|_| false), (vec![], None));
    {
        let (f, why) = assess(&eight[2], "oracle", &recs(plain), &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // Performance Pack only: a plain Java 8 isn't affected.
    assert_eq!(assess(&eight[0], "oracle corporation", &recs(java_entry()), &|_| false), (vec![], None));
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
    tools(&mut s, &[mysql.clone(), java], &HashMap::new()).unwrap();
    assert_eq!(testing::kinds(&s), [("mysql".into(), "CVE-2026-114952".into(), "warn".into())]);
    assert_eq!(s.findings[0].location, "/usr/sbin/mysqld");
    // No tool the table names: nothing asked.
    let before = net.requests().len();
    tools(&mut s, &[], &HashMap::new()).unwrap();
    assert_eq!(net.requests().len(), before);
    // A CVE already reported for this install (by OSV) isn't repeated; a
    // second install of the same version at another path is its own.
    let other = crate::component::Component { path: "/opt/mysql/bin/mysqld".into(), ..mysql.clone() };
    tools(&mut s, &[mysql, other], &HashMap::new()).unwrap();
    let at: Vec<&str> = s.findings.iter().map(|f| f.location.as_str()).collect();
    assert_eq!(at, ["/usr/sbin/mysqld", "/opt/mysql/bin/mysqld"]);
}

/// A CVE JSON 5 record trimmed to what is read: its id, title, one
/// `affected[]` entry as the index serves it, and the CNA's base score.
fn cve(id: &str, title: &str, affected: Value, score: f64) -> Value {
    json!({"cveMetadata": {"cveId": id, "state": "PUBLISHED"},
           "containers": {"cna": {"title": title, "affected": [affected],
                                  "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": score}}]}}})
}

/// `rec` with its `cveMetadata.datePublished` on `day`.
fn published(mut rec: Value, day: &str) -> Value {
    rec["cveMetadata"]["datePublished"] = json!(format!("{day}T12:00:00.000Z"));
    rec
}

/// CVE-2024-4577 as filed (published 2024-06-09): the 8.1 to 8.3 trains,
/// a default of affected.
fn php_4577() -> Value {
    published(
        cve(
            "CVE-2024-4577",
            "Argument Injection in PHP-CGI",
            json!({"vendor": "PHP Group", "product": "PHP", "defaultStatus": "affected", "versions": [
                {"lessThan": "8.1.29", "status": "affected", "version": "8.1.*", "versionType": "semver"},
                {"lessThan": "8.2.20", "status": "affected", "version": "8.2.*", "versionType": "semver"},
                {"lessThan": "8.3.8", "status": "affected", "version": "8.3.*", "versionType": "semver"}]}),
            9.8,
        ),
        "2024-06-09",
    )
}

/// PHP's records as the index serves them (2026-11-17), `affected[]` as
/// filed, with their publication days.
fn php_records() -> (Vec<Value>, Vec<Value>) {
    let group = vec![
        published(
            cve(
                "CVE-2026-109618",
                "RCE via OOM corruption",
                json!({"vendor": "PHP Group", "product": "PHP", "packageName": "php-src", "defaultStatus": "unaffected", "versions": [
                {"status": "affected", "version": "8.2.*", "lessThan": "8.2.35", "versionType": "semver"},
                {"status": "affected", "version": "8.3.*", "lessThan": "8.3.36", "versionType": "semver"},
                {"status": "affected", "version": "8.4.*", "lessThan": "8.4.27", "versionType": "semver"},
                {"status": "affected", "version": "8.5.*", "lessThan": "8.5.12", "versionType": "semver"}]}),
                8.1,
            ),
            "2026-10-21",
        ),
        published(
            cve(
                "CVE-2024-8932",
                "OOB access in ldap_escape",
                json!({"vendor": "PHP Group", "product": "PHP", "defaultStatus": "affected", "versions": [
                {"lessThan": "8.1.31", "status": "affected", "version": "8.1.*", "versionType": "semver"},
                {"lessThan": "8.2.26", "status": "affected", "version": "8.2.*", "versionType": "semver"},
                {"lessThan": "8.3.14", "status": "affected", "version": "8.3.*", "versionType": "semver"}]}),
                9.8,
            ),
            "2024-11-22",
        ),
        php_4577(),
    ];
    let bare = vec![
        cve(
            "CVE-2026-14355",
            "ext/openssl: Memory corruption in openssl_encrypt with AES-WRAP-PAD",
            json!({"vendor": "php", "product": "php", "defaultStatus": "affected", "versions": [
                {"status": "affected", "version": "8.2.0", "lessThan": "8.2.32", "versionType": "semver"},
                {"status": "affected", "version": "8.3.0", "lessThan": "8.3.32", "versionType": "semver"},
                {"status": "affected", "version": "8.4.0", "lessThan": "8.4.23", "versionType": "semver"},
                {"status": "affected", "version": "8.5.0", "lessThan": "8.5.8", "versionType": "semver"}]}),
            4.8,
        ),
        cve(
            "CVE-2019-11043",
            "Underflow in PHP-FPM can lead to RCE",
            json!({"vendor": "PHP", "product": "PHP", "versions": [
                {"lessThan": "7.1.33", "status": "affected", "version": "7.1.x", "versionType": "custom"},
                {"lessThan": "7.2.24", "status": "affected", "version": "7.2.x", "versionType": "custom"},
                {"lessThan": "7.3.11", "status": "affected", "version": "7.3.x", "versionType": "custom"}]}),
            8.7,
        ),
        cve(
            "CVE-2014-3622",
            "",
            json!({"vendor": "PHP", "product": "PHP", "versions": [{"status": "affected", "version": "5.6.x before 5.6.1"}]}),
            0.0,
        ),
    ];
    (group, bare)
}

/// Rust's records as the index serves them (2026-11-17).
fn rust_records() -> (Vec<Value>, Vec<Value>) {
    let lang = vec![cve(
        "CVE-2024-24576",
        "Rusts's `std::process::Command` did not properly escape arguments of batch files on Windows",
        json!({"vendor": "rust-lang", "product": "rust", "versions": [{"version": "< 1.77.2", "status": "affected"}]}),
        10.0,
    )];
    let project = vec![cve(
        "CVE-2025-11233",
        "Rust standard library didn't detect all path separators on Cygwin",
        json!({"vendor": "Rust Project", "product": "std", "defaultStatus": "unaffected", "versions": [
            {"lessThan": "1.89.0", "status": "affected", "version": "1.87.0", "versionType": "semver"}]}),
        6.3,
    )];
    (lang, project)
}

/// The index, for PHP and Rust: the vendors and products their records
/// are filed under (`browse/php` lists many more products than these).
fn runtimes_index() -> Fake {
    Fake::new(|r| {
        let (group, bare) = php_records();
        let (lang, project) = rust_records();
        let page = crate::sources::cve_records::tests::page;
        let u = r.url.as_str();
        Ok(if u.ends_with("/browse/php%20group") {
            Response::ok(json!(["php imagick extension", "php"]).to_string())
        } else if u.ends_with("/browse/php") {
            Response::ok(json!(["php", "php_fi", "pear", "frankenphp"]).to_string())
        } else if u.ends_with("/browse/rust-lang") {
            Response::ok(json!(["cargo", "regex", "rust"]).to_string())
        } else if u.ends_with("/browse/rust%20lang") {
            Response::ok(json!(["rust"]).to_string())
        } else if u.ends_with("/browse/rust%20project") {
            Response::ok(json!(["cargo", "std"]).to_string())
        } else if u.contains("search/php%20group/php?") {
            Response::ok(page(&group, 2))
        } else if u.contains("search/php/php?") {
            Response::ok(page(&bare, 3))
        } else if u.contains("search/rust-lang/rust?") {
            Response::ok(page(&lang, 1))
        } else if u.contains("search/rust%20project/std?") {
            Response::ok(page(&project, 1))
        } else if u.contains("/search/") {
            Response::ok(page(&[], 0))
        } else {
            Response::not_found()
        })
    })
}

fn runtime(name: &str, version: &str) -> crate::component::Component {
    let (repo, tag) = match name {
        "php" => ("https://github.com/php/php-src.git", format!("php-{version}")),
        _ => ("https://github.com/rust-lang/rust.git", version.to_string()),
    };
    crate::component::Component {
        kind: "runtime".into(),
        name: name.into(),
        version: version.into(),
        path: format!("/usr/local/bin/{name}"),
        osv: Some(("GIT".into(), repo.into(), tag)),
        ..Default::default()
    }
}

/// OSV's answer for each component: nothing.
fn osv_empty(found: &[crate::component::Component]) -> HashMap<Item, Vec<Value>> {
    found.iter().filter_map(|c| c.osv.clone()).map(|i| (i, Vec::new())).collect()
}

fn failures(s: &Scan) -> Vec<(String, String, String, String)> {
    s.findings
        .iter()
        .filter(|f| f.kind != "unchecked")
        .map(|f| (f.component.clone(), f.vuln_id.clone(), f.status.clone(), f.fixed.clone()))
        .collect()
}

fn row(c: &str, id: &str, status: &str, fixed: &str) -> (String, String, String, String) {
    (c.into(), id.into(), status.into(), fixed.into())
}

#[test]
fn php_and_rust_record_shapes_are_read() {
    let affected = |range: &str, fixed: &str| Verdict::Affected { range: range.into(), fixed: fixed.into() };
    let php = |versions: Value, default: &str| json!({"vendor": "PHP Group", "product": "PHP", "versions": versions, "defaultStatus": default});
    // `8.3.*` with `lessThan` (CVE-2026-109618): the 8.3 train up to its fix.
    let trains = php(
        json!([{"status": "affected", "version": "8.3.*", "lessThan": "8.3.36"},
               {"status": "affected", "version": "8.4.*", "lessThan": "8.4.27"}]),
        "unaffected",
    );
    assert_eq!(judge(&parts("8.4.20"), &trains), affected(">=8.4.*, <8.4.27", "8.4.27"));
    assert_eq!(judge(&parts("8.4.0"), &trains), affected(">=8.4.*, <8.4.27", "8.4.27"));
    assert_eq!(judge(&parts("8.3.13"), &trains), affected(">=8.3.*, <8.3.36", "8.3.36"));
    for clean in ["8.4.27", "8.3.36", "8.5.0", "8.2.9"] {
        assert_eq!(judge(&parts(clean), &trains), Verdict::Unaffected, "{clean}");
    }
    // The same with a default of affected (CVE-2024-8932): past the fix of its
    // own listed train is clean; a train the record doesn't list is unknown.
    let default = php(json!([{"status": "affected", "version": "8.3.*", "lessThan": "8.3.14"}]), "affected");
    assert_eq!(judge(&parts("8.3.13"), &default), affected(">=8.3.*, <8.3.14", "8.3.14"));
    assert_eq!(judge(&parts("8.3.14"), &default), Verdict::Unaffected);
    assert_eq!(judge(&parts("8.4.20"), &default), Verdict::Unknown);
    assert_eq!(judge(&parts("7.4.33"), &default), Verdict::Unknown);
    // A plain start and fix in one train (CVE-2026-14355, `8.4.0` to `8.4.23`).
    let plain = php(json!([{"status": "affected", "version": "8.4.0", "lessThan": "8.4.23"}]), "affected");
    assert_eq!(judge(&parts("8.4.22"), &plain), affected(">=8.4.0, <8.4.23", "8.4.23"));
    assert_eq!(judge(&parts("8.4.27"), &plain), Verdict::Unaffected);
    // `7.4.X` (CVE-2022-31629) and `7.3.x` with `lessThanOrEqual` (CVE-2021-21703).
    let upper = php(json!([{"version": "7.4.X", "status": "affected", "lessThan": "7.4.31"}]), "");
    assert_eq!(judge(&parts("7.4.30"), &upper), affected(">=7.4.X, <7.4.31", "7.4.31"));
    let le = php(json!([{"lessThanOrEqual": "7.3.31", "status": "affected", "version": "7.3.x"}]), "");
    assert_eq!(judge(&parts("7.3.31"), &le), affected(">=7.3.x, <=7.3.31", ""));
    // Trains with their fix in words (CVE-2020-7067, CVE-2019-11038, CVE-2014-3622).
    let below = php(
        json!([{"status": "affected", "version": "7.2.x below 7.2.30"},
               {"status": "affected", "version": "7.3.x below 7.3.17 and 7.4.x below 7.4.5"}]),
        "",
    );
    assert_eq!(judge(&parts("7.2.29"), &below), affected(">=7.2.x, <7.2.30", "7.2.30"));
    assert_eq!(judge(&parts("7.3.16"), &below), affected(">=7.3.x, <7.3.17", "7.3.17"));
    assert_eq!(judge(&parts("7.4.4"), &below), affected(">=7.4.x, <7.4.5", "7.4.5"));
    assert_eq!(judge(&parts("7.4.5"), &below), Verdict::Unaffected);
    let lt = php(json!([{"status": "affected", "version": "7.1.x < 7.1.30"}]), "");
    assert_eq!(judge(&parts("7.1.29"), &lt), affected(">=7.1.x, <7.1.30", "7.1.30"));
    let before = php(json!([{"status": "affected", "version": "5.6.x before 5.6.1"}]), "");
    assert_eq!(judge(&parts("5.6.0"), &before), affected(">=5.6.x, <5.6.1", "5.6.1"));
    assert_eq!(judge(&parts("8.4.20"), &before), Verdict::Unaffected);
    // Comparisons alone, as GitHub's records write them (CVE-2024-24576, CVE-2023-40030).
    let rust =
        |v: &str| json!({"vendor": "rust-lang", "product": "rust", "versions": [{"version": v, "status": "affected"}]});
    assert_eq!(judge(&parts("1.76.0"), &rust("< 1.77.2")), affected("<1.77.2", "1.77.2"));
    assert_eq!(judge(&parts("1.77.2"), &rust("< 1.77.2")), Verdict::Unaffected);
    assert_eq!(judge(&parts("1.71.1"), &rust(">= 1.60.0, < 1.72")), affected(">=1.60.0, <1.72", "1.72"));
    assert_eq!(judge(&parts("1.59.0"), &rust(">= 1.60.0, < 1.72")), Verdict::Unaffected);
    assert_eq!(judge(&parts("1.72.0"), &rust(">= 1.60.0, < 1.72")), Verdict::Unaffected);
    assert_eq!(judge(&parts("3.0"), &rust("<= 3.0")), affected("<=3.0", ""));
    assert_eq!(judge(&parts("9.1"), &rust(">= 5.0")), affected(">=5.0", ""));
    // Spellings not read stay unknown, never clean.
    for odd in ["> 1.0", "= 1.0", "1.18.0 and later [fixed: 1.30.0]", "8.3.x below soon", ">= 1.0, >= 2.0", "< "] {
        assert_eq!(judge(&parts("1.5"), &rust(odd)), Verdict::Unknown, "{odd}");
    }
}

#[test]
fn spelled_versions_and_release_trains() {
    let one = |v: &str| spelled(&json!({"status": "affected", "version": v}));
    assert_eq!(one("< 1.77.2"), Some(vec![json!({"status": "affected", "version": "0", "lessThan": "1.77.2"})]));
    assert_eq!(one(">= 5.0"), Some(vec![json!({"status": "affected", "version": "5.0", "lessThan": "*"})]));
    assert_eq!(
        one("7.3.x below 7.3.17 and 7.4.x below 7.4.5"),
        Some(vec![
            json!({"status": "affected", "version": "7.3.x", "lessThan": "7.3.17"}),
            json!({"status": "affected", "version": "7.4.x", "lessThan": "7.4.5"})
        ])
    );
    // One version, a span, a train missing its fix, a fixed train without the `.x`: not spelled out.
    for none in ["8.4.20", "8.4.0-8.4.13", "7.2.x below", "7.2 below 7.2.30", "7.2.x below 7.2.30 and soon"] {
        assert_eq!(one(none), None, "{none}");
    }
    // An entry that already has its bound is read as it is.
    assert_eq!(spelled(&json!({"status": "affected", "version": "< 1", "lessThan": "2"})), None);
    assert_eq!(train_of("8.3.*", "8.3.36"), Some(parts("8.3")));
    assert_eq!(train_of("7.4.X", "7.4.31"), Some(parts("7.4")));
    assert_eq!(train_of("8.4.0", "8.4.23"), Some(parts("8.4")));
    assert_eq!(train_of("1.87.0", "1.89.0"), None, "spans trains");
    assert_eq!(train_of("24.8.0", "24.11.17.0"), None);
    assert_eq!(train_of("0", "1.77.2"), None);
    assert_eq!(train_of("*", "3"), None);
}

#[test]
fn php_8_4_20_fails_cve_2026_109618_and_8_4_27_does_not() {
    let d = TempDir::new("php-cve").unwrap();
    let net = runtimes_index();
    let mut s = testing::scan(&net, &d);
    let php = [runtime("php", "8.4.20")];
    tools(&mut s, &php, &osv_empty(&php)).unwrap();
    assert_eq!(
        failures(&s),
        [row("php", "CVE-2026-109618", "fail", "8.4.27"), row("php", "CVE-2026-14355", "fail", "8.4.23")]
    );
    let f = &s.findings[0];
    assert_eq!(
        (f.kind.as_str(), f.affected_range.as_str(), f.severity.as_str()),
        ("runtime", ">=8.4.*, <8.4.27", "HIGH")
    );
    assert_eq!(f.note, "RCE via OOM corruption (CVE record for vendor \"PHP Group\", product \"PHP\")");
    assert_eq!(f.fix_cmd, "Update php to 8.4.27 or later from its vendor");
    // CVE-2024-8932 lists the 8.1 to 8.3 trains with a default of affected:
    // 8.4 can't be judged by it, and says so.
    assert_eq!(
        testing::unchecked_note(&s, &unjudged_label(TOOLS_WHAT)),
        "php 8.4.20: CVE-2024-8932 and CVE-2024-4577 list no range for the 8.4 line (versions not listed count as affected)."
    );
    let urls: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
    assert!(urls.iter().any(|u| u.ends_with("/browse/php%20group")) && urls.iter().any(|u| u.ends_with("/browse/php")));

    // The fixed release: neither record fails it (CVE-2026-14355's 8.4 train ends at 8.4.23).
    let mut s = testing::scan(&net, &d);
    let fixed = [runtime("php", "8.4.27")];
    tools(&mut s, &fixed, &osv_empty(&fixed)).unwrap();
    assert_eq!(failures(&s), []);
    assert_eq!(
        testing::unchecked_note(&s, &unjudged_label(TOOLS_WHAT)),
        "php 8.4.27: CVE-2024-8932 and CVE-2024-4577 list no range for the 8.4 line (versions not listed count as affected)."
    );

    // 8.3.13, which OSV's php-src answer leaves clean: CVE-2024-8932 among three.
    let mut s = testing::scan(&net, &d);
    let old = [runtime("php", "8.3.13")];
    tools(&mut s, &old, &osv_empty(&old)).unwrap();
    assert_eq!(
        failures(&s),
        [
            row("php", "CVE-2026-109618", "fail", "8.3.36"),
            row("php", "CVE-2024-8932", "fail", "8.3.14"),
            row("php", "CVE-2026-14355", "fail", "8.3.32")
        ]
    );
    assert_eq!(s.findings[1].severity, "CRITICAL");
    assert!(!s.findings.iter().any(|f| f.kind == "unchecked"), "every record judges 8.3: {:?}", testing::kinds(&s));
}

#[test]
fn rust_is_judged_by_the_rust_lang_and_std_records() {
    let d = TempDir::new("rust-cve").unwrap();
    let net = runtimes_index();
    let mut s = testing::scan(&net, &d);
    let old = [runtime("rust", "1.76.0")];
    tools(&mut s, &old, &osv_empty(&old)).unwrap();
    assert_eq!(failures(&s), [row("rust", "CVE-2024-24576", "fail", "1.77.2")]);
    assert_eq!((s.findings[0].affected_range.as_str(), s.findings[0].severity.as_str()), ("<1.77.2", "CRITICAL"));
    assert!(s.findings.iter().all(|f| f.kind != "unchecked"), "{:?}", testing::kinds(&s));
    // The index keeps `rust-lang` with its hyphen.
    assert!(net.requests().iter().any(|r| r.url.ends_with("/browse/rust-lang")));
    for (version, want) in [("1.77.2", vec![]), ("1.88.0", vec![row("rust", "CVE-2025-11233", "fail", "1.89.0")])] {
        let mut s = testing::scan(&net, &d);
        let c = [runtime("rust", version)];
        tools(&mut s, &c, &osv_empty(&c)).unwrap();
        assert_eq!(failures(&s), want, "{version}");
    }
}

#[test]
fn php_and_rust_ask_cve_records_only_when_osv_has_nothing() {
    let d = TempDir::new("osv-first").unwrap();
    let net = runtimes_index();
    let found = [runtime("php", "8.4.20"), runtime("rust", "1.76.0")];
    // OSV answered for both: its findings stand, nothing else is asked.
    let mut answered = osv_empty(&found);
    for v in answered.values_mut() {
        v.push(json!({"id": "CVE-2026-1"}));
    }
    let mut s = testing::scan(&net, &d);
    tools(&mut s, &found, &answered).unwrap();
    assert!(s.findings.is_empty() && net.requests().is_empty(), "{:?}", testing::kinds(&s));
    // An answer with no CVE in it (PHP 8.2's lone OSS-Fuzz record) isn't
    // coverage: the records decide.
    let mut fuzz = osv_empty(&found[1..]);
    for v in fuzz.values_mut() {
        v.push(json!({"id": "OSV-2021-1199", "aliases": []}));
    }
    let mut s = testing::scan(&net, &d);
    tools(&mut s, &found[1..], &fuzz).unwrap();
    assert_eq!(failures(&s), [row("rust", "CVE-2024-24576", "fail", "1.77.2")]);
    // An alias counts: a GHSA or RUSTSEC record for a CVE is coverage.
    for v in fuzz.values_mut() {
        v.push(json!({"id": "RUSTSEC-2024-0001", "aliases": ["CVE-2024-24576"]}));
    }
    let mut s = testing::scan(&net, &d);
    tools(&mut s, &found[1..], &fuzz).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
    // OSV couldn't be asked (no answer at all): the records decide too.
    let mut s = testing::scan(&net, &d);
    tools(&mut s, &found[1..], &HashMap::new()).unwrap();
    assert_eq!(failures(&s), [row("rust", "CVE-2024-24576", "fail", "1.77.2")]);
    // OSV had nothing and the index can't be reached: not checked, not clean.
    let d = TempDir::new("osv-first-offline").unwrap();
    let offline = Fake::offline();
    let mut s = testing::scan(&offline, &d);
    tools(&mut s, &found, &osv_empty(&found)).unwrap();
    assert_eq!(failures(&s), []);
    assert_eq!(testing::unchecked_note(&s, &unreached(TOOLS_WHAT)), "php, rust");
    // The other table tools don't wait for OSV.
    let java = crate::component::Component { name: "java".into(), version: "17.0.12".into(), ..runtime("rust", "1") };
    assert_eq!(tool_subjects(std::slice::from_ref(&java), &|_| true).len(), 1);
    assert_eq!(tool_subjects(&found, &|_| true), []);
    assert_eq!(tool_subjects(&found, &|_| false).len(), 4, "two spellings each");
}

/// endoflife.date's PHP cycles as it serves them (2026-11-17), trimmed:
/// 8.4 was first released 2024-11-21, 8.3 2023-11-23.
const PHP_CYCLES: &str = r#"[{"cycle": "8.5", "releaseDate": "2025-11-20", "eol": "2029-12-31", "latest": "8.5.12"},
    {"cycle": "8.4", "releaseDate": "2024-11-21", "eol": "2028-12-31", "latest": "8.4.27"},
    {"cycle": "8.3", "releaseDate": "2023-11-23", "eol": "2027-12-31", "latest": "8.3.36"},
    {"cycle": "5.6", "eol": "2018-12-31", "latest": "5.6.40"}]"#;

fn php_subject(version: &str, released: Option<&str>) -> Subject {
    let mut x = tool_subjects(&[runtime("php", version)], &|_| false).remove(0);
    x.released = released.map(str::to_string);
    x
}

fn on(entry: Value, id: &str, day: &str) -> Record {
    Record { id: id.into(), title: "t".into(), published: day.into(), score: None, affected: vec![entry] }
}

#[test]
fn a_train_released_after_the_record_is_not_what_it_calls_affected() {
    let entry = |rec: Value| rec["containers"]["cna"]["affected"][0].clone();
    let (group, _) = php_records();
    let e8932 = entry(group[1].clone());
    let e4577 = entry(php_4577());
    let i = |v: &str| parts(v);
    // Every listed train is older than 8.4, under a default of affected.
    assert!(unlisted_later_train(&i("8.4.27"), &e8932) && unlisted_later_train(&i("8.5.0"), &e4577));
    // Not for a listed train, a default of unaffected, or a range that names no train.
    assert!(!unlisted_later_train(&i("8.3.20"), &e8932));
    assert!(!unlisted_later_train(&i("8.4.27"), &entry(group[0].clone())));
    let open = json!({"defaultStatus": "affected", "versions": [{"status": "affected", "version": "0", "lessThan": "8.3.14"}]});
    assert!(!unlisted_later_train(&i("8.4.27"), &open));
    assert!(!unlisted_later_train(&i("8.4.27"), &json!({"defaultStatus": "affected", "versions": []})));
    let words =
        json!({"defaultStatus": "affected", "versions": [{"status": "affected", "version": "7.3.x below 7.3.17"}]});
    assert!(unlisted_later_train(&i("8.4.27"), &words));

    let day84 = Some("2024-11-21");
    // CVE-2024-4577, published 2024-06-09, before 8.4's first release: 8.4.27 is clean.
    let x = php_subject("8.4.27", day84);
    assert_eq!(
        assess(&x, "php group", &[on(e4577.clone(), "CVE-2024-4577", "2024-06-09")], &|_| false),
        (vec![], None)
    );
    // CVE-2024-8932 was published 2024-11-22, the day after 8.4's first
    // release (2024-11-21): it could have meant 8.4, so 8.4.27 stays unjudged.
    {
        let (f, why) = assess(&x, "php group", &[on(e8932.clone(), "CVE-2024-8932", "2024-11-22")], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // A record published after 8.4 that lists only 8.3: unjudged.
    let only83 = json!({"vendor": "PHP Group", "product": "PHP", "defaultStatus": "affected",
        "versions": [{"status": "affected", "version": "8.3.*", "lessThan": "8.3.40"}]});
    {
        let (f, why) = assess(&x, "php group", &[on(only83, "CVE-2026-6", "2025-03-01")], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // Either date unknown: unjudged.
    let unknown = php_subject("8.4.27", None);
    {
        let (f, why) = assess(&unknown, "php group", &[on(e4577.clone(), "CVE-2024-4577", "2024-06-09")], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    {
        let (f, why) = assess(&x, "php group", &[on(e4577.clone(), "CVE-2024-4577", "")], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    let odd = php_subject("8.4.27", Some("soon"));
    {
        let (f, why) = assess(&odd, "php group", &[on(e4577.clone(), "CVE-2024-4577", "2024-06-09")], &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // A listed train is still judged by its range.
    let (found, unknown) = assess(
        &php_subject("8.3.5", Some("2023-11-23")),
        "php group",
        &[on(e4577, "CVE-2024-4577", "2024-06-09")],
        &|_| false,
    );
    assert!(unknown.is_none(), "{unknown:?}");
    assert_eq!((found[0].vuln_id.as_str(), found[0].fixed.as_str()), ("CVE-2024-4577", "8.3.8"));
}

#[test]
fn the_tool_check_takes_the_train_date_from_the_end_of_life_copy() {
    let d = TempDir::new("php-later").unwrap();
    let net = Fake::new(|r| {
        let page = crate::sources::cve_records::tests::page;
        let u = r.url.as_str();
        Ok(if u.ends_with("/php.json") {
            Response::ok(PHP_CYCLES)
        } else if u.ends_with("/browse/php%20group") {
            Response::ok(json!(["php"]).to_string())
        } else if u.contains("/browse/") {
            Response::ok("[]")
        } else if u.contains("search/php%20group/php?") {
            Response::ok(page(&[php_4577()], 1))
        } else {
            Response::not_found()
        })
    });
    let mut php = runtime("php", "8.4.27");
    php.eol = Some(("php".into(), "8.4".into()));
    let found = [php];
    // endoflife.date not fetched yet: 8.4's first release is unknown.
    let mut s = testing::scan(&net, &d);
    tools(&mut s, &found, &osv_empty(&found)).unwrap();
    assert_eq!(
        testing::unchecked_note(&s, &unjudged_label(TOOLS_WHAT)),
        "php 8.4.27: CVE-2024-4577 lists no range for the 8.4 line (versions not listed count as affected)."
    );
    // Fetched, as the inventory check does before this one: clean, nothing more asked of it.
    let mut s = testing::scan(&net, &d);
    crate::sources::endoflife::eol_prefetch(&s.cache, &net, &["php".to_string()], false).unwrap();
    let before = net.requests().iter().filter(|r| r.url.ends_with("/php.json")).count();
    tools(&mut s, &found, &osv_empty(&found)).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
    assert_eq!(net.requests().iter().filter(|r| r.url.ends_with("/php.json")).count(), before);
    assert_eq!(crate::sources::endoflife::released(&s.cache, "php", "8.4").unwrap().as_deref(), Some("2024-11-21"));
    assert_eq!(crate::sources::endoflife::released(&s.cache, "php", "5.6").unwrap(), None, "no date on the page");
    assert_eq!(crate::sources::endoflife::released(&s.cache, "nodejs", "24").unwrap(), None, "never fetched");
}

/// Eric's #230 item 2: a version is compared with a record only when both
/// number their releases the same way.
#[test]
fn versions_are_compared_only_within_one_scheme() {
    assert!(same_major("9", "10") && same_major("24", "24") && same_major("2026", "2025"));
    assert!(!same_major("262", "2026"), "a build number against a year");
    assert!(!same_major("2024", "5") && !same_major("262", "9"));
    let releases = json!({"vendor": "JetBrains", "product": "IntelliJ IDEA", "defaultStatus": "unaffected",
        "versions": [{"status": "affected", "version": "0", "lessThan": "2026.3"}]});
    assert!(same_scheme(&parts("2026.2.1"), &releases));
    assert!(!same_scheme(&parts("262.8665.42"), &releases));
    // Nothing dotted to compare with: the judgement decides.
    assert!(same_scheme(
        &parts("262.1"),
        &json!({"versions": [{"status": "affected", "version": "*", "lessThan": "*"}]})
    ));
    // Inclusive spans, spelled ranges and trains are read too.
    assert!(same_scheme(&parts("8.4.2"), &mysql_entry()));
    assert!(!same_scheme(&parts("2024.1"), &entry(json!([{"status": "affected", "version": "< 1.77.2"}]))));
    assert!(same_scheme(&parts("24.10.3.0"), &circutor()));

    let ide = |v: &str| Subject {
        kind: "app".into(),
        name: "IntelliJ IDEA".into(),
        version: v.into(),
        vendors: vec!["jetbrains".into()],
        product: Some("IntelliJ IDEA".into()),
        ..Default::default()
    };
    let recs = [record("CVE-2026-1", releases, Some(7.5))];
    // The build number of a current IntelliJ: not comparable, not failed.
    {
        let (f, why) = assess(&ide("263.4567.12"), "jetbrains", &recs, &|_| false);
        assert!(f.is_empty() && why.is_some(), "{why:?}");
    }
    // The same release as the records number it: judged.
    let (found, unknown) = assess(&ide("2026.2.1"), "jetbrains", &recs, &|_| false);
    assert!(unknown.is_none(), "{unknown:?}");
    assert_eq!((found[0].status.as_str(), found[0].fixed.as_str()), ("fail", "2026.3"));
    assert_eq!(assess(&ide("2026.3"), "jetbrains", &recs, &|_| false), (vec![], None));
}

/// Oracle lists the supported versions a flaw affects. A train it left out
/// of a record is unaffected when it was out and supported on the day the
/// record was published (Java 27 and Oracle's October 2026 records); a
/// train out of support then, out only later, or with no dates is not
/// checked, and the reason says which.
#[test]
fn a_java_train_oracle_supported_and_left_out_is_unaffected() {
    let oct = json!({"vendor": "Oracle Corporation", "product": "Oracle Java SE", "versions": [
        {"version": "8u503", "status": "affected"},
        {"version": "8u503-perf", "status": "affected"},
        {"version": "Oracle Java SE:11.0.32.1", "status": "affected"},
        {"version": "17.0.20.1", "status": "affected"},
        {"version": "21.0.12.1", "status": "affected"},
        {"version": "25.0.4.1", "status": "affected"}
    ]});
    let recs = [
        Record { published: "2026-10-20T00:00:00".into(), ..record("CVE-2026-91451", oct.clone(), Some(7.5)) },
        Record { published: "2026-10-20T00:00:00".into(), ..record("CVE-2026-91410", oct, Some(5.3)) },
    ];
    let java = |v: &str, released: Option<&str>, end: Option<&str>| {
        let mut x = tool_subjects(&[runtime("java", v)], &|_| false).remove(0);
        x.released = released.map(str::to_string);
        x.support_end = end.map(str::to_string);
        x
    };
    let judged = |x: &Subject| assess(x, "oracle corporation", &recs, &|_| false);
    // Temurin 27: out 2026-09-22, supported to 2027-03-23.
    assert_eq!(judged(&java("27.0.1.0.2", Some("2026-09-22"), Some("2027-03-23"))), (vec![], None));
    // An LTS with no end date yet: supported.
    assert_eq!(judged(&java("27.0.1.0.2", Some("2026-09-22"), Some(""))), (vec![], None));
    // 26: its support ended the day 27 came out.
    let (none, why) = judged(&java("26.0.2", Some("2026-03-23"), Some("2026-09-22")));
    assert!(none.is_empty());
    assert_eq!(
        why.as_deref(),
        Some(
            "CVE-2026-91451 and CVE-2026-91410 name the 8, 11, 17, 21 and 25 trains but not 26, which was out of support at publication"
        )
    );
    // A train out after the records were published.
    let (_, why) = judged(&java("29.0.1", Some("2027-09-21"), Some("2028-03-21")));
    assert!(why.unwrap().ends_with("but not 29, which came out after publication"));
    // No dates: can't tell.
    let (_, why) = judged(&java("27.0.1.0.2", None, None));
    assert!(why.unwrap().contains("Pantry has no release and support dates for 27"));
    // A listed train is still judged: 25.0.3 is affected.
    let (found, why) = judged(&java("25.0.3", Some("2025-09-22"), Some("2031-09-30")));
    assert_eq!((found.len(), why), (2, None));
}

#[test]
fn support_end_reads_the_end_of_life_copy() {
    let d = crate::utils::temp::TempDir::new("support-end").unwrap();
    let cache = crate::db::Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let rows = json!([
        {"cycle": "27", "releaseDate": "2026-09-22", "eol": "2027-03-23"},
        {"cycle": "25", "releaseDate": "2025-09-22", "eol": false},
        {"cycle": "8", "releaseDate": "2014-03-18", "eol": true}
    ]);
    crate::sources::endoflife::store_for_tests(&cache, "eclipse-temurin", &rows);
    let end = |c: &str| crate::sources::endoflife::support_end(&cache, "eclipse-temurin", c).unwrap();
    assert_eq!(end("27").as_deref(), Some("2027-03-23"));
    assert_eq!(end("25").as_deref(), Some(""), "no end yet");
    assert_eq!(end("8").as_deref(), Some("1970-01-01"), "ended, day not named");
    assert_eq!(end("99"), None);
}

#[test]
fn nvds_entries_count_only_for_subjects_that_ask_and_only_on_their_system() {
    let nvd = |platforms: Value| {
        json!({"vendor": "circutor", "product": "powerstudio_scada_wave", "nvd": true, "defaultStatus": "unaffected",
               "platforms": platforms, "versions": [{"version": "0", "lessThan": "25.0", "status": "affected"}]})
    };
    let ids = |x: &Subject, e: Value| -> Vec<String> {
        assess(x, "circutor", &[record("CVE-2026-9", e, None)], &|_| false).0.into_iter().map(|f| f.vuln_id).collect()
    };
    let mut x = program("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA");
    assert!(ids(&x, nvd(json!([]))).is_empty(), "a program that doesn't ask for NVD's entries");
    x.nvd = true;
    assert_eq!(ids(&x, nvd(json!([]))), ["CVE-2026-9"]);
    x.system = "windows".into();
    assert_eq!(ids(&x, nvd(json!(["windows", "linux"]))), ["CVE-2026-9"]);
    assert!(ids(&x, nvd(json!(["macos"]))).is_empty(), "another system's");
    // The publisher's platforms are read the same way; architectures limit nothing.
    let cna = |platforms: Value| {
        let mut e = circutor();
        e["platforms"] = platforms;
        e
    };
    assert_eq!(ids(&x, cna(json!(["Windows 11", "x64"]))), ["CVE-2026-9"]);
    assert_eq!(ids(&x, cna(json!(["64 bit"]))), ["CVE-2026-9"]);
    assert!(ids(&x, cna(json!(["Mac OS X", "Linux"]))).is_empty());
    assert!(ids(&x, cna(json!(["Android"]))).is_empty(), "a phone's");
    assert!(ids(&x, cna(json!(["iOS", "iPadOS"]))).is_empty());
}
