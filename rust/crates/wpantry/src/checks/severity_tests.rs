use super::*;
use crate::sources::testing::cache;

fn finding(kind: &str, id: &str, status: &str, severity: &str) -> Finding {
    Finding {
        kind: kind.into(),
        component: "x".into(),
        vuln_id: id.into(),
        status: status.into(),
        severity: severity.into(),
        ..Default::default()
    }
}

#[test]
fn every_finding_gets_cvss_words_scores_and_a_severity() {
    let (_d, c) = cache();
    let put = |id: &str, aliases: &str, rec: serde_json::Value| {
        c.conn
            .execute(
                "INSERT INTO vulns (id, aliases, record) VALUES (?, ?, ?)",
                rusqlite::params![id, aliases, rec.to_string()],
            )
            .unwrap();
    };
    // A CVE with only a CVSS 4.0 vector (as Python's are).
    put(
        "CVE-2026-115557",
        "",
        serde_json::json!({"id": "CVE-2026-115557", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}),
    );
    // A CVE filed as a GitHub advisory: the finding names the CVE.
    put(
        "GHSA-vmqv-hx8q-j7mg",
        "CVE-2025-55305",
        serde_json::json!({"id": "GHSA-vmqv-hx8q-j7mg", "aliases": ["CVE-2025-55305"], "database_specific": {"severity": "MODERATE"}, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:L"}]}),
    );
    c.conn.execute("INSERT INTO epss VALUES ('CVE-2025-55305', 0.12, 0.95)", []).unwrap();
    c.set("epss_date", "2026-11-05T12:03:04Z").unwrap();
    c.set("epss_model", "v2026.06.15").unwrap();
    let mut all = vec![
        finding("runtime", "CVE-2026-115557", "fail", ""),
        finding("app", "CVE-2025-55305", "warn", ""),
        finding("package", "GHSA-none-none-none", "fail", ""),
        finding("os", "USN-1-1", "fail", "IMPORTANT"),
        finding("package", "MAL-2026-1", "fail", "MALICIOUS"),
        finding("runtime", "EOL", "fail", ""),
        finding("app", "OUTDATED", "warn", ""),
        finding("suspect-code", "SUSPECT-STRING-DECODER", "warn", ""),
        finding("posture", "POSTURE-FIREWALL", "fail", "MEDIUM"),
        finding("unchecked", "UNCHECKED", "warn", ""),
    ];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut all);
    let got: Vec<(&str, Option<f64>, &str, Option<f64>)> =
        all.iter().map(|f| (f.severity.as_str(), f.cvss, f.cvss_version.as_str(), f.epss)).collect();
    assert_eq!(
        got,
        [
            ("CRITICAL", Some(9.3), "4.0", None),
            ("MEDIUM", Some(6.1), "3.1", Some(0.12)),
            ("HIGH", None, "", None),
            ("HIGH", None, "", None),
            ("CRITICAL", None, "", None),
            ("HIGH", None, "", None),
            ("LOW", None, "", None),
            ("LOW", None, "", None),
            ("MEDIUM", None, "", None),
            ("", None, "", None),
        ]
    );
    assert_eq!(all[1].epss_percentile, Some(0.95));
    assert_eq!((all[1].epss_date.as_str(), all[1].epss_model.as_str()), ("2026-11-05T12:03:04Z", "v2026.06.15"));
    assert_eq!((all[0].epss_date.as_str(), all[0].epss_model.as_str()), ("", ""), "no score, no copy named");
    assert!(
        is_advisory("CVE-2024-3094")
            && is_advisory("GHSA-a-b-c")
            && is_advisory("MAL-2026-1")
            && is_advisory("RUSTSEC-2024-1")
    );
    assert!(
        !is_advisory("POSTURE-FIREWALL")
            && !is_advisory("SUSPECT-RAW-IP")
            && !is_advisory("EOL")
            && !is_advisory("OS-UPDATE")
    );
}

#[test]
fn an_advisory_with_no_score_has_its_cve_asked_about() {
    let (_d, c) = crate::sources::testing::cache();
    // Go's record names the CVE and has no score; the finding names the CVE.
    c.put_vuln(&serde_json::json!({"id": "GO-2026-4341", "aliases": ["CVE-2025-61726"]})).unwrap();
    let net = crate::utils::net::Fake::new(|r| {
        Ok(if r.url.contains("api.osv.dev") {
            crate::utils::net::Response { status: 404, body: Vec::new(), etag: None }
        } else {
            crate::utils::net::Response::ok(
                serde_json::json!({"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]}]}})
                .to_string(),
            )
        })
    });
    let mut all = vec![finding("runtime", "CVE-2025-61726", "fail", "")];
    enrich(&c, &net, false, &mut all);
    assert_eq!((all[0].severity.as_str(), all[0].cvss, all[0].cvss_version.as_str()), ("HIGH", Some(7.5), "3.1"));
    let mut offline = vec![finding("runtime", "CVE-2026-9", "fail", "")];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut offline);
    assert_eq!((offline[0].severity.as_str(), offline[0].cvss), ("HIGH", None), "no score: wpantry's own rating");
}

/// An OUTDATED finding fails only when KEV lists exploited CVEs in its
/// gap (`exploited`): that is HIGH, like a browser behind past its grace.
#[test]
fn a_failing_outdated_finding_is_high() {
    assert_eq!(own(&finding("app", "OUTDATED", "fail", "")), "HIGH");
    assert_eq!(own(&finding("app", "OUTDATED", "warn", "")), "LOW");
    assert_eq!(own(&finding("app", "BROWSER", "fail", "")), own(&finding("runtime", "OUTDATED", "fail", "")));
}

/// Model findings: a known-bad model or an appended program is CRITICAL;
/// any other model rule, the template phrase rules among them, is HIGH
/// when it fails and LOW when it warns.
#[test]
fn model_findings_rate_by_whether_they_fail() {
    use crate::checks::models::ids;
    for id in [ids::KNOWN_BAD, ids::APPENDED_PROGRAM] {
        assert_eq!(own(&finding("model", id, "fail", "")), "CRITICAL", "{id}");
    }
    for id in [ids::OVERRIDE, ids::TAMPER, ids::ASSEMBLED, ids::INJECTION, ids::DATA_GAP] {
        assert_eq!(own(&finding("model", id, "fail", "")), "HIGH", "{id}");
        assert_eq!(own(&finding("model", id, "warn", "")), "LOW", "{id}");
    }
}

/// Oracle: the contract's caps. An advisory with 13 aliases and 9 weakness
/// types gives the first 12 and 8 (CVE ids first), no more.
#[test]
fn advisory_text_caps_aliases_at_12_and_weaknesses_at_8() {
    let (_d, c) = crate::sources::testing::cache();
    let aliases: Vec<String> = (1..=13).map(|n| format!("CVE-2026-{n:04}")).collect();
    let cwes: Vec<String> = [20, 22, 77, 78, 79, 89, 94, 287, 502].iter().map(|n| format!("CWE-{n}")).collect();
    c.put_vuln(&serde_json::json!({
        "id": "GHSA-aaaa-bbbb-cccc", "aliases": aliases, "summary": "Many names",
        "database_specific": {"cwe_ids": cwes},
    }))
    .unwrap();
    let text = advisory_text(&c, "GHSA-aaaa-bbbb-cccc");
    assert_eq!(text.aliases, aliases[..12], "{:?}", text.aliases);
    assert_eq!(text.cwe, cwes[..8], "{:?}", text.cwe);
}

/// Oracle: an area the scan could not check is not an advisory, even when
/// its id has an advisory's shape and the cache holds that advisory: it
/// never gains a summary, aliases or weakness types, in the scan's own
/// step or when an old report is read back. Known bad: drop the
/// `kind != "unchecked"` guard and it reads like a security notice.
#[test]
fn an_unchecked_finding_never_gains_advisory_text() {
    let (_d, c) = crate::sources::testing::cache();
    c.put_vuln(&serde_json::json!({
        "id": "CVE-2026-4242", "aliases": ["GHSA-aaaa-bbbb-cccc"], "summary": "Remote code execution",
        "database_specific": {"cwe_ids": ["CWE-94"]},
    }))
    .unwrap();
    let mut scanned = vec![finding("unchecked", "CVE-2026-4242", "warn", "")];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut scanned);
    let mut read_back = vec![finding("unchecked", "CVE-2026-4242", "warn", "")];
    crate::reporters::jsonl::with_text(&c, &mut read_back);
    for f in scanned.iter().chain(&read_back) {
        assert!(f.summary.is_empty() && f.aliases.is_empty() && f.cwe.is_empty(), "{f:?}");
    }
    // Positive control: the same id on a real finding gains the text.
    let mut real = vec![finding("runtime", "CVE-2026-4242", "fail", "")];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut real);
    assert_eq!(real[0].summary, "Remote code execution");
    assert_eq!(real[0].cwe, ["CWE-94"]);
}

/// Risk: `enrich` read an advisory's records for the scores and again for
/// its text: each read is an unindexed `aliases LIKE` scan of `vulns`
/// (seconds on a real cache). Oracle: the count of those reads, taken at the
/// one function that makes them. N findings sharing M ids cost M reads, and
/// an unchecked finding costs none. Known bad: drop the shared memo and the
/// count is 2 * M.
#[test]
fn enrich_reads_each_advisorys_records_once_for_scores_and_text() {
    let (_d, c) = crate::sources::testing::cache();
    c.put_vuln(&serde_json::json!({"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1"], "summary": "one"})).unwrap();
    let mut all: Vec<Finding> = Vec::new();
    for (i, id) in ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc", "CVE-2026-9"].iter().cycle().take(9).enumerate() {
        all.push(finding("runtime", id, "fail", ["", "HIGH", ""][i % 3]));
        all[i].component = format!("c{i}");
    }
    all.push(finding("unchecked", "CVE-2026-77", "warn", ""));
    super::lookups::reset();
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut all);
    assert_eq!(super::lookups::taken(), 3, "9 findings over 3 ids, plus an unchecked one that is never looked up");
    // The memo does not change what the findings get.
    assert_eq!(all[0].summary, "one");
}

const V98: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V50: &str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L";

/// A record of a source on this machine, as a load leaves it, with a CVSS
/// vector and the package `x` the test findings are about.
fn local_record(c: &Cache, source: &str, id: &str, vector: &str) {
    let rec = serde_json::json!({"id": id, "severity": [{"type": "CVSS_V3", "score": vector}],
        "affected": [{"package": {"ecosystem": "npm", "name": "x"}}]});
    c.conn
        .execute(
            "INSERT INTO local_vulns VALUES (?, ?, 'a.json', '', '', ?)",
            rusqlite::params![source, id, rec.to_string()],
        )
        .unwrap();
    c.conn.execute("INSERT INTO local_vuln_names VALUES (?, ?, 'x')", rusqlite::params![source, id]).unwrap();
}

/// Risk (the same class as a local record deciding an OSV finding): a
/// finding from a source on this machine goes without its CVSS score and
/// version though its record carries a vector, or is rated from an OSV
/// record that merely shares its id; or a local record moves an OSV
/// finding's rating. Oracle: `enrich`'s cvss and version per finding: a local
/// finding takes its own record's, an OSV finding keeps OSV's, whatever the
/// local table holds for the same id.
#[test]
fn a_local_finding_is_rated_from_its_own_record_and_an_osv_one_from_osvs() {
    let (_d, c) = cache();
    c.conn
        .execute(
            "INSERT INTO vulns (id, aliases, record) VALUES ('CVE-2026-5', '', ?)",
            [serde_json::json!({"id": "CVE-2026-5", "severity": [{"type": "CVSS_V3", "score": V98}]}).to_string()],
        )
        .unwrap();
    local_record(&c, "t-src", "CVE-2026-5", V50);
    local_record(&c, "t-src", "TEAM-1", V98);
    local_record(&c, "t-src", "TEAM-2", "");
    let local = |id: &str| Finding { local_source: "t-src".into(), ..finding("project", id, "fail", "") };
    let mut all =
        vec![local("TEAM-1"), local("CVE-2026-5"), finding("project", "CVE-2026-5", "fail", ""), local("TEAM-2")];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut all);
    let got: Vec<(Option<f64>, &str, &str)> =
        all.iter().map(|f| (f.cvss, f.cvss_version.as_str(), f.severity.as_str())).collect();
    assert_eq!(
        got,
        [
            (Some(9.8), "3.1", "CRITICAL"),
            (Some(5.5), "3.1", "MEDIUM"),
            (Some(9.8), "3.1", "CRITICAL"),
            (None, "", "HIGH"),
        ],
        "own record for a local finding (not OSV's same id), OSV's for an OSV finding, none and wpantry's own rating for a record with no score"
    );
}

/// Risk (same flaw as the export's): a local advisory on a runtime is rated
/// from nothing because the lookup compared the finding's component name
/// (`go`) with the OSV package name (`stdlib`) the record is filed under.
/// Oracle: `enrich`'s cvss and version for a runtime finding whose
/// component differs from its record's package are the record's own.
#[test]
fn a_local_advisory_on_a_runtime_is_rated_from_its_own_record() {
    let (_d, c) = cache();
    local_record(&c, "t-src", "TEAM-GO", V98);
    c.conn.execute("UPDATE local_vuln_names SET name = 'stdlib' WHERE id = 'TEAM-GO'", []).unwrap();
    let mut all = vec![Finding {
        component: "go".into(),
        local_source: "t-src".into(),
        ..finding("runtime", "TEAM-GO", "fail", "")
    }];
    enrich(&c, &crate::utils::net::Fake::offline(), true, &mut all);
    assert_eq!((all[0].cvss, all[0].cvss_version.as_str(), all[0].severity.as_str()), (Some(9.8), "3.1", "CRITICAL"));
}

/// Risk: two records of one source that share an alias but cover different
/// packages are keyed and looked up as one, so both packages' findings are
/// rated from whichever record id sorts first. Oracle: `enrich`'s cvss for
/// each finding, whose vuln_id is the shared CVE id, is its own package's
/// record's, in either order of the two findings.
#[test]
fn two_records_of_one_source_sharing_an_alias_rate_each_finding_from_its_own() {
    let (_d, c) = cache();
    for (id, package, vector) in [("TEAM-A-STDLIB", "stdlib", V98), ("TEAM-B-LEFTPAD", "left-pad", V50)] {
        local_record(&c, "t-src", id, vector);
        c.conn.execute("UPDATE local_vulns SET aliases = 'CVE-2026-77' WHERE id = ?", [id]).unwrap();
        c.conn.execute("UPDATE local_vuln_names SET name = ? WHERE id = ?", [package, id]).unwrap();
    }
    let of = |component: &str| Finding {
        component: component.into(),
        local_source: "t-src".into(),
        ..finding("project", "CVE-2026-77", "fail", "")
    };
    for order in [["left-pad", "stdlib"], ["stdlib", "left-pad"]] {
        let mut all: Vec<Finding> = order.iter().map(|c| of(c)).collect();
        enrich(&c, &crate::utils::net::Fake::offline(), true, &mut all);
        let got: Vec<(&str, Option<f64>)> = all.iter().map(|f| (f.component.as_str(), f.cvss)).collect();
        let want: Vec<(&str, Option<f64>)> =
            order.iter().map(|c| (*c, Some(if *c == "stdlib" { 9.8 } else { 5.5 }))).collect();
        assert_eq!(got, want, "{order:?}");
    }
}
