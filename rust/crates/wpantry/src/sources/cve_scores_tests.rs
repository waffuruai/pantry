use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};
use serde_json::json;

fn not_found() -> Response {
    Response { status: 404, body: Vec::new(), etag: None }
}

/// CVE.org's record for a Go CVE: no score from the publisher, CISA's and
/// Red Hat's added.
fn go_cve() -> Value {
    json!({"cveMetadata": {"cveId": "CVE-2025-61726"}, "containers": {
    "cna": {"providerMetadata": {"shortName": "Go"}, "affected": []},
    "adp": [
        {"providerMetadata": {"shortName": "redhat-SADP"}, "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 5.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]},
        {"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
            {"other": {"type": "ssvc"}},
            {"cvssV3_1": {"version": "3.1", "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]}
    ]}})
}

#[test]
fn a_cve_records_score_is_the_publishers_else_cisas() {
    let (s, vector, who) = of_cve_record(&go_cve()).unwrap();
    assert_eq!((s.value, s.version.as_str(), who.as_str()), (7.5, "3.1", "cve.org (CISA)"), "CISA's before Red Hat's");
    assert!(vector.ends_with("A:H"));
    let own = json!({"containers": {"cna": {"metrics": [
        {"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
        {"cvssV4_0": {"vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]},
        "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}}]}]}});
    let (s, _, who) = of_cve_record(&own).unwrap();
    assert_eq!((s.value, s.version.as_str(), who.as_str()), (9.3, "4.0", "cve.org"), "the publisher's, newest version");
    let bare = json!({"containers": {"cna": {"metrics": [{"cvssV3_0": {"version": "3.0", "baseScore": 6.5, "vectorString": "garbled"}}]}}});
    assert_eq!(
        of_cve_record(&bare).map(|f| (f.0.value, f.0.version)),
        Some((6.5, "3.0".into())),
        "a base score without a vector"
    );
    assert!(of_cve_record(&json!({"containers": {"cna": {"affected": "n/a"}}})).is_none());
    assert!(of_cve_record(&json!({"error": "not found"})).is_none());
}

#[test]
fn osv_first_then_cve_org_and_each_answer_is_kept() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        Ok(match r.url.as_str() {
            u if u.ends_with("/vulns/CVE-2026-1") => Response::ok(
                json!({"id": "CVE-2026-1", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}).to_string(),
            ),
            u if u.contains("api.osv.dev") => not_found(),
            u if u.ends_with("/CVE-2025-61726") => Response::ok(go_cve().to_string()),
            _ => not_found(),
        })
    });
    let cves: Vec<String> = ["CVE-2026-1", "CVE-2025-61726", "CVE-2026-404", "CVE-2026-1"].map(String::from).to_vec();
    fill(&c, &net, false, &cves).unwrap();
    assert_eq!(lookup(&c, "CVE-2026-1").unwrap().map(|s| s.value), Some(9.8), "OSV's record");
    assert_eq!(lookup(&c, "CVE-2025-61726").unwrap().map(|s| s.value), Some(7.5), "CVE.org's, after OSV had none");
    assert_eq!(lookup(&c, "CVE-2026-404").unwrap(), None);
    let asked = net.requests().len();
    assert_eq!(asked, 5, "OSV for each CVE once, CVE.org for the two OSV couldn't score");
    // Every answer is kept for a week, a CVE with no score included.
    fill(&c, &net, false, &cves).unwrap();
    assert_eq!(net.requests().len(), asked);
    let source: String =
        c.conn.query_row("SELECT source FROM cve_scores WHERE cve = 'CVE-2025-61726'", [], |r| r.get(0)).unwrap();
    assert_eq!(source, "cve.org (CISA)");
    // Offline asks nothing; unreachable keeps nothing, so the next scan asks again.
    let (_e, fresh) = cache();
    fill(&fresh, &Fake::offline(), true, &cves).unwrap();
    fill(&fresh, &Fake::offline(), false, &cves).unwrap();
    let kept: i64 = fresh.conn.query_row("SELECT COUNT(*) FROM cve_scores", [], |r| r.get(0)).unwrap();
    assert_eq!(kept, 0);
}
