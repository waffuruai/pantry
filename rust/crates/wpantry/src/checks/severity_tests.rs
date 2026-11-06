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
    enrich(&c, &mut all);
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
