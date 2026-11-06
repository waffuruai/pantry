use super::*;
use crate::checks::Outcome;
use crate::history::{ScanDetail, ScanRow};
use crate::reporters::{History, Part};

fn finding(severity: &str, status: &str, kev: bool) -> Finding {
    Finding {
        kind: "package".into(),
        component: "x".into(),
        severity: severity.into(),
        status: status.into(),
        kev,
        ..Default::default()
    }
}

fn exposure(severity: &str, days: f64, resolved: bool) -> Exposure {
    Exposure {
        component: "lib".into(),
        version: "1.0".into(),
        vuln_id: "CVE-1".into(),
        severity: severity.into(),
        first_at: 1000.0,
        days_exposed: days,
        resolved_at: resolved.then_some(2000.0),
        ..Default::default()
    }
}

#[test]
fn the_summary_counts_against_the_policy_targets() {
    let fixes = vec![
        Fix {
            at: 10.0,
            command: "brew upgrade x".into(),
            mode: "auto".into(),
            ok: true,
            verified_scan: Some(2),
            user: "eric".into(),
            host: "mac".into(),
            ..Default::default()
        },
        Fix { at: 20.0, command: "npm i -g y@2".into(), mode: "auto".into(), ok: false, ..Default::default() },
    ];
    let report = Report {
        outcome: Outcome {
            scan_id: 2,
            findings: vec![
                finding("CRITICAL", "fail", true),
                finding("HIGH", "fail", false),
                finding("", "warn", false),
                Finding { kind: "unchecked".into(), component: "CISA KEV".into(), ..Default::default() },
            ],
            ..Default::default()
        },
        scan: ScanDetail { row: ScanRow { id: 2, finished_at: 3.0, ..Default::default() }, ..Default::default() },
        after_fixes: true,
        history: Some(History {
            since_days: 14,
            exposures: vec![
                exposure("CRITICAL", 20.0, false),
                exposure("CRITICAL", 3.0, true),
                exposure("HIGH", 45.0, true),
            ],
            fixes,
            scans: vec![
                ScanRow {
                    id: 1,
                    finished_at: 86400.0 * 3.0,
                    host: "mac".into(),
                    user: "eric".into(),
                    ..Default::default()
                },
                ScanRow {
                    id: 2,
                    finished_at: 86400.0 * 3.5,
                    host: "mac".into(),
                    user: "eric".into(),
                    ..Default::default()
                },
            ],
            events: Vec::new(),
        }),
        part: Part::Summary,
    };
    let s = summary(&report);
    let crit = &s.levels[0];
    assert_eq!(
        (crit.severity, crit.target, crit.open_fail, crit.overdue, crit.resolved, crit.resolved_late),
        ("CRITICAL", Some(14), 1, 1, 1, 0)
    );
    let high = &s.levels[1];
    assert_eq!(
        (high.target, high.resolved, high.resolved_late, high.median_days),
        (Some(30), 1, 1, 45.0),
        "45 days is past 30"
    );
    assert_eq!(s.levels.last().unwrap().severity, "", "the unrated ones are counted too");
    assert_eq!((s.kev_open, s.scans, s.hosts.clone(), s.days_without_scan), (1, 2, vec!["mac".to_string()], 13));
    assert_eq!(s.oldest.as_ref().map(|o| o.4), Some(20.0));
    assert_eq!(s.gaps, ["CISA KEV"]);
    let md = md(&s);
    assert!(md.contains("| Critical | 14 | 1 | 0 | 1 | 1 | 0 | 3 |"), "{md}");
    assert!(
        md.contains("| eric@mac | `brew upgrade x` | ok | #2 |") && md.contains("| - | `npm i -g y@2` | failed | - |"),
        "{md}"
    );
    assert!(md.contains("ISO 27001 A.8.8"));
    let csv = csv(&s);
    assert!(
        csv.starts_with("metric,value\r\n")
            && csv.contains("critical_overdue,1\r\n")
            && csv.contains("high_resolved_late,1")
    );
    let j = json(&s).dumps();
    assert!(j.contains("\"known_exploited_open\": 1") && j.contains("\"who\": \"eric@mac\""), "{j}");
}
