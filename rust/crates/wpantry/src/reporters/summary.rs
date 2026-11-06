//! `wpantry report summary`: one page for a CSO, an auditor or an insurer.
//! Where the machine stands now (what is open, by severity, and what is
//! known to be exploited), how fast what was found got fixed against the
//! remediation targets, whether the checks ran (scans, hosts, gaps), who
//! fixed what and when, and which controls each part is evidence for.
//!
//! The targets are our security policy's (`SECURITY.md`: Critical 14 days,
//! High 30, Medium 90, Low 180). A file of your own will set them (#171).

use super::Report;
use crate::finding::Finding;
use crate::history::{Exposure, Fix, stamp};
use crate::utils::json::{J, obj};

/// The days to remediate by severity: our security policy's.
pub const TARGETS: [(&str, i64); 4] = [("CRITICAL", 14), ("HIGH", 30), ("MODERATE", 90), ("LOW", 180)];

/// The controls the summary is evidence for: (framework and control, what
/// in the summary shows it).
pub const CONTROLS: [(&str, &str); 7] = [
    ("SOC 2 CC7.1", "vulnerabilities identified: the scans, their scope and what they found"),
    ("SOC 2 CC7.2", "systems monitored: scan cadence, known-exploited advisories, sources that couldn't be checked"),
    ("SOC 2 CC7.4", "vulnerabilities remediated: times to fix against the targets, overdue items"),
    ("SOC 2 CC8.1", "changes made under control: each fix, who ran it, when, and the scan that verified it"),
    ("ISO 27001 A.8.8", "technical vulnerabilities managed: exposure, severity, remediation against the targets"),
    ("ISO 27001 A.8.16", "monitoring activities: the audit log of scans and events"),
    ("ISO 27001 A.5.24–5.28", "incidents: what was exposed, from when to when, and the evidence kept"),
];

/// A severity as the targets name it; "" when there is none.
pub fn level(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" | "MALICIOUS" => "CRITICAL",
        "HIGH" | "IMPORTANT" => "HIGH",
        "MODERATE" | "MEDIUM" => "MODERATE",
        "LOW" => "LOW",
        _ => "",
    }
}

/// One severity's line of the summary.
#[derive(Clone, Debug, PartialEq)]
pub struct Level {
    /// CRITICAL, HIGH, MODERATE, LOW, or "" (no severity rated).
    pub severity: &'static str,
    /// The target in days, when there is one.
    pub target: Option<i64>,
    /// In the latest scan: failing and warning findings.
    pub open_fail: usize,
    pub open_warn: usize,
    /// Open exposures past their target.
    pub overdue: usize,
    /// Resolved in the period, and how many of them after their target.
    pub resolved: usize,
    pub resolved_late: usize,
    /// Median days to resolve, of those resolved in the period.
    pub median_days: f64,
}

/// The summary.
#[derive(Clone, Debug)]
pub struct Summary {
    pub since_days: i64,
    pub generated_at: f64,
    pub scan_id: i64,
    pub scan_finished: f64,
    pub levels: Vec<Level>,
    pub kev_open: usize,
    /// The open Critical or High exposure seen first: (severity, component,
    /// version, advisory, days open).
    pub oldest: Option<(String, String, String, String, f64)>,
    pub median_days: f64,
    pub p90_days: f64,
    pub scans: usize,
    pub hosts: Vec<String>,
    pub users: Vec<String>,
    /// Days in the period on which no scan finished.
    pub days_without_scan: i64,
    /// What the latest scan couldn't check.
    pub gaps: Vec<String>,
    pub fixes: Vec<Fix>,
}

fn percentile(mut xs: Vec<f64>, p: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let i = ((xs.len() - 1) as f64 * p).round() as usize;
    (xs[i] * 10.0).round() / 10.0
}

/// The summary of `report`, whose history it needs.
pub fn summary(report: &Report) -> Summary {
    let empty = super::History::default();
    let h = report.history.as_ref().unwrap_or(&empty);
    let now = crate::utils::os::now();
    let findings: Vec<&Finding> = report.outcome.findings.iter().filter(|f| f.kind != "unchecked").collect();
    let target = |s: &str| TARGETS.iter().find(|(l, _)| *l == s).map(|(_, d)| *d);
    let levels = TARGETS
        .iter()
        .map(|(l, _)| *l)
        .chain([""])
        .map(|sev| {
            let open: Vec<&&Finding> = findings.iter().filter(|f| level(&f.severity) == sev).collect();
            let exposures: Vec<&Exposure> = h.exposures.iter().filter(|e| level(&e.severity) == sev).collect();
            let resolved: Vec<&&Exposure> = exposures.iter().filter(|e| e.resolved_at.is_some()).collect();
            let limit = target(sev);
            let late = |e: &Exposure| limit.is_some_and(|t| e.days_exposed > t as f64);
            Level {
                severity: sev,
                target: limit,
                open_fail: open.iter().filter(|f| f.status == "fail").count(),
                open_warn: open.iter().filter(|f| f.status != "fail").count(),
                overdue: exposures.iter().filter(|e| e.resolved_at.is_none() && late(e)).count(),
                resolved: resolved.len(),
                resolved_late: resolved.iter().filter(|e| late(e)).count(),
                median_days: percentile(resolved.iter().map(|e| e.days_exposed).collect(), 0.5),
            }
        })
        .filter(|l| !l.severity.is_empty() || l.open_fail + l.open_warn + l.resolved > 0)
        .collect();
    let oldest = h
        .exposures
        .iter()
        .filter(|e| e.resolved_at.is_none() && matches!(level(&e.severity), "CRITICAL" | "HIGH"))
        .min_by(|a, b| a.first_at.partial_cmp(&b.first_at).unwrap_or(std::cmp::Ordering::Equal))
        .map(|e| {
            (level(&e.severity).to_string(), e.component.clone(), e.version.clone(), e.vuln_id.clone(), e.days_exposed)
        });
    let resolved_days: Vec<f64> =
        h.exposures.iter().filter(|e| e.resolved_at.is_some()).map(|e| e.days_exposed).collect();
    let mut hosts: Vec<String> = h.scans.iter().map(|s| s.host.clone()).filter(|x| !x.is_empty()).collect();
    hosts.sort();
    hosts.dedup();
    let mut users: Vec<String> = h.scans.iter().map(|s| s.user.clone()).filter(|x| !x.is_empty()).collect();
    users.sort();
    users.dedup();
    let mut days: Vec<i64> = h.scans.iter().map(|s| (s.finished_at / crate::db::DAY).floor() as i64).collect();
    days.sort();
    days.dedup();
    Summary {
        since_days: h.since_days,
        generated_at: now,
        scan_id: report.outcome.scan_id,
        scan_finished: report.scan.row.finished_at,
        levels,
        kev_open: findings.iter().filter(|f| f.kev).count(),
        oldest,
        median_days: percentile(resolved_days.clone(), 0.5),
        p90_days: percentile(resolved_days, 0.9),
        scans: h.scans.len(),
        hosts,
        users,
        days_without_scan: (h.since_days - days.len() as i64).max(0),
        gaps: report.outcome.findings.iter().filter(|f| f.kind == "unchecked").map(|f| f.component.clone()).collect(),
        fixes: h.fixes.clone(),
    }
}

/// A severity's name in a sentence.
pub fn name(severity: &str) -> &str {
    match severity {
        "" => "Not rated",
        "CRITICAL" => "Critical",
        "HIGH" => "High",
        "MODERATE" => "Medium",
        "LOW" => "Low",
        s => s,
    }
}

/// Who ran a fix: `user@host`, or "-" before wpantry recorded it.
pub fn who(f: &Fix) -> String {
    match (f.user.as_str(), f.host.as_str()) {
        ("", "") => "-".into(),
        (u, "") => u.into(),
        (u, h) => format!("{u}@{h}"),
    }
}

/// The summary as JSON.
pub fn json(s: &Summary) -> J {
    let levels = s
        .levels
        .iter()
        .map(|l| {
            obj([
                ("severity", name(l.severity).into()),
                ("target_days", l.target.map_or(J::Null, J::Int)),
                ("open_fail", J::Int(l.open_fail as i64)),
                ("open_warn", J::Int(l.open_warn as i64)),
                ("overdue", J::Int(l.overdue as i64)),
                ("resolved", J::Int(l.resolved as i64)),
                ("resolved_late", J::Int(l.resolved_late as i64)),
                ("median_days_to_resolve", J::Float(l.median_days)),
            ])
        })
        .collect();
    obj([
        ("since_days", J::Int(s.since_days)),
        ("generated_at", stamp(s.generated_at).as_str().into()),
        ("scan_id", J::Int(s.scan_id)),
        ("scan_finished", stamp(s.scan_finished).as_str().into()),
        ("by_severity", J::Arr(levels)),
        ("known_exploited_open", J::Int(s.kev_open as i64)),
        (
            "oldest_open_critical_or_high",
            s.oldest.as_ref().map_or(J::Null, |(sev, c, v, id, d)| {
                obj([
                    ("severity", name(sev).into()),
                    ("component", c.as_str().into()),
                    ("version", v.as_str().into()),
                    ("advisory", id.as_str().into()),
                    ("days_open", J::Float(*d)),
                ])
            }),
        ),
        ("median_days_to_resolve", J::Float(s.median_days)),
        ("p90_days_to_resolve", J::Float(s.p90_days)),
        ("scans", J::Int(s.scans as i64)),
        ("hosts", J::Arr(s.hosts.iter().map(|h| h.as_str().into()).collect())),
        ("users", J::Arr(s.users.iter().map(|u| u.as_str().into()).collect())),
        ("days_without_a_scan", J::Int(s.days_without_scan)),
        ("not_checked", J::Arr(s.gaps.iter().map(|g| g.as_str().into()).collect())),
        (
            "fixes",
            J::Arr(
                s.fixes
                    .iter()
                    .map(|f| {
                        obj([
                            ("when", stamp(f.at).as_str().into()),
                            ("who", who(f).as_str().into()),
                            ("command", f.command.as_str().into()),
                            ("mode", f.mode.as_str().into()),
                            ("ok", f.ok.into()),
                            ("verified_scan", f.verified_scan.map_or(J::Null, J::Int)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "controls",
            J::Arr(
                CONTROLS
                    .iter()
                    .map(|(c, what)| obj([("control", (*c).into()), ("evidence", (*what).into())]))
                    .collect(),
            ),
        ),
    ])
}

/// The summary as `metric,value` CSV rows.
pub fn csv(s: &Summary) -> String {
    let mut rows: Vec<(String, String)> = vec![
        ("since_days".into(), s.since_days.to_string()),
        ("scan_id".into(), s.scan_id.to_string()),
        ("scan_finished".into(), stamp(s.scan_finished)),
        ("known_exploited_open".into(), s.kev_open.to_string()),
        ("median_days_to_resolve".into(), s.median_days.to_string()),
        ("p90_days_to_resolve".into(), s.p90_days.to_string()),
        ("scans".into(), s.scans.to_string()),
        ("hosts".into(), s.hosts.join(" ")),
        ("users".into(), s.users.join(" ")),
        ("days_without_a_scan".into(), s.days_without_scan.to_string()),
        ("not_checked".into(), s.gaps.len().to_string()),
        ("fixes_run".into(), s.fixes.len().to_string()),
        ("fixes_failed".into(), s.fixes.iter().filter(|f| !f.ok).count().to_string()),
        ("fixes_verified".into(), s.fixes.iter().filter(|f| f.verified_scan.is_some()).count().to_string()),
    ];
    for l in &s.levels {
        let n = name(l.severity).to_lowercase().replace(' ', "_");
        rows.push((format!("{n}_open_fail"), l.open_fail.to_string()));
        rows.push((format!("{n}_open_warn"), l.open_warn.to_string()));
        rows.push((format!("{n}_overdue"), l.overdue.to_string()));
        rows.push((format!("{n}_resolved"), l.resolved.to_string()));
        rows.push((format!("{n}_resolved_late"), l.resolved_late.to_string()));
        if let Some(t) = l.target {
            rows.push((format!("{n}_target_days"), t.to_string()));
        }
    }
    let mut t = String::from("metric,value\r\n");
    for (k, v) in rows {
        t.push_str(&format!("{},{}\r\n", super::csv::field(&k), super::csv::field(&v)));
    }
    t
}

/// The summary as Markdown.
pub fn md(s: &Summary) -> String {
    use super::md::cell;
    let mut t = format!(
        "# Security summary\n\nThe last {} days, to {}. Latest scan #{} finished {}.\n",
        s.since_days,
        stamp(s.generated_at),
        s.scan_id,
        stamp(s.scan_finished)
    );
    t.push_str("\n## Where we stand\n\n| Severity | Target (days) | Failing now | Warning now | Overdue | Resolved | Resolved late | Median days to resolve |\n|---|---|---|---|---|---|---|---|\n");
    for l in &s.levels {
        t.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            name(l.severity),
            l.target.map_or("-".into(), |d| d.to_string()),
            l.open_fail,
            l.open_warn,
            l.overdue,
            l.resolved,
            l.resolved_late,
            l.median_days
        ));
    }
    t.push_str(&format!("\n- Known exploited, open now: {}\n", s.kev_open));
    if let Some((sev, c, v, id, d)) = &s.oldest {
        t.push_str(&format!(
            "- Oldest open Critical or High: {} {} {} ({}), open {d} days\n",
            cell(c),
            cell(v),
            cell(id),
            name(sev)
        ));
    }
    t.push_str(&format!("- Time to resolve: median {} days, 90th percentile {} days\n", s.median_days, s.p90_days));
    t.push_str(&format!(
        "\n## Did the checks run\n\n- Scans: {} on {} ({}), run by {}\n- Days without a scan: {}\n- Not checked in the latest scan: {}\n",
        s.scans,
        plural_hosts(s.hosts.len()),
        cell(&s.hosts.join(", ")),
        cell(&s.users.join(", ")),
        s.days_without_scan,
        if s.gaps.is_empty() { "nothing".into() } else { cell(&s.gaps.join(", ")) }
    ));
    t.push_str("\n## Who fixed what\n\n");
    if s.fixes.is_empty() {
        t.push_str("No fixes ran in the period.\n");
    } else {
        t.push_str("| When | Who | Command | Result | Verified by scan |\n|---|---|---|---|---|\n");
        for f in &s.fixes {
            t.push_str(&format!(
                "| {} | {} | `{}` | {} | {} |\n",
                stamp(f.at),
                cell(&who(f)),
                cell(&f.command).replace('`', "'"),
                if f.ok { "ok" } else { "failed" },
                f.verified_scan.map_or("-".into(), |v| format!("#{v}"))
            ));
        }
    }
    t.push_str("\n## Evidence for\n\n| Control | What shows it |\n|---|---|\n");
    for (c, what) in CONTROLS {
        t.push_str(&format!("| {c} | {what} |\n"));
    }
    t
}

fn plural_hosts(n: usize) -> String {
    if n == 1 { "1 host".into() } else { format!("{n} hosts") }
}

#[cfg(test)]
#[path = "summary_tests.rs"]
mod tests;
