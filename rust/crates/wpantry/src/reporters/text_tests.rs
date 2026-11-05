use super::*;

#[test]
fn report_groups_by_kind_with_reasons_and_fixes() {
    let adv = |id: &str, kev: bool, sev: &str, note: &str, fixed: &str| Finding {
        kind: "project".into(),
        component: "smallvec".into(),
        version: "1.6.0".into(),
        location: "/w/app/Cargo.lock".into(),
        vuln_id: id.into(),
        status: "fail".into(),
        fixed: fixed.into(),
        kev,
        severity: sev.into(),
        note: note.into(),
        fix_cmd: format!("cd /w/app && cargo update -p smallvec --precise {fixed}"),
        ..Default::default()
    };
    let scan = Outcome {
        scan_id: 1,
        findings: vec![
            Finding {
                kind: "unchecked".into(),
                component: "CISA KEV".into(),
                vuln_id: "UNCHECKED".into(),
                status: "warn".into(),
                note: "down".into(),
                ..Default::default()
            },
            adv("CVE-2021-25900", true, "CRITICAL", "Buffer overflow in SmallVec::insert_many", "1.6.1"),
            adv("CVE-2019-15551", false, "HIGH", "Double free", "1.0.0"),
            Finding {
                kind: "mcp".into(),
                component: "y-mcp (project: y)".into(),
                version: "unpinned".into(),
                location: "/w/app/.mcp.json".into(),
                vuln_id: "UNPINNED".into(),
                status: "warn".into(),
                note: "`npx y-mcp` runs the latest release on every launch".into(),
                fix_cmd: "Pin y-mcp to a reviewed version in /w/app/.mcp.json".into(),
                ..Default::default()
            },
            Finding {
                kind: "secret".into(),
                component: "app/.env".into(),
                location: "line 3, commit abc123".into(),
                vuln_id: "aws-access-token".into(),
                status: "fail".into(),
                note: "AWS access key".into(),
                fix_cmd: "Rotate it".into(),
                ..Default::default()
            },
            Finding {
                kind: "bundled".into(),
                component: "Cursor ext x › lodash".into(),
                version: "4.17.20".into(),
                vuln_id: "CVE-2021-23337".into(),
                status: "warn".into(),
                fixed: "4.17.21".into(),
                fix_cmd: "Update the extension".into(),
                ..Default::default()
            },
        ],
        counts: vec![("git repos".into(), 1), ("project dependencies".into(), 10)],
        unfixed: 1,
        unknown_licenses: 0,
    };
    let mut lines = Vec::new();
    assert_eq!(report(&scan, "/c/w.db", &mut |l| lines.push(l.to_string())), 1);
    assert_eq!(
        lines,
        [
            "",
            "==> Security scan (/c/w.db)",
            "  checked 1 git repos, 10 project dependencies",
            "",
            "project",
            "  ✗ smallvec 1.6.0 (/w/app/Cargo.lock) - (CVE-2021-25900 KEV CRITICAL) Buffer overflow in SmallVec::insert_many. And 1 more: CVE-2019-15551. Fix: cd /w/app && cargo update -p smallvec --precise 1.6.1",
            "",
            "secret",
            "  ✗ app/.env (line 3, commit abc123) - (aws-access-token) AWS access key. Fix: Rotate it",
            "",
            "bundled",
            "  ⚠ Cursor ext x - (1 package, 1 advisory) lodash 4.17.20 → 4.17.21. Fix: Update the extension",
            "",
            "mcp",
            "  ⚠ y-mcp (project: y) unpinned (/w/app/.mcp.json) - (UNPINNED) `npx y-mcp` runs the latest release on every launch. Fix: Pin y-mcp to a reviewed version in /w/app/.mcp.json",
            "",
            "not checked",
            "  ⚠ CISA KEV - down",
            "",
            "  · 1 applicable advisories have no released fix yet (wpantry search --applicable)",
            "✗ 2 thing(s) to update (3 advisories), 2 warning(s). See the plan: wpantry fix --dryrun Incomplete: 1 source(s) couldn't be checked (offline?); re-run when they're reachable.",
        ]
    );
}
