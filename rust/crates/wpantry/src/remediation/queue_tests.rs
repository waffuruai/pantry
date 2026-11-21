use super::*;

fn f(kind: &str, component: &str, vuln_id: &str, status: &str, fix_cmd: &str, auto: bool) -> Finding {
    Finding {
        kind: kind.into(),
        component: component.into(),
        vuln_id: vuln_id.into(),
        status: status.into(),
        fix_cmd: fix_cmd.into(),
        fix_auto: auto,
        ..Default::default()
    }
}

#[test]
fn ids_are_short_stable_and_recognised() {
    let a = f("brew", "curl", "CVE-2026-1", "fail", "brew upgrade curl", true);
    assert_eq!(a.id(), a.clone().id(), "the same finding, the same id");
    assert!(is_id(&a.id()) && is_id(&a.id().to_lowercase()), "{}", a.id());
    assert_ne!(a.id(), f("brew", "curl", "CVE-2026-2", "fail", "", false).id());
    assert!(!is_id("CVE-2026-1") && !is_id("F-xyz") && !is_id("F-0123456789a"));
    let all = [a.clone()];
    assert_eq!(find(&all, &a.id().to_lowercase()).map(|x| x.vuln_id.as_str()), Some("CVE-2026-1"));
}

#[test]
fn the_queue_is_in_fix_order_with_who_does_each() {
    let fs = vec![
        f("brew", "slack", "CVE-2026-9", "warn", "brew upgrade slack", true),
        f("unchecked", "OSV", "UNCHECKED", "warn", "", false),
        f("brew", "curl", "CVE-2026-1", "fail", "brew upgrade curl", true),
        f("secret", "~/r/.env", "github-pat", "fail", "# If it's real…\nrepo=~/r", false),
        f("project", "lodash", "GHSA-1", "fail", "", false),
        f("posture", "FileVault", "POSTURE-FILEVAULT", "fail", "sudo fdesetup enable", false),
    ];
    let q = items(&fs);
    let ids: Vec<&str> = q.iter().map(|i| i.finding.component.as_str()).collect();
    // failures first (a committed secret before the rest), then the warning;
    // no gap, and nothing without a fix
    assert_eq!(ids, ["~/r/.env", "curl", "FileVault", "slack"]);
    let how: Vec<&str> = q.iter().map(|i| i.how.name()).collect();
    assert_eq!(how, ["terminal", "wpantry", "you", "wpantry"]);
    assert_eq!(q[0].run(), format!("wpantry fix secret {}", fs[3].id()));
    assert_eq!(q[1].run(), format!("wpantry fix {} --dry-run", fs[2].id()));
    assert_eq!(q[2].run(), "sudo fdesetup enable");
    let j = q[1].to_json().dumps();
    assert!(j.contains(&format!("\"id\": \"{}\"", fs[2].id())) && j.contains("\"how\": \"wpantry\""), "{j}");
    // next skips what a fix was tried for
    let done: HashSet<String> = [fs[3].key()].into();
    let (n, left) = next(&q, &done);
    assert_eq!((n.map(|i| i.finding.component.as_str()), left), (Some("curl"), 3));
    let all: HashSet<String> = q.iter().map(|i| i.finding.key()).collect();
    assert_eq!(next(&q, &all).1, 0);
}
