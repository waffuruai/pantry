use super::*;
use crate::checks::machine::testing;
use crate::utils::net::Fake;

#[test]
fn flags_and_launchd_listings_parse() {
    assert_eq!(flag("1\n"), Some(true));
    assert_eq!(flag("NO"), Some(false));
    assert_eq!(flag("2026-10-30 07:12:16 +0000: The domain/default pair of (x, y) does not exist"), None);
    assert_eq!(flag(""), None);
    let listing = "disabled services = {\n\t\"com.openssh.sshd\" => disabled\n\t\"com.apple.screensharing\" => enabled\n\t\"com.apple.smbd\" => true\n}\n";
    assert_eq!(launchd_disabled(listing, "com.openssh.sshd"), Some(true));
    assert_eq!(launchd_disabled(listing, "com.apple.screensharing"), Some(false));
    assert_eq!(launchd_disabled(listing, "com.apple.smbd"), Some(true));
    assert_eq!(launchd_disabled(listing, "com.apple.AEServer"), None);
}

#[test]
fn skip_list_matches_ids_with_or_without_the_prefix() {
    let runner = |_: &[&str]| String::new();
    let all = run(&[], &runner).len();
    if all == 0 {
        return; // an OS without checks
    }
    let first = checks()[0].id;
    let _ = &first;
    let without: Vec<String> = vec![first.trim_start_matches("POSTURE-").to_ascii_lowercase()];
    assert_eq!(run(&without, &runner).len(), all - 1);
    let with: Vec<String> = vec![first.to_string()];
    assert_eq!(run(&with, &runner).len(), all - 1);
}

#[test]
fn fixes_say_who_applies_them() {
    assert_eq!(admin("x"), Some(Fix { cmd: "x", admin: true }));
    assert_eq!(user("x"), Some(Fix { cmd: "x", admin: false }));
}

#[test]
fn severities_and_odd_flags() {
    assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    assert_eq!(Severity::High.as_str(), "HIGH");
    assert_eq!(Severity::Medium.as_str(), "MEDIUM");
    assert_eq!(Severity::Low.as_str(), "LOW");
    assert_eq!(flag("maybe\n"), None);
    assert_eq!(flag("true"), Some(true));
    // Every check has an id, a title and an explanation, and the tool checks come last.
    let all = checks();
    assert!(all.iter().all(|c| c.id.starts_with("POSTURE-") && !c.title.is_empty() && !c.explain.is_empty()));
    assert!(all.len() >= any::dev_settings::CHECKS.len());
    let tail: Vec<&str> = all[all.len() - any::dev_settings::CHECKS.len()..].iter().map(|c| c.id).collect();
    assert_eq!(tail, any::dev_settings::CHECKS.iter().map(|c| c.id).collect::<Vec<_>>());
}

#[cfg(unix)]
#[test]
fn the_real_runner_runs_a_command() {
    assert_eq!(real_runner(&["echo", "x"]), "x\n");
    assert_eq!(real_runner(&["/nonexistent/command"]), "");
}

#[test]
fn posture_reports_what_fails_and_what_it_cannot_tell() {
    let d = crate::utils::temp::TempDir::new("posture").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    // A machine that answers nothing: every check fails or can't tell.
    posture_with(&mut s, &|_argv: &[&str]| String::new());
    assert!(!s.findings.is_empty());
    for f in &s.findings {
        assert_eq!(f.kind, "posture");
        assert!(f.vuln_id.starts_with("POSTURE-"), "{}", f.vuln_id);
        assert!(f.status == "fail" || f.status == "warn", "{f:?}");
        assert!(!f.fix_cmd.is_empty(), "{f:?}");
        if f.status == "fail" {
            assert!(f.severity == "CRITICAL" || f.severity == "HIGH", "{f:?}");
        }
    }
    assert!(s.counts.iter().any(|(k, n)| k == "security settings checked" && *n > 0));
    let unknown: Vec<&Finding> = s.findings.iter().filter(|f| f.note.starts_with("couldn't tell: ")).collect();
    assert!(unknown.iter().all(|f| f.status == "warn" && !f.fix_auto));
}
