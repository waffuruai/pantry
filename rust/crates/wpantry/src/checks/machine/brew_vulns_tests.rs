use super::*;
use crate::checks::machine::catalog::MISE_FIX;

use crate::checks::machine::testing;
use crate::utils::net::Fake;

#[test]
fn cellar_lists_formulae_and_versions() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    for v in ["openssl@3/3.6.0", "openssl@3/3.5.4", "jq/1.8.1", "jq/.DS_Store"] {
        std::fs::create_dir_all(d.path().join("Cellar").join(v)).unwrap();
    }
    assert_eq!(cellar_listing(&d.path().join("Cellar")).as_deref(), Some("jq 1.8.1\nopenssl@3 3.5.4 3.6.0"));
    assert_eq!(cellar_listing(&d.path().join("nowhere")), None);
}

fn cache() -> (crate::utils::temp::TempDir, Cache) {
    let d = crate::utils::temp::TempDir::new("brew").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    (d, c)
}

fn result() -> Value {
    json!({"checked": 2, "findings": [
        {"formula": "jq", "version": "1.7", "vulnerabilities": [
            {"id": "GHSA-jq", "aliases": ["CVE-2026-7"], "summary": "jq overflow", "severity": "high", "fixed_versions": ["1.8.1"]},
            {"id": "", "summary": "no id"}]}]})
}

#[test]
fn a_cellar_beside_brew() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    std::fs::create_dir_all(d.path().join("bin")).unwrap();
    std::fs::create_dir_all(d.path().join("Cellar/jq/1.8.1")).unwrap();
    let listing = cellar(&d.path().join("bin/brew"));
    // HOMEBREW_PREFIX or HOMEBREW_CELLAR in the environment point at the
    // real Cellar instead, whatever it holds.
    if std::env::var_os("HOMEBREW_PREFIX").is_none() && std::env::var_os("HOMEBREW_CELLAR").is_none() {
        assert_eq!(listing.as_deref(), Some("jq 1.8.1"));
    }
}

#[test]
fn brew_job_is_nothing_without_brew_and_not_stale_offline() {
    let (_d, c) = cache();
    if let Some(job) = brew_job(&c, false, true).unwrap() {
        assert!(!job.stale, "offline never reruns");
        assert_eq!(job.fingerprint.len(), 64);
        assert!(brew_job(&c, true, false).unwrap().unwrap().stale, "--refresh always does");
    } else {
        assert!(which("brew").is_none());
    }
}

#[cfg(unix)]
fn fake_brew(dir: &Path, stdout: &str, stderr: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let exe = dir.join("brew");
    std::fs::write(&exe, format!("#!/bin/sh\necho '{stdout}'\necho '{stderr}' >&2\nexit 1\n")).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

#[cfg(unix)]
#[test]
fn brew_scan_parses_json_and_reports_old_homebrew() {
    let d = crate::utils::temp::TempDir::new("brew").unwrap();
    let ok = BrewJob::new(&fake_brew(d.path(), r#"{"checked": 1, "findings": []}"#, "warning"), "fp", true);
    assert_eq!(brew_scan(&ok).unwrap(), json!({"checked": 1, "findings": []}));
    let old = BrewJob::new(&fake_brew(d.path(), "", "Error: Unknown command: vulns"), "fp", true);
    assert!(matches!(brew_scan(&old), Err(Error::Missing(m)) if m.contains("brew update")));
    let broken = BrewJob::new(&fake_brew(d.path(), "not json", "Error: boom\nError: the last line"), "fp", true);
    assert!(matches!(brew_scan(&broken), Err(Error::Failed(m)) if m == "brew vulns failed: Error: the last line"));
    let gone = BrewJob::new(&d.path().join("nowhere/brew"), "fp", true);
    assert!(matches!(brew_scan(&gone), Err(Error::Failed(_))));
}

#[test]
fn brew_vulns_caches_a_run_and_stores_its_advisories() {
    let (_d, c) = cache();
    assert!(brew_vulns(&c, None, None, false, false).unwrap().is_none());
    let job = BrewJob::new(Path::new("/nonexistent/brew"), "fp", true);
    // Offline with nothing cached: unchecked, not clean.
    assert!(matches!(brew_vulns(&c, Some(&job), None, false, true), Err(Error::Offline(_))));
    let got = brew_vulns(&c, Some(&job), Some(Ok(result())), false, false).unwrap().unwrap();
    assert_eq!(got["checked"], 2);
    assert_eq!(got["findings"][0]["formula"], "jq");
    let rec = c.vuln("GHSA-jq").unwrap().expect("stored for the report");
    assert_eq!(rec["aliases"], json!(["CVE-2026-7"]));
    assert_eq!(rec["affected"][0]["package"]["name"], "jq");
    assert_eq!(rec["database_specific"]["severity"], "high");
    assert!(c.vuln("").unwrap().is_none(), "an advisory without an id isn't stored");
    // Fresh for the same Cellar: no scan runs (the exe doesn't exist).
    assert_eq!(brew_vulns(&c, Some(&job), None, false, false).unwrap().unwrap()["checked"], 2);
    assert_eq!(brew_vulns(&c, Some(&job), None, false, true).unwrap().unwrap()["checked"], 2);
    // Known advisories aren't stored again; a scan that fails isn't cached.
    brew_vulns(&c, Some(&job), Some(Ok(result())), true, false).unwrap();
    assert!(matches!(
        brew_vulns(&c, Some(&job), Some(Err(Error::Failed("x".into()))), true, false),
        Err(Error::Failed(_))
    ));
    let other = BrewJob::new(Path::new("/nonexistent/brew"), "other", true);
    assert!(
        matches!(brew_vulns(&c, Some(&other), None, false, false), Err(Error::Failed(_))),
        "a changed Cellar scans again"
    );
}

#[test]
fn brew_vulns_finding_for_mise_stays_manual() {
    assert_eq!(manual("mise"), Some(MISE_FIX));
    assert_eq!(manual("node"), None);
}

#[test]
fn brew_vulns_findings_malicious_unfixed_and_manual() {
    let d = crate::utils::temp::TempDir::new("brew").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    s.kev.insert("CVE-2026-7".into());
    let job = BrewJob::new(&d.path().join("brew"), "fp", true);
    let ran = serde_json::json!({"checked": 3, "findings": [
        {"formula": "mise", "version": "2026.10.19", "vulnerabilities": [
            {"id": "GHSA-m", "severity": "high", "summary": "mise bug", "fixed_versions": ["2026.10.21"]}]},
        {"formula": "jq", "version": "1.7", "vulnerabilities": [
            {"id": "MAL-0001", "summary": "a backdoor"},
            {"id": "GHSA-nofix", "fixed_versions": []},
            {"id": "GHSA-cve", "aliases": ["CVE-2026-7"], "summary": "jq overflow",
             "fixed_versions": ["1.8.1", "76b7feab363d547e06151c8a8aa0ca72ade0594a"]}]}]});
    brew(&mut s, Some(&job), Some(Ok(ran))).unwrap();
    assert_eq!(s.counts, [("Homebrew formulae".to_string(), 3)]);
    assert_eq!(s.unfixed, 1);
    assert_eq!(
        testing::kinds(&s),
        [
            ("mise".to_string(), "GHSA-m".to_string(), "fail".to_string()),
            ("jq".to_string(), "MAL-0001".to_string(), "fail".to_string()),
            ("jq".to_string(), "CVE-2026-7".to_string(), "fail".to_string()),
        ]
    );
    let (mise, mal, jq) = (&s.findings[0], &s.findings[1], &s.findings[2]);
    assert_eq!(
        (mise.fix_cmd.as_str(), mise.fix_auto, mise.severity.as_str(), mise.fixed.as_str()),
        (MISE_FIX, false, "HIGH", "2026.10.21")
    );
    assert_eq!(
        (mal.severity.as_str(), mal.kev, mal.fix_cmd.as_str()),
        ("MALICIOUS", true, &*REMOVE.replace("{}", "jq"))
    );
    assert_eq!(
        (jq.fix_cmd.as_str(), jq.fix_auto, jq.kev, jq.fixed.as_str(), jq.note.as_str()),
        ("brew upgrade jq", true, true, "1.8.1", "jq overflow")
    );
    assert_eq!((jq.kind.as_str(), jq.location.as_str()), ("brew", "Homebrew"));
}

#[test]
fn brew_vulns_missing_failing_or_absent() {
    let net = Fake::offline();
    let d = crate::utils::temp::TempDir::new("brew").unwrap();
    let mut s = testing::scan(&net, &d);
    brew(&mut s, None, None).unwrap();
    assert!(s.findings.is_empty());
    let job = BrewJob::new(&d.path().join("brew"), "fp", true);
    brew(&mut s, Some(&job), Some(Err(Error::Missing("brew vulns (run: brew update)".into())))).unwrap();
    let f = &s.findings[0];
    assert_eq!(
        (f.component.as_str(), f.vuln_id.as_str(), f.fix_cmd.as_str(), f.fix_auto),
        ("brew vulns", "MISSING", "brew update", true)
    );
    let d2 = crate::utils::temp::TempDir::new("brew").unwrap();
    let mut s2 = testing::scan(&net, &d2);
    brew(&mut s2, Some(&job), Some(Err(Error::Failed("brew vulns failed: boom".into())))).unwrap();
    assert_eq!(testing::unchecked_note(&s2, "Homebrew formulae (brew vulns)"), "brew vulns failed: boom");
    let d3 = crate::utils::temp::TempDir::new("brew").unwrap();
    let mut s3 = testing::scan(&net, &d3);
    assert!(brew(&mut s3, Some(&job), Some(Err(Error::Cache(rusqlite::Error::InvalidQuery)))).is_err());
}
