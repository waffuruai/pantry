use super::*;

fn finding(id: &str, status: &str) -> Finding {
    Finding {
        kind: "project".into(),
        component: "repo/Cargo.lock".into(),
        version: "1.0.0".into(),
        location: "/r/Cargo.lock".into(),
        vuln_id: id.into(),
        status: status.into(),
        fixed: "1.0.1".into(),
        severity: "HIGH".into(),
        ..Default::default()
    }
}

#[test]
fn exposures_open_touch_and_resolve_within_a_scope() {
    let d = crate::utils::temp::TempDir::new("history").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    let t0 = now() - 3.0 * 86400.0;
    let s1 =
        record_scan(&c, t0, &[finding("CVE-1", "fail"), finding("CVE-2", "warn")], &[("git repos".into(), 1)], &opts)
            .unwrap();
    let s2 = record_scan(&c, now(), &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    assert_eq!((s1, s2), (1, 2));
    let open: Vec<_> = exposures(&c, 0.0).unwrap();
    assert_eq!(open.len(), 2);
    let one = open.iter().find(|e| e.vuln_id == "CVE-1").unwrap();
    let two = open.iter().find(|e| e.vuln_id == "CVE-2").unwrap();
    assert!(one.resolved_at.is_none());
    assert_eq!(two.resolved_at.map(|_| true), Some(true), "not seen by the second scan of the same scope");
    assert!(two.days_exposed < 0.01, "{}", two.days_exposed);
    // Another scope never resolves it.
    let other = Options { machine: true, paths: None, ..Default::default() };
    record_scan(&c, now(), &[], &[], &other).unwrap();
    assert!(exposures(&c, 0.0).unwrap().iter().find(|e| e.vuln_id == "CVE-1").unwrap().resolved_at.is_none());
    // Seen again: reopened.
    record_scan(&c, now(), &[finding("CVE-1", "fail"), finding("CVE-2", "warn")], &[], &opts).unwrap();
    assert!(exposures(&c, 0.0).unwrap().iter().all(|e| e.resolved_at.is_none()));
    assert_eq!(scans(&c, 0.0).unwrap().len(), 4);
    assert_eq!(events(&c, 0.0).unwrap().iter().filter(|e| e.kind == "scan").count(), 4);
    // A fix for CVE-2, verified by the next complete scan of the scope that no longer lists it.
    record_fix(&c, Some(4), "brew upgrade x", "auto", true, &[key_of(&finding("CVE-2", "warn"))]).unwrap();
    let s5 = record_scan(&c, now(), &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, 4, s5).unwrap(), 1);
    let f = fixes(&c, 0.0).unwrap();
    assert_eq!((f.len(), f[0].ok, f[0].verified_scan), (1, true, Some(5)));
    assert_eq!(f[0].targets, [key_of(&finding("CVE-2", "warn"))]);
    assert_eq!(scans(&c, 0.0).unwrap()[4].unchecked, 0);
    c.close().unwrap();
}

fn gap() -> Finding {
    Finding {
        kind: "unchecked".into(),
        component: "repo dependencies against OSV".into(),
        vuln_id: "UNCHECKED".into(),
        status: "warn".into(),
        note: "offline and not cached".into(),
        ..Default::default()
    }
}

#[test]
fn an_incomplete_recheck_resolves_nothing() {
    let d = crate::utils::temp::TempDir::new("history-gap").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    // The source is down: the scan lists only the gap. The exposure stays open.
    let s2 = record_scan(&c, 2.0, &[gap()], &[], &opts).unwrap();
    let e = exposures(&c, 0.0).unwrap();
    assert_eq!(e.len(), 1);
    assert!(e[0].resolved_at.is_none(), "a source outage is not a fix: {e:?}");
    assert_eq!(scans(&c, 0.0).unwrap()[1].unchecked, 1);
    assert_eq!(events(&c, 0.0).unwrap()[1].detail["unchecked"], 1);
    // Back online and still listed: still open. Back online and gone: resolved.
    record_scan(&c, 3.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
    let s4 = record_scan(&c, 4.0, &[], &[], &opts).unwrap();
    let e = exposures(&c, 0.0).unwrap();
    assert!(e[0].resolved_at.is_some());
    assert!(s2 < s4);
    c.close().unwrap();
}

#[test]
fn scope_includes_what_the_scan_looked_for() {
    let repos = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    assert_eq!(scope_of(&repos), "repos:/r");
    let licenses = Options { licenses: true, ..repos.clone() };
    assert_eq!(scope_of(&licenses), "repos:/r+licenses");
    let policy = Options {
        policy: crate::checks::Policy { install_scripts: Some("/p/allow.txt".into()), ..Default::default() },
        ..repos.clone()
    };
    assert_eq!(scope_of(&policy), "repos:/r;policy:install-scripts=/p/allow.txt");
    let hooks = Options {
        policy: crate::checks::Policy { hooks: Some("/p/hooks.txt".into()), ..Default::default() },
        ..repos.clone()
    };
    assert_eq!(scope_of(&hooks), "repos:/r;policy:hooks=/p/hooks.txt");
    // A scan without --licenses never resolves what a licenses scan found.
    let d = crate::utils::temp::TempDir::new("history-scope").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let license = Finding { kind: "license".into(), vuln_id: "LICENSE".into(), ..finding("LICENSE", "warn") };
    record_scan(&c, 1.0, &[license], &[], &licenses).unwrap();
    record_scan(&c, 2.0, &[], &[], &repos).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
    record_scan(&c, 3.0, &[], &[], &licenses).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_some());
    c.close().unwrap();
}

#[test]
fn a_fix_is_verified_only_by_complete_negative_evidence() {
    let d = crate::utils::temp::TempDir::new("history-fix").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    let target = key_of(&finding("CVE-1", "fail"));
    let s1 = record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    // A failed fix is never verified, whatever the re-check says.
    record_fix(&c, Some(s1), "npm install -g x@2", "auto", false, std::slice::from_ref(&target)).unwrap();
    let s2 = record_scan(&c, 2.0, &[], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, s1, s2).unwrap(), 0);
    assert_eq!(fixes(&c, 0.0).unwrap()[0].verified_scan, None, "a failed fix marked verified");
    // A successful fix, re-checked by a scan with a gap: not verified.
    let s3 = record_scan(&c, 3.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    record_fix(&c, Some(s3), "npm install -g x@2", "auto", true, std::slice::from_ref(&target)).unwrap();
    let s4 = record_scan(&c, 4.0, &[gap()], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, s3, s4).unwrap(), 0);
    // Re-checked by a complete scan that still lists it: not verified.
    let s5 = record_scan(&c, 5.0, &[finding("CVE-1", "fail")], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, s3, s5).unwrap(), 0);
    // Re-checked by a complete scan that no longer lists it: verified.
    let s6 = record_scan(&c, 6.0, &[], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, s3, s6).unwrap(), 1);
    let f = fixes(&c, 0.0).unwrap();
    assert_eq!((f[0].verified_scan, f[1].verified_scan), (None, Some(s6)));
    // A fix with no known target has nothing to verify against.
    record_fix(&c, Some(s6), "brew upgrade", "auto", true, &[]).unwrap();
    let s7 = record_scan(&c, 7.0, &[], &[], &opts).unwrap();
    assert_eq!(verify_fixes(&c, s6, s7).unwrap(), 0);
    c.close().unwrap();
}

#[test]
fn stamps_are_utc_dates() {
    assert_eq!(stamp(0.0), "1970-01-01 00:00 UTC");
    assert_eq!(stamp(1_793_348_743.0), "2026-10-30 08:25 UTC");
    assert_eq!(civil_from_days(0), (1970, 1, 1));
}

#[test]
fn a_personal_folder_exclusion_cannot_resolve_full_scan_exposures() {
    let d = crate::utils::temp::TempDir::new("personal-scope").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let full = Options { machine: true, paths: Some(vec!["/r".into()]), ..Default::default() };
    let background = Options { no_personal_files: true, ..full.clone() };
    assert_eq!(scope_of(&full), "machine:/r");
    assert_eq!(scope_of(&background), "machine:/r;no-personal-files");
    // No machine pass means this flag changes no coverage.
    let repos = Options { machine: false, ..background.clone() };
    assert_eq!(scope_of(&repos), "repos:/r");
    record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &full).unwrap();
    record_scan(&c, 2.0, &[], &[], &background).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
    record_scan(&c, 3.0, &[], &[], &full).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_some());
    c.close().unwrap();
}
