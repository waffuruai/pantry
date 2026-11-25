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
    // The scope it was seen in, so a caller can scan that scope again.
    assert_eq!(one.scope, "repos:/r");
    assert_eq!(one.to_json()["scope"], "repos:/r");
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
    // Since 2026-11-21 the flag also keeps the personal folders out
    // of the repo walk, so a repo-only scan with it covers less too.
    let repos = Options { machine: false, ..background.clone() };
    assert_eq!(scope_of(&repos), "repos:/r;no-personal-files");
    record_scan(&c, 1.0, &[finding("CVE-1", "fail")], &[], &full).unwrap();
    record_scan(&c, 2.0, &[], &[], &background).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none());
    record_scan(&c, 3.0, &[], &[], &full).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_some());
    c.close().unwrap();
}

#[test]
fn an_exposure_keeps_its_first_epss_score_as_the_latest_moves() {
    let d = crate::utils::temp::TempDir::new("history").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    let scored = |e: Option<f64>, p: Option<f64>| Finding { epss: e, epss_percentile: p, ..finding("CVE-1", "fail") };
    record_scan(&c, 1.0, &[scored(None, None)], &[], &opts).unwrap();
    let first = |c: &Cache| {
        let e = exposures(c, 0.0).unwrap().remove(0);
        (e.first_epss, e.first_epss_percentile, e.epss)
    };
    assert_eq!(first(&c), (None, None, None), "not scored yet");
    record_scan(&c, 2.0, &[scored(Some(0.02), Some(0.6))], &[], &opts).unwrap();
    record_scan(&c, 3.0, &[scored(Some(0.4), Some(0.99))], &[], &opts).unwrap();
    assert_eq!(first(&c), (Some(0.02), Some(0.6), Some(0.4)), "the first score stays; the latest moves");
}

#[test]
fn targeted_fix_history_waits_for_a_complete_later_scan_of_the_same_scope() {
    let dir = crate::utils::temp::TempDir::new("targeted-fix-history").unwrap();
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    let opts = Options { machine: false, paths: Some(vec!["/r".into()]), ..Default::default() };
    let finding = finding("CVE-1", "fail");
    let target = key_of(&finding);
    let before = now() - 60.0;
    let scan = record_scan(&cache, before, std::slice::from_ref(&finding), &[], &opts).unwrap();
    record_fix(&cache, Some(scan), "patch failed", "mitigate", false, std::slice::from_ref(&target)).unwrap();
    record_fix(&cache, Some(scan), "patch worked", "mitigate", true, &[target]).unwrap();
    let other = Options { paths: Some(vec!["/different".into()]), ..opts.clone() };
    record_scan(&cache, now(), &[], &[], &other).unwrap();
    record_scan(&cache, now(), &[gap()], &[], &opts).unwrap();
    // It finished after the fix but started before it, so it cannot verify it.
    record_scan(&cache, before, &[], &[], &opts).unwrap();
    assert!(fixes(&cache, 0.0).unwrap().iter().all(|f| f.verified_scan.is_none()));
    let verified = record_scan(&cache, now(), &[], &[], &opts).unwrap();
    let history = fixes(&cache, 0.0).unwrap();
    assert_eq!(history[0].verified_scan, None);
    assert_eq!(history[1].verified_scan, Some(verified));
}

/// The two findings `--no-personal-files` adds on macOS, as the scan makes them.
fn skipped_by_choice() -> Vec<Finding> {
    ["Personal documents and images", "Safari settings"]
        .iter()
        .map(|what| Finding {
            kind: "unchecked".into(),
            component: (*what).into(),
            vuln_id: "UNCHECKED".into(),
            status: "warn".into(),
            note: "Skipped by your choice (--no-personal-files).".into(),
            excluded: true,
            ..Default::default()
        })
        .collect()
}

/// Oracle: a machine scan with `--no-personal-files` (`machine:~;no-personal-files`)
/// carries only the user's own exclusions, so a later scan of the same
/// scope that no longer lists an exposure resolves it and verifies the
/// targeted fix for it. Known-bad case: the same scan with one real source
/// failure beside the exclusions resolves and verifies nothing.
#[test]
fn a_chosen_exclusion_still_resolves_and_verifies_but_a_source_failure_does_not() {
    let d = crate::utils::temp::TempDir::new("history-excluded").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let chosen = Options { machine: true, no_personal_files: true, ..Default::default() };
    assert_eq!(scope_of(&chosen), "machine:~;no-personal-files");
    let exposed = finding("CVE-1", "fail");
    let target = key_of(&exposed);
    let mut first = skipped_by_choice();
    first.push(exposed.clone());
    let before = now() - 60.0;
    let s1 = record_scan(&c, before, &first, &[], &chosen).unwrap();
    assert_eq!(scans(&c, 0.0).unwrap()[0].unchecked, 0, "a chosen exclusion is not a gap");
    assert_eq!(events(&c, 0.0).unwrap()[0].detail["excluded"], 2);
    record_fix(&c, Some(s1), "patch", "mitigate", true, std::slice::from_ref(&target)).unwrap();

    // Known-bad: a real source failure beside the exclusions blocks both.
    let mut broken = skipped_by_choice();
    broken.push(gap());
    record_scan(&c, now(), &broken, &[], &chosen).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none(), "a source outage is not a fix");
    assert!(fixes(&c, 0.0).unwrap()[0].verified_scan.is_none());
    assert_eq!(scans(&c, 0.0).unwrap()[1].unchecked, 1);

    // Same exclusions, every source answered, the exposure gone: resolved and verified.
    let s3 = record_scan(&c, now(), &skipped_by_choice(), &[], &chosen).unwrap();
    let e = exposures(&c, 0.0).unwrap();
    assert!(e[0].resolved_at.is_some(), "{e:?}");
    assert_eq!(fixes(&c, 0.0).unwrap()[0].verified_scan, Some(s3));
    // `fix --verify`'s path agrees: the scan counts as complete.
    record_fix(&c, Some(s1), "brew upgrade x", "auto", true, std::slice::from_ref(&target)).unwrap();
    assert_eq!(verify_fixes(&c, s1, s3).unwrap(), 1);
    c.close().unwrap();
}

/// Risk: the scheduled job's scope became `machine:~;no-personal-files`, and
/// an exposure resolves only under an identical scope, so everything a full
/// `machine:~` scan had recorded stayed open for good once the job stopped
/// listing it. The fix (a no-personal-files machine scan also closes what
/// `machine:~` recorded) must never close what that scan did not read.
/// Oracle: where each exposure is. Outside the personal folders the job read
/// it, so its absence is real; inside them (any spelling: `..`, `~`, a
/// different case on macOS and Windows) or in Safari's protected data it did
/// not, so it stays open until a full scan; a full scan closes the rest.
/// Known bad, each by one change: drop the folder test and the Documents
/// exposures close; drop the new rule and the fixed ones stay open.
#[test]
fn a_no_personal_files_scan_closes_full_scan_exposures_it_could_see_and_no_others() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    let d = crate::utils::temp::TempDir::new("closes").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let full = Options { machine: true, ..Default::default() };
    let job = Options { no_personal_files: true, ..full.clone() };
    assert_eq!((scope_of(&full).as_str(), scope_of(&job).as_str()), ("machine:~", "machine:~;no-personal-files"));
    let at = |kind: &str, component: &str, location: String, id: &str| Finding {
        kind: kind.into(),
        component: component.into(),
        location,
        vuln_id: id.into(),
        status: "fail".into(),
        ..Default::default()
    };
    let p = |rel: &str| home.join(rel).to_string_lossy().into_owned();
    // (name, finding, whether the job's scan can close it)
    let mut cases = vec![
        ("a repo's lockfile outside the folders", at("project", "app", p("code/app/Cargo.lock"), "CVE-1"), true),
        ("a Homebrew formula", at("brew", "openssl@3", String::new(), "CVE-2"), true),
        ("a lockfile in Documents", at("project", "doc", p("Documents/proj/Cargo.lock"), "CVE-3"), false),
        ("a file in Downloads", at("malware", "x", p("Downloads/x"), "MALWARE"), false),
        ("a path folded with ..", at("project", "dots", p("Library/../Desktop/p/Cargo.lock"), "CVE-4"), false),
        ("a path spelled with ~", at("project", "tilde", "~/Documents/p/Cargo.lock".into(), "CVE-5"), false),
        ("a secret in some repo (no path, only `line 3`)", at("secret", "repo/.env", "line 3".into(), "aws"), false),
        (
            "a document found in Downloads (no location)",
            at("document", "~/Downloads/a.pdf", String::new(), "DOC"),
            false,
        ),
        ("Safari's protected data", at("posture", "Safari", String::new(), "POSTURE-SAFARI-SAFE-FILES"), false),
        // The folders macOS guards too are left out there, and read elsewhere.
        (
            "Pictures (left out on macOS only)",
            at("project", "pics", p("Pictures/proj/Cargo.lock"), "CVE-8"),
            !cfg!(target_os = "macos"),
        ),
        ("a file in Mail (macOS only)", at("malware", "m", p("Library/Mail/x"), "MALWARE"), !cfg!(target_os = "macos")),
        // Folders compare without case where the volume does not tell them apart.
        (
            "Documents spelled in lower case",
            at("project", "lower", p("documents/proj/Cargo.lock"), "CVE-6"),
            !cfg!(any(target_os = "macos", windows)),
        ),
    ];
    // The same folder from its canonical path (a symlinked home, as on macOS).
    match std::fs::canonicalize(&home) {
        Ok(canon) if canon != home => cases.push((
            "Documents from the canonical home",
            at("project", "canon", canon.join("Documents/p/Cargo.lock").to_string_lossy().into_owned(), "CVE-7"),
            false,
        )),
        _ => println!("home has no other spelling here: the canonical-path case is skipped"),
    }
    let found: Vec<Finding> = cases.iter().map(|c| c.1.clone()).collect();
    record_scan(&c, 1.0, &found, &[], &full).unwrap();
    // The job reads everything outside the folders and lists none of it now.
    record_scan(&c, 2.0, &skipped_by_choice(), &[], &job).unwrap();
    let open = |c: &Cache| -> Vec<String> {
        exposures(c, 0.0).unwrap().into_iter().filter(|e| e.resolved_at.is_none()).map(|e| e.component).collect()
    };
    let still_open = open(&c);
    for (name, f, closes) in &cases {
        assert_eq!(
            !still_open.contains(&f.component),
            *closes,
            "{name}: the no-personal-files scan {} it (open now: {still_open:?})",
            if *closes { "must close" } else { "must not close" }
        );
    }
    // A full scan reads everything: it closes what is left.
    record_scan(&c, 3.0, &[], &[], &full).unwrap();
    assert!(open(&c).is_empty(), "a full scan closes the rest: {:?}", open(&c));
    c.close().unwrap();
}

/// Risk: the new rule closing across scopes it was not meant for. Oracle:
/// the scope strings. A scan limited by `--path`, a repo-only scan and a
/// scan with other policy files each stay in their own scope.
#[test]
fn a_no_personal_files_scan_closes_only_the_whole_machine_scope_it_belongs_to() {
    let _home = crate::utils::files::test_home();
    let d = crate::utils::temp::TempDir::new("closes-scopes").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let outside = Finding {
        kind: "project".into(),
        component: "app".into(),
        location: crate::utils::files::home().join("code/Cargo.lock").to_string_lossy().into_owned(),
        vuln_id: "CVE-1".into(),
        status: "fail".into(),
        ..Default::default()
    };
    let full = Options { machine: true, ..Default::default() };
    let licensed = Options { licenses: true, ..full.clone() };
    record_scan(&c, 1.0, std::slice::from_ref(&outside), &[], &licensed).unwrap();
    // `machine:~` is another scope than `machine:~+licenses`: no closing.
    record_scan(&c, 2.0, &skipped_by_choice(), &[], &Options { no_personal_files: true, ..full.clone() }).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_none(), "another scope's exposure stays open");
    // Its own flag-less counterpart does close it.
    record_scan(&c, 3.0, &skipped_by_choice(), &[], &Options { no_personal_files: true, ..licensed.clone() }).unwrap();
    assert!(exposures(&c, 0.0).unwrap()[0].resolved_at.is_some());
    c.close().unwrap();
}
