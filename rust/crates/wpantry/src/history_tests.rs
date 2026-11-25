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
    // A project scan's runtimes make it another scope than the repo checks alone.
    assert_eq!(scope_of(&Options { project: true, ..repos.clone() }), "project:/r");
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

/// A scan of `findings`, saved as a scan saves it.
fn scan_of(c: &Cache, findings: &[Finding], scope: &str) -> i64 {
    let opts = Options { paths: Some(vec![scope.into()]), ..Default::default() };
    c.replace_findings(findings).unwrap();
    record_scan(c, now(), findings, &[], &opts).unwrap()
}

fn latest_ids(c: &Cache) -> Vec<String> {
    let mut ids: Vec<String> = crate::reporters::jsonl::findings(c).unwrap().into_iter().map(|f| f.vuln_id).collect();
    ids.sort();
    ids
}

#[test]
fn each_scan_keeps_its_findings_and_runs_lists_them_latest_first() {
    let d = crate::utils::temp::TempDir::new("runs").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    assert_eq!((runs(&c).unwrap(), latest_scan(&c).unwrap()), (Vec::new(), None));
    let a = scan_of(&c, &[finding("CVE-1", "fail"), finding("CVE-2", "warn")], "/a");
    let b = scan_of(&c, &[], "/b");
    let listed = runs(&c).unwrap();
    let got: Vec<(i64, &str, i64, i64, i64, bool)> = listed
        .iter()
        .map(|r| (r.row.id, r.row.scope.as_str(), r.row.fails, r.row.warns, r.findings, r.latest))
        .collect();
    // A scan that found nothing is a kept scan too.
    assert_eq!(got, [(b, "repos:/b", 0, 0, 0, true), (a, "repos:/a", 1, 1, 2, false)]);
    assert!(is_kept(&c, a).unwrap() && !is_kept(&c, 99).unwrap());
    let json: Value = serde_json::from_str(&runs_json(&listed)).unwrap();
    assert_eq!(json["keeps"], KEEP_RUNS);
    assert_eq!(json["runs"][1]["scan"], a);
    assert_eq!(
        (&json["runs"][1]["findings"], &json["runs"][1]["latest"], &json["runs"][1]["scope"]),
        (&json!(2), &json!(false), &json!("repos:/a"))
    );
    assert!(json["runs"][0]["finished"].as_str().unwrap().ends_with(" UTC"));
}

#[test]
fn pruning_the_latest_scan_shows_the_one_before_it_again() {
    let d = crate::utils::temp::TempDir::new("runs").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let a = scan_of(&c, &[finding("CVE-1", "fail")], "/a");
    let b = scan_of(&c, &[finding("CVE-2", "fail"), finding("CVE-3", "fail")], "/b");
    let wrong = scan_of(&c, &[finding("CVE-9", "fail")], "/wrong");
    assert_eq!((latest_scan(&c).unwrap(), latest_ids(&c)), (Some(wrong), vec!["CVE-9".to_string()]));
    let (row, gone) = prune_run(&c, wrong).unwrap().unwrap();
    assert_eq!((row.id, row.scope.as_str(), gone), (wrong, "repos:/wrong", 1));
    assert_eq!((latest_scan(&c).unwrap(), latest_ids(&c)), (Some(b), vec!["CVE-2".to_string(), "CVE-3".to_string()]));
    // An older one goes without touching what report shows.
    assert_eq!(prune_run(&c, a).unwrap().map(|(_, n)| n), Some(1));
    assert_eq!((latest_scan(&c).unwrap(), latest_ids(&c).len()), (Some(b), 2));
    assert_eq!(runs(&c).unwrap().iter().map(|r| r.row.id).collect::<Vec<_>>(), [b]);
    // Twice, or a scan there never was: nothing to prune.
    assert_eq!(prune_run(&c, a).unwrap(), None);
    assert_eq!(prune_run(&c, 99).unwrap(), None);
    // The scan log keeps every row, and says what was pruned.
    assert_eq!(scans(&c, f64::MIN).unwrap().len(), 3);
    let pruned: Vec<Value> =
        events(&c, 0.0).unwrap().into_iter().filter(|e| e.kind == "prune").map(|e| e.detail["scan"].clone()).collect();
    assert_eq!(pruned, [json!(wrong), json!(a)]);
    // The last one gone: no scan to report, and no findings left behind.
    prune_run(&c, b).unwrap().unwrap();
    assert_eq!((latest_scan(&c).unwrap(), latest_ids(&c)), (None, Vec::new()));
}

#[test]
fn only_the_latest_scans_keep_their_findings() {
    let d = crate::utils::temp::TempDir::new("runs").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let ids: Vec<i64> = (0..KEEP_RUNS + 2).map(|_| scan_of(&c, &[finding("CVE-1", "fail")], "/a")).collect();
    let kept: Vec<i64> = runs(&c).unwrap().iter().map(|r| r.row.id).collect();
    assert_eq!(kept.len() as i64, KEEP_RUNS);
    assert_eq!((kept[0], *kept.last().unwrap()), (*ids.last().unwrap(), ids[2]));
    let rows: i64 = c.conn.query_row("SELECT COUNT(*) FROM run_findings", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, KEEP_RUNS, "the two oldest scans' findings are gone");
    assert!(!is_kept(&c, ids[0]).unwrap() && !is_kept(&c, ids[1]).unwrap());
    assert_eq!(scans(&c, f64::MIN).unwrap().len() as i64, KEEP_RUNS + 2, "their rows stay in the scan log");
}

#[test]
fn a_scan_that_never_ended_is_told_once_and_one_still_running_each_time() {
    let d = crate::utils::temp::TempDir::new("runs").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    assert_eq!(unfinished(&c, &|_| panic!("nothing to ask about")).unwrap(), []);
    // Two other processes began scans; 41's is gone, 42's is still there.
    c.set("scan_running:41", r#"{"started_at": 86400.0, "scope": "machine:~"}"#).unwrap();
    c.set("scan_running:42", r#"{"started_at": 90000.0, "scope": "project:/r"}"#).unwrap();
    let found = unfinished(&c, &|pid| pid == 42).unwrap();
    assert_eq!(
        found,
        [
            Unfinished { pid: 41, started_at: 86400.0, scope: "machine:~".into(), running: false },
            Unfinished { pid: 42, started_at: 90000.0, scope: "project:/r".into(), running: true },
        ]
    );
    assert_eq!(
        found[0].line(Some(58)),
        "ℹ the scan of machine:~ started 1970-01-02 00:00 UTC didn't finish: nothing of it was saved, and wpantry report shows scan 58"
    );
    assert_eq!(
        found[0].line(None),
        "ℹ the scan of machine:~ started 1970-01-02 00:00 UTC didn't finish: nothing of it was saved"
    );
    assert_eq!(
        found[1].line(Some(58)),
        "ℹ the scan of project:/r started 1970-01-02 01:00 UTC is still running (pid 42): when it finishes, wpantry report shows it"
    );
    let again: Vec<u32> = unfinished(&c, &|pid| pid == 42).unwrap().iter().map(|u| u.pid).collect();
    assert_eq!(again, [42], "the interrupted one was told");
    // This process's own scan: noted at once, gone when it ends, and never "still running" to itself.
    let opts = Options { machine: true, ..Default::default() };
    scan_started(&c, &opts, 5.0).unwrap();
    let mine = unfinished(&c, &|_| true).unwrap().into_iter().find(|u| u.pid == std::process::id()).unwrap();
    assert_eq!((mine.scope.as_str(), mine.started_at, mine.running), ("machine:~", 5.0, false));
    scan_started(&c, &opts, 6.0).unwrap();
    scan_finished(&c).unwrap();
    assert_eq!(unfinished(&c, &|_| true).unwrap().iter().map(|u| u.pid).collect::<Vec<_>>(), [42]);
}
