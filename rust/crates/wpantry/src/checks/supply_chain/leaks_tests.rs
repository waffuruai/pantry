use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;

/// Only a list of findings is a result; no report, an empty one or
/// another shape is a run that didn't finish, so nothing is cached as
/// "no secrets".
#[test]
fn a_report_is_a_list_of_findings_or_the_run_failed() {
    let d = TempDir::new("gitleaks-report").unwrap();
    let report = d.path().join("report.json");
    assert!(matches!(report_rows(&report), Err(Error::Failed(_))), "no report");
    for text in ["", "   \n", "{}", "null", "[{}]", r#"[{"RuleID": "aws", "Fingerprint": ""}]"#, "[1]"] {
        std::fs::write(&report, text).unwrap();
        assert!(matches!(report_rows(&report), Err(Error::Failed(_))), "{text:?} is not a clean report");
    }
    std::fs::write(&report, "[]").unwrap();
    assert_eq!(report_rows(&report).unwrap(), Vec::<Value>::new(), "gitleaks writes [] for no findings");
    std::fs::write(
        &report,
        r#"[{"RuleID": "aws-access-token", "File": "x.env", "StartLine": 3, "Commit": "0123456789abcdef0123",
                "Fingerprint": "0123456789abcdef0123:x.env:aws-access-token:3", "Description": "AWS", "Secret": "REDACTED"}]"#,
    )
    .unwrap();
    let rows = report_rows(&report).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(str_at(&rows[0], "rule"), "aws-access-token");
    assert_eq!(str_at(&rows[0], "commit"), "0123456789ab");
    assert_eq!(rows[0]["line"], 3);
    assert!(rows[0].get("Secret").is_none(), "only the redacted fields are kept");
}

#[test]
fn tips_come_from_head_refs_and_packed_refs() {
    let d = TempDir::new("tips").unwrap();
    let git = d.path().join(".git");
    std::fs::create_dir_all(git.join("refs/heads/feat")).unwrap();
    std::fs::create_dir_all(git.join("refs/remotes/origin")).unwrap();
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let c = "c".repeat(40);
    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(git.join("refs/heads/main"), format!("{a}\n")).unwrap();
    std::fs::write(git.join("refs/heads/feat/x"), format!("{b}\n")).unwrap();
    std::fs::write(git.join("packed-refs"), format!("# pack-refs with: peeled\n{c} refs/remotes/origin/dev\n^{a}\n"))
        .unwrap();
    // Refs nested past the depth cap are not read.
    std::fs::create_dir_all(git.join("refs/d1/d2/d3/d4/d5/d6/d7/d8/d9")).unwrap();
    std::fs::write(git.join("refs/d1/d2/d3/d4/d5/d6/d7/d8/d9/deep"), format!("{}\n", "e".repeat(40))).unwrap();
    assert_eq!(tips(d.path()), [a.clone(), b.clone(), c.clone()].into_iter().collect());
    // A worktree: .git is a file naming the gitdir, whose commondir holds the refs.
    let wt = d.path().join("wt");
    let wtgit = git.join("worktrees/wt");
    std::fs::create_dir_all(&wt).unwrap();
    std::fs::create_dir_all(&wtgit).unwrap();
    std::fs::write(wt.join(".git"), format!("gitdir: {}\n", wtgit.display())).unwrap();
    std::fs::write(wtgit.join("commondir"), "../..\n").unwrap();
    std::fs::write(wtgit.join("HEAD"), format!("{}\n", "d".repeat(40))).unwrap();
    let got = tips(&wt);
    assert!(got.contains(&"d".repeat(40)) && got.contains(&a) && got.contains(&c), "{got:?}");
}

/// A git repo made here: `git` with a private HOME, so nothing of the
/// machine's config is read. None when git can't make one.
fn git_repo(d: &TempDir, args: &[&[&str]]) -> Option<PathBuf> {
    let home = d.path().join("home");
    let repo = d.path().join("repo");
    std::fs::create_dir_all(&home).ok()?;
    std::fs::create_dir_all(&repo).ok()?;
    let git = |argv: &[&str]| -> bool {
        let mut full: Vec<&OsStr> = vec![OsStr::new("git"), OsStr::new("-C"), repo.as_os_str()];
        full.extend(["-c", "user.name=w", "-c", "user.email=w@example.invalid"].map(OsStr::new));
        full.extend(argv.iter().map(OsStr::new));
        let env = [("HOME", home.to_str().unwrap()), ("GIT_CONFIG_NOSYSTEM", "1")];
        exec(&full, &env, Duration::from_secs(30)).is_ok_and(|o| o.code == Some(0))
    };
    for a in args {
        if !git(a) {
            return None;
        }
    }
    Some(repo)
}

/// Refs kept the reftable way (git 2.45+) can't be read as files: the
/// tips come from git itself then.
#[test]
fn tips_of_an_unfamiliar_layout_come_from_git() {
    let d = TempDir::new("tips-reftable").unwrap();
    let Some(repo) =
        git_repo(&d, &[&["init", "-q", "--ref-format=reftable"], &["commit", "-q", "--allow-empty", "-m", "a"]])
    else {
        eprintln!("skipped: this git can't make a reftable repo");
        return;
    };
    let got = tips(&repo);
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got.iter().all(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit())));
}

/// An executable script standing in for gitleaks: `version` prints one;
/// a scan records its argv beside the script, copies `report.json`
/// there to the report path, and exits with `exit.code` when present.
#[cfg(unix)]
fn gitleaks(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("gitleaks");
    std::fs::write(
        &p,
        "#!/bin/sh\nd=\"$(dirname \"$0\")\"\necho run >> \"$d/runs.txt\"\n\
             if [ \"$1\" = version ]; then echo 8.21.2; exit 0; fi\n\
             printf '%s\\n' \"$@\" > \"$d/argv.txt\"\nprev=\"\"\n\
             for a in \"$@\"; do if [ \"$prev\" = --report-path ]; then cp \"$d/report.json\" \"$a\"; fi; prev=\"$a\"; done\n\
             if [ -f \"$d/exit.code\" ]; then echo \"rules failed to load\" >&2; exit \"$(cat \"$d/exit.code\")\"; fi\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("report.json"), "[]").unwrap();
    p
}

fn hit(fp: &str) -> Value {
    json!({"rule": "aws-access-token", "file": "x.env", "line": 3, "commit": "0123456789ab",
           "fingerprint": fp, "description": "AWS"})
}

fn argv(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("argv.txt")).unwrap_or_default().lines().map(str::to_string).collect()
}

#[test]
fn without_gitleaks_the_job_is_missing() {
    let d = TempDir::new("no-gitleaks").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    // With whatever this machine has on PATH: a job, or Missing.
    match job(&c, d.path(), &d.path().join("gitleaks.toml"), 1) {
        Ok(j) => assert!(!j.own_policy && j.cached.is_none()),
        Err(Error::Missing(m)) => assert_eq!(m, "gitleaks"),
        Err(e) => panic!("{e}"),
    }
    let Err(err) = job_with(&c, d.path(), &d.path().join("gitleaks.toml"), 1, None) else { panic!("no gitleaks") };
    assert!(matches!(err, Error::Missing(ref m) if m == "gitleaks"), "{err}");
}

/// The first scan is full; its hits and the tips are cached under the
/// policy's and gitleaks' fingerprint, and reused while the refs stand
/// still (also offline, where nothing ever runs).
#[cfg(unix)]
#[test]
fn a_first_scan_is_full_and_cached_until_the_refs_move() {
    let d = TempDir::new("gitleaks-full").unwrap();
    let exe = gitleaks(d.path());
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git/refs/heads")).unwrap();
    std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    let a = "a".repeat(40);
    std::fs::write(repo.join(".git/refs/heads/main"), format!("{a}\n")).unwrap();
    std::fs::write(repo.join(".gitleaks.toml"), "[allowlist]\n").unwrap();
    let config = d.path().join("gitleaks.toml");
    std::fs::write(&config, "title = \"wpantry\"\n").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let job = job_with(&c, &repo, &config, 3, Some(exe.clone())).unwrap();
    assert!(job.own_policy, "the repo's own config is reported, not used");
    assert!(job.fingerprint.starts_with("v2:8.21.2:"), "{}", job.fingerprint);
    assert!(job.cached.is_none() && job.since().is_none());
    assert!(stale(&job, false, false), "nothing cached");
    assert!(!stale(&job, false, true), "never offline");
    assert!(matches!(finish(&c, &job, None, false, true), Err(Error::Offline(_))), "offline and not cached");
    std::fs::write(
        d.path().join("report.json"),
        json!([{"RuleID": "aws-access-token", "File": "x.env",
        "StartLine": 3, "Commit": "0123456789abcdef", "Fingerprint": "fp1", "Description": "AWS"}])
        .to_string(),
    )
    .unwrap();
    let res = run_job(&job).unwrap();
    assert_eq!(res["tips"], json!([a]));
    assert_eq!(res["hits"], json!([hit("fp1")]));
    let args = argv(d.path());
    let i = args.iter().position(|x| x == "git").unwrap();
    assert_eq!(args[i + 1], repo.to_string_lossy());
    assert!(args.contains(&"--redact".to_string()) && args.contains(&"--config".to_string()), "{args:?}");
    assert!(!args.contains(&"--log-opts".to_string()), "a first scan has no history to exclude");
    let found = finish(&c, &job, Some(Ok(res)), false, false).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].rule.as_str(), found[0].fingerprint.as_str(), found[0].line), ("aws-access-token", "fp1", 3));
    // The next job finds the result cached and current: no run, offline or not.
    let job = job_with(&c, &repo, &config, 3, Some(exe.clone())).unwrap();
    assert_eq!(job.since().map(|t| t.len()), Some(1));
    assert!(!stale(&job, false, false));
    assert!(stale(&job, true, false), "--refresh");
    let runs = || std::fs::read_to_string(d.path().join("runs.txt")).unwrap().lines().count();
    let before = runs();
    assert_eq!(finish(&c, &job, None, false, false).unwrap()[0].fingerprint, "fp1");
    assert_eq!(finish(&c, &job, None, false, true).unwrap().len(), 1);
    assert_eq!(runs(), before, "gitleaks' version is asked once per binary, and the scan not at all");
    // A source failure while a result is cached keeps the cached one;
    // without one it is the failure; an internal error passes through.
    let job = job_with(&c, &repo, &config, 3, Some(exe.clone())).unwrap();
    assert_eq!(finish(&c, &job, Some(Err(Error::Offline("x".into()))), true, false).unwrap().len(), 1);
    assert_eq!(finish(&c, &job, Some(Err(Error::Invalid("x".into()))), true, false).unwrap().len(), 1);
    assert!(matches!(finish(&c, &job, Some(Err(Error::Failed("x".into()))), true, false), Err(Error::Failed(_))));
    let other = d.path().join("other");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    let job = job_with(&c, &other, &config, 3, Some(exe.clone())).unwrap();
    assert!(matches!(finish(&c, &job, Some(Err(Error::Offline("x".into()))), false, false), Err(Error::Offline(_))));
    // A failing run is an error with the tail of its stderr, never a clean result.
    std::fs::write(d.path().join("exit.code"), "3").unwrap();
    let err = run_job(&job).unwrap_err();
    assert_eq!(err.to_string(), "gitleaks exited 3: rules failed to load");
    assert!(
        matches!(finish(&c, &job, None, false, false), Err(Error::Failed(_))),
        "finish runs it when nothing ran ahead"
    );
}

/// Once the refs move, only the commits since the remembered tips are
/// scanned and the earlier hits carried over, minus any now ignored;
/// a remembered tip that is gone (rewritten history), or too many of
/// them, means a full scan again.
#[cfg(unix)]
#[test]
fn later_scans_cover_the_new_commits_and_keep_the_old_hits() {
    let d = TempDir::new("gitleaks-incr").unwrap();
    let Some(repo) = git_repo(&d, &[&["init", "-q"], &["commit", "-q", "--allow-empty", "-m", "a"]]) else {
        panic!("git can't make a repo here");
    };
    let exe = gitleaks(d.path());
    let config = d.path().join("gitleaks.toml");
    std::fs::write(&config, "").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let first = tips(&repo);
    assert_eq!(first.len(), 1, "{first:?}");
    let old = first.iter().next().unwrap().clone();
    let job = job_with(&c, &repo, &config, 1, Some(exe.clone())).unwrap();
    c.put_run(&job.key, &job.fingerprint, &json!({"tips": [old], "hits": [hit("fp1"), hit("fp2")]})).unwrap();
    assert!(git_repo(&d, &[&["commit", "-q", "--allow-empty", "-m", "b"]]).is_some());
    std::fs::write(repo.join(".gitleaksignore"), "# reviewed\nfp2\n\n").unwrap();
    let job = job_with(&c, &repo, &config, 1, Some(exe.clone())).unwrap();
    assert!(job.cached.is_none(), "the ignore file changed the fingerprint: scanned in full again");
    c.put_run(&job.key, &job.fingerprint, &json!({"tips": [old], "hits": [hit("fp1"), hit("fp2")]})).unwrap();
    let job = job_with(&c, &repo, &config, 1, Some(exe.clone())).unwrap();
    assert!(stale(&job, false, false), "the refs moved");
    std::fs::write(d.path().join("report.json"), "[]").unwrap();
    let res = run_job(&job).unwrap();
    let args = argv(d.path());
    let i = args.iter().position(|x| x == "--log-opts").expect("only the new commits");
    assert_eq!(args[i + 1], format!("--full-history --all --diff-filter=tuxdb ^{old}"));
    assert_eq!(res["hits"], json!([hit("fp1")]), "fp2 is ignored now; fp1 still stands");
    assert_eq!(res["tips"], json!(tips(&repo).iter().collect::<Vec<_>>()));
    // A remembered tip that no longer exists: everything is scanned.
    c.put_run(&job.key, &job.fingerprint, &json!({"tips": ["f".repeat(40)], "hits": [hit("fp1")]})).unwrap();
    let job = job_with(&c, &repo, &config, 1, Some(exe.clone())).unwrap();
    let res = run_job(&job).unwrap();
    assert!(!argv(d.path()).contains(&"--log-opts".to_string()));
    assert_eq!(res["hits"], json!([]), "a full scan reports what it found, not the old hits");
    // Too many tips to list: a full scan too.
    let many: Vec<String> = (0..=MAX_TIPS).map(|i| format!("{i:040x}")).collect();
    c.put_run(&job.key, &job.fingerprint, &json!({"tips": many, "hits": []})).unwrap();
    let job = job_with(&c, &repo, &config, 1, Some(exe)).unwrap();
    assert!(job.since().is_none());
    run_job(&job).unwrap();
    assert!(!argv(d.path()).contains(&"--log-opts".to_string()));
}

#[test]
fn gitleaks_runs_at_once_from_the_jobs_flag_or_the_cores() {
    let d = TempDir::new("jobs").unwrap();
    let net = Fake::offline();
    assert_eq!(gitleaks_at_once(&testing::scan(&net, &d, Options { jobs: Some(7), ..Default::default() })), 7);
    let n = gitleaks_at_once(&testing::scan(&net, &d, Options::default()));
    assert!((1..=4).contains(&n), "{n}");
}

/// A finding per redacted hit: a provider rule fails, a generic one
/// warns; a repo's own gitleaks config is reported as ignored.
#[test]
fn secrets_from_a_scan_run_ahead() {
    let d = TempDir::new("secrets").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, ".gitleaks.toml", "[allowlist]\n");
    // The binary never runs here: a missing one makes its version "".
    let exe = Some(d.path().join("no-gitleaks"));
    let jobs = secret_jobs(&s, &[(name.clone(), root.clone())], exe).unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].1, "nothing cached: stale");
    let ran = json!({"tips": [], "hits": [
        {"rule": "aws-access-token", "file": "x.env", "line": 3, "commit": "0123456789ab", "fingerprint": "fp1", "description": "AWS"},
        {"rule": "generic-api-key", "file": "cfg.py", "line": 9, "commit": "abcdef012345", "fingerprint": "fp2", "description": "Generic"}]});
    secrets(&mut s, &[(name.clone(), root.clone())], jobs, vec![Some(Ok(ran))]).unwrap();
    assert!(s.counts.contains(&("repos scanned for secrets".to_string(), 1)), "{:?}", s.counts);
    let policy = testing::by_id(&s, "REPO-POLICY");
    assert_eq!(policy.len(), 1);
    assert_eq!((policy[0].component.as_str(), policy[0].status.as_str()), ("app/.gitleaks.toml", "warn"));
    let aws = testing::by_id(&s, "aws-access-token");
    assert_eq!(aws.len(), 1);
    assert_eq!(
        (
            aws[0].kind.as_str(),
            aws[0].component.as_str(),
            aws[0].location.as_str(),
            aws[0].status.as_str(),
            aws[0].note.as_str()
        ),
        ("secret", "app/x.env", "line 3, commit 0123456789ab", "fail", "AWS")
    );
    assert_eq!(
        aws[0].fix_cmd,
        format!(
            "If it's real: rotate it, then purge it from history. If not: add fp1 to {}/.gitleaksignore",
            short(&root.to_string_lossy())
        )
    );
    let generic = testing::by_id(&s, "generic-api-key");
    assert_eq!((generic[0].status.as_str(), generic[0].note.as_str()), ("warn", "Generic (review: generic rule)"));
    // The result is cached now: the next jobs aren't stale, and finish reads them without a run.
    let jobs = secret_jobs(&s, &[(name.clone(), root.clone())], Some(d.path().join("no-gitleaks"))).unwrap();
    assert!(!jobs[0].1);
    let before = s.findings.len();
    secrets(&mut s, &[(name.clone(), root.clone())], jobs, vec![None]).unwrap();
    assert_eq!(s.findings.len(), before + 3, "the same three again");
    assert_eq!(testing::by_id(&s, "aws-access-token").len(), 2);
    // A run that failed as a source: that repo is unchecked, the rest go on.
    let (other, oroot) = testing::repo(&d, "other");
    let repos = [(name.clone(), root.clone()), (other, oroot)];
    let jobs = secret_jobs(&s, &repos, Some(d.path().join("no-gitleaks"))).unwrap();
    secrets(&mut s, &repos, jobs, vec![None, Some(Err(Error::Offline("gitleaks: killed".into())))]).unwrap();
    assert_eq!(testing::unchecked(&s), ["secrets in other's history (gitleaks)"]);
    // An internal error passes through.
    let jobs = secret_jobs(&s, &repos, Some(d.path().join("no-gitleaks"))).unwrap();
    let io = Error::Io(std::io::Error::other("disk"));
    assert!(matches!(secrets(&mut s, &repos, jobs, vec![None, Some(Err(io))]), Err(Error::Io(_))));
    assert!(secret_jobs(&s, &[], None).unwrap().is_empty());
}

#[test]
fn without_gitleaks_the_tool_is_missing() {
    let d = TempDir::new("no-gitleaks").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    let jobs = secret_jobs(&s, &[(name.clone(), root.clone())], None).unwrap();
    assert!(!jobs[0].1, "nothing to run");
    secrets(&mut s, &[(name, root)], jobs, vec![None]).unwrap();
    assert_eq!(s.findings.len(), 1);
    let f = &s.findings[0];
    assert_eq!(
        (f.kind.as_str(), f.component.as_str(), f.vuln_id.as_str(), f.status.as_str()),
        ("tool", "gitleaks", "MISSING", "fail")
    );
    let has_brew = which("brew").is_some();
    assert_eq!(f.fix_auto, has_brew);
    assert_eq!(
        f.fix_cmd,
        if has_brew { "brew install gitleaks".to_string() } else { format!("Install gitleaks: {GITLEAKS_INSTALL}") }
    );
}

/// History's big files are marked binary for git, so gitleaks never reads
/// them; only those the new commits add are listed on a later scan.
#[test]
fn big_files_in_history_are_marked_binary() {
    assert_eq!(attr_pattern(b"data/big set [v2].json"), "/data/big*set*v2*.json");
    assert_eq!(attr_pattern("é/x".as_bytes()), "/*/x");
    let d = TempDir::new("big-files").unwrap();
    let Some(repo) = git_repo(&d, &[&["init", "-q"]]) else { panic!("git can't make a repo here") };
    std::fs::write(repo.join("big set.json"), vec![b'x'; ((MAX_MB << 20) + 1) as usize]).unwrap();
    std::fs::write(repo.join("small.txt"), "fine").unwrap();
    git_repo(&d, &[&["add", "-A"], &["commit", "-q", "-m", "a"]]).unwrap();
    assert_eq!(big_files(&repo, &["--all".into()]), "/big*set.json -diff\n");
    assert_eq!(big_files(&repo, &["--all".into(), "^HEAD".into()]), "", "nothing new since the tip");
    let attrs = d.path().join("attributes");
    std::fs::write(&attrs, big_files(&repo, &["--all".into()])).unwrap();
    let attrs_file = format!("core.attributesFile={}", attrs.display());
    let log = [
        OsStr::new("git"),
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("-c"),
        OsStr::new(&attrs_file),
        OsStr::new("log"),
        OsStr::new("-p"),
    ];
    let out = exec(&log, &[], Duration::from_secs(30)).unwrap();
    assert!(
        out.stdout.contains("Binary files /dev/null and b/big set.json differ"),
        "{}",
        &out.stdout[..out.stdout.len().min(400)]
    );
    assert!(out.stdout.contains("+fine"));
}
