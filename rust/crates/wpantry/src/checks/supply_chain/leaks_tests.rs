use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;
use crate::utils::process::exec;
use crate::utils::temp::TempDir;

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

/// A GitHub token, built here so this file holds none.
fn token() -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let tail: String = (0..36).map(|i| ALNUM[(i * 7 + 3) % ALNUM.len()] as char).collect();
    format!("{}{}_{tail}", "gh", "p")
}

fn git(repo: &Path, home: &Path, args: &[&str]) -> bool {
    let mut full: Vec<&OsStr> = vec![OsStr::new("git"), OsStr::new("-C"), repo.as_os_str()];
    full.extend(
        ["-c", "user.name=w", "-c", "user.email=w@example.invalid", "-c", "commit.gpgsign=false"].map(OsStr::new),
    );
    full.extend(args.iter().map(OsStr::new));
    let env = [("HOME", home.to_str().unwrap()), ("GIT_CONFIG_NOSYSTEM", "1")];
    exec(&full, &env, Duration::from_secs(30)).is_ok_and(|o| o.code == Some(0))
}

/// A repo whose history added a token in `cfg.env` (line 2) and then
/// deleted it, and a lockfile and an image holding one, which aren't read.
fn leaky_repo(d: &TempDir) -> Option<(PathBuf, PathBuf)> {
    let (home, repo) = (d.path().join("home"), d.path().join("repo"));
    std::fs::create_dir_all(&home).ok()?;
    std::fs::create_dir_all(&repo).ok()?;
    let t = token();
    testing::write(&repo, "cfg.env", format!("# settings\ntoken = \"{t}\"\n"));
    testing::write(&repo, "package-lock.json", format!("{{\"token\": \"{t}\"}}\n"));
    testing::write(&repo, "logo.bin", [b"\x00\x01".as_slice(), format!("token = \"{t}\"").as_bytes()].concat());
    for args in [
        &["init", "-q"][..],
        &["add", "."],
        &["commit", "-q", "-m", "add"],
        &["rm", "-q", "cfg.env"],
        &["commit", "-q", "-m", "rm"],
    ] {
        if !git(&repo, &home, args) {
            return None;
        }
    }
    Some((repo, home))
}

#[test]
fn history_is_scanned_by_blob_and_cached_until_the_refs_move() {
    let d = TempDir::new("secrets-history").unwrap();
    let Some((repo, home)) = leaky_repo(&d) else {
        eprintln!("skipped: no git");
        return;
    };
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options::default());
    let rules = Rules::new(None);
    let scanner = rules.scanner().unwrap();
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert!(stale(&j, false, false), "nothing cached");
    assert!(!stale(&j, false, true), "never offline");
    let ran = run_job(&j, &scanner).unwrap();
    let hits = ran["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}: the lockfile and the binary aren't read");
    let hit = &hits[0];
    assert_eq!((str_at(hit, "rule"), str_at(hit, "file"), hit["line"].as_i64()), ("github-pat", "cfg.env", Some(2)));
    // The commit is the one that added the file, though it's deleted since.
    let added = run(&git_argv(&repo, &["rev-list", "--max-count=1", "HEAD~1"]), Duration::from_secs(10));
    assert_eq!(str_at(hit, "commit"), &added.trim()[..12]);
    assert_eq!(str_at(hit, "fingerprint"), format!("{}:cfg.env:github-pat:2", added.trim()));
    assert_eq!(ran["unchecked"], 0);
    let scanned = ran["new"].as_array().unwrap().len();
    let (leaks, unchecked) = finish(&s.cache, &j, Some(Ok(ran)), false, false).unwrap();
    assert_eq!((leaks.len(), unchecked, leaks[0].confidence.as_str()), (1, 0, "high"));
    // Cached: the next job isn't stale, and finish reads it without a run.
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert!(!stale(&j, false, false));
    assert_eq!(finish(&s.cache, &j, None, false, false).unwrap().0, leaks);
    // A new commit moves the refs: only its new file is read.
    testing::write(&repo, "notes.md", "nothing here\n");
    assert!(git(&repo, &home, &["add", "."]) && git(&repo, &home, &["commit", "-q", "-m", "notes"]));
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert!(stale(&j, false, false));
    let ran = run_job(&j, &scanner).unwrap();
    assert_eq!(ran["new"].as_array().unwrap().len(), 1, "of {} blobs before, none read again", scanned);
    assert_eq!(ran["hits"].as_array().unwrap().len(), 1, "the old hit stands");
    finish(&s.cache, &j, Some(Ok(ran)), false, false).unwrap();
    // Listing its fingerprint in .gitleaksignore drops it, and changes what's cached under.
    testing::write(&repo, ".gitleaksignore", format!("{}:cfg.env:github-pat:2\n", added.trim()));
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert!(stale(&j, false, false));
    let ran = run_job(&j, &scanner).unwrap();
    assert!(ran["hits"].as_array().unwrap().is_empty());
    // Other rules are another fingerprint: everything is read again.
    let other = Rules::new(Some("// none\n".into()));
    assert_ne!(other.fingerprint, rules.fingerprint);
    let j = job(&s.cache, &repo, &other, 2).unwrap();
    assert!(stale(&j, false, false));
}

#[test]
fn a_repo_that_cant_be_listed_is_an_error() {
    let d = TempDir::new("secrets-notgit").unwrap();
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options::default());
    let rules = Rules::new(None);
    let (_, root) = testing::repo(&d, "app");
    let j = job(&s.cache, &root, &rules, 1).unwrap();
    assert!(run_job(&j, &rules.scanner().unwrap()).is_err());
}

#[test]
fn scans_run_at_once_from_the_jobs_flag_or_the_cores() {
    let d = TempDir::new("jobs").unwrap();
    let net = Fake::offline();
    assert_eq!(scans_at_once(&testing::scan(&net, &d, Options { jobs: Some(7), ..Default::default() })), 7);
    let n = scans_at_once(&testing::scan(&net, &d, Options::default()));
    assert!((1..=4).contains(&n), "{n}");
}

/// A finding per redacted hit: a high-confidence rule fails, the others
/// warn; a repo's own gitleaks config is reported as not used.
#[test]
fn secrets_from_a_scan_run_ahead() {
    let d = TempDir::new("secrets").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, ".gitleaks.toml", "[allowlist]\n");
    let rules = Rules::new(None);
    let jobs = secret_jobs(&s, &[(name.clone(), root.clone())], &rules).unwrap();
    assert!(jobs[0].1, "nothing cached: stale");
    let ran = json!({"tips": [], "unchecked": 3, "new": [], "hits": [
        {"rule": "aws-access-token", "file": "x.env", "line": 3, "commit": "0123456789ab", "fingerprint": "fp1",
         "description": "AWS", "confidence": "high", "tags": []},
        {"rule": "generic-api-key", "file": "cfg.py", "line": 9, "commit": "abcdef012345", "fingerprint": "fp2",
         "description": "Generic", "confidence": "low", "tags": ["decoded:base64", "decode-depth:1"]}]});
    secrets(&mut s, &[(name.clone(), root.clone())], jobs, vec![Some(Ok(ran))]).unwrap();
    assert!(s.counts.contains(&("repos scanned for secrets".to_string(), 1)), "{:?}", s.counts);
    let policy = testing::by_id(&s, "REPO-POLICY");
    assert_eq!((policy[0].component.as_str(), policy[0].status.as_str()), ("app/.gitleaks.toml", "warn"));
    let aws = testing::by_id(&s, "aws-access-token");
    assert_eq!(
        (aws[0].component.as_str(), aws[0].location.as_str(), aws[0].status.as_str(), aws[0].note.as_str()),
        ("app/x.env", "line 3, commit 0123456789ab", "fail", "AWS")
    );
    assert_eq!(
        aws[0].fix_cmd,
        format!(
            "If it's real: rotate it, then purge it from history. If not: add fp1 to {}/.gitleaksignore",
            short(&root.to_string_lossy())
        )
    );
    let generic = testing::by_id(&s, "generic-api-key");
    assert_eq!(
        (generic[0].status.as_str(), generic[0].note.as_str()),
        ("warn", "Generic (base64-encoded) (review: low confidence rule)")
    );
    assert_eq!(testing::unchecked(&s), ["secrets in 3 files of app's history"]);
    // Left for later: still stale though the refs haven't moved.
    let jobs = secret_jobs(&s, &[(name.clone(), root.clone())], &rules).unwrap();
    assert!(jobs[0].1);
    // A run that failed as a source: that repo is unchecked, the rest go on.
    let (other, oroot) = testing::repo(&d, "other");
    let repos = [(name.clone(), root.clone()), (other, oroot)];
    let jobs = secret_jobs(&s, &repos, &rules).unwrap();
    let ok = json!({"tips": [], "unchecked": 0, "new": [], "hits": []});
    secrets(&mut s, &repos, jobs, vec![Some(Ok(ok)), Some(Err(Error::Offline("killed".into())))]).unwrap();
    assert!(testing::unchecked(&s).contains(&"secrets in other's history"), "{:?}", testing::unchecked(&s));
    // An internal error passes through.
    let jobs = secret_jobs(&s, &repos, &rules).unwrap();
    let io = Error::Io(std::io::Error::other("disk"));
    let ok = json!({"tips": [], "unchecked": 0, "new": [], "hits": []});
    assert!(matches!(secrets(&mut s, &repos, jobs, vec![Some(Ok(ok)), Some(Err(io))]), Err(Error::Io(_))));
    assert!(secret_jobs(&s, &[], &rules).unwrap().is_empty());
}
