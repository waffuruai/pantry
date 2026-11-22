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
    let (leaks, unchecked, _) = finish(&s.cache, &j, Some(Ok(ran)), false, false).unwrap();
    assert_eq!((leaks.len(), unchecked.total(), leaks[0].confidence.as_str()), (1, 0, "high"));
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
    // A .pantryignore skipping the file for secrets: it isn't read again,
    // and editing the file changes what's cached under.
    testing::write(&repo, ".pantryignore", "[secret]\ncfg.env\nfixtures/\n");
    testing::write(&repo, "fixtures/t.env", format!("token = \"{}\"\n", token()));
    assert!(git(&repo, &home, &["add", "fixtures"]) && git(&repo, &home, &["commit", "-q", "-m", "fixtures"]));
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert!(stale(&j, false, false));
    let ran = run_job(&j, &scanner).unwrap();
    assert!(ran["hits"].as_array().unwrap().is_empty(), "{ran}");
    assert!(ran["new"].as_array().unwrap().is_empty(), "the new fixture isn't read: {ran}");
    assert_eq!(ran["skipped"], 2, "cfg.env and the fixture: {ran}");
    let (_, _, skipped) = finish(&s.cache, &j, Some(Ok(ran)), false, false).unwrap();
    assert_eq!(skipped, 2);
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    assert_eq!(finish(&s.cache, &j, None, false, false).unwrap().2, 2, "kept with the cached run");
    // A rule-only section still reads the file (other rules may hit it).
    testing::write(&repo, ".pantryignore", "fixtures/\n[secret aws-access-token]\ncfg.env\n");
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    let ran = run_job(&j, &scanner).unwrap();
    assert_eq!(ran["hits"].as_array().unwrap().len(), 1, "{ran}");
    // Other rules are another fingerprint: everything is read again.
    let other = Rules::new(Some("// none\n".into()));
    assert_ne!(other.fingerprint, rules.fingerprint);
    let j = job(&s.cache, &repo, &other, 2).unwrap();
    assert!(stale(&j, false, false));
}

#[test]
fn ignoring_a_copy_doesnt_hide_the_original() {
    let d = TempDir::new("secrets-copy").unwrap();
    let (home, repo) = (d.path().join("home"), d.path().join("repo"));
    std::fs::create_dir_all(&home).unwrap();
    let text = format!("token = \"{}\"\n", token());
    // The same blob at two paths; history lists it at the first, fixtures/.
    testing::write(&repo, "fixtures/a.env", &text);
    testing::write(&repo, "src/a.env", &text);
    testing::write(&repo, ".pantryignore", "fixtures/\n");
    for args in [&["init", "-q"][..], &["add", "."], &["commit", "-q", "-m", "add"]] {
        if !git(&repo, &home, args) {
            eprintln!("skipped: no git");
            return;
        }
    }
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options::default());
    let rules = Rules::new(None);
    let j = job(&s.cache, &repo, &rules, 1).unwrap();
    let ran = run_job(&j, &rules.scanner().unwrap()).unwrap();
    let files: Vec<&str> = ran["hits"].as_array().unwrap().iter().map(|h| str_at(h, "file")).collect();
    assert_eq!(files, ["src/a.env"], "{ran}");
    assert_eq!(ran["skipped"], 0, "{ran}");
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
fn the_cores_go_to_the_repos_that_need_scanning() {
    let d = TempDir::new("secrets-threads").unwrap();
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options { jobs: Some(4), ..Default::default() });
    let rules = Rules::new(None);
    let repos: Vec<Repo> = ["a", "b"].iter().map(|n| testing::repo(&d, n)).collect();
    let jobs = secret_jobs(&s, &repos, &rules).unwrap();
    // Two stale repos split the cores.
    let want = (parallel::cores() / 2).max(1);
    assert!(jobs.iter().all(|(j, stale)| *stale && j.as_ref().unwrap().threads == want));
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
        fix(&short(&root.to_string_lossy()), "x.env", &[("aws-access-token", 3, "0123456789ab")], false)
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

#[test]
fn a_partial_clones_missing_files_are_not_checked_and_not_fetched() {
    let d = TempDir::new("secrets-partial").unwrap();
    let Some((repo, home)) = leaky_repo(&d) else {
        eprintln!("skipped: no git");
        return;
    };
    let part = d.path().join("part");
    let cloned = git(&repo, &home, &["config", "uploadpack.allowfilter", "true"])
        && git(
            d.path(),
            &home,
            &["clone", "-q", "--no-local", "--filter=blob:none", "--no-checkout", repo.to_str().unwrap(), "part"],
        );
    if !cloned {
        eprintln!("skipped: this git can't make a partial clone");
        return;
    }
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options::default());
    let rules = Rules::new(None);
    let j = job(&s.cache, &part, &rules, 1).unwrap();
    let ran = run_job(&j, &rules.scanner().unwrap()).unwrap();
    assert!(ran["hits"].as_array().unwrap().is_empty(), "{ran}");
    assert_eq!(ran["unchecked"], 3, "the three files history holds, none fetched");
    let listed = run(&git_argv(&part, &["rev-list", "--objects", "--all", "--missing=print"]), Duration::from_secs(10));
    assert_eq!(listed.lines().filter(|l| l.starts_with('?')).count(), 3, "still missing: {listed}");
}

/// A file over 10 MB is left unread, and said so; `--deep` reads it, and
/// the note names the command that would.
#[test]
fn a_deep_scan_reads_what_a_default_one_is_too_big_for() {
    let d = TempDir::new("secrets-deep").unwrap();
    let home = d.path().join("home");
    let repo = d.path().join("big");
    std::fs::create_dir_all(&home).unwrap();
    let mut dump = "x = 1\n".repeat((MAX_BLOB as usize / 6) + 1);
    dump.push_str(&format!("token = \"{}\"\n", token()));
    testing::write(&repo, "dump.txt", dump);
    for args in [&["init", "-q"][..], &["add", "."], &["commit", "-q", "-m", "dump"]] {
        if !git(&repo, &home, args) {
            eprintln!("skipped: no git");
            return;
        }
    }
    let net = Fake::offline();
    let s = testing::scan(&net, &d, Options::default());
    let rules = Rules::new(None);
    let scanner = rules.scanner().unwrap();
    let j = job(&s.cache, &repo, &rules, 2).unwrap();
    let ran = run_job(&j, &scanner).unwrap();
    assert!(ran["hits"].as_array().unwrap().is_empty());
    assert_eq!(Unread::read(&ran), Unread { too_big: 1, ..Unread::default() });
    let mut j = job(&s.cache, &repo, &rules, 2).unwrap();
    j.deep = true;
    let ran = run_job(&j, &scanner).unwrap();
    assert_eq!(ran["hits"].as_array().unwrap().len(), 1, "{ran}");
    assert_eq!(Unread::read(&ran).total(), 0);
}

#[test]
fn the_unread_note_gives_the_command_that_reads_them() {
    let u = Unread { late: 2, too_big: 1, missing: 3 };
    assert_eq!(
        unread_note(&u, "~/my repo", false),
        "2 not reached in this scan's time, 1 over 10 MB, 3 missing from this partial clone. \
         Scan this repo on its own, with files up to 256 MB and no time limit: `wpantry scan --path ~/'my repo' --no-machine --deep`. \
         Download them with `git -C ~/'my repo' backfill` (git 2.49+), then scan again"
    );
    assert_eq!(unread_note(&Unread { too_big: 1, ..Unread::default() }, "~/r", true), "1 over 256 MB");
    // A result cached before the reasons were kept counts them as late.
    assert_eq!(Unread::read(&json!({"unchecked": 4})), Unread { late: 4, ..Unread::default() });
}

/// A secret's fix is a script: the line to look at, the history rewrite in
/// a mirror clone, and the ignore entry; paths quoted, `~` left to expand,
/// and never the secret itself.
#[test]
fn a_secrets_fix_is_the_commands_to_run() {
    let one = fix("~/my repo", "config/app's.env", &[("aws-access-token", 3, "0123456789ab")], false);
    let want = [
        "# If it's real: rotate it first, then take it out of history.",
        "# This rewrites history: warn everyone with a clone, and re-clone afterwards. Needs git-filter-repo 2.47+.",
        "repo=~/'my repo'",
        "",
        "# 1. Show the line the secret is on",
        r#"git -C "$repo" show '0123456789ab:config/app'"'"'s.env' | sed -n 3p"#,
        "",
        "# 2. Paste the secret: it isn't shown, or kept in your shell history",
        "printf 'Secret: '; stty -echo; read -r SECRET; stty echo; echo",
        r#"printf '%s==>REDACTED\n' "$SECRET" >> ~/.pantry-redact; unset SECRET"#,
        "",
        "# 3. Rewrite history in a fresh mirror clone, push it, and clean up",
        r#"git clone --mirror "$(git -C "$repo" remote get-url origin)" ~/.pantry-rewrite.git"#,
        "git -C ~/.pantry-rewrite.git filter-repo --sensitive-data-removal --replace-text ~/.pantry-redact",
        "git -C ~/.pantry-rewrite.git push --force --mirror origin",
        "rm -rf ~/.pantry-redact ~/.pantry-rewrite.git",
        "",
        "# If it isn't a secret: leave the file out of this rule's findings",
        r#"printf '\n[secret aws-access-token]\n%s\n' '/config/app'"'"'s.env' >> "$repo/.pantryignore""#,
    ];
    assert_eq!(one.lines().collect::<Vec<_>>(), want);
    assert_eq!(fix_target(&one), Some(("~/my repo".to_string(), "config/app's.env".to_string())));
    // The shell reads it: `sh -n` parses without running anything.
    if let Ok(out) = std::process::Command::new("sh").args(["-n", "-c", &one]).output() {
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    // Several hits: one line per commit, at most three.
    let many = fix(
        "~/r",
        "a.txt",
        &[("jwt", 1, "c1"), ("jwt", 9, "c1"), ("jwt", 2, "c2"), ("jwt", 3, "c3"), ("jwt", 4, "c4")],
        true,
    );
    assert!(many.starts_with("# 5 hits in a.txt (generic rules: review). If any is real"), "{many}");
    assert!(many.contains("# 2. Paste each secret: run these two lines once for each"), "{many}");
    assert!(
        many.contains("git -C \"$repo\" show c1:a.txt | sed -n '1p;9p'\n")
            && many.contains("c3:a.txt")
            && !many.contains("c4:a.txt"),
        "{many}"
    );
}

fn leak(rule: &str, file: &str, line: i64, commit: &str, confidence: &str) -> Leak {
    Leak {
        rule: rule.into(),
        file: file.into(),
        line,
        commit: commit.into(),
        fingerprint: format!("{commit}:{file}:{rule}:{line}"),
        description: "Generic".into(),
        confidence: confidence.into(),
        tags: Vec::new(),
    }
}

#[test]
fn one_rule_in_one_file_is_one_finding_whatever_versions_repeat_it() {
    // A config file's password in 8 versions (found newest first: c0 is the
    // newest), at line 4 in the oldest four and line 3 since, and a key beside it.
    let mut found: Vec<Leak> =
        (0..8).map(|v| leak("generic-password", "cfg.yml", 3 + v / 4, &format!("c{v}"), "low")).collect();
    found.insert(2, leak("generic-api-key", "cfg.yml", 9, "c0", "low"));
    found.push(leak("generic-password", "cfg.yml", 4, "c7", "medium"));
    found.push(leak("aws-access-token", "x.env", 1, "c3", "high"));
    let groups = by_file_and_rule(&found);
    let sizes: Vec<(&str, &str, usize)> =
        groups.iter().map(|g| (g[0].file.as_str(), g[0].rule.as_str(), g.len())).collect();
    assert_eq!(
        sizes,
        [("cfg.yml", "generic-password", 9), ("cfg.yml", "generic-api-key", 1), ("x.env", "aws-access-token", 1)]
    );
    let f = finding("app", "~/app", &groups[0]);
    assert_eq!(f.component, "app/cfg.yml");
    assert_eq!(f.status, "warn");
    // The medium hit speaks for the group; the repeated place counts once.
    assert_eq!(f.note, "Generic (review: medium confidence rule); 8 hits in 8 versions of the file");
    // Oldest first, so a newer commit doesn't move the location (or the id).
    assert_eq!(
        f.location,
        "line 4, commit c7; line 4, commit c6; line 4, commit c5; line 4, commit c4; line 3, commit c3"
    );
    assert_eq!(places(&f.location).len(), PLACES);
    assert_eq!(places(&f.location)[4], (3, "c3".to_string()));
    let mut newer = vec![leak("generic-password", "cfg.yml", 3, "n", "low")];
    newer.extend(groups[0].iter().map(|l| (*l).clone()));
    let refs: Vec<&Leak> = newer.iter().collect();
    assert_eq!(finding("app", "~/app", &refs).location, f.location);
    assert!(f.fix_cmd.starts_with("# 8 hits in cfg.yml (generic rules: review)."), "{}", f.fix_cmd);
    // One hit reads as before.
    let aws = finding("app", "~/app", &groups[2]);
    assert_eq!(
        (aws.location.as_str(), aws.status.as_str(), aws.note.as_str()),
        ("line 1, commit c3", "fail", "Generic")
    );
    assert_eq!(places("line 1, commit c3"), [(1, "c3".to_string())]);
    assert!(places("").is_empty());
}

#[test]
fn generic_hits_in_tests_are_one_finding_per_rule_naming_every_place() {
    let found = vec![
        leak("generic-password", "spec/a_spec.rb", 9, "c2", "low"),
        leak("generic-password", "spec/a_spec.rb", 3, "c1", "low"),
        leak("generic-password", "tests/b_test.py", 4, "c1", "medium"),
        leak("generic-api-key", "tests/b_test.py", 5, "c1", "low"),
        leak("github-pat", "tests/b_test.py", 6, "c1", "high"),
        leak("generic-password", "src/db.rb", 2, "c1", "low"),
    ];
    let none = |_: &str, _: &str, _: &str| None;
    let (fs, counts) = findings("~/r", "~/r", &found, false, &none);
    assert!(counts.is_empty());
    let got: Vec<(&str, &str, &str, &str)> = fs
        .iter()
        .map(|(f, _)| (f.component.as_str(), f.location.as_str(), f.vuln_id.as_str(), f.status.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("~/r/tests/b_test.py", "line 6, commit c1", "github-pat", "fail"),
            ("~/r/src/db.rb", "line 2, commit c1", "generic-password", "warn"),
            ("~/r", TESTS, "generic-password", "warn"),
            ("~/r", TESTS, "generic-api-key", "warn"),
        ],
        "a provider's token in a test is its own finding"
    );
    let tests = &fs[2].0;
    assert_eq!(
        tests.note,
        "Generic (in tests; review: medium confidence rule); 3 lines in 2 files: spec/a_spec.rb (lines 3, 9); tests/b_test.py (line 4)"
    );
    for show in ["show c1:spec/a_spec.rb | sed -n 3p", "show c2:spec/a_spec.rb | sed -n 9p", "show c1:tests/b_test.py"]
    {
        assert!(tests.fix_cmd.contains(show), "{show}: {}", tests.fix_cmd);
    }
    assert!(tests.fix_cmd.contains("printf '%s\\n' /spec/a_spec.rb /tests/b_test.py >>"), "{}", tests.fix_cmd);
    // A new hit in a test leaves the finding's id as it was.
    let mut more = found.clone();
    more.insert(0, leak("generic-password", "tests/c_test.py", 1, "c3", "low"));
    let (again, _) = findings("~/r", "~/r", &more, false, &none);
    assert_eq!(again[2].0.id(), tests.id());
    // An ignore file's entry for one test file leaves its hits out.
    let skip = |_: &str, rule: &str, file: &str| {
        (rule == "generic-password" && file == "spec/a_spec.rb").then_some("findings skipped by a repo's .pantryignore")
    };
    let (fs, counts) = findings("~/r", "~/r", &found, false, &skip);
    assert_eq!(counts, [("findings skipped by a repo's .pantryignore", 1)]);
    assert!(fs[2].0.note.ends_with("1 line in 1 file: tests/b_test.py (line 4)"), "{}", fs[2].0.note);
}

#[test]
fn vendored_generic_hits_only_with_deep_and_env_files_fail() {
    let found = vec![
        leak("generic-password", "vendor/rails/base.rb", 3, "c1", "low"),
        leak("github-pat", "vendor/rails/base.rb", 4, "c1", "high"),
        leak("generic-password", "backend/.env", 2, "c1", "low"),
        leak("generic-password", "tests/.env", 2, "c1", "low"),
        leak("generic-password", "backend/.env.example", 2, "c1", "low"),
    ];
    let none = |_: &str, _: &str, _: &str| None;
    let (fs, counts) = findings("~/r", "~/r", &found, false, &none);
    assert_eq!(counts, [(VENDORED, 1)]);
    let got: Vec<(&str, &str)> = fs.iter().map(|(f, _)| (f.component.as_str(), f.status.as_str())).collect();
    assert_eq!(
        got,
        [
            ("~/r/vendor/rails/base.rb", "fail"),
            ("~/r/backend/.env", "fail"),
            ("~/r/tests/.env", "fail"),
            ("~/r/backend/.env.example", "warn"),
        ]
    );
    assert!(fs[1].0.note.ends_with("(in a committed env or credential file)"), "{}", fs[1].0.note);
    assert!(!fs[1].0.fix_cmd.contains("review"), "{}", fs[1].0.fix_cmd);
    let (fs, counts) = findings("~/r", "~/r", &found, true, &none);
    assert!(counts.is_empty());
    assert_eq!(fs.len(), 5, "--deep reports vendored code");
}

#[test]
fn clones_of_one_repo_share_their_findings() {
    let found = vec![leak("generic-password", "src/db.rb", 2, "c1", "low")];
    let forked = vec![
        leak("generic-password", "src/db.rb", 2, "c1", "low"),
        leak("generic-password", "src/db.rb", 2, "c9", "low"),
    ];
    let none = |_: &str, _: &str, _: &str| None;
    let mut made = Vec::new();
    for (name, found) in [("~/a/r", &found), ("~/b/r", &found), ("~/c/r", &forked)] {
        made.extend(findings(name, name, found, false, &none).0.into_iter().map(|(f, k)| (f, k, name.to_string())));
    }
    let fs = merge_clones(made);
    let got: Vec<&str> = fs.iter().map(|f| f.component.as_str()).collect();
    assert_eq!(got, ["~/a/r/src/db.rb", "~/c/r/src/db.rb"], "a fork with another version is its own");
    assert!(fs[0].note.ends_with("; also in 1 other clone: ~/b/r"), "{}", fs[0].note);
    assert!(!fs[1].note.contains("also in"));
}
