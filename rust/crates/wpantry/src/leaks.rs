//! Secrets committed to the scanned repos' history, found with gitleaks.
//!
//! Each repo's history is scanned once in full, then only the commits its
//! refs gained since (`--log-opts "… ^old-tip"`), and the hits are kept in
//! the cache: the first scan of a big repo costs minutes, every later one
//! costs the new commits. A full scan happens again when gitleaks, the
//! policy or the repo's .gitleaksignore changes, or when a remembered tip
//! is gone (history rewritten). Findings are redacted: the cache and the
//! report hold the rule, file, line, commit and fingerprint, never the
//! secret.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::system::{TempDir, exec, fingerprint, run, which};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// Rules too broad to fail on their own: their hits are reviewed, not trusted.
pub const GENERIC: &[&str] =
    &["generic-api-key", "generic-secret", "hashicorp-tf-password", "curl-auth-header", "curl-auth-user"];

/// One redacted gitleaks hit.
#[derive(Clone, Debug, PartialEq)]
pub struct Leak {
    pub rule: String,
    pub file: String,
    pub line: i64,
    pub commit: String,
    pub fingerprint: String,
    pub description: String,
}

/// `gitleaks version`, asked once per binary: a scan of many repos would
/// otherwise start gitleaks once per repo just to read its version.
fn version(exe: &Path) -> String {
    static SEEN: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());
    let mut seen = SEEN.lock().expect("lock");
    if let Some((_, v)) = seen.iter().find(|(e, _)| e == exe) {
        return v.clone();
    }
    let v = run(&[exe.as_os_str(), OsStr::new("version")], Duration::from_secs(15)).trim().to_string();
    seen.push((exe.to_path_buf(), v.clone()));
    v
}

/// One repo's scan: the binary, the policy it uses (always the caller's: a
/// repo's own .gitleaks.toml could allow everything, so it is reported,
/// not obeyed), the fingerprint its cached result is kept under, and the
/// tips of the repo's refs now.
pub struct Job {
    exe: PathBuf,
    repo: PathBuf,
    config: PathBuf,
    key: String,
    fingerprint: String,
    tips: BTreeSet<String>,
    /// What the cache remembers, when the fingerprint still matches:
    /// the tips it was scanned at, and the hits.
    cached: Option<(BTreeSet<String>, Vec<Value>)>,
    /// The repo carries its own `.gitleaks.toml`, which this scan ignores.
    pub own_policy: bool,
    /// Processes per gitleaks run (GOMAXPROCS), so parallel scans share
    /// the machine instead of each taking every core.
    threads: usize,
}

impl Job {
    /// The commits a scan this run must cover: everything (None), or only
    /// what the refs gained since the remembered tips.
    fn since(&self) -> Option<&BTreeSet<String>> {
        let (tips, _) = self.cached.as_ref()?;
        (!tips.is_empty() && tips.len() <= MAX_TIPS).then_some(tips)
    }
}

/// More remembered tips than this and the exclusion list isn't worth
/// passing: scan in full.
const MAX_TIPS: usize = 200;

/// What scanning `repo` takes, without running gitleaks: [`stale`] says
/// whether to [`run_job`] it, [`finish`] reads or stores the result.
/// `Missing` without gitleaks. `threads` is what each run may use.
pub fn job(cache: &Cache, repo: &Path, default_config: &Path, threads: usize) -> Result<Job> {
    job_with(cache, repo, default_config, threads, which("gitleaks"))
}

/// As [`job`], with the gitleaks binary given (None: not installed).
pub fn job_with(
    cache: &Cache,
    repo: &Path,
    default_config: &Path,
    threads: usize,
    exe: Option<PathBuf>,
) -> Result<Job> {
    let exe = exe.ok_or_else(|| Error::Missing("gitleaks".into()))?;
    let own_policy = repo.join(".gitleaks.toml").is_file();
    let config = default_config.to_path_buf();
    let fingerprint =
        format!("v2:{}:{}", version(&exe), fingerprint(&[config.as_path(), repo.join(".gitleaksignore").as_path()]));
    let key = format!("gitleaks:{}", repo.display());
    let tips = tips(repo);
    let cached = cache.run(&key)?.filter(|(fp, _, _)| *fp == fingerprint).and_then(|(_, _, res)| {
        let tips: BTreeSet<String> = json::strs_at(&res, "tips").into_iter().collect();
        let hits = res.get("hits")?.as_array()?.clone();
        Some((tips, hits))
    });
    Ok(Job { key, exe, repo: repo.to_path_buf(), config, fingerprint, tips, cached, own_policy, threads })
}

/// The commits the repo's refs point at: HEAD and every ref, read from
/// .git without a process (worktrees and packed refs included); `git
/// for-each-ref` when the layout is unfamiliar.
pub fn tips(repo: &Path) -> BTreeSet<String> {
    fn is_sha(s: &str) -> bool {
        (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
    }
    fn read(p: &Path) -> String {
        crate::system::read_capped(p, 1 << 20).unwrap_or_default()
    }
    fn walk(dir: &Path, out: &mut BTreeSet<String>, depth: usize) {
        if depth > 8 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out, depth + 1);
            } else {
                let v = read(&p);
                let v = v.trim();
                if is_sha(v) {
                    out.insert(v.to_string());
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    let dot = repo.join(".git");
    // A worktree's .git is a file naming its gitdir; its refs live in the
    // common dir.
    let gitdir = if dot.is_file() {
        read(&dot).trim().strip_prefix("gitdir: ").map(|d| repo.join(d)).unwrap_or(dot.clone())
    } else {
        dot
    };
    let common = {
        let c = read(&gitdir.join("commondir"));
        let c = c.trim();
        if c.is_empty() { gitdir.clone() } else { gitdir.join(c) }
    };
    let head = read(&gitdir.join("HEAD"));
    let head = head.trim();
    if is_sha(head) {
        out.insert(head.to_string());
    }
    for line in read(&common.join("packed-refs")).lines() {
        if let Some((sha, _)) = line.split_once(' ')
            && is_sha(sha)
        {
            out.insert(sha.to_string());
        }
    }
    walk(&common.join("refs"), &mut out, 0);
    if out.is_empty() {
        let listed = run(
            &[
                OsStr::new("git"),
                OsStr::new("-C"),
                repo.as_os_str(),
                OsStr::new("for-each-ref"),
                OsStr::new("--format=%(objectname)"),
            ],
            Duration::from_secs(15),
        );
        out.extend(listed.lines().map(str::trim).filter(|l| is_sha(l)).map(str::to_string));
        let head = run(
            &[OsStr::new("git"), OsStr::new("-C"), repo.as_os_str(), OsStr::new("rev-parse"), OsStr::new("HEAD")],
            Duration::from_secs(15),
        );
        if is_sha(head.trim()) {
            out.insert(head.trim().to_string());
        }
    }
    out
}

/// Whether [`finish`] would run gitleaks rather than reuse the cached
/// result: nothing cached under this policy and gitleaks, or the refs
/// moved, or `refresh`; never when offline.
pub fn stale(job: &Job, refresh: bool, offline: bool) -> bool {
    if offline {
        return false;
    }
    refresh || job.cached.as_ref().is_none_or(|(tips, _)| *tips != job.tips)
}

/// gitleaks over the repo's history (all of it, or what the refs gained
/// since the remembered tips): the redacted hits, as cached.
pub fn run_job(job: &Job) -> Result<Value> {
    let dir = TempDir::new("gitleaks")?;
    let report = dir.path().join("report.json");
    let nice = which("nice");
    let mut argv: Vec<&OsStr> = Vec::new();
    if let Some(n) = &nice {
        argv.extend([n.as_os_str(), OsStr::new("-n"), OsStr::new("10")]);
    }
    argv.extend([
        job.exe.as_os_str(),
        "git".as_ref(),
        job.repo.as_os_str(),
        "--redact".as_ref(),
        "--no-banner".as_ref(),
        "--log-level".as_ref(),
        "error".as_ref(),
        "--exit-code".as_ref(),
        "0".as_ref(),
        "--max-target-megabytes".as_ref(),
        "10".as_ref(),
        "--report-format".as_ref(),
        "json".as_ref(),
        "--report-path".as_ref(),
        report.as_os_str(),
    ]);
    if job.config.is_file() {
        argv.extend([OsStr::new("--config"), job.config.as_os_str()]);
    }
    // gitleaks' own history options are dropped when --log-opts is given,
    // so they are repeated here, with the remembered tips excluded; a tip
    // that no longer exists means rewritten history: scan everything.
    let since = job.since().filter(|tips| tips_exist(&job.repo, tips));
    let log_opts = since.map(|tips| {
        let mut s = String::from("--full-history --all --diff-filter=tuxdb");
        for t in tips {
            s.push_str(" ^");
            s.push_str(t);
        }
        s
    });
    if let Some(opts) = &log_opts {
        argv.extend([OsStr::new("--log-opts"), OsStr::new(opts)]);
    }
    let threads = job.threads.max(1).to_string();
    let out = exec(&argv, &[("GOMAXPROCS", threads.as_str())], Duration::from_secs(1800))?;
    if out.code != Some(0) {
        let tail: String = out.stderr.trim().chars().rev().take(200).collect::<Vec<_>>().into_iter().rev().collect();
        return Err(Error::Failed(format!(
            "gitleaks exited {}: {tail}",
            out.code.map_or("by a signal".into(), |c| c.to_string())
        )));
    }
    let mut rows = report_rows(&report)?;
    if since.is_some()
        && let Some((_, old)) = &job.cached
    {
        // The earlier hits still stand, minus any since listed in .gitleaksignore.
        let ignored = ignored(&job.repo);
        let seen: BTreeSet<String> = rows.iter().map(|r| str_at(r, "fingerprint").to_string()).collect();
        for hit in old {
            let fp = str_at(hit, "fingerprint");
            if !seen.contains(fp) && !ignored.contains(fp) {
                rows.push(hit.clone());
            }
        }
    }
    Ok(json!({"tips": job.tips.iter().collect::<Vec<_>>(), "hits": rows}))
}

/// The redacted hits in the report gitleaks wrote: a list of findings, `[]`
/// when it found none (gitleaks 8 always writes the file). No file, an
/// empty one, or any other shape is a run that didn't finish, never a clean
/// one, so nothing of it is cached.
fn report_rows(report: &Path) -> Result<Vec<Value>> {
    let text = std::fs::read(report).map_err(|e| Error::Failed(format!("gitleaks wrote no report: {e}")))?;
    let found = json::parse(&text, json::MAX_DOCUMENT).map_err(|e| Error::Failed(format!("gitleaks report: {e}")))?;
    let Value::Array(found) = found else {
        return Err(Error::Failed("gitleaks report isn't a list of findings".into()));
    };
    found
        .iter()
        .map(|f| {
            let rule = f.get("RuleID").and_then(Value::as_str).filter(|s| !s.is_empty());
            let fp = f.get("Fingerprint").and_then(Value::as_str).filter(|s| !s.is_empty());
            let (Some(rule), Some(fp)) = (rule, fp) else {
                return Err(Error::Failed("gitleaks report has a finding without RuleID and Fingerprint".into()));
            };
            Ok(json!({"rule": rule, "file": str_at(f, "File"),
                      "line": f.get("StartLine").and_then(Value::as_i64).unwrap_or(0),
                      "commit": str_at(f, "Commit").chars().take(12).collect::<String>(),
                      "fingerprint": fp, "description": str_at(f, "Description")}))
        })
        .collect()
}

/// Whether every commit is still in the repo (one git call for all of them).
fn tips_exist(repo: &Path, tips: &BTreeSet<String>) -> bool {
    let mut argv: Vec<&OsStr> = vec![
        OsStr::new("git"),
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("rev-list"),
        OsStr::new("--no-walk=unsorted"),
        OsStr::new("--max-count=1"),
    ];
    argv.extend(tips.iter().map(|t| OsStr::new(t.as_str())));
    argv.push(OsStr::new("--"));
    exec(&argv, &[], Duration::from_secs(60)).is_ok_and(|o| o.code == Some(0))
}

/// The fingerprints the repo's .gitleaksignore lists.
fn ignored(repo: &Path) -> BTreeSet<String> {
    crate::system::read_capped(&repo.join(".gitleaksignore"), 1 << 20)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// The leaks in the job's repo: the cached result while the refs haven't
/// moved, else `ran` (a [`run_job`] made ahead, beside other repos'), else
/// a scan now. The result is stored under the job's fingerprint.
pub fn finish(cache: &Cache, job: &Job, ran: Option<Result<Value>>, refresh: bool, offline: bool) -> Result<Vec<Leak>> {
    let res = if !stale(job, refresh, offline) {
        match &job.cached {
            Some((_, hits)) => Value::Array(hits.clone()),
            None => return Err(Error::Offline(format!("{}: offline and not cached", job.key))),
        }
    } else {
        match ran.unwrap_or_else(|| run_job(job)) {
            Ok(res) => {
                cache.put_run(&job.key, &job.fingerprint, &res)?;
                cache.commit()?;
                res.get("hits").cloned().unwrap_or(Value::Array(vec![]))
            }
            Err(e @ (Error::Offline(_) | Error::Invalid(_))) => match &job.cached {
                Some((_, hits)) => Value::Array(hits.clone()),
                None => return Err(Error::Offline(format!("{}: {e}", job.key))),
            },
            Err(e) => return Err(e),
        }
    };
    Ok(res
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(|f| Leak {
            rule: str_at(f, "rule").into(),
            file: str_at(f, "file").into(),
            line: f.get("line").and_then(Value::as_i64).unwrap_or(0),
            commit: str_at(f, "commit").into(),
            fingerprint: str_at(f, "fingerprint").into(),
            description: str_at(f, "description").into(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        std::fs::write(
            git.join("packed-refs"),
            format!("# pack-refs with: peeled\n{c} refs/remotes/origin/dev\n^{a}\n"),
        )
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
        assert_eq!(
            (found[0].rule.as_str(), found[0].fingerprint.as_str(), found[0].line),
            ("aws-access-token", "fp1", 3)
        );
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
        assert!(matches!(
            finish(&c, &job, Some(Err(Error::Offline("x".into()))), false, false),
            Err(Error::Offline(_))
        ));
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
}
