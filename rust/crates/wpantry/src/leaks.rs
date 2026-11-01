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
    let exe = which("gitleaks").ok_or_else(|| Error::Missing("gitleaks".into()))?;
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
}
