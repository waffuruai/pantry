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

use crate::checks::Scan;
use crate::checks::supply_chain::GITLEAKS_INSTALL;
use crate::checks::supply_chain::repos::Repo;
use crate::db::Cache;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::utils::files::fingerprint;
use crate::utils::files::short;
use crate::utils::json::{self, str_at};
use crate::utils::parallel;
use crate::utils::process::exec;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::temp::TempDir;
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
        crate::utils::files::read_capped(p, 1 << 20).unwrap_or_default()
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
    crate::utils::files::read_capped(&repo.join(".gitleaksignore"), 1 << 20)
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

/// gitleaks scans run at once on a first run (`--jobs`): each is CPU-bound,
/// so together they get the machine's cores, not each of them all of them.
pub(crate) fn gitleaks_at_once(scan: &Scan) -> usize {
    scan.opts.jobs.unwrap_or_else(|| (parallel::cores() / 2).clamp(1, 4))
}

/// Each repo's gitleaks job (with the `gitleaks` binary; None: not
/// installed), its fingerprint and ref tips read at once, and whether its
/// cached result is stale.
pub(crate) fn secret_jobs(scan: &Scan, repos: &[Repo], gitleaks: Option<PathBuf>) -> Result<Vec<(Result<Job>, bool)>> {
    if repos.is_empty() {
        return Ok(Vec::new());
    }
    let config = scan.opts.policy.gitleaks_config(&scan.cache)?;
    let threads = (parallel::cores() / gitleaks_at_once(scan)).max(1);
    repos
        .iter()
        .map(|(_, root)| {
            let job = job_with(&scan.cache, root, &config, threads, gitleaks.clone());
            let stale = match &job {
                Ok(j) => stale(j, scan.opts.refresh, scan.opts.offline),
                Err(_) => false,
            };
            Ok((job, stale))
        })
        .collect()
}

/// Secrets committed anywhere in the repos' history, from the jobs
/// [`secret_jobs`] made and the scans run ahead (`ran`), in the repos'
/// order. A provider-specific rule (AWS, GitHub, OpenAI, …) fails; a generic
/// one asks for review.
pub(crate) fn secrets(
    scan: &mut Scan,
    repos: &[Repo],
    jobs: Vec<(Result<Job>, bool)>,
    ran: Vec<Option<Result<Value>>>,
) -> Result<()> {
    let (refresh, offline) = (scan.opts.refresh, scan.opts.offline);
    for (((name, root), (job, _)), ran) in repos.iter().zip(jobs).zip(ran) {
        scan.status(&format!("Scanning {name}'s git history for secrets (gitleaks)"));
        if job.as_ref().is_ok_and(|j| j.own_policy) {
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/.gitleaks.toml"),
                vuln_id: "REPO-POLICY".into(),
                status: "warn".into(),
                note: "the repo's own gitleaks config was ignored; the scan used your policy".into(),
                fix_cmd: "Review the repo's .gitleaks.toml; pass it with --gitleaks-config to scan with it".into(),
                ..Default::default()
            });
        }
        let found = match job.and_then(|job| finish(&scan.cache, &job, ran, refresh, offline)) {
            Ok(f) => f,
            Err(Error::Missing(_)) => {
                let has_brew = which("brew").is_some();
                scan.add(Finding {
                    kind: "tool".into(),
                    component: "gitleaks".into(),
                    vuln_id: "MISSING".into(),
                    status: "fail".into(),
                    note: "secrets in the repos' history can't be checked".into(),
                    fix_auto: has_brew,
                    fix_cmd: if has_brew {
                        "brew install gitleaks".into()
                    } else {
                        format!("Install gitleaks: {GITLEAKS_INSTALL}")
                    },
                    ..Default::default()
                });
                return Ok(());
            }
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("secrets in {name}'s history (gitleaks)"), &e.to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        scan.count("repos scanned for secrets", 1);
        for f in found {
            let generic = GENERIC.contains(&f.rule.as_str());
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/{}", f.file),
                location: format!("line {}, commit {}", f.line, f.commit),
                vuln_id: f.rule.clone(),
                status: if generic { "warn" } else { "fail" }.into(),
                note: format!("{}{}", f.description, if generic { " (review: generic rule)" } else { "" }),
                fix_cmd: format!(
                    "If it's real: rotate it, then purge it from history. If not: add {} to {}/.gitleaksignore",
                    f.fingerprint,
                    short(&root.to_string_lossy())
                ),
                ..Default::default()
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "leaks_tests.rs"]
mod tests;
