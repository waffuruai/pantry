//! Secrets committed to the scanned repos' history, found with gitleaks.
//!
//! Each repo's full history is scanned once per new HEAD (and when gitleaks,
//! the config or the repo's .gitleaksignore changes), then cached. Findings
//! are redacted: the cache and the report hold the rule, file, line, commit
//! and fingerprint, never the secret.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::system::{TempDir, exec, fingerprint, now, run, which};
use serde_json::{Value, json};
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

/// One repo's scan: the binary, the config it uses (the repo's own
/// .gitleaks.toml replaces the default) and the fingerprint its cached
/// result is kept under.
pub struct Job {
    exe: PathBuf,
    repo: PathBuf,
    config: PathBuf,
    key: String,
    fingerprint: String,
}

/// What scanning `repo` takes, without the cache: [`stale`] says whether to
/// [`run_job`] it, [`finish`] reads or stores the result. `Missing` without
/// gitleaks.
pub fn job(repo: &Path, default_config: &Path) -> Result<Job> {
    let exe = which("gitleaks").ok_or_else(|| Error::Missing("gitleaks".into()))?;
    let head = run(
        &[OsStr::new("git"), OsStr::new("-C"), repo.as_os_str(), OsStr::new("rev-parse"), OsStr::new("HEAD")],
        Duration::from_secs(15),
    );
    let own = repo.join(".gitleaks.toml");
    let config = if own.is_file() { own } else { default_config.to_path_buf() };
    let fingerprint = format!(
        "{}:{}:{}",
        head.trim(),
        version(&exe),
        fingerprint(&[config.as_path(), repo.join(".gitleaksignore").as_path()])
    );
    Ok(Job { key: format!("gitleaks:{}", repo.display()), exe, repo: repo.to_path_buf(), config, fingerprint })
}

/// Whether [`finish`] would scan again rather than reuse the cached result
/// (the rule in [`Cache::memo`]).
pub fn stale(cache: &Cache, job: &Job, refresh: bool, offline: bool) -> Result<bool> {
    if offline {
        return Ok(false);
    }
    let cached = cache.run(&job.key)?.filter(|(fp, _, _)| *fp == job.fingerprint);
    Ok(refresh || !cached.is_some_and(|(_, at, _)| at > now() - MAX_AGE))
}

/// gitleaks over the repo's history: the redacted hits, as cached.
pub fn run_job(job: &Job) -> Result<Value> {
    let dir = TempDir::new("gitleaks")?;
    let report = dir.path().join("report.json");
    let mut argv: Vec<&OsStr> = vec![
        job.exe.as_os_str(),
        "git".as_ref(),
        job.repo.as_os_str(),
        "--redact".as_ref(),
        "--no-banner".as_ref(),
        "--log-level".as_ref(),
        "error".as_ref(),
        "--exit-code".as_ref(),
        "0".as_ref(),
        "--report-format".as_ref(),
        "json".as_ref(),
        "--report-path".as_ref(),
        report.as_os_str(),
    ];
    if job.config.is_file() {
        argv.extend([OsStr::new("--config"), job.config.as_os_str()]);
    }
    let out = exec(&argv, &[], Duration::from_secs(1800))?;
    if out.code != Some(0) {
        let tail: String = out.stderr.trim().chars().rev().take(200).collect::<Vec<_>>().into_iter().rev().collect();
        return Err(Error::Failed(format!(
            "gitleaks exited {}: {tail}",
            out.code.map_or("by a signal".into(), |c| c.to_string())
        )));
    }
    let text = std::fs::read(&report).unwrap_or_default();
    let found = if text.iter().all(u8::is_ascii_whitespace) {
        Value::Array(vec![])
    } else {
        json::parse(&text, json::MAX_DOCUMENT)?
    };
    let rows: Vec<Value> = found
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(|f| {
            json!({"rule": str_at(f, "RuleID"), "file": str_at(f, "File"),
                   "line": f.get("StartLine").and_then(Value::as_i64).unwrap_or(0),
                   "commit": str_at(f, "Commit").chars().take(12).collect::<String>(),
                   "fingerprint": str_at(f, "Fingerprint"), "description": str_at(f, "Description")})
        })
        .collect();
    Ok(Value::Array(rows))
}

/// Cached results are reused for a week while the repo's HEAD, gitleaks and
/// the config stay the same.
const MAX_AGE: f64 = 7.0 * 86400.0;

/// The leaks in the job's repo: the cached result while fresh, else `ran`
/// (a [`run_job`] made ahead, beside other repos'), else a scan now.
pub fn finish(cache: &Cache, job: &Job, ran: Option<Result<Value>>, refresh: bool, offline: bool) -> Result<Vec<Leak>> {
    let res =
        cache.memo(&job.key, || ran.unwrap_or_else(|| run_job(job)), MAX_AGE, &job.fingerprint, refresh, offline)?;
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
