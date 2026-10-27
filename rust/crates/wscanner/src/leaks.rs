//! Secrets committed to the scanned repos' history, found with gitleaks.
//!
//! Each repo's full history is scanned once per new HEAD (and when gitleaks,
//! the config or the repo's .gitleaksignore changes), then cached. Findings
//! are redacted: the cache and the report hold the rule, file, line, commit
//! and fingerprint, never the secret.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::system::{TempDir, exec, fingerprint, run, which};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::Path;
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

/// The leaks in one repo's history. The repo's own .gitleaks.toml replaces
/// `default_config`.
pub fn scan(cache: &Cache, repo: &Path, default_config: &Path, refresh: bool, offline: bool) -> Result<Vec<Leak>> {
    let exe = which("gitleaks").ok_or_else(|| Error::Missing("gitleaks".into()))?;
    let head = run(
        &[OsStr::new("git"), OsStr::new("-C"), repo.as_os_str(), OsStr::new("rev-parse"), OsStr::new("HEAD")],
        Duration::from_secs(15),
    );
    let own = repo.join(".gitleaks.toml");
    let config = if own.is_file() { own } else { default_config.to_path_buf() };
    let fp = format!(
        "{}:{}:{}",
        head.trim(),
        run(&[exe.as_os_str(), OsStr::new("version")], Duration::from_secs(15)).trim(),
        fingerprint(&[config.as_path(), repo.join(".gitleaksignore").as_path()])
    );
    let gitleaks = || -> Result<Value> {
        let dir = TempDir::new("gitleaks")?;
        let report = dir.path().join("report.json");
        let mut argv: Vec<&OsStr> = vec![
            exe.as_os_str(),
            "git".as_ref(),
            repo.as_os_str(),
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
        if config.is_file() {
            argv.extend([OsStr::new("--config"), config.as_os_str()]);
        }
        let out = exec(&argv, &[], Duration::from_secs(1800))?;
        if out.code != Some(0) {
            let tail: String =
                out.stderr.trim().chars().rev().take(200).collect::<Vec<_>>().into_iter().rev().collect();
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
    };
    let key = format!("gitleaks:{}", repo.display());
    let res = cache.memo(&key, gitleaks, 7.0 * 86400.0, &fp, refresh, offline)?;
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
