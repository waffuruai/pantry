//! `--deep`'s secret scan of files: every file in scope, not only git
//! history, so a key in an uncommitted `.env`, in `~/.aws` or under `/opt`
//! is found. One step of the files pass ([`crate::checks::files::pass`]):
//! each file is read once with the other checks, and its result is kept
//! while it's unchanged, so a second deep scan reads only what changed.
//!
//! Paths betterleaks' prefilter skips aren't read, nor files over
//! [`MAX_FILE`] (counted as not checked); the scanner skips binary content.
//! A secret is redacted as in history: the rule, file and line, never the
//! secret.

use super::Scanner;
use crate::checks::Scan;
use crate::checks::files::{Contents, Read, Stats, When};
use crate::finding::Finding;
use crate::utils::files::short;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The largest file read; a bigger one is counted as not checked.
pub const MAX_FILE: u64 = crate::checks::supply_chain::leaks::MAX_BLOB;

/// The scanner a pass's secret step uses, and what its results are kept
/// under (the rules' fingerprint).
pub struct Engine {
    pub scanner: Scanner,
    pub fingerprint: String,
}

/// One secret found in a file.
#[derive(Clone, Debug, PartialEq)]
pub struct Secret {
    pub rule: String,
    pub description: String,
    pub line: usize,
    /// `high`, `medium` or `low`: a high-confidence rule fails.
    pub confidence: String,
    /// The encoding it was found under (`base64`), when it was decoded.
    pub decoded: Option<String>,
}

/// The files of a root the step reads, and how many it leaves out as too big.
#[derive(Debug, Default)]
pub struct Plan {
    pub reads: Vec<Read>,
    pub too_big: Vec<PathBuf>,
}

pub fn plan(engine: Option<&Engine>, root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    let mut p = Plan::default();
    let Some(engine) = engine else { return p };
    for (dir, files) in walk {
        for f in files {
            let path = dir.join(f);
            let Some(s) = stat(&path).filter(|s| s.file && !s.link) else { continue };
            if engine.scanner.skips_path(&path.to_string_lossy()) {
                continue;
            }
            if s.size > MAX_FILE {
                p.too_big.push(path);
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            p.reads.push(Read { path, rel, cap: MAX_FILE, role: 0, when: When::Always });
        }
    }
    p
}

/// The secrets in one file; none without an engine or its contents.
pub fn file(engine: Option<&Engine>, read: &Read, c: &Contents) -> Vec<Secret> {
    let (Some(engine), Some(bytes)) = (engine, c.bytes) else { return Vec::new() };
    engine
        .scanner
        .scan(bytes, &read.path.to_string_lossy(), None)
        .into_iter()
        .map(|f| Secret {
            rule: f.rule,
            description: f.description,
            line: f.start_line,
            confidence: crate::checks::supply_chain::leaks::confidence(f.confidence).into(),
            decoded: f.tags.iter().find_map(|t| t.strip_prefix("decoded:")).map(String::from),
        })
        .collect()
}

/// A root's files with secrets in them, how many it read, and the files
/// it left out as too big.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Found {
    pub files: Vec<(PathBuf, Vec<Secret>)>,
    pub read: usize,
    pub too_big: Vec<PathBuf>,
}

pub fn finish(plan: &Plan, outs: &[Option<&Vec<Secret>>]) -> Found {
    let files = plan
        .reads
        .iter()
        .zip(outs)
        .filter_map(|(r, o)| o.filter(|s| !s.is_empty()).map(|s| (r.path.clone(), s.clone())))
        .collect();
    Found { files, read: plan.reads.len(), too_big: plan.too_big.clone() }
}

/// How many unreadable folders a not-checked note names; the rest are counted.
const NAMED: usize = 8;

/// The deep scan's findings: each secret in a file that the history scan
/// didn't already report, the files too big to read, and, by root, the
/// folders this user can't read.
pub fn report(scan: &mut Scan) {
    let jobs = scan.secret_file_jobs();
    let deep_roots: Vec<PathBuf> = if scan.opts.machine && scan.opts.personal_files() && !scan.opts.scoped() {
        crate::checks::files::roots::deep(&scan.home).into_iter().map(|r| r.path).collect()
    } else {
        Vec::new()
    };
    let results = scan.read_files();
    let found: Vec<(PathBuf, Found)> = jobs.iter().map(|j| (j.root.clone(), results.secrets(j))).collect();
    let mut roots: Vec<PathBuf> = found.iter().map(|(r, _)| r.clone()).collect();
    for r in deep_roots {
        if !roots.contains(&r) {
            roots.push(r);
        }
    }
    // Every deep root, the malware scan's too: a folder neither could list.
    let unreadable: Vec<(PathBuf, Vec<PathBuf>)> =
        roots.into_iter().map(|r| (r.clone(), results.unreadable(&r))).filter(|(_, d)| !d.is_empty()).collect();
    let mut seen: HashSet<(PathBuf, String, usize)> = HashSet::new();
    let (mut read, mut too_big) = (0, 0);
    let mut findings = Vec::new();
    for (_, f) in &found {
        read += f.read;
        too_big += f.too_big.len();
        for (path, secrets) in &f.files {
            for s in secrets {
                let key = (path.clone(), s.rule.clone(), s.line);
                if scan.history_secrets.contains(&key) || !seen.insert(key) {
                    continue;
                }
                findings.push(finding(path, s));
            }
        }
    }
    for f in findings {
        scan.add(f);
    }
    scan.count("files scanned for secrets", read as i64);
    if too_big > 0 {
        scan.unchecked(
            &format!("secrets in {too_big} files over {} MB", MAX_FILE >> 20),
            "bigger than the secret scan reads",
        );
    }
    for (root, dirs) in unreadable {
        let mut named: Vec<String> = dirs.iter().take(NAMED).map(|d| short(&d.to_string_lossy())).collect();
        if dirs.len() > NAMED {
            named.push(format!("and {} more", dirs.len() - NAMED));
        }
        let hint = if cfg!(target_os = "macos") {
            ". On macOS, give your terminal Full Disk Access (System Settings, Privacy & Security) and scan again"
        } else {
            ". Scan again as a user who can read them"
        };
        scan.unchecked(
            &format!(
                "{} folder{} under {} this user can't read",
                dirs.len(),
                if dirs.len() == 1 { "" } else { "s" },
                short(&root.to_string_lossy())
            ),
            &format!("{}{hint}", named.join(", ")),
        );
    }
}

/// A secret in a file on this machine, not in history: rotate it, then
/// take it out of the file.
fn finding(path: &Path, s: &Secret) -> Finding {
    let sure = s.confidence == "high";
    let file = short(&path.to_string_lossy());
    let decoded = s.decoded.as_ref().map(|k| format!(" ({k}-encoded)")).unwrap_or_default();
    Finding {
        kind: "secret".into(),
        component: file.clone(),
        location: format!("line {}", s.line),
        vuln_id: s.rule.clone(),
        status: if sure { "fail" } else { "warn" }.into(),
        note: format!(
            "{}{decoded}, in a file on this machine{}",
            s.description,
            if sure { String::new() } else { format!(" (review: {} confidence rule)", s.confidence) }
        ),
        fix_cmd: format!(
            "{}Rotate it where it was issued, then take it out of {file} (line {}): keep it in your keychain or a secret manager instead",
            if sure { "" } else { "If it's real: " },
            s.line
        ),
        ..Default::default()
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
