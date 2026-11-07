//! Secrets committed to the scanned repos' history, found with Pantry's own
//! scanner ([`crate::checks::secrets`]: betterleaks' rules on `wpantry-yara`).
//!
//! History is read as files, not diffs: every blob any ref reaches (`git
//! rev-list --objects --all`, newest first) is scanned once, at the first
//! path it's found at, and its result is kept under its hash, its path and
//! the rules' fingerprint (`secret_blobs`). A later scan reads only the
//! blobs it hasn't seen, so a repo costs its new files, and a scan that runs
//! out of time ([`BUDGET`]) goes on from there next time; what it didn't
//! reach is reported as not checked. A hit's commit is the first that added
//! its blob. Findings are redacted: the cache and the report hold the rule,
//! file, line, commit and fingerprint, never the secret.
//!
//! Paths betterleaks' prefilter skips (images, fonts, lockfiles, vendored
//! code) aren't read, and the scanner skips binary content. Blobs over
//! [`MAX_BLOB`] aren't read either, and are counted as not checked.

use crate::checks::Scan;
use crate::checks::secrets::{Scanner, rules};
use crate::checks::supply_chain::repos::Repo;
use crate::db::Cache;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::utils::files::fingerprint;
use crate::utils::files::short;
use crate::utils::json::{self, str_at};
use crate::utils::parallel;
use crate::utils::process::{lines, pipe_lines, run};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS secret_blobs (
    blob TEXT NOT NULL, rules TEXT NOT NULL, hits TEXT NOT NULL, PRIMARY KEY (blob, rules));";

/// How long one repo's scan may read history; what's left waits for the next scan.
pub const BUDGET: Duration = Duration::from_secs(30 * 60);
/// The largest file read, in history: a bigger one is counted as not checked.
pub const MAX_BLOB: u64 = 256 << 20;
/// How long listing a repo's objects, or its commits' files, may take.
const LIST_TIMEOUT: Duration = Duration::from_secs(600);
/// Bumped when the scanner's results change for the same rules.
const SCANNER: &str = "secrets-v1";

/// One redacted secret in a repo's history.
#[derive(Clone, Debug, PartialEq)]
pub struct Leak {
    pub rule: String,
    pub file: String,
    pub line: i64,
    pub commit: String,
    pub fingerprint: String,
    pub description: String,
    pub confidence: String,
    pub tags: Vec<String>,
}

/// The rules a scan uses: the bundled ones and the user's own (`--secret-rules`).
pub struct Rules {
    pub extra: Option<String>,
    /// What a cached result is kept under: the rules, and the scanner.
    pub fingerprint: String,
}

impl Rules {
    pub fn new(extra: Option<String>) -> Rules {
        let text = format!("{SCANNER}\n{}\n{}", rules::BUNDLED, extra.as_deref().unwrap_or(""));
        Rules { fingerprint: crate::utils::sha256::hex(text.as_bytes())[..16].to_string(), extra }
    }

    pub fn scanner(&self) -> Result<Scanner> {
        let extra: Vec<(&str, &str)> = self.extra.as_deref().map(|e| ("user", e)).into_iter().collect();
        Ok(Scanner::new(rules::RuleSet::load(&extra)?))
    }
}

/// One repo's scan: what its cached result is kept under, the tips of its
/// refs now, and what the cache remembers.
pub struct Job {
    repo: PathBuf,
    key: String,
    /// The rules' fingerprint and the repo's .gitleaksignore's.
    fingerprint: String,
    rules: String,
    tips: BTreeSet<String>,
    /// The tips last scanned at, the hits, and how many files weren't reached.
    cached: Option<(BTreeSet<String>, Vec<Value>, u64)>,
    /// The cache file, read from the scan's own thread.
    db: PathBuf,
    /// The repo carries a `.gitleaks.toml`, which this scan doesn't use.
    pub own_policy: bool,
    /// Threads the scan may use.
    threads: usize,
}

pub fn job(cache: &Cache, repo: &Path, rules: &Rules, threads: usize) -> Result<Job> {
    let own_policy = repo.join(".gitleaks.toml").is_file();
    let fingerprint = format!("{}:{}", rules.fingerprint, fingerprint(&[repo.join(".gitleaksignore").as_path()]));
    let key = format!("secrets:{}", repo.display());
    let cached = cache.run(&key)?.filter(|(fp, _, _)| *fp == fingerprint).and_then(|(_, _, res)| {
        let tips: BTreeSet<String> = json::strs_at(&res, "tips").into_iter().collect();
        let hits = res.get("hits")?.as_array()?.clone();
        Some((tips, hits, res.get("unchecked").and_then(Value::as_u64).unwrap_or(0)))
    });
    Ok(Job {
        repo: repo.to_path_buf(),
        key,
        fingerprint,
        rules: rules.fingerprint.clone(),
        tips: tips(repo),
        cached,
        db: cache.file().to_path_buf(),
        own_policy,
        threads,
    })
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
        let git = |args: &[&str]| {
            let mut argv: Vec<&OsStr> = vec![OsStr::new("git"), OsStr::new("-C"), repo.as_os_str()];
            argv.extend(args.iter().map(OsStr::new));
            run(&argv, Duration::from_secs(15))
        };
        out.extend(
            git(&["for-each-ref", "--format=%(objectname)"])
                .lines()
                .map(str::trim)
                .filter(|l| is_sha(l))
                .map(str::to_string),
        );
        let head = git(&["rev-parse", "HEAD"]);
        if is_sha(head.trim()) {
            out.insert(head.trim().to_string());
        }
    }
    out
}

/// Whether [`finish`] would scan rather than reuse the cached result: nothing
/// cached under these rules, the refs moved, files were left for later, or
/// `refresh`; never when offline.
pub fn stale(job: &Job, refresh: bool, offline: bool) -> bool {
    if offline {
        return false;
    }
    refresh || job.cached.as_ref().is_none_or(|(tips, _, unchecked)| *tips != job.tips || *unchecked > 0)
}

/// A blob of history to read: its hash, the first path it's at, its size.
struct Blob {
    sha: String,
    path: String,
    size: u64,
}

fn git_argv<'a>(repo: &'a Path, args: &'a [&'a str]) -> Vec<&'a OsStr> {
    let mut argv: Vec<&OsStr> = vec![OsStr::new("git"), OsStr::new("-C"), repo.as_os_str()];
    argv.extend(args.iter().map(OsStr::new));
    argv
}

/// Every blob the refs reach, newest first, once each, at its first path.
/// An error when git can't read the repo (the listing alone would read as
/// a repo with nothing in it).
fn blobs(repo: &Path) -> Result<Vec<Blob>> {
    let ok = crate::utils::process::exec(&git_argv(repo, &["rev-parse", "--git-dir"]), &[], Duration::from_secs(30))
        .is_ok_and(|o| o.code == Some(0));
    if !ok {
        return Err(Error::Failed(format!("git can't read {}", repo.display())));
    }
    let list = git_argv(repo, &["rev-list", "--objects", "--all"]);
    let check = git_argv(repo, &["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)"]);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    pipe_lines(&list, &check, LIST_TIMEOUT, |line| {
        let mut parts = line.splitn(4, |&b| b == b' ');
        let (Some(sha), Some(b"blob"), Some(size)) = (parts.next(), parts.next(), parts.next()) else { return };
        let path = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
        let sha = String::from_utf8_lossy(sha).into_owned();
        let size = std::str::from_utf8(size).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        if seen.insert(sha.clone()) {
            out.push(Blob { sha, path, size });
        }
    })?;
    Ok(out)
}

/// Read `blobs`' contents with one `git cat-file --batch`, handing each to
/// `each` until it returns false or `deadline` passes; how many it read.
fn read_blobs<'b>(
    repo: &Path,
    blobs: &[&'b Blob],
    deadline: Instant,
    mut each: impl FnMut(&'b Blob, Vec<u8>) -> bool,
) -> Result<usize> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(["cat-file", "--batch"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).env("NO_COLOR", "1");
    let mut child = crate::utils::process::spawn(&mut cmd).map_err(|e| Error::Failed(format!("git cat-file: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let shas: Vec<String> = blobs.iter().map(|b| b.sha.clone()).collect();
    let writer = std::thread::spawn(move || {
        for sha in shas {
            if writeln!(stdin, "{sha}").is_err() {
                break;
            }
        }
    });
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut read = 0;
    let mut header = Vec::new();
    for blob in blobs {
        if Instant::now() >= deadline {
            break;
        }
        header.clear();
        if out.read_until(b'\n', &mut header)? == 0 {
            break;
        }
        // `<sha> blob <size>`, or `<sha> missing`.
        let size = std::str::from_utf8(&header).ok().and_then(|h| h.split_whitespace().nth(2)?.parse::<u64>().ok());
        let Some(size) = size else { continue };
        let mut data = Vec::with_capacity(size as usize);
        (&mut out).take(size).read_to_end(&mut data)?;
        let mut newline = [0u8; 1];
        out.read_exact(&mut newline)?;
        read += 1;
        if !each(blob, data) {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = writer.join();
    Ok(read)
}

/// The first commit (full hash) that added each of `wanted`, from the
/// history's raw diffs, oldest first.
fn added_in(repo: &Path, wanted: &HashSet<String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    let argv =
        git_argv(repo, &["log", "--all", "--reverse", "--raw", "--no-abbrev", "--no-renames", "--format=%x00%H"]);
    let mut commit = String::new();
    let _ = lines(&argv, LIST_TIMEOUT, |line| {
        if let Some(sha) = line.strip_prefix(b"\0") {
            commit = String::from_utf8_lossy(sha).into_owned();
        } else if line.first() == Some(&b':') {
            // `:100644 100644 <old> <new> M\tpath`
            let new = line.split(|&b| b == b' ').nth(3).map(|s| String::from_utf8_lossy(s).into_owned());
            if let Some(new) = new
                && wanted.contains(&new)
                && !out.contains_key(&new)
            {
                out.insert(new, commit.clone());
            }
        }
    });
    out
}

/// The cached result of each blob at its path, from the cache file, read
/// while the scan's own connection holds its transaction.
fn cached_blobs(db: &Path, rules: &str, blobs: &[Blob]) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    let Ok(conn) = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return out;
    };
    let Ok(mut stmt) = conn.prepare("SELECT hits FROM secret_blobs WHERE blob=? AND rules=?") else { return out };
    for b in blobs {
        let key = blob_key(b);
        let hits: Option<String> = stmt.query_row(rusqlite::params![key, rules], |r| r.get(0)).ok();
        if let Some(v) = hits.and_then(|h| serde_json::from_str(&h).ok()) {
            out.insert(key, v);
        }
    }
    out
}

fn blob_key(b: &Blob) -> String {
    format!("{}:{}", b.sha, b.path)
}

/// Scan the repo's history: the blobs not cached, as many as [`BUDGET`]
/// allows, on the job's threads. The result, as cached: the tips, the
/// redacted hits, how many files weren't checked, and the new blobs'
/// results (`new`, for [`finish`] to keep).
pub fn run_job(job: &Job, scanner: &Scanner) -> Result<Value> {
    let all = blobs(&job.repo)?;
    let mut too_big = 0;
    let mut todo: Vec<&Blob> = Vec::new();
    let wanted: Vec<Blob> = all.into_iter().filter(|b| !scanner.skips_path(&b.path)).collect();
    let cached = cached_blobs(&job.db, &job.rules, &wanted);
    for b in &wanted {
        if cached.contains_key(&blob_key(b)) {
            continue;
        }
        if b.size > MAX_BLOB {
            too_big += 1;
        } else {
            todo.push(b);
        }
    }
    let deadline = Instant::now() + BUDGET;
    let results: Mutex<Vec<(String, Value)>> = Mutex::new(Vec::new());
    let (tx, rx) = std::sync::mpsc::sync_channel::<(&Blob, Vec<u8>)>(job.threads * 2);
    let rx = Mutex::new(rx);
    let read = std::thread::scope(|s| -> Result<usize> {
        for _ in 0..job.threads.max(1) {
            s.spawn(|| {
                loop {
                    let next = rx.lock().expect("lock").recv();
                    let Ok((blob, data)) = next else { break };
                    let hits: Vec<Value> = scanner
                        .scan(&data, &blob.path, None)
                        .into_iter()
                        .map(|f| {
                            json!({"rule": f.rule, "line": f.start_line, "description": f.description,
                                   "confidence": confidence(f.confidence), "tags": f.tags})
                        })
                        .collect();
                    results.lock().expect("lock").push((blob_key(blob), Value::Array(hits)));
                }
            });
        }
        let read = read_blobs(&job.repo, &todo, deadline, |blob, data| tx.send((blob, data)).is_ok());
        drop(tx);
        read
    })?;
    let new = results.into_inner().expect("lock");
    let unchecked = (todo.len() - read) as u64 + too_big;
    // Every blob's hits, cached or new, with the commit that added it.
    let by_key: HashMap<&str, &Value> =
        cached.iter().map(|(k, v)| (k.as_str(), v)).chain(new.iter().map(|(k, v)| (k.as_str(), v))).collect();
    let hit_blobs: Vec<&Blob> = wanted
        .iter()
        .filter(|b| by_key.get(blob_key(b).as_str()).is_some_and(|h| h.as_array().is_some_and(|a| !a.is_empty())))
        .collect();
    let shas: HashSet<String> = hit_blobs.iter().map(|b| b.sha.clone()).collect();
    let commits = added_in(&job.repo, &shas);
    let ignored = ignored(&job.repo);
    let mut rows = Vec::new();
    for b in hit_blobs {
        let commit = commits.get(&b.sha).cloned().unwrap_or_default();
        for h in by_key[blob_key(b).as_str()].as_array().into_iter().flatten() {
            let rule = str_at(h, "rule");
            let line = h.get("line").and_then(Value::as_i64).unwrap_or(0);
            let fp = format!("{commit}:{}:{rule}:{line}", b.path);
            if ignored.contains(&fp) {
                continue;
            }
            rows.push(json!({"rule": rule, "file": b.path, "line": line,
                             "commit": commit.chars().take(12).collect::<String>(), "fingerprint": fp,
                             "description": str_at(h, "description"), "confidence": str_at(h, "confidence"),
                             "tags": h.get("tags").cloned().unwrap_or(Value::Array(vec![]))}));
        }
    }
    Ok(json!({"tips": job.tips.iter().collect::<Vec<_>>(), "hits": rows, "unchecked": unchecked,
              "new": new.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()}))
}

fn confidence(c: Option<rules::Confidence>) -> &'static str {
    match c {
        Some(rules::Confidence::High) | None => "high",
        Some(rules::Confidence::Medium) => "medium",
        Some(rules::Confidence::Low) => "low",
    }
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

/// The leaks in the job's repo, and how many of its files weren't checked:
/// the cached result while the refs haven't moved, else `ran` (a
/// [`run_job`] made ahead, beside other work). A run's new blob results and
/// its summary are stored.
pub fn finish(
    cache: &Cache,
    job: &Job,
    ran: Option<Result<Value>>,
    refresh: bool,
    offline: bool,
) -> Result<(Vec<Leak>, u64)> {
    let (hits, unchecked) = if !stale(job, refresh, offline) {
        match &job.cached {
            Some((_, hits, unchecked)) => (hits.clone(), *unchecked),
            None => return Err(Error::Offline(format!("{}: offline and not cached", job.key))),
        }
    } else {
        let Some(ran) = ran else { return Err(Error::Failed(format!("{}: not scanned", job.key))) };
        let res = ran?;
        for pair in res.get("new").and_then(Value::as_array).into_iter().flatten() {
            let (Some(key), Some(hits)) = (pair.get(0).and_then(Value::as_str), pair.get(1)) else { continue };
            cache.conn.execute(
                "INSERT OR REPLACE INTO secret_blobs (blob, rules, hits) VALUES (?, ?, ?)",
                rusqlite::params![key, job.rules, hits.to_string()],
            )?;
        }
        let unchecked = res.get("unchecked").and_then(Value::as_u64).unwrap_or(0);
        let hits = res.get("hits").and_then(Value::as_array).cloned().unwrap_or_default();
        cache.put_run(
            &job.key,
            &job.fingerprint,
            &json!({"tips": res.get("tips"), "hits": hits, "unchecked": unchecked}),
        )?;
        cache.commit()?;
        (hits, unchecked)
    };
    let leaks = hits
        .iter()
        .map(|f| Leak {
            rule: str_at(f, "rule").into(),
            file: str_at(f, "file").into(),
            line: f.get("line").and_then(Value::as_i64).unwrap_or(0),
            commit: str_at(f, "commit").into(),
            fingerprint: str_at(f, "fingerprint").into(),
            description: str_at(f, "description").into(),
            confidence: str_at(f, "confidence").into(),
            tags: json::strs_at(f, "tags"),
        })
        .collect();
    Ok((leaks, unchecked))
}

/// Secret scans at once on a first run (`--jobs`): each is CPU-bound, so
/// together they share the machine's cores.
pub(crate) fn scans_at_once(scan: &Scan) -> usize {
    scan.opts.jobs.unwrap_or_else(|| (parallel::cores() / 2).clamp(1, 4))
}

/// Each repo's secret job, and whether its cached result is stale.
pub(crate) fn secret_jobs(scan: &Scan, repos: &[Repo], rules: &Rules) -> Result<Vec<(Result<Job>, bool)>> {
    let threads = (parallel::cores() / scans_at_once(scan)).max(1);
    repos
        .iter()
        .map(|(_, root)| {
            let job = job(&scan.cache, root, rules, threads);
            let stale = job.as_ref().is_ok_and(|j| stale(j, scan.opts.refresh, scan.opts.offline));
            Ok((job, stale))
        })
        .collect()
}

/// Secrets committed anywhere in the repos' history, from the jobs
/// [`secret_jobs`] made and the scans run ahead (`ran`), in the repos'
/// order. A high-confidence rule fails; the others ask for review.
pub(crate) fn secrets(
    scan: &mut Scan,
    repos: &[Repo],
    jobs: Vec<(Result<Job>, bool)>,
    ran: Vec<Option<Result<Value>>>,
) -> Result<()> {
    let (refresh, offline) = (scan.opts.refresh, scan.opts.offline);
    for (((name, root), (job, _)), ran) in repos.iter().zip(jobs).zip(ran) {
        scan.status(&format!("Scanning {name}'s git history for secrets"));
        if job.as_ref().is_ok_and(|j| j.own_policy) {
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/.gitleaks.toml"),
                vuln_id: "REPO-POLICY".into(),
                status: "warn".into(),
                note: "the repo's own gitleaks config isn't used; the scan used Pantry's rules".into(),
                fix_cmd: "Review the repo's .gitleaks.toml; to add rules, write them as YARA and pass --secret-rules"
                    .into(),
                ..Default::default()
            });
        }
        let (found, unchecked) = match job.and_then(|job| finish(&scan.cache, &job, ran, refresh, offline)) {
            Ok(f) => f,
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("secrets in {name}'s history"), &e.to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        scan.count("repos scanned for secrets", 1);
        if unchecked > 0 {
            scan.unchecked(
                &format!("secrets in {unchecked} files of {name}'s history"),
                "not reached in this scan's time, or over 256 MB; the next scan goes on from here",
            );
        }
        for f in found {
            let sure = f.confidence == "high";
            let decoded = f.tags.iter().find_map(|t| t.strip_prefix("decoded:")).map(|k| format!(" ({k}-encoded)"));
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/{}", f.file),
                location: format!("line {}, commit {}", f.line, f.commit),
                vuln_id: f.rule.clone(),
                status: if sure { "fail" } else { "warn" }.into(),
                note: format!(
                    "{}{}{}",
                    f.description,
                    decoded.unwrap_or_default(),
                    if sure { String::new() } else { format!(" (review: {} confidence rule)", f.confidence) }
                ),
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
