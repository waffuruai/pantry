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
//! code) aren't read, and the scanner skips binary content, sniffed before
//! the rest is read. Blobs over [`MAX_BLOB`] aren't read either, and are
//! counted as not checked, as are a partial clone's missing blobs: git is
//! never asked to fetch them.

use crate::checks::Scan;
use crate::checks::secrets::{Scanner, noise, rules};
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS secret_blobs (
    blob TEXT NOT NULL, rules TEXT NOT NULL, hits TEXT NOT NULL, PRIMARY KEY (blob, rules));";

/// How long one repo's scan may read history; what's left waits for the next scan.
pub const BUDGET: Duration = Duration::from_secs(30 * 60);
/// The largest file read, in history: a bigger one is counted as not
/// checked. It bounds memory too: about three blobs per thread are held at
/// once.
pub const MAX_BLOB: u64 = 10 << 20;
/// How long listing a repo's objects, or its commits' files, may take.
const LIST_TIMEOUT: Duration = Duration::from_secs(600);
/// With `--deep`: no blob bigger than this is read, and a repo's scan may
/// read history for this long. Blobs over [`MAX_BLOB`] are read one at a
/// time, so memory stays bounded.
pub const DEEP_MAX_BLOB: u64 = 256 << 20;
pub const DEEP_BUDGET: Duration = Duration::from_secs(6 * 60 * 60);
/// Bumped when the scanner's results change for the same rules.
const SCANNER: &str = "secrets-v3";

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

/// The files of a repo's history a scan didn't read, by why.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Unread {
    /// Not reached in the scan's time.
    pub late: u64,
    /// Bigger than the scan reads.
    pub too_big: u64,
    /// Missing from a partial clone.
    pub missing: u64,
}

impl Unread {
    pub fn total(&self) -> u64 {
        self.late + self.too_big + self.missing
    }

    /// As a run's or the cache's JSON keeps it; a result without the
    /// reasons counts them all as late.
    fn read(v: &Value) -> Unread {
        let count = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        if v.get("late").is_none() {
            return Unread { late: count("unchecked"), ..Unread::default() };
        }
        Unread { late: count("late"), too_big: count("too_big"), missing: count("missing") }
    }
}

/// What one scan's history scans have found in blobs, so a blob that
/// several repos hold (clones, forks, a repo and its worktrees' history) is
/// read and scanned once, by the first scan to reach it, and the others
/// take its result. A result depends only on the rules, the blob's bytes
/// and the path it is scanned at, which is what a slot is kept under.
#[derive(Default)]
pub struct Shared {
    slots: Mutex<HashMap<[u8; 16], Slot>>,
    changed: Condvar,
    /// How many blobs a scan took to read and scan (the rest were another
    /// scan's, or cached).
    claimed: AtomicUsize,
}

enum Slot {
    /// A scan is reading it.
    Claimed,
    /// The scan that claimed it ran out of time or failed: free to claim.
    Dropped,
    /// Its hits (an empty array for none).
    Hits(Value),
}

enum Claim {
    Mine,
    Done(Value),
    Theirs,
}

impl Shared {
    /// How many blobs scans of this run took to read and scan.
    pub fn claimed(&self) -> usize {
        self.claimed.load(Ordering::Relaxed)
    }

    /// The slot of `blob` under `rules` (the rules' fingerprint): a hash,
    /// so a scan of a million blobs holds sixteen bytes of each.
    fn key(rules: &str, blob: &Blob) -> [u8; 16] {
        let mut h = crate::utils::sha256::Sha256::new();
        for part in [rules, &blob.sha, &blob.path] {
            h.update(part.as_bytes());
            h.update(&[0]);
        }
        let mut key = [0; 16];
        key.copy_from_slice(&h.finish()[..16]);
        key
    }

    fn claim(&self, key: [u8; 16]) -> Claim {
        let mut slots = self.slots.lock().expect("lock");
        match slots.get(&key) {
            Some(Slot::Hits(v)) => Claim::Done(v.clone()),
            Some(Slot::Claimed) => Claim::Theirs,
            Some(Slot::Dropped) | None => {
                slots.insert(key, Slot::Claimed);
                self.claimed.fetch_add(1, Ordering::Relaxed);
                Claim::Mine
            }
        }
    }

    /// `key`'s hits, or None when its scan didn't get to them.
    fn finish(&self, key: [u8; 16], hits: Option<Value>) {
        let slot = hits.map_or(Slot::Dropped, Slot::Hits);
        self.slots.lock().expect("lock").insert(key, slot);
        self.changed.notify_all();
    }

    /// Frees what this scan claimed and never finished.
    fn release(&self, keys: &[[u8; 16]]) {
        let mut slots = self.slots.lock().expect("lock");
        for key in keys {
            if let Some(slot @ Slot::Claimed) = slots.get_mut(key) {
                *slot = Slot::Dropped;
            }
        }
        self.changed.notify_all();
    }

    /// The hits of a blob another scan claimed, once it has them; None when
    /// that scan let it go, or `deadline` passed.
    fn wait(&self, key: [u8; 16], deadline: Instant) -> Option<Value> {
        let mut slots = self.slots.lock().expect("lock");
        loop {
            match slots.get(&key) {
                Some(Slot::Hits(v)) => return Some(v.clone()),
                Some(Slot::Claimed) => {
                    let left = deadline.checked_duration_since(Instant::now())?;
                    slots = self.changed.wait_timeout(slots, left).expect("lock").0;
                }
                Some(Slot::Dropped) | None => return None,
            }
        }
    }
}

/// Lets go of a scan's unfinished claims when it ends, however it ends.
struct Release<'a> {
    shared: &'a Shared,
    keys: Vec<[u8; 16]>,
}

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.shared.release(&self.keys);
    }
}

/// One repo's scan: what its cached result is kept under, the tips of its
/// refs now, and what the cache remembers.
pub struct Job {
    repo: PathBuf,
    key: String,
    /// The rules' fingerprint, and the repo's .pantryignore's.
    fingerprint: String,
    rules: String,
    tips: BTreeSet<String>,
    /// The tips last scanned at, the hits, the files not read, and how
    /// many .pantryignore skipped.
    cached: Option<(BTreeSet<String>, Vec<Value>, Unread, u64)>,
    /// The cache file, read from the scan's own thread.
    db: PathBuf,
    /// The repo carries a `.gitleaks.toml`, which this scan doesn't use.
    pub own_policy: bool,
    /// Threads the scan may use.
    threads: usize,
    /// `--deep`: blobs up to [`DEEP_MAX_BLOB`], for up to [`DEEP_BUDGET`].
    pub deep: bool,
    /// What the other repos' scans of this run have found in blobs.
    pub shared: Arc<Shared>,
}

pub fn job(cache: &Cache, repo: &Path, rules: &Rules, threads: usize) -> Result<Job> {
    let own_policy = repo.join(".gitleaks.toml").is_file();
    let files = [repo.join(crate::checks::ignore::FILE)];
    let fingerprint = format!("{}:{}", rules.fingerprint, fingerprint(&files));
    let key = format!("secrets:{}", repo.display());
    let cached = cache.run(&key)?.filter(|(fp, _, _)| *fp == fingerprint).and_then(|(_, _, res)| {
        let tips: BTreeSet<String> = json::strs_at(&res, "tips").into_iter().collect();
        let hits = res.get("hits")?.as_array()?.clone();
        let count = |k: &str| res.get(k).and_then(Value::as_u64).unwrap_or(0);
        Some((tips, hits, Unread::read(&res), count("skipped")))
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
        deep: false,
        shared: Arc::default(),
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
    refresh || job.cached.as_ref().is_none_or(|(tips, _, unread, _)| *tips != job.tips || unread.total() > 0)
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

/// Every blob the refs reach, newest first, once each, at its first path,
/// and how many more it reaches that aren't here (a partial clone's). An
/// error when git can't read the repo (the listing alone would read as a
/// repo with nothing in it).
fn blobs(repo: &Path) -> Result<(Vec<Blob>, u64)> {
    // Why git can't be run (not found, and where wpantry looked) is part of the error: a scan
    // that left a PATH folder out may have lost the only git it had.
    let probe = crate::utils::process::exec(&git_argv(repo, &["rev-parse", "--git-dir"]), &[], Duration::from_secs(30));
    match probe {
        Ok(o) if o.code == Some(0) => {}
        Ok(_) => return Err(Error::Failed(format!("git can't read {}", repo.display()))),
        Err(e) => return Err(Error::Failed(format!("git can't read {}: {e}", repo.display()))),
    }
    // A partial clone's missing blobs come through as `?<sha>`, and
    // cat-file reports them `missing`, instead of git fetching them.
    let list = git_argv(repo, &["rev-list", "--objects", "--all", "--missing=print"]);
    let check = git_argv(repo, &["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)"]);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut missing = 0;
    pipe_lines(&list, &check, LIST_TIMEOUT, |line| {
        let mut parts = line.splitn(4, |&b| b == b' ');
        let (Some(sha), kind) = (parts.next(), parts.next()) else { return };
        if kind == Some(b"missing") {
            missing += u64::from(seen.insert(String::from_utf8_lossy(sha).into_owned()));
            return;
        }
        let (Some(b"blob"), Some(size)) = (kind, parts.next()) else { return };
        let path = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
        let sha = String::from_utf8_lossy(sha).into_owned();
        let size = std::str::from_utf8(size).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        if seen.insert(sha.clone()) {
            out.push(Blob { sha, path, size });
        }
    })?;
    Ok((out, missing))
}

/// Read `blobs`' contents with one `git cat-file --batch`, handing each to
/// `each` until it returns false or `deadline` passes; how many it read. A
/// binary blob is handed over as its first bytes alone (all the scanner
/// needs to skip it), so model weights and data dumps aren't held whole.
fn read_blobs<'b>(
    repo: &Path,
    blobs: &[&'b Blob],
    deadline: Instant,
    mut each: impl FnMut(&'b Blob, Vec<u8>) -> bool,
) -> Result<usize> {
    let mut cmd = Command::new(crate::utils::process::program(std::ffi::OsStr::new("git"))?);
    cmd.arg("-C").arg(repo).args(["cat-file", "--batch"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).env("NO_COLOR", "1");
    cmd.env("GIT_NO_LAZY_FETCH", "1");
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
        let head = size.min(crate::checks::secrets::fragments::SNIFF as u64);
        let mut data = Vec::with_capacity(head as usize);
        (&mut out).take(head).read_to_end(&mut data)?;
        if crate::checks::secrets::fragments::binary(&data) {
            std::io::copy(&mut (&mut out).take(size - head), &mut std::io::sink())?;
        } else {
            data.reserve((size - head) as usize);
            (&mut out).take(size - head).read_to_end(&mut data)?;
        }
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

/// Every path each of `wanted` (blob hashes) has been at in the history,
/// from its raw diffs.
fn paths_of(repo: &Path, wanted: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let argv = git_argv(
        repo,
        &[
            "-c",
            "log.showRoot=true",
            "-c",
            "core.quotePath=false",
            "log",
            "--all",
            "--raw",
            "--diff-merges=first-parent",
            "--no-abbrev",
            "--no-renames",
            "--format=",
        ],
    );
    let _ = lines(&argv, LIST_TIMEOUT, |line| {
        // `:100644 100644 <old> <new> M\tpath`
        if line.first() != Some(&b':') {
            return;
        }
        let Some(tab) = line.iter().position(|&b| b == b'\t') else { return };
        let new = line[..tab].split(|&b| b == b' ').nth(3).map(|s| String::from_utf8_lossy(s).into_owned());
        if let Some(new) = new
            && wanted.contains(&new)
        {
            let path = String::from_utf8_lossy(&line[tab + 1..]).into_owned();
            let list = out.entry(new).or_default();
            if !list.contains(&path) {
                list.push(path);
            }
        }
    });
    out
}

/// The first commit (full hash) that added each of `wanted`, from the
/// history's raw diffs, oldest first.
fn added_in(repo: &Path, wanted: &HashSet<String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    // The root commit's files and a merge's own changes count too, whatever
    // the user's log config says.
    let argv = git_argv(
        repo,
        &[
            "-c",
            "log.showRoot=true",
            "log",
            "--all",
            "--reverse",
            "--raw",
            "--diff-merges=first-parent",
            "--no-abbrev",
            "--no-renames",
            "--format=%x00%H",
        ],
    );
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
    run_job_at(job, scanner, &|_| {})
}

/// [`run_job`], saying which repo's history it is reading.
pub fn run_job_at(job: &Job, scanner: &Scanner, at: &(dyn Fn(&std::path::Path) + Sync)) -> Result<Value> {
    at(&job.repo);
    let (all, missing) = blobs(&job.repo)?;
    let mut too_big = 0;
    let mut todo: Vec<&Blob> = Vec::new();
    // What .pantryignore skips for the secret check isn't read at all.
    let ignore = crate::checks::ignore::Ignore::load(&job.repo.join(crate::checks::ignore::FILE)).and_then(|r| r.ok());
    let skipped = |path: &str| ignore.as_ref().is_some_and(|ig| ig.skips_kind("secret", path));
    let (mut wanted, mut ignored): (Vec<Blob>, Vec<Blob>) =
        all.into_iter().filter(|b| !scanner.skips_path(&b.path)).partition(|b| !skipped(&b.path));
    // A blob is listed at the first path it's found at. One the file skips
    // there is read anyway when another of its paths isn't skipped, at that
    // path: ignoring a copy mustn't hide the original.
    if !ignored.is_empty() {
        let shas: HashSet<String> = ignored.iter().map(|b| b.sha.clone()).collect();
        let paths = paths_of(&job.repo, &shas);
        let mut still = Vec::new();
        for mut b in ignored {
            let other = paths.get(&b.sha).and_then(|ps| ps.iter().find(|p| !skipped(p) && !scanner.skips_path(p)));
            match other {
                Some(p) => {
                    b.path = p.clone();
                    wanted.push(b);
                }
                None => still.push(b),
            }
        }
        ignored = still;
    }
    let cached = cached_blobs(&job.db, &job.rules, &wanted);
    for b in &wanted {
        if cached.contains_key(&blob_key(b)) {
            continue;
        }
        if b.size > if job.deep { DEEP_MAX_BLOB } else { MAX_BLOB } {
            too_big += 1;
        } else {
            todo.push(b);
        }
    }
    // Smallest first: the code and config secrets are written in come before
    // data dumps, so a scan cut short by the budget has read what matters
    // most. Ties stay newest first.
    todo.sort_by_key(|b| b.size);
    let deadline = Instant::now() + if job.deep { DEEP_BUDGET } else { BUDGET };
    let results: Mutex<Vec<(String, Value)>> = Mutex::new(Vec::new());
    // Rounds: the blobs no other scan of this run has, read here; then the
    // ones another scan was reading, taken from it, and read here too if it
    // let them go. A blob is read once by the run, not once by each repo
    // that holds it.
    let mut queue: Vec<&Blob> = todo.clone();
    while !queue.is_empty() {
        let mut mine: Vec<&Blob> = Vec::new();
        let mut theirs: Vec<(&Blob, [u8; 16])> = Vec::new();
        for b in queue.drain(..) {
            let key = Shared::key(&job.rules, b);
            match job.shared.claim(key) {
                Claim::Mine => mine.push(b),
                Claim::Done(hits) => results.lock().expect("lock").push((blob_key(b), hits)),
                Claim::Theirs => theirs.push((b, key)),
            }
        }
        {
            // Whatever of mine isn't finished (out of time, or an error) is
            // let go for another scan to take.
            let _release =
                Release { shared: &job.shared, keys: mine.iter().map(|b| Shared::key(&job.rules, b)).collect() };
            // The blobs over MAX_BLOB a deep scan reads come last, one at a time.
            let split = mine.partition_point(|b| b.size <= MAX_BLOB);
            for (part, threads) in [(&mine[..split], job.threads.max(1)), (&mine[split..], 1)] {
                if part.is_empty() {
                    continue;
                }
                let (tx, rx) = std::sync::mpsc::sync_channel::<(&Blob, Vec<u8>)>(threads * 2);
                let rx = Mutex::new(rx);
                std::thread::scope(|s| -> Result<usize> {
                    for _ in 0..threads {
                        s.spawn(|| {
                            loop {
                                let next = rx.lock().expect("lock").recv();
                                let Ok((blob, data)) = next else { break };
                                let key = Shared::key(&job.rules, blob);
                                // Out of time: the blob is left for the next scan.
                                let Some(found) = scanner.scan_until(&data, &blob.path, None, Some(deadline)) else {
                                    job.shared.finish(key, None);
                                    continue;
                                };
                                let hits: Vec<Value> = found
                                    .into_iter()
                                    .map(|f| {
                                        json!({"rule": f.rule, "line": f.start_line, "description": f.description,
                                       "confidence": confidence(f.confidence), "tags": f.tags})
                                    })
                                    .collect();
                                let hits = Value::Array(hits);
                                job.shared.finish(key, Some(hits.clone()));
                                results.lock().expect("lock").push((blob_key(blob), hits));
                            }
                        });
                    }
                    let read = read_blobs(&job.repo, part, deadline, |blob, data| tx.send((blob, data)).is_ok());
                    drop(tx);
                    read
                })?;
            }
        }
        // Mine are all finished or let go: waiting on theirs can't cycle.
        for (b, key) in theirs {
            match job.shared.wait(key, deadline) {
                Some(hits) => results.lock().expect("lock").push((blob_key(b), hits)),
                None if Instant::now() < deadline => queue.push(b),
                None => {}
            }
        }
    }
    let new = results.into_inner().expect("lock");
    let unread = Unread { late: (todo.len() - new.len()) as u64, too_big, missing };
    // Every blob's hits, cached or new, with the commit that added it.
    let by_key: HashMap<&str, &Value> =
        cached.iter().map(|(k, v)| (k.as_str(), v)).chain(new.iter().map(|(k, v)| (k.as_str(), v))).collect();
    let hit_blobs: Vec<&Blob> = wanted
        .iter()
        .filter(|b| by_key.get(blob_key(b).as_str()).is_some_and(|h| h.as_array().is_some_and(|a| !a.is_empty())))
        .collect();
    let shas: HashSet<String> = hit_blobs.iter().map(|b| b.sha.clone()).collect();
    let commits = added_in(&job.repo, &shas);
    let mut rows = Vec::new();
    for b in hit_blobs {
        let commit = commits.get(&b.sha).cloned().unwrap_or_default();
        for h in by_key[blob_key(b).as_str()].as_array().into_iter().flatten() {
            let rule = str_at(h, "rule");
            let line = h.get("line").and_then(Value::as_i64).unwrap_or(0);
            let fp = format!("{commit}:{}:{rule}:{line}", b.path);
            rows.push(json!({"rule": rule, "file": b.path, "line": line,
                             "commit": commit.chars().take(12).collect::<String>(), "fingerprint": fp,
                             "description": str_at(h, "description"), "confidence": str_at(h, "confidence"),
                             "tags": h.get("tags").cloned().unwrap_or(Value::Array(vec![]))}));
        }
    }
    Ok(json!({"tips": job.tips.iter().collect::<Vec<_>>(), "hits": rows, "unchecked": unread.total(),
               "late": unread.late, "too_big": unread.too_big, "missing": unread.missing, "skipped": ignored.len(),
              "new": new.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()}))
}

pub(crate) fn confidence(c: Option<rules::Confidence>) -> &'static str {
    match c {
        Some(rules::Confidence::High) | None => "high",
        Some(rules::Confidence::Medium) => "medium",
        Some(rules::Confidence::Low) => "low",
    }
}

/// The leaks in the job's repo, the files it didn't read and why, and how
/// many its .pantryignore skipped:
/// the cached result while the refs haven't moved, else `ran` (a
/// [`run_job`] made ahead, beside other work). A run's new blob results and
/// its summary are stored.
pub fn finish(
    cache: &Cache,
    job: &Job,
    ran: Option<Result<Value>>,
    refresh: bool,
    offline: bool,
) -> Result<(Vec<Leak>, Unread, u64)> {
    let (hits, unread, skipped) = if !stale(job, refresh, offline) {
        match &job.cached {
            Some((_, hits, unread, skipped)) => (hits.clone(), *unread, *skipped),
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
        let (unread, skipped) = (Unread::read(&res), res.get("skipped").and_then(Value::as_u64).unwrap_or(0));
        let hits = res.get("hits").and_then(Value::as_array).cloned().unwrap_or_default();
        cache.put_run(
            &job.key,
            &job.fingerprint,
            &json!({"tips": res.get("tips"), "hits": hits, "unchecked": unread.total(), "late": unread.late,
                    "too_big": unread.too_big, "missing": unread.missing, "skipped": skipped}),
        )?;
        cache.commit()?;
        (hits, unread, skipped)
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
    Ok((leaks, unread, skipped))
}

/// Secret scans at once on a first run (`--jobs`): each is CPU-bound, so
/// together they share the machine's cores.
pub(crate) fn scans_at_once(scan: &Scan) -> usize {
    scan.opts.jobs.unwrap_or_else(|| (parallel::cores() / 2).clamp(1, 4))
}

/// Each repo's secret job, and whether its cached result is stale.
pub(crate) fn secret_jobs(scan: &Scan, repos: &[Repo], rules: &Rules) -> Result<Vec<(Result<Job>, bool)>> {
    // The repos of one run share what their scans find in blobs.
    let shared = Arc::new(Shared::default());
    let mut jobs: Vec<(Result<Job>, bool)> = repos
        .iter()
        .map(|(_, root)| {
            let job = job(&scan.cache, root, rules, 1).map(|mut j| {
                j.deep = scan.opts.deep;
                j.shared = shared.clone();
                j
            });
            let stale = job.as_ref().is_ok_and(|j| stale(j, scan.opts.refresh, scan.opts.offline));
            Ok((job, stale))
        })
        .collect::<Result<_>>()?;
    // The cores go to the scans that run: fewer stale repos, more each.
    let running = jobs.iter().filter(|(_, s)| *s).count().clamp(1, scans_at_once(scan));
    let threads = (parallel::cores() / running).max(1);
    for (job, _) in &mut jobs {
        if let Ok(j) = job {
            j.threads = threads;
        }
    }
    Ok(jobs)
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
    let mut made: Vec<(Finding, String, String)> = Vec::new();
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
        let (found, unread, skipped) = match job.and_then(|job| finish(&scan.cache, &job, ran, refresh, offline)) {
            Ok(f) => f,
            Err(e) if e.is_source() => {
                scan.missed(&format!("secrets in {name}'s history"), &e);
                continue;
            }
            Err(e) => return Err(e),
        };
        scan.count("repos scanned for secrets", 1);
        scan.count("files in git history skipped by a repo's .pantryignore", skipped as i64);
        if unread.total() > 0 {
            let (why, run) = unread_note(&unread, &short(&root.to_string_lossy()), scan.opts.deep);
            scan.unchecked_until(&format!("secrets in {} files of {name}'s history", unread.total()), &why, &run);
        }
        // What history holds, so `--deep`'s read of the files doesn't
        // report it again.
        for f in &found {
            scan.history_secrets.insert((root.join(&f.file), f.rule.clone(), f.line.max(0) as usize));
        }
        let skipper = crate::checks::ignore::Skipper::new(root);
        let skip = |kind: &str, id: &str, rel: &str| skipper.skips(kind, id, rel);
        let (fs, counts) = findings(name, &short(&root.to_string_lossy()), &found, scan.opts.deep, &skip);
        for (what, n) in counts {
            scan.count(what, n);
        }
        made.extend(fs.into_iter().map(|(f, key)| (f, key, name.clone())));
    }
    for f in merge_clones(made) {
        scan.add(f);
    }
    Ok(())
}

/// Where a repo's generic hits in tests are, as a finding's location.
pub const TESTS: &str = "test files";
/// The count of vendored files whose generic hits only `--deep` reports.
pub const VENDORED: &str = "files of vendored code a generic secret rule hit (reported with --deep)";

/// What a repo's hits left out, by count.
pub type Counts = Vec<(&'static str, i64)>;
/// A test file's versions (commit, oldest first) and their lines.
type Versions<'a> = Vec<(&'a str, Vec<i64>)>;

/// Whether an ignore file skips a hit (kind, rule, path in the repo): the
/// count it goes under if so.
pub type Skip<'a> = &'a dyn Fn(&str, &str, &str) -> Option<&'static str>;

/// A repo's (`name`, at `repo`) hits as findings, each with what makes it
/// the same finding in a clone of the repo; and what was left out, by
/// count. One finding per file and rule, except for a generic rule:
///
/// - in an env or credential file, it fails ([`finding`]);
/// - in tests, one finding per rule names every place ([`test_finding`]);
/// - in vendored code, none, unless `deep`.
pub fn findings(name: &str, repo: &str, found: &[Leak], deep: bool, skip: Skip) -> (Vec<(Finding, String)>, Counts) {
    fn bump(counts: &mut Counts, what: &'static str) {
        match counts.iter_mut().find(|(w, _)| *w == what) {
            Some((_, n)) => *n += 1,
            None => counts.push((what, 1)),
        }
    }
    let mut counts = Vec::new();
    let mut out = Vec::new();
    let mut tests: Vec<Vec<&Leak>> = Vec::new();
    for group in by_file_and_rule(found) {
        let (file, rule) = (group[0].file.as_str(), group[0].rule.as_str());
        let generic = rule.starts_with("generic-") && noise::secret_file(file).is_none();
        if generic && !deep && noise::vendored(file) {
            bump(&mut counts, VENDORED);
            continue;
        }
        if generic && noise::test(file) {
            // One finding for many files: the ignore files are asked here,
            // as no one path of it would match.
            if let Some(what) = skip("secret", rule, file) {
                bump(&mut counts, what);
                continue;
            }
            match tests.iter_mut().find(|t| t[0].rule == rule) {
                Some(t) => t.extend(group),
                None => tests.push(group),
            }
            continue;
        }
        let key = clone_key(rule, file, &group);
        out.push((finding(name, repo, &group), key));
    }
    for group in tests {
        let key = clone_key(&group[0].rule, TESTS, &group);
        out.push((test_finding(name, repo, &group), key));
    }
    (out, counts)
}

/// What a finding is in any clone of its repo: its rule, its file (or
/// [`TESTS`]) and every place, commits included.
fn clone_key(rule: &str, file: &str, group: &[&Leak]) -> String {
    let mut places: Vec<String> = group.iter().map(|h| format!("{}:{}:{}", h.file, h.line, h.commit)).collect();
    places.sort_unstable();
    places.dedup();
    format!("{rule}|{file}|{}", places.join(","))
}

/// Findings that clones (or forks) of one repo share, the same file at the
/// same commits, as one: the first repo's, naming the others.
pub fn merge_clones(made: Vec<(Finding, String, String)>) -> Vec<Finding> {
    let mut out: Vec<(Finding, String, Vec<String>)> = Vec::new();
    for (f, key, name) in made {
        match out.iter_mut().find(|(_, k, _)| *k == key) {
            Some((_, _, also)) => also.push(name),
            None => out.push((f, key, Vec::new())),
        }
    }
    out.into_iter()
        .map(|(mut f, _, also)| {
            if !also.is_empty() {
                f.note.push_str(&format!(
                    "; also in {} other clone{}: {}",
                    also.len(),
                    if also.len() == 1 { "" } else { "s" },
                    also.join(", ")
                ));
            }
            f
        })
        .collect()
}

/// The places a collapsed finding names; its note counts them all.
pub const PLACES: usize = 5;

/// The leaks grouped by file and rule, in the order found (newest version
/// first): every version of a file repeats its hits, so one rule in one file
/// is one finding.
pub fn by_file_and_rule(found: &[Leak]) -> Vec<Vec<&Leak>> {
    let mut groups: Vec<Vec<&Leak>> = Vec::new();
    let mut at: HashMap<(&str, &str), usize> = HashMap::new();
    for f in found {
        match at.get(&(f.file.as_str(), f.rule.as_str())) {
            Some(&i) => groups[i].push(f),
            None => {
                at.insert((&f.file, &f.rule), groups.len());
                groups.push(vec![f]);
            }
        }
    }
    groups
}

fn rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// One rule's hits in one file of a repo (`name`, at `repo`) as a finding:
/// it fails when any hit is of high confidence, or the file is an env or
/// credential file (not a template of one).
pub fn finding(name: &str, repo: &str, group: &[&Leak]) -> Finding {
    let f = group.iter().max_by_key(|f| rank(&f.confidence)).copied().unwrap_or(group[0]);
    let held = noise::secret_file(&f.file) == Some(true);
    let sure = f.confidence == "high" || held;
    let decoded = group
        .iter()
        .find_map(|f| f.tags.iter().find_map(|t| t.strip_prefix("decoded:")))
        .map(|k| format!(" ({k}-encoded)"));
    // Oldest version first: a new commit adds places at the end, so the
    // finding keeps its location, and its id, as history grows.
    let mut places: Vec<(i64, &str)> = Vec::new();
    for version in group.chunk_by(|a, b| a.commit == b.commit).rev() {
        for h in version {
            if !places.contains(&(h.line, h.commit.as_str())) {
                places.push((h.line, &h.commit));
            }
        }
    }
    let versions = group.iter().map(|h| h.commit.as_str()).collect::<HashSet<_>>().len();
    let count = match (places.len(), versions) {
        (1, _) => String::new(),
        (n, 1) => format!("; {n} hits"),
        (n, v) => format!("; {n} hits in {v} versions of the file"),
    };
    let hits: Vec<(&str, i64, &str)> = places.iter().map(|(line, commit)| (f.rule.as_str(), *line, *commit)).collect();
    Finding {
        kind: "secret".into(),
        component: format!("{name}/{}", f.file),
        location: location(&places),
        vuln_id: f.rule.clone(),
        status: if sure { "fail" } else { "warn" }.into(),
        note: format!(
            "{}{}{}{count}",
            f.description,
            decoded.unwrap_or_default(),
            if f.confidence == "high" {
                String::new()
            } else if held {
                " (in a committed env or credential file)".to_string()
            } else {
                format!(" (review: {} confidence rule)", f.confidence)
            }
        ),
        fix_cmd: fix(repo, &f.file, &hits, !sure),
        ..Default::default()
    }
}

/// A generic rule's hits in a repo's tests as one finding, at [`TESTS`]:
/// its note names every file and line. It asks for review.
pub fn test_finding(name: &str, repo: &str, group: &[&Leak]) -> Finding {
    let f = group.iter().max_by_key(|f| rank(&f.confidence)).copied().unwrap_or(group[0]);
    // Each file's versions (oldest first) and their lines.
    let mut files: Vec<(&str, Versions)> = Vec::new();
    for h in group.iter().rev() {
        let i = match files.iter().position(|(file, _)| *file == h.file) {
            Some(i) => i,
            None => {
                files.push((&h.file, Vec::new()));
                files.len() - 1
            }
        };
        let versions = &mut files[i].1;
        match versions.iter_mut().find(|(c, _)| *c == h.commit) {
            Some((_, lines)) if !lines.contains(&h.line) => lines.push(h.line),
            Some(_) => {}
            None => versions.push((&h.commit, vec![h.line])),
        }
    }
    files.sort_by(|a, b| a.0.cmp(b.0));
    let lines_of = |versions: &[(&str, Vec<i64>)]| {
        let mut all: Vec<i64> = versions.iter().flat_map(|(_, l)| l.iter().copied()).collect();
        all.sort_unstable();
        all.dedup();
        all
    };
    let hits: usize = files.iter().map(|(_, v)| lines_of(v).len()).sum();
    let named: Vec<String> = files
        .iter()
        .map(|(file, versions)| {
            let lines: Vec<String> = lines_of(versions).iter().map(i64::to_string).collect();
            format!("{file} (line{} {})", if lines.len() == 1 { "" } else { "s" }, lines.join(", "))
        })
        .collect();
    Finding {
        kind: "secret".into(),
        component: name.to_string(),
        location: TESTS.into(),
        vuln_id: f.rule.clone(),
        status: "warn".into(),
        note: format!(
            "{} (in tests; review: {} confidence rule); {hits} line{} in {} file{}: {}",
            f.description,
            f.confidence,
            if hits == 1 { "" } else { "s" },
            files.len(),
            if files.len() == 1 { "" } else { "s" },
            named.join("; ")
        ),
        fix_cmd: tests_fix(repo, &f.rule, &files),
        ..Default::default()
    }
}

/// What to do about a rule's hits in a repo's tests: look at the lines,
/// and if none is real, leave the files out of that rule's findings.
fn tests_fix(repo: &str, rule: &str, files: &[(&str, Versions)]) -> String {
    use crate::checks::supply_chain::quote;
    let mut out = vec![
        format!(
            "# {rule} in {} test file{} (generic rule: review): test values, unless one is real.",
            files.len(),
            if files.len() == 1 { "" } else { "s" }
        ),
        "# If one is real: rotate it first, then take it out of history with git filter-repo --sensitive-data-removal."
            .to_string(),
        format!("repo={}", sh_path(repo)),
        String::new(),
        "# 1. Show the lines".to_string(),
    ];
    for (file, versions) in files {
        for (commit, lines) in versions {
            let lines: Vec<String> = lines.iter().map(|l| format!("{l}p")).collect();
            out.push(format!(
                "git -C \"$repo\" show {} | sed -n {}",
                quote(&format!("{commit}:{file}")),
                quote(&lines.join(";"))
            ));
        }
    }
    let paths: Vec<String> = files.iter().map(|(file, _)| quote(&format!("/{file}"))).collect();
    out.extend([
        String::new(),
        "# If none is: leave these files out of this rule's findings".to_string(),
        format!("printf '\\n[secret {rule}]\\n' >> \"$repo/{}\"", crate::checks::ignore::FILE),
        format!("printf '%s\\n' {} >> \"$repo/{}\"", paths.join(" "), crate::checks::ignore::FILE),
    ]);
    out.join("\n")
}

/// `line 12, commit abc; line 40, commit def`: the first [`PLACES`] of a
/// finding's (line, commit) places.
pub fn location(places: &[(i64, &str)]) -> String {
    let shown: Vec<String> =
        places.iter().take(PLACES).map(|(line, commit)| format!("line {line}, commit {commit}")).collect();
    shown.join("; ")
}

/// The (line, commit) places a [`location`] names.
pub fn places(location: &str) -> Vec<(i64, String)> {
    location
        .split("; ")
        .filter_map(|p| {
            let (line, commit) = p.strip_prefix("line ")?.split_once(", commit ")?;
            Some((line.parse().ok()?, commit.to_string()))
        })
        .collect()
}

/// Why history files went unread, and the commands that read them, one a
/// line: a deep scan of the one repo for those out of time or too big,
/// `git backfill` for a partial clone's.
fn unread_note(u: &Unread, repo: &str, deep: bool) -> (String, String) {
    let mut why = Vec::new();
    if u.late > 0 {
        why.push(format!("{} not reached in this scan's time", u.late));
    }
    if u.too_big > 0 {
        why.push(format!("{} over {} MB", u.too_big, if deep { DEEP_MAX_BLOB } else { MAX_BLOB } >> 20));
    }
    if u.missing > 0 {
        why.push(format!("{} missing from this partial clone", u.missing));
    }
    let r = sh_path(repo);
    let mut note = why.join(", ");
    let mut run = Vec::new();
    if u.missing > 0 {
        note.push_str(". Download them (git 2.49+), then scan again");
        run.push(format!("git -C {r} backfill"));
    }
    if !deep && u.late + u.too_big > 0 {
        note.push_str(&format!(
            ". Scan this repo on its own, with files up to {} MB and no time limit",
            DEEP_MAX_BLOB >> 20
        ));
        run.push(format!("wpantry scan --path {r} --no-machine --deep"));
    } else if deep && u.late > 0 {
        note.push_str(". The next scan goes on from here");
    }
    (note, run.join("\n"))
}

/// What to do about secrets found in one file of a repo's history, as a
/// script to read and run a step at a time: show the line each secret is
/// on, then, if one is real (and rotated), rewrite history without it in
/// a fresh mirror clone and force-push; if none is, add the file to the
/// repo's .pantryignore. The secret itself is never in it: it is pasted
/// at a prompt with echo off. `repo` is a `~/…` path, `hits` the rule,
/// line and commit of each, and `review` whether only lower-confidence
/// rules hit.
pub fn fix(repo: &str, file: &str, hits: &[(&str, i64, &str)], review: bool) -> String {
    use crate::checks::supply_chain::quote;
    let one = hits.len() == 1;
    let mut by_commit: Vec<(&str, Vec<i64>)> = Vec::new();
    for (_, line, commit) in hits {
        match by_commit.iter_mut().find(|(c, _)| c == commit) {
            Some((_, lines)) if !lines.contains(line) => lines.push(*line),
            Some(_) => {}
            None => by_commit.push((commit, vec![*line])),
        }
    }
    let mut rules: Vec<&str> = hits.iter().map(|(rule, _, _)| *rule).collect();
    rules.sort_unstable();
    rules.dedup();
    let section = match rules[..] {
        [rule] => format!("[secret {rule}]"),
        _ => "[secret]".to_string(),
    };
    let review = if review { " (generic rules: review)" } else { "" };
    let mut out = vec![
        if one {
            format!("# If it's real{review}: rotate it first, then take it out of history.")
        } else {
            format!(
                "# {} hits in {file}{review}. If any is real: rotate it first, then take it out of history.",
                hits.len()
            )
        },
        "# This rewrites history: warn everyone with a clone, and re-clone afterwards. Needs git-filter-repo 2.47+."
            .to_string(),
        format!("repo={}", sh_path(repo)),
        String::new(),
        format!("# 1. Show the line{} the secret is on", if one { "" } else { "s" }),
    ];
    for (commit, lines) in by_commit.iter().take(3) {
        let lines: Vec<String> = lines.iter().map(|l| format!("{l}p")).collect();
        out.push(format!(
            "git -C \"$repo\" show {} | sed -n {}",
            quote(&format!("{commit}:{file}")),
            quote(&lines.join(";"))
        ));
    }
    out.extend([
        String::new(),
        if one {
            "# 2. Paste the secret: it isn't shown, or kept in your shell history".to_string()
        } else {
            "# 2. Paste each secret: run these two lines once for each".to_string()
        },
        "printf 'Secret: '; stty -echo; read -r SECRET; stty echo; echo".to_string(),
        "printf '%s==>REDACTED\\n' \"$SECRET\" >> ~/.pantry-redact; unset SECRET".to_string(),
        String::new(),
        "# 3. Rewrite history in a fresh mirror clone, push it, and clean up".to_string(),
        "git clone --mirror \"$(git -C \"$repo\" remote get-url origin)\" ~/.pantry-rewrite.git".to_string(),
        "git -C ~/.pantry-rewrite.git filter-repo --sensitive-data-removal --replace-text ~/.pantry-redact".to_string(),
        "git -C ~/.pantry-rewrite.git push --force --mirror origin".to_string(),
        "rm -rf ~/.pantry-redact ~/.pantry-rewrite.git".to_string(),
        String::new(),
        if one {
            "# If it isn't a secret: leave the file out of this rule's findings".to_string()
        } else {
            format!(
                "# If none is: leave the file out of {} findings",
                if rules.len() == 1 { "this rule's" } else { "the secret rules'" }
            )
        },
        format!(
            "printf '\\n{section}\\n%s\\n' {} >> \"$repo/{}\"",
            quote(&format!("/{file}")),
            crate::checks::ignore::FILE
        ),
    ]);
    out.join("\n")
}

/// The repo and file a secret's [`fix`] is for, read back from it.
pub fn fix_target(fix: &str) -> Option<(String, String)> {
    let split = crate::remediation::shlex_split;
    let repo =
        fix.lines().find_map(|l| l.strip_prefix("repo=").and(split(l)))?.first()?.strip_prefix("repo=")?.to_string();
    let show = fix.lines().find(|l| l.starts_with("git -C \"$repo\" show "))?;
    let words = split(show)?;
    let (_, file) = words.get(4)?.split_once(':')?;
    Some((repo, file.to_string()))
}

/// A path for the shell: quoted, with a leading `~/` left outside the
/// quotes so it still expands.
fn sh_path(p: &str) -> String {
    use crate::checks::supply_chain::quote;
    match p.strip_prefix("~/") {
        Some(rest) => format!("~/{}", quote(rest)),
        None => quote(p),
    }
}

#[cfg(test)]
#[path = "leaks_tests.rs"]
mod tests;
