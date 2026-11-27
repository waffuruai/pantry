//! `scan project --changes`: only what a commit or a pull request adds.
//!
//! The files a change adds, copies, modifies, renames or retypes are read
//! from git's objects, at the version the change records: the index
//! `git commit` is about to write ([`Changes::Staged`], `GIT_INDEX_FILE`
//! honoured), or a revision ([`Changes::Range`], against its merge base
//! with a base). The working tree and the index are never written, nor
//! anything else in the repo: every git command here only reads, with
//! optional locks off and no lazy fetch.
//!
//! Each file is scanned for secrets in memory. The dependency files among
//! them, and the repo's `.pantryignore` at that version, are written to a
//! private temporary folder for the lockfile readers, which want files;
//! their findings name the repo's paths. Nothing is kept: the caller shows
//! the [`Outcome`] and records no run.

use crate::checks::secrets::Scanner;
use crate::checks::supply_chain::{install_scripts, leaks, projects, repos};
use crate::checks::{Outcome, Scan, ignore, severity};
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::utils::files::{command_path, short};
use crate::utils::temp::TempDir;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The largest file read; a bigger one is reported not checked.
pub const MAX_FILE: u64 = leaks::MAX_BLOB;

/// What `--changes` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Changes {
    /// `staged`: the index.
    Staged,
    /// `<base>[...<head>]`: from the merge base of `base` and `head` to `head`.
    Range { base: String, head: String },
}

impl Changes {
    /// `staged`, `main`, `main...HEAD`, `origin/dev...feature`. Two dots
    /// are refused: `git diff A..B` compares the tips, not what B adds.
    pub fn parse(spec: &str) -> std::result::Result<Changes, String> {
        let spec = spec.trim();
        if spec == "staged" {
            return Ok(Changes::Staged);
        }
        let (base, head) = match spec.split_once("...") {
            Some((b, h)) => (b, if h.is_empty() { "HEAD" } else { h }),
            None if spec.contains("..") => {
                return Err(format!(
                    "'{spec}': two dots compare the tips; for what a branch adds, write BASE...HEAD (three dots) or BASE"
                ));
            }
            None => (spec, "HEAD"),
        };
        let bad = |r: &str| r.is_empty() || r.starts_with('-') || r.contains("...");
        if bad(base) || bad(head) {
            return Err(format!("'{spec}': expected staged, BASE or BASE...HEAD"));
        }
        Ok(Changes::Range { base: base.into(), head: head.into() })
    }

    /// What the report calls them.
    pub fn describe(&self) -> String {
        match self {
            Changes::Staged => "staged files".into(),
            Changes::Range { base, head } if head == "HEAD" => format!("files changed since {base}"),
            Changes::Range { base, head } => format!("files changed in {base}...{head}"),
        }
    }
}

/// One file a change records: its path from the repo's top, and its blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub sha: String,
}

/// What a change records: the files with a path that is safe to name, and
/// the paths refused ([`safe_path`]), which are never read or written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub files: Vec<Change>,
    /// Shown escaped (`{:?}`): they can hold control characters.
    pub refused: Vec<String>,
}

impl Listing {
    fn push(&mut self, path: &[u8], sha: &str) {
        match std::str::from_utf8(path).ok().filter(|p| safe_path(p)) {
            Some(p) => self.files.push(Change { path: p.to_string(), sha: sha.to_string() }),
            None => self.refused.push(format!("{:?}", String::from_utf8_lossy(path))),
        }
    }

    /// Only what is under `prefix` (the scanned folder from the top).
    fn under(mut self, prefix: &str) -> Listing {
        self.files.retain(|c| c.path.starts_with(prefix));
        self
    }
}

/// Whether git's path `p` (from the repo's top, `/`-separated) can be
/// joined under a folder and stay there: relative, every component a plain
/// name (not empty, `.`, `..` or `.git` in any case), no NUL; on Windows
/// also no `\`, `:`, trailing dot or space, or reserved device name. Git
/// stores such names in a crafted tree or index unless fsck is on, and a
/// pull request from a fork can carry one.
pub fn safe_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.contains('\0') {
        return false;
    }
    p.split('/').all(|c| {
        !c.is_empty() && c != "." && c != ".." && !c.eq_ignore_ascii_case(".git") && (!cfg!(windows) || windows_name(c))
    })
}

/// A path component Windows reads as itself: no separator, drive or stream
/// (`\`, `:`), no trailing dot or space (dropped, so `..` or `.git` come
/// back), and no device name (`CON`, `nul.txt`, `COM1`).
pub(crate) fn windows_name(c: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    let stem = c.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    let numbered = (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem[3..].chars().all(|d| d.is_ascii_digit());
    !c.contains(['\\', ':', '<', '>', '"', '|', '?', '*'])
        && !c.ends_with(['.', ' '])
        && !c.chars().any(|ch| (ch as u32) < 32)
        && !DEVICES.contains(&stem.as_str())
        && !numbered
}

/// A repo, read with git's plumbing and nothing that writes.
pub struct Git {
    /// The git found on PATH, spawned by its path (`utils::process::program`).
    git: PathBuf,
    top: PathBuf,
    /// The scanned folder from the top (`web/`), "" at the top.
    prefix: String,
    /// The git variables a hook is given, made absolute: they are read
    /// from the top, not from where wpantry was started.
    env: Vec<(&'static str, OsString)>,
}

/// The variables that place a repo, which a hook sets (`git commit <paths>`
/// points `GIT_INDEX_FILE` at a temporary index).
const PLACES: [&str; 5] = ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"];

impl Git {
    /// The repo `dir` is in; an error (a usage error to the caller) when
    /// it isn't in one or git can't run.
    pub fn open(dir: &Path) -> std::result::Result<Git, String> {
        let cwd = std::env::current_dir().unwrap_or_default();
        let env = PLACES
            .iter()
            .filter_map(|k| {
                let v = std::env::var_os(k).filter(|v| !v.is_empty())?;
                let p = PathBuf::from(&v);
                Some((*k, if p.is_absolute() { v } else { cwd.join(p).into_os_string() }))
            })
            .collect();
        let program = crate::utils::process::program(std::ffi::OsStr::new("git"))
            .map_err(|e| format!("--changes reads a git repo with git, which can't run: {e}"))?;
        let mut git = Git { git: program, top: dir.to_path_buf(), prefix: String::new(), env };
        let out = git
            .run(&["rev-parse", "--show-toplevel", "--show-prefix"])
            .map_err(|e| format!("--changes reads a git repo, and {} isn't in one ({e})", dir.display()))?;
        let text = String::from_utf8_lossy(&out);
        let mut lines = text.lines();
        let top = lines.next().filter(|t| !t.is_empty()).ok_or("--changes needs a work tree, not a bare repo")?;
        git.top = std::fs::canonicalize(top).unwrap_or_else(|_| PathBuf::from(top));
        git.prefix = lines.next().unwrap_or("").to_string();
        Ok(git)
    }

    /// The repo's top folder.
    pub fn top(&self) -> &Path {
        &self.top
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.git);
        cmd.arg("-C").arg(&self.top);
        // Only reads: no index refresh written behind our back, no objects
        // fetched into a partial clone, no pager, no prompt.
        cmd.env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("NO_COLOR", "1");
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        cmd
    }

    /// `git ARGS`'s stdout; its stderr's first line when it fails.
    fn run(&self, args: &[&str]) -> std::result::Result<Vec<u8>, String> {
        let out = self.command().args(args).stdin(Stdio::null()).output().map_err(|e| format!("git can't run: {e}"))?;
        if out.status.success() {
            return Ok(out.stdout);
        }
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err.lines().next().unwrap_or("git failed").trim_start_matches("fatal: ").to_string())
    }

    /// The commit `rev` names, or why it doesn't.
    fn commit(&self, rev: &str) -> std::result::Result<String, String> {
        let out = self.run(&["rev-parse", "--verify", "--quiet", "--end-of-options", &format!("{rev}^{{commit}}")]);
        match out {
            Ok(o) if !o.is_empty() => Ok(String::from_utf8_lossy(&o).trim().to_string()),
            _ => Err(format!(
                "no commit '{rev}' in {} (in CI, fetch it first: git fetch origin {rev}, or check out with full history)",
                short(&self.top.to_string_lossy())
            )),
        }
    }

    /// The files `changes` records under the scanned folder: added, copied,
    /// modified, renamed or retyped regular files (deletions, submodules and
    /// symlinks add no content to scan).
    pub fn changed(&self, changes: &Changes) -> std::result::Result<Listing, String> {
        const DIFF: [&str; 6] =
            ["-z", "--raw", "--no-renames", "--diff-filter=d", "--no-abbrev", "--ignore-submodules=all"];
        // Each git run costs tens of milliseconds: the usual case takes one,
        // and a failure is looked into only once it happens.
        let raw = match changes {
            Changes::Staged => {
                let mut args = vec!["diff-index", "--cached"];
                args.extend(DIFF);
                args.extend(["HEAD", "--"]);
                match self.run(&args) {
                    Ok(raw) => raw,
                    // No commit yet: everything staged is new.
                    Err(_) if self.commit("HEAD").is_err() => {
                        return Ok(parse_ls(&self.run(&["ls-files", "-s", "-z"])?).under(&self.prefix));
                    }
                    Err(e) => return Err(e),
                }
            }
            Changes::Range { base, head } => {
                let mb = match self.run(&["merge-base", "--end-of-options", base, head]) {
                    Ok(mb) => String::from_utf8_lossy(&mb).trim().to_string(),
                    Err(_) => {
                        self.commit(base)?;
                        self.commit(head)?;
                        return Err(format!(
                            "'{base}' and '{head}' have no common ancestor (a shallow clone? fetch more history)"
                        ));
                    }
                };
                let mut args = vec!["diff-tree", "-r"];
                args.extend(DIFF);
                args.extend(["--end-of-options", mb.as_str(), head.as_str(), "--"]);
                self.run(&args)?
            }
        };
        Ok(parse_raw(&raw).under(&self.prefix))
    }

    /// The repo's `.pantryignore` at the version `changes` records, as an
    /// object name `git cat-file` reads: the index's entry (`:path`, which
    /// `GIT_INDEX_FILE` moves), or `head`'s.
    pub fn ignore_file(&self, changes: &Changes) -> String {
        match changes {
            Changes::Staged => format!(":{}", ignore::FILE),
            Changes::Range { head, .. } => format!("{head}:{}", ignore::FILE),
        }
    }

    /// The contents of `shas` (object names), by name, with one `git
    /// cat-file --batch`: a blob over [`MAX_FILE`] as `None`, one missing (a
    /// partial clone's, or a path that isn't there) left out.
    pub fn blobs(&self, shas: &[String]) -> Result<HashMap<String, Option<Vec<u8>>>> {
        let mut out = HashMap::new();
        if shas.is_empty() {
            return Ok(out);
        }
        let mut cmd = self.command();
        cmd.args(["cat-file", "--batch"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child =
            crate::utils::process::spawn(&mut cmd).map_err(|e| Error::Failed(format!("git cat-file: {e}")))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let list: Vec<String> = shas.to_vec();
        let writer = std::thread::spawn(move || {
            for sha in list {
                if writeln!(stdin, "{sha}").is_err() {
                    break;
                }
            }
        });
        let mut r = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut header = Vec::new();
        for sha in shas {
            header.clear();
            if r.read_until(b'\n', &mut header)? == 0 {
                break;
            }
            // `<sha> blob <size>`, or `<sha> missing`.
            let h = String::from_utf8_lossy(&header);
            let Some(size) = h.split_whitespace().nth(2).and_then(|s| s.parse::<u64>().ok()) else { continue };
            let data = if size > MAX_FILE {
                std::io::copy(&mut (&mut r).take(size), &mut std::io::sink())?;
                None
            } else {
                let mut d = Vec::with_capacity(size as usize);
                (&mut r).take(size).read_to_end(&mut d)?;
                Some(d)
            };
            let mut newline = [0u8; 1];
            r.read_exact(&mut newline)?;
            out.insert(sha.clone(), data);
        }
        let _ = child.wait();
        let _ = writer.join();
        Ok(out)
    }
}

/// `git diff-index`/`diff-tree --raw -z`: `:<old mode> <new mode> <old>
/// <new> <status>` NUL `<path>` NUL; the regular files' new blobs.
pub fn parse_raw(raw: &[u8]) -> Listing {
    let mut out = Listing::default();
    let mut parts = raw.split(|&b| b == 0);
    while let (Some(head), Some(path)) = (parts.next(), parts.next()) {
        let head = String::from_utf8_lossy(head);
        let fields: Vec<&str> = head.trim_start_matches(':').split(' ').collect();
        let [_, mode, _, sha, ..] = fields.as_slice() else { continue };
        if regular(mode) && !sha.bytes().all(|b| b == b'0') {
            out.push(path, sha);
        }
    }
    out
}

/// `git ls-files -s -z` (`<mode> <sha> <stage>\t<path>`): the regular
/// files, at stage 0.
fn parse_ls(raw: &[u8]) -> Listing {
    let mut out = Listing::default();
    for rec in raw.split(|&b| b == 0) {
        let Some(tab) = rec.iter().position(|&b| b == b'\t') else { continue };
        let meta = String::from_utf8_lossy(&rec[..tab]);
        let f: Vec<&str> = meta.split(' ').collect();
        if let [mode, sha, "0"] = f.as_slice()
            && regular(mode)
        {
            out.push(&rec[tab + 1..], sha);
        }
    }
    out
}

fn regular(mode: &str) -> bool {
    mode == "100644" || mode == "100755"
}

/// Whether the dependency checks read `path` (a lockfile, a manifest the
/// lockfile readers take, a Gradle build file or catalog), outside the
/// folders a repo scan never enters (`node_modules`, `vendor`, …).
pub fn is_dependency(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split('/').collect();
    let Some(name) = parts.pop() else { return false };
    if parts.iter().any(|p| crate::utils::walk::PRUNE.contains(p)) {
        return false;
    }
    repos::is_lockfile(name) || crate::checks::lockfiles::gradle_build::declared(Path::new(path))
}

/// The scan: secrets in every file of `files`, and the dependency checks
/// (OSV, malicious packages, install scripts) over the dependency files
/// among them. `scan.opts` says offline or not; nothing is recorded.
///
/// `rules` is the secret scanner [`rules`] began compiling, which takes
/// about as long as git's listing: they run side by side.
pub fn run(
    mut scan: Scan,
    git: &Git,
    changes: &Changes,
    listing: &Listing,
    rules: std::thread::JoinHandle<Result<Scanner>>,
) -> Result<Outcome> {
    let top = git.top().to_path_buf();
    let files = &listing.files;
    scan.status(&format!("Reading the {}", changes.describe()));
    let ignore_sha = Some(git.ignore_file(changes));
    let mut shas: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for sha in files.iter().map(|c| &c.sha).chain(ignore_sha.as_ref()) {
        if seen.insert(sha.clone()) {
            shas.push(sha.clone());
        }
    }
    let blobs = git.blobs(&shas)?;
    scan.count(&changes.describe(), (files.len() + listing.refused.len()) as i64);
    refused(&mut scan, &listing.refused);

    // The dependency files, and the ignore file, as files for their readers.
    let tmp = TempDir::new("changes")?;
    let staged = std::fs::canonicalize(tmp.path()).unwrap_or_else(|_| tmp.path().to_path_buf());
    if let Some(Some(data)) = ignore_sha.as_ref().and_then(|s| blobs.get(s)) {
        std::fs::write(staged.join(ignore::FILE), data)?;
    }
    let deps: Vec<&Change> = files.iter().filter(|c| is_dependency(&c.path)).collect();
    for c in &deps {
        if let Some(Some(data)) = blobs.get(&c.sha) {
            let to = staged.join(&c.path);
            if let Some(dir) = to.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&to, data)?;
        }
    }
    let name = short(&top.to_string_lossy());
    if !deps.is_empty() {
        let repos = vec![(name.clone(), staged.clone())];
        scan.repos = repos.clone();
        scan.use_sources();
        scan.load_kev()?;
        projects::projects(&mut scan, &repos)?;
        install_scripts::install_scripts(&mut scan, &repos, &[]);
    }

    // Secrets, in memory, at the repo's paths.
    scan.status("Scanning the changed files for secrets");
    let scanner = rules.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))?;
    let mut too_big = 0;
    let mut missing = 0;
    let mut todo: Vec<(PathBuf, &[u8])> = Vec::new();
    for c in files {
        let path = top.join(&c.path);
        match blobs.get(&c.sha) {
            None => missing += 1,
            Some(None) => too_big += 1,
            Some(Some(data)) if !scanner.skips_path(&path.to_string_lossy()) => todo.push((path, data)),
            Some(Some(_)) => {}
        }
    }
    let width = scan.opts.jobs.unwrap_or_else(crate::utils::parallel::cores);
    let found =
        crate::utils::parallel::par_map(&todo, width, |(path, data)| scanner.scan(data, &path.to_string_lossy(), None));
    scan.count("files scanned for secrets", todo.len() as i64);
    for ((path, _), hits) in todo.iter().zip(found) {
        let mut lines = HashSet::new();
        for h in hits {
            if lines.insert((h.rule.clone(), h.start_line)) {
                let sure = leaks::confidence(h.confidence) == "high";
                let decoded = h.tags.iter().find_map(|t| t.strip_prefix("decoded:")).map(String::from);
                scan.add(secret(path, &h.rule, &h.description, h.start_line, sure, decoded, changes));
            }
        }
    }
    if too_big > 0 {
        scan.unchecked(
            &format!("secrets in {too_big} changed files over {} MB", MAX_FILE >> 20),
            "bigger than the secret scan reads",
        );
    }
    if missing > 0 {
        scan.unchecked(
            &format!("{missing} changed files"),
            "their contents aren't in this clone (a partial clone): fetch them, then scan again",
        );
    }

    // The findings name the repo's files, not the temporary copies.
    let at = command_path(&staged);
    let raw = staged.to_string_lossy().into_owned();
    let shown = command_path(&top);
    for f in &mut scan.findings {
        relocate(f, &[at.as_str(), raw.as_str()], &shown);
    }
    // The ignore files: the repo's at the change's version.
    scan.repos = vec![(name, top.clone())];
    ignore::apply_files(&mut scan, &ignore::user_file(), &|_| staged.join(ignore::FILE));
    if !deps.is_empty() {
        scan.status("Rating the findings");
        severity::enrich(&scan.cache, scan.net, scan.opts.offline, &mut scan.findings);
    }
    drop(tmp);
    let outcome = Outcome {
        scan_id: 0,
        findings: scan.findings,
        counts: scan.counts,
        unfixed: scan.unfixed,
        unknown_licenses: scan.unknown_licenses,
    };
    // The answers fetched stay cached for the next scan; a cache that
    // can't be written loses them, not the scan.
    if let Err(e) = scan.cache.close() {
        (scan.note)(&format!("the advisory cache couldn't be saved ({e}); this scan's answers weren't kept"));
    }
    Ok(outcome)
}

/// The paths refused ([`safe_path`]): none is read, written or scanned, so
/// the change fails (a checkout would write outside the repo or into
/// `.git`, which no honest change asks) and they are listed as not checked.
fn refused(scan: &mut Scan, paths: &[String]) {
    if paths.is_empty() {
        return;
    }
    for p in paths {
        scan.add(Finding {
            kind: "config".into(),
            component: p.clone(),
            vuln_id: UNSAFE_PATH.into(),
            status: "fail".into(),
            note: "a path no checkout should write (absolute, `..`, `.git`, or a name this system reserves): not read or scanned".into(),
            fix_cmd: "Find out who made this tree or index entry, and take the path out of the change".into(),
            ..Default::default()
        });
    }
    scan.unchecked(
        &format!("{} changed files with unsafe paths", paths.len()),
        "refused: not read, written or scanned for secrets or dependencies",
    );
}

/// The id of a finding for a path [`safe_path`] refuses.
pub const UNSAFE_PATH: &str = "UNSAFE-PATH";

/// The secret scanner, the bundled rules and the user's (`--secret-rules`),
/// compiled on a thread of its own while git lists the change.
pub fn rules(policy: &crate::checks::Policy) -> std::thread::JoinHandle<Result<Scanner>> {
    let extra = policy.secret_rules();
    std::thread::spawn(move || leaks::Rules::new(extra?).scanner())
}

/// A secret in a file the change records.
fn secret(
    path: &Path,
    rule: &str,
    description: &str,
    line: usize,
    sure: bool,
    decoded: Option<String>,
    changes: &Changes,
) -> Finding {
    let file = short(&path.to_string_lossy());
    let decoded = decoded.map(|k| format!(" ({k}-encoded)")).unwrap_or_default();
    let undo = match changes {
        Changes::Staged => "unstage it and take it out before committing",
        Changes::Range { .. } => "take it out of the change (and out of its commits' history)",
    };
    Finding {
        kind: "secret".into(),
        component: file.clone(),
        location: format!("line {line}"),
        vuln_id: rule.into(),
        status: if sure { "fail" } else { "warn" }.into(),
        note: format!(
            "{description}{decoded}, in the {}{}",
            changes.describe(),
            if sure { String::new() } else { " (review: a lower-confidence rule)".into() }
        ),
        fix_cmd: format!(
            "{}Rotate it where it was issued, then {undo} ({file}, line {line}). A false positive: list the file under [secret] in .pantryignore",
            if sure { "" } else { "If it's real: " },
        ),
        ..Default::default()
    }
}

/// `f`'s paths under one of `from` (the temporary copies) as under `to`
/// (the repo); a path in a command is quoted when the repo's needs it.
pub fn relocate(f: &mut Finding, from: &[&str], to: &str) {
    let swap = |s: &str| from.iter().fold(s.to_string(), |s, x| if x.is_empty() { s } else { s.replace(x, to) });
    f.component = swap(&f.component);
    f.location = swap(&f.location);
    f.note = swap(&f.note);
    f.fix_cmd = f
        .fix_cmd
        .split(' ')
        .map(|w| {
            if from.iter().any(|x| !x.is_empty() && w.starts_with(x)) {
                crate::checks::supply_chain::quote(&swap(w))
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
}

/// Whether `files` holds a dependency file: then the scan needs the
/// advisory cache and the network.
pub fn touches_dependencies(files: &[Change]) -> bool {
    files.iter().any(|c| is_dependency(&c.path))
}

#[cfg(test)]
#[path = "changes_tests.rs"]
mod tests;
