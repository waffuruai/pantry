//! Editing the ignore files for `wpantry ignore`: work out the narrowest
//! rule the file format can say for one finding, append it to your file or
//! a repo's `.pantryignore`, list what the files hold, and take a rule out
//! again. [`crate::checks::ignore`] reads the files; this module only
//! writes what that reader will honour, and checks that it does.
//!
//! What a rule can say is what the format has: a path pattern under a
//! section for a check (`[secret]`) or for one of its rules or advisories
//! (`[secret github-pat]`). It can't name a package, a line or a version,
//! so the narrowest rule for a finding is its path under its own section,
//! and a finding with no path (a machine setting) can't be ignored here.
//!
//! Every write is checked against the real filter first: the new rule must
//! leave the finding out, must not leave out any other finding of the
//! latest scan, and must not add a line the reader can't use. A file is
//! changed only by appending a block (a blank line, the section header, the
//! pattern and a comment naming the finding, when and why), or by deleting
//! exactly the lines of a block this command wrote, or one rule line. Every
//! other byte, line ending and comment stays. The file is replaced
//! atomically, and never through a link that leaves the repo or the
//! config folder.
//!
//! ```text
//! # an existing file, then the block `ignore add` appends:
//!
//! [secret github-pat]
//! /config/legacy.py
//! # wpantry ignore: F-3fa9c01b2e | 2026-11-25 14:03 UTC | revoked in 2025
//! ```
//!
//! TODO: a `--expires` date on a rule, once the file format can carry one
//! (`specs/design/pantryignore.md`, "Not done").

use crate::checks::ignore::{self, FILE, Ignore, InScope, MAX, Skip};
use crate::checks::supply_chain::leaks;
use crate::error::Error;
use crate::finding::Finding;
use crate::history::stamp;
use crate::remediation::queue::is_id;
use crate::utils::files::short;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The comment line that follows each rule this command writes.
pub const MARK: &str = "# wpantry ignore: ";
/// The longest reason kept.
pub const REASON_MAX: usize = 300;

/// Which file a rule goes in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Your ignore file: `$XDG_CONFIG_HOME/wpantry/ignore`.
    User,
    /// The repo's `.pantryignore`.
    Repo,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Repo => "repo",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "user" => Some(Scope::User),
            "repo" => Some(Scope::Repo),
            _ => None,
        }
    }

    fn skip(self) -> Skip {
        match self {
            Scope::User => Skip::User,
            Scope::Repo => Skip::Repo,
        }
    }
}

/// A request that can't be done, with a stable code for a program and a
/// sentence for a person. Nothing was changed.
#[derive(Clone, Debug, PartialEq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

/// Why an operation stopped: refused (exit 1) or failed (exit 3).
#[derive(Debug)]
pub enum Stop {
    Refused(Refused),
    Failed(Error),
}

impl From<std::io::Error> for Stop {
    fn from(e: std::io::Error) -> Stop {
        Stop::Failed(Error::Io(e))
    }
}

fn refuse<T>(code: &'static str, message: impl Into<String>) -> Result<T, Stop> {
    Err(Stop::Refused(Refused { code, message: message.into() }))
}

/// Where things are: your home (for `~/`) and your ignore file.
#[derive(Clone, Debug)]
pub struct Env {
    pub home: PathBuf,
    pub user_file: PathBuf,
    /// The folders the latest scan looked down from: each `--path` it was
    /// given, else home. A repo's file is the one that scan read, which
    /// depends on where it started ([`repo_of`]). Empty when no scan says.
    pub roots: Vec<PathBuf>,
}

impl Env {
    /// This machine's, before any scan is known.
    pub fn real() -> Env {
        Env { home: crate::utils::files::home(), user_file: ignore::user_file(), roots: Vec::new() }
    }

    /// With the roots of the scan whose findings are being acted on:
    /// `paths` as that scan recorded them (none: it scanned home).
    pub fn scanned(mut self, paths: &[PathBuf]) -> Env {
        let roots: Vec<PathBuf> = if paths.is_empty() { vec![self.home.clone()] } else { paths.to_vec() };
        // As the scan resolved them, and as given: a finding's path is under one spelling or the other.
        self.roots = roots.iter().flat_map(|r| [std::fs::canonicalize(r).ok(), Some(r.clone())]).flatten().collect();
        self.roots.dedup();
        self
    }
}

/// One ignore file: whose it is and where.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub scope: Scope,
    pub file: PathBuf,
}

impl Target {
    pub fn user(env: &Env) -> Target {
        Target { scope: Scope::User, file: env.user_file.clone() }
    }

    pub fn repo(root: &Path) -> Target {
        Target { scope: Scope::Repo, file: root.join(FILE) }
    }

    /// What identifies the file in rule ids and in the log: your file, or
    /// the repo's file by its real path.
    pub fn key(&self) -> String {
        match self.scope {
            Scope::User => "user".into(),
            Scope::Repo => format!("repo:{}", file_key(&self.file)),
        }
    }
}

/// A file's real location: its directory resolved (links, `/var` against
/// `/private/var`), its own name kept.
pub fn file_key(path: &Path) -> String {
    let resolved =
        path.parent().and_then(|d| std::fs::canonicalize(d).ok()).zip(path.file_name()).map(|(d, n)| d.join(n));
    crate::utils::files::strip_verbatim(&resolved.as_deref().unwrap_or(path).to_string_lossy())
}

/// What the comment after a rule says about it.
#[derive(Clone, Debug, PartialEq)]
pub struct Mark {
    /// The finding the rule was written for.
    pub finding_id: String,
    pub when: String,
    pub reason: String,
}

/// One pattern line of an ignore file.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// `R-` and ten hex digits of the file, the section, the pattern and
    /// which copy of it this is: the same until the line is edited.
    pub id: String,
    pub scope: Scope,
    /// The file's [`file_key`].
    pub file: String,
    /// 1-based.
    pub line: usize,
    /// The header it sits under, as `check id` (`""` before any header).
    pub section: String,
    /// False under a header the scan can't read: the rule applies to nothing.
    pub active: bool,
    pub pattern: String,
    /// Set for a rule this command wrote.
    pub mark: Option<Mark>,
    index: usize,
}

fn norm(inner: &str) -> String {
    inner.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn rule_id(key: &str, section: &str, pattern: &str, nth: usize) -> String {
    let digest = crate::utils::sha256::hex(format!("{key}|{section}|{pattern}|{nth}").as_bytes());
    format!("R-{}", &digest[..10])
}

fn parse_mark(rest: &str) -> Option<Mark> {
    let mut parts = rest.splitn(3, " | ");
    let finding_id = parts.next()?.trim();
    is_id(finding_id).then(|| Mark {
        finding_id: format!("F-{}", finding_id[2..].to_ascii_lowercase()),
        when: parts.next().unwrap_or("").trim().to_string(),
        reason: parts.next().unwrap_or("").trim().to_string(),
    })
}

/// The pattern lines of a file's text, read as [`Ignore::parse`] reads
/// it: a line is a comment, a header or a pattern, in that order. A
/// comment that is a mark, right after a rule, belongs to it.
pub fn rules_of(text: &str, target: &Target) -> Vec<Rule> {
    let (key, file) = (target.key(), file_key(&target.file));
    let mut out: Vec<Rule> = Vec::new();
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let (mut section, mut active) = (String::new(), true);
    for (i, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if ignore::is_skippable(line) {
            if let Some(rest) = line.strip_prefix(MARK)
                && let Some(last) = out.last_mut()
                && last.index + 1 == i
                && last.mark.is_none()
            {
                last.mark = parse_mark(rest);
            }
            continue;
        }
        if let Some(inner) = ignore::header(line) {
            section = norm(inner);
            active = ignore::section(inner).is_ok();
            continue;
        }
        if ignore::is_pattern(line) {
            let nth = seen.entry((section.clone(), line.to_string())).or_insert(0);
            let id = rule_id(&key, &section, line, *nth);
            *nth += 1;
            out.push(Rule {
                id,
                scope: target.scope,
                file: file.clone(),
                line: i + 1,
                section: section.clone(),
                active,
                pattern: line.to_string(),
                mark: None,
                index: i,
            });
        }
    }
    out
}

// Files ---------------------------------------------------------------

/// A file opened to be changed.
struct Open {
    /// Where the new text goes: the file, or what a link in the config
    /// folder points at.
    write_to: PathBuf,
    text: String,
    perms: Option<std::fs::Permissions>,
}

/// Read a target's text for editing, or start an empty one. Refuses a link
/// that leaves the repo or the config folder (a repo's link is never read
/// by a scan, so none is written through), anything that isn't a regular
/// file, a file over the size the reader takes, and text that isn't UTF-8.
/// `create` makes the config folder, private, when it's missing.
fn open(t: &Target, create: bool) -> Result<Option<Open>, Stop> {
    let shown = short(&t.file.to_string_lossy());
    let mut write_to = t.file.clone();
    match std::fs::symlink_metadata(&t.file) {
        Ok(m) if m.file_type().is_symlink() => {
            if t.scope == Scope::Repo {
                return refuse(
                    "unsafe-file",
                    format!("{shown} is a link, which a scan never reads, so nothing is written through it"),
                );
            }
            let real = std::fs::canonicalize(&t.file).ok();
            let dir = t.file.parent().and_then(|d| std::fs::canonicalize(d).ok());
            match (real, dir) {
                (Some(real), Some(dir)) if real.starts_with(&dir) && real.is_file() => write_to = real,
                _ => {
                    return refuse(
                        "unsafe-file",
                        format!(
                            "{shown} is a link that leaves its folder (or points at nothing): edit its target by hand"
                        ),
                    );
                }
            }
        }
        Ok(m) if !m.file_type().is_file() => {
            return refuse("unsafe-file", format!("{shown} is not a regular file"));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            let dir = t.file.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
            if !dir.is_dir() {
                make_dir(dir)?;
            }
            return Ok(Some(Open { write_to, text: String::new(), perms: None }));
        }
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::metadata(&write_to)?;
    if meta.len() > MAX {
        return refuse("too-big", format!("{shown} is over {} bytes, which a scan won't read: trim it first", MAX));
    }
    let Ok(text) = String::from_utf8(std::fs::read(&write_to)?) else {
        return refuse("not-utf8", format!("{shown} isn't UTF-8 text: edit it by hand"));
    };
    Ok(Some(Open { write_to, text, perms: Some(meta.permissions()) }))
}

/// A private directory (and any missing parents).
fn make_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Replace a file with `text` in one step: a temporary file beside it,
/// private for your own file, synced, then renamed over it. An existing
/// file keeps its permissions.
fn write_atomic(o: &Open, private: bool, text: &str) -> std::io::Result<()> {
    let dir = o.write_to.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = o.write_to.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = dir.join(format!(".{name}.wpantry-{}-{stamp}.tmp", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            opts.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let done = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        if let Some(p) = &o.perms {
            f.set_permissions(p.clone())?;
        }
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &o.write_to)
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// The line ending the file uses where it ends: `\r\n`, else `\n`.
fn eol(text: &str) -> &'static str {
    match text.rfind('\n') {
        Some(i) if text[..i].ends_with('\r') => "\r\n",
        _ => "\n",
    }
}

// Adding --------------------------------------------------------------

/// What `ignore add` is asked.
pub struct Request<'a> {
    pub finding: &'a Finding,
    /// The latest scan's findings: what a new rule must not leave out.
    pub all: &'a [Finding],
    pub scope: Scope,
    /// Every place the same rule or advisory was found for the same
    /// package (one rule each), not only this one.
    pub all_places: bool,
    pub reason: Option<&'a str>,
    pub now: f64,
}

/// One rule written.
#[derive(Clone, Debug, PartialEq)]
pub struct Written {
    pub id: String,
    pub section: String,
    pub pattern: String,
    /// The finding it was written for: the one asked, for every rule of
    /// an `--all-places` run (so removing it removes them all).
    pub finding_id: String,
    /// The place it names, as the finding carries it.
    pub place: String,
}

/// A finding of the same package that this run didn't cover, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct LeftOut {
    pub finding_id: String,
    pub why: String,
}

#[derive(Debug)]
pub enum Added {
    Wrote {
        target: Target,
        rules: Vec<Written>,
        left_out: Vec<LeftOut>,
    },
    /// Nothing to write: the file already leaves it out.
    Already {
        target: Target,
    },
}

/// A reason as the comment keeps it: one line, plain.
pub fn clean_reason(reason: &str) -> Result<String, Refused> {
    let r = reason.trim();
    if r.chars().any(char::is_control) {
        return Err(Refused { code: "bad-reason", message: "the reason must be one line of plain text".into() });
    }
    if r.chars().count() > REASON_MAX {
        return Err(Refused { code: "bad-reason", message: format!("the reason is over {REASON_MAX} characters") });
    }
    Ok(r.to_string())
}

/// The repo a path is in, as the scan that found it sees it: the first
/// folder with a `.git` on the way down from that scan's root to the path.
/// A scan looks only below where it starts, stops at the first `.git` it
/// meets and reads that folder's `.pantryignore` alone, so:
///
/// - a submodule or a checkout nested in a repo is part of the repo around
///   it, when the scan started at or above that repo;
/// - a repo above the folder the scan was pointed at (`--path dev/app`
///   under `dev/.git`) is not the scan's: `dev/app` is.
///
/// What counts as a repo is the scan's rule ([`repos::discover`]): a `.git`
/// folder with a `HEAD`, or a `.git` file at the scan's root. With no repo
/// on the way (a folder scanned as one project), none: a repo's file is a
/// repo's. With no scan to ask (`roots` empty, or the path under none of them), the
/// nearest folder at or above the path with a `.git`.
fn repo_of(path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let nearest =
        || path.ancestors().find(|a| std::fs::symlink_metadata(a.join(".git")).is_ok()).map(Path::to_path_buf);
    // The innermost root holding the path: the scan that walked it.
    let Some(root) = roots.iter().filter(|r| path.starts_with(r)).max_by_key(|r| r.components().count()) else {
        return nearest();
    };
    let below = path.strip_prefix(root).unwrap_or(Path::new(""));
    let mut dir = root.clone();
    let mut steps = below.components();
    for level in 0.. {
        if let Ok(git) = std::fs::symlink_metadata(dir.join(".git")) {
            let repo = (git.is_dir() && dir.join(".git/HEAD").is_file()) || (level == 0 && !git.is_dir());
            // Any `.git` ends the scan's descent, a repo or not.
            return repo.then_some(dir);
        }
        match steps.next() {
            Some(step) => dir.push(step),
            None => break,
        }
    }
    None
}

/// A path as a pattern: glob characters and a trailing space escaped.
fn text_of(rel: &Path) -> Result<String, Refused> {
    let joined = ignore::joined(rel);
    if joined.chars().any(char::is_control) {
        return Err(Refused {
            code: "odd-path",
            message: "the path has a control character in it, which a line of the file can't hold".into(),
        });
    }
    let mut s = ignore::escape(&joined);
    if s.ends_with(' ') {
        s.truncate(s.len() - 1);
        s.push_str("\\ ");
    }
    Ok(s)
}

/// Where a finding is, as a pattern for `scope`'s file, and the repo
/// root for a repo's.
struct Placed {
    pattern: String,
    root: Option<PathBuf>,
}

fn place(f: &Finding, scope: Scope, env: &Env) -> Result<Placed, Refused> {
    let no = |code, message: String| Err(Refused { code, message });
    if f.location == leaks::TESTS {
        return no(
            "grouped",
            format!(
                "{} is one finding for a rule's hits in many of the repo's test files; the file format can only name the whole repo for it, which would also hide that rule in the repo's other files. Skip the test files by hand",
                f.id()
            ),
        );
    }
    let Some(abs) =
        [f.location.as_str(), f.component.as_str()].into_iter().find_map(|p| ignore::absolute(p, &env.home))
    else {
        let hint = if f.kind == "posture" {
            " A security setting is skipped in the posture policy (`skip = [\"ID\"]` in posture.toml, or --no-posture)."
        } else {
            ""
        };
        return no(
            "no-path",
            format!(
                "{} ({} {}) names no file or folder, and an ignore file skips by path.{hint}",
                f.id(),
                f.kind,
                f.component
            ),
        );
    };
    match scope {
        Scope::Repo => {
            let Some(root) = repo_of(&abs, &env.roots) else {
                return no(
                    "not-in-repo",
                    format!(
                        "{} is not inside a git repo ({}): a repo's .pantryignore can't hold it. Use --scope user",
                        f.id(),
                        short(&abs.to_string_lossy())
                    ),
                );
            };
            let rel = abs.strip_prefix(&root).unwrap_or(&abs);
            if rel.as_os_str().is_empty() {
                return no(
                    "names-the-repo",
                    format!("{} is about the repo as a whole, which a pattern relative to its root can't name", f.id()),
                );
            }
            Ok(Placed { pattern: format!("/{}", text_of(rel)?), root: Some(root) })
        }
        Scope::User => {
            let pattern = match abs.strip_prefix(&env.home) {
                Ok(rel) if !rel.as_os_str().is_empty() => format!("~/{}", text_of(rel)?),
                _ if cfg!(windows) => text_of(&abs)?,
                _ => format!("/{}", text_of(&abs)?),
            };
            Ok(Placed { pattern, root: None })
        }
    }
}

/// The filter a file's text makes, as the scan reads it.
fn filter(text: &str, scope: Scope, env: &Env) -> Ignore {
    match scope {
        Scope::User => Ignore::parse_user(text, &env.home),
        Scope::Repo => Ignore::parse(text),
    }
}

/// Whether `ig` (your file, or the repo at `root`'s) leaves `f` out, by
/// the scan's own decision.
fn judged(f: &Finding, scope: Scope, ig: &Ignore, root: Option<&Path>, env: &Env) -> Option<Skip> {
    match (scope, root) {
        (Scope::Repo, Some(root)) => {
            let name = root.to_string_lossy().into_owned();
            let repo = InScope { name: &name, root, ignore: Some(std::borrow::Cow::Borrowed(ig)) };
            ignore::skipped_by(f, &[repo], None, &env.home)
        }
        _ => ignore::skipped_by(f, &[], Some(ig), &env.home),
    }
}

/// The header a rule goes under, if the file's reader takes it.
fn header_for(f: &Finding) -> Result<String, Refused> {
    let bad = |why: String| Refused { code: "not-ignorable", message: why };
    if f.kind == "unchecked" {
        return Err(bad(format!("{} is a source that couldn't be asked, not a finding to dismiss", f.id())));
    }
    let id = f.vuln_id.trim();
    let inner = if id.is_empty() { f.kind.clone() } else { format!("{} {id}", f.kind) };
    let header = format!("[{inner}]");
    match ignore::section(&inner) {
        Ok((Some(kind), rule))
            if kind == f.kind && rule.as_deref().unwrap_or("") == id && ignore::header(&header) == Some(&inner) =>
        {
            Ok(header)
        }
        _ => Err(bad(format!(
            "{} can't be named in an ignore file's section header (`[{inner}]` isn't one the scan reads)",
            f.id()
        ))),
    }
}

/// Work out, check and write the rule for a finding (see the module
/// docs). `Already` when the file leaves the finding out as it is.
pub fn add(req: &Request, env: &Env) -> Result<Added, Stop> {
    let f = req.finding;
    let reason = match req.reason {
        Some(r) => Some(clean_reason(r).map_err(Stop::Refused)?).filter(|r| !r.is_empty()),
        None => None,
    };
    let header = header_for(f).map_err(Stop::Refused)?;
    if req.scope == Scope::Repo && ignore::repo_cannot_skip(f) {
        return refuse(
            "repo-cannot-skip",
            format!(
                "a repo's .pantryignore can't skip {} ({} {}): it protects you from the repo itself, so only your own file may. Use --scope user",
                f.id(),
                f.kind,
                f.vuln_id
            ),
        );
    }
    let first = place(f, req.scope, env).map_err(Stop::Refused)?;
    let root = first.root.clone();
    // The findings one rule per place covers: this one, and with
    // --all-places the same advisory or rule for the same package elsewhere.
    let mut targets: Vec<(&Finding, Placed)> = vec![(f, first)];
    let mut left_out: Vec<LeftOut> = Vec::new();
    if req.all_places {
        let mut keys = vec![f.key()];
        for g in req.all.iter().filter(|g| g.kind == f.kind && g.component == f.component && g.vuln_id == f.vuln_id) {
            if keys.contains(&g.key()) {
                continue;
            }
            keys.push(g.key());
            let why = if req.scope == Scope::Repo && ignore::repo_cannot_skip(g) {
                Some("a repo's file can't skip it".to_string())
            } else {
                match place(g, req.scope, env) {
                    Ok(p) if p.root == root => {
                        targets.push((g, p));
                        None
                    }
                    Ok(_) => Some("it is in another repo".to_string()),
                    Err(r) => Some(r.message),
                }
            };
            if let Some(why) = why {
                left_out.push(LeftOut { finding_id: g.id(), why });
            }
        }
    }
    let target = match (req.scope, &root) {
        (Scope::Repo, Some(root)) => Target::repo(root),
        _ => Target::user(env),
    };
    let opened = open(&target, true)?.expect("created on demand");
    let before = filter(&opened.text, req.scope, env);
    let skipped_now = |g: &Finding, ig: &Ignore| judged(g, req.scope, ig, root.as_deref(), env);
    let todo: Vec<&(&Finding, Placed)> =
        targets.iter().filter(|(g, _)| skipped_now(g, &before) != Some(req.scope.skip())).collect();
    if todo.is_empty() {
        return Ok(Added::Already { target });
    }
    // The block: a blank line, then per rule its header, pattern and mark.
    let nl = eol(&opened.text);
    let mut added = String::new();
    if !opened.text.is_empty() {
        if !opened.text.ends_with('\n') {
            added.push_str(nl);
        }
        added.push_str(nl);
    }
    let mut seen_patterns: Vec<&str> = Vec::new();
    let mut written = Vec::new();
    for (g, p) in todo.iter().map(|t| (t.0, &t.1)) {
        if seen_patterns.contains(&p.pattern.as_str()) {
            continue;
        }
        seen_patterns.push(&p.pattern);
        if !written.is_empty() {
            added.push_str(nl);
        }
        let mut mark = format!("{MARK}{} | {}", f.id(), stamp(req.now));
        if let Some(r) = &reason {
            mark.push_str(" | ");
            mark.push_str(r);
        }
        added.push_str(&format!("{header}{nl}{}{nl}{mark}{nl}", p.pattern));
        written.push((g, p));
    }
    let text = format!("{}{added}", opened.text);
    if text.len() as u64 > MAX {
        return refuse("too-big", format!("the file would pass {MAX} bytes, which a scan won't read"));
    }
    // The oracle: the reader must take every new line, leave out what was
    // asked, and leave out nothing else it kept before.
    let after = filter(&text, req.scope, env);
    if after.problems.len() != before.problems.len() {
        return refuse("rule-not-honoured", "the rule would not read cleanly, so nothing was written");
    }
    for (g, _) in &written {
        if skipped_now(g, &after) != Some(req.scope.skip()) {
            return refuse(
                "rule-not-honoured",
                format!(
                    "the rule written for {} would not leave it out (an unusual path?), so nothing was written",
                    g.id()
                ),
            );
        }
    }
    let covered: Vec<String> = targets.iter().map(|(g, _)| g.key()).collect();
    let hidden: Vec<String> = req
        .all
        .iter()
        .filter(|g| g.kind != "unchecked" && !covered.contains(&g.key()))
        .filter(|g| skipped_now(g, &before).is_none() && skipped_now(g, &after) == Some(req.scope.skip()))
        .map(Finding::id)
        .collect();
    if !hidden.is_empty() {
        let shown: Vec<&str> = hidden.iter().take(5).map(String::as_str).collect();
        let more = if hidden.len() > 5 { format!(" and {} more", hidden.len() - 5) } else { String::new() };
        return refuse(
            "would-hide-others",
            format!(
                "an ignore file names a path and a rule, not a package or a line, and the narrowest rule for {} would also leave out {}{more}. Nothing was written; add the rule by hand if you want that",
                f.id(),
                shown.join(", ")
            ),
        );
    }
    write_atomic(&opened, req.scope == Scope::User, &text)?;
    let fresh = rules_of(&text, &target);
    let tail = &fresh[fresh.len().saturating_sub(written.len())..];
    let rules = written
        .iter()
        .zip(tail)
        .map(|((g, p), r)| Written {
            id: r.id.clone(),
            section: r.section.clone(),
            pattern: p.pattern.clone(),
            finding_id: f.id(),
            place: if g.location.is_empty() { g.component.clone() } else { g.location.clone() },
        })
        .collect();
    Ok(Added::Wrote { target, rules, left_out })
}

// Reading and removing --------------------------------------------------

/// A file's rules, or None when it doesn't exist. A repo's link, or a file
/// that can't be read as text, is an error message (the scan reports the
/// same).
pub fn read_rules(t: &Target) -> Result<Option<Vec<Rule>>, String> {
    match std::fs::symlink_metadata(&t.file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(m) if t.scope == Scope::Repo && !m.file_type().is_file() => {
            return Err("not a regular file (a link or a special file); a scan doesn't read it".into());
        }
        Ok(_) => {}
    }
    match ignore::read(&t.file) {
        None => Ok(None),
        Some(Err(e)) => Err(e),
        Some(Ok(text)) => Ok(Some(rules_of(&text, t))),
    }
}

/// Which rules `remove` takes out.
#[derive(Clone, Copy, Debug)]
pub enum Want<'a> {
    /// The rule with this id, written by hand or by this command.
    Rule(&'a str),
    /// Every rule this command wrote for this finding.
    Finding(&'a str),
}

/// A rule taken out of a file.
#[derive(Clone, Debug, PartialEq)]
pub struct Removed {
    pub rule: Rule,
}

fn is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

fn bare(line: &str) -> &str {
    let l = line.strip_suffix('\n').unwrap_or(line);
    l.strip_suffix('\r').unwrap_or(l)
}

/// The text without these rules (by line index) and the mark comments
/// after them. A header this command wrote for a rule goes with it, and the
/// blank line before it, when nothing else sits under it.
fn without(text: &str, drop: &[&Rule]) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut gone = vec![false; lines.len()];
    let mut marked: Vec<&Rule> = Vec::new();
    for r in drop {
        gone[r.index] = true;
        if lines.get(r.index + 1).is_some_and(|l| bare(l).starts_with(MARK)) {
            gone[r.index + 1] = true;
            marked.push(r);
        }
    }
    for r in marked {
        let Some(h) = r.index.checked_sub(1) else { continue };
        let head = ignore::header(bare(lines[h])).map(norm);
        if gone[h] || !head.is_some_and(|h| h.eq_ignore_ascii_case(&r.section)) {
            continue;
        }
        // Nothing but blanks, comments and the next header (or the end) may follow.
        let alone = lines[r.index + 1..]
            .iter()
            .enumerate()
            .filter(|(i, l)| !gone[r.index + 1 + i] && !ignore::is_skippable(bare(l)))
            .map(|(_, l)| ignore::header(bare(l)).is_some())
            .next()
            .unwrap_or(true);
        if alone {
            gone[h] = true;
            if h > 0 && !gone[h - 1] && is_blank(lines[h - 1]) {
                gone[h - 1] = true;
            }
        }
    }
    lines.iter().zip(&gone).filter(|(_, g)| !**g).map(|(l, _)| *l).collect()
}

/// Take out the rules `want` names from `targets` (the files to look in),
/// and write each changed file. Refuses when a rule id matches in more
/// than one file. Returns the rules removed.
pub fn remove(targets: &[Target], want: Want) -> Result<Vec<Removed>, Stop> {
    let mut found: Vec<(&Target, Open, Vec<Rule>)> = Vec::new();
    for t in targets {
        let Some(o) = open(t, false)? else { continue };
        let all = rules_of(&o.text, t);
        let hit: Vec<Rule> = all
            .into_iter()
            .filter(|r| match want {
                Want::Rule(id) => r.id.eq_ignore_ascii_case(id),
                Want::Finding(id) => r.mark.as_ref().is_some_and(|m| m.finding_id.eq_ignore_ascii_case(id)),
            })
            .collect();
        if !hit.is_empty() {
            found.push((t, o, hit));
        }
    }
    if let Want::Rule(id) = want
        && found.len() > 1
    {
        return refuse("ambiguous", format!("{id} is in {} files (give --path for the repo you mean)", found.len()));
    }
    let mut removed = Vec::new();
    for (t, o, hit) in found {
        let refs: Vec<&Rule> = hit.iter().collect();
        let text = without(&o.text, &refs);
        write_atomic(&o, t.scope == Scope::User, &text)?;
        removed.extend(hit.into_iter().map(|rule| Removed { rule }));
    }
    Ok(removed)
}

/// The repo whose file `--path DIR` means: DIR when it holds a
/// `.pantryignore`, else the repo the latest scan read DIR under
/// ([`repo_of`]), else DIR.
pub fn repo_for(dir: &Path, env: &Env) -> PathBuf {
    let dir = whole(dir);
    if std::fs::symlink_metadata(dir.join(FILE)).is_ok() {
        return dir;
    }
    repo_of(&dir, &env.roots).unwrap_or(dir)
}

/// A directory by its whole path: made absolute (`.` and `src` have no
/// folder above them to look in), with `.` and `..` folded by name so the
/// folders looked in are the ones the path means (`app/src/../../other` is
/// `other`, not something under `app`). Nothing is opened or resolved.
fn whole(dir: &Path) -> PathBuf {
    use std::path::Component;
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut out = PathBuf::new();
    for c in absolute.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[path = "ignore_edit_tests.rs"]
mod tests;
