//! What a scan leaves out: a repo's [`FILE`] at its root, and your own
//! ignore file ([`user_file`]). Both hold gitignore patterns in sections.
//! Lines before any section apply to every check. `[kind]` applies to one
//! check (a finding's `kind`), `[kind id]` to one of its rules or
//! advisories (the finding's `vuln_id`), and `[*]` to every check again. A
//! finding is left out when a path it names matches, and the scan counts
//! what was left out (`specs/design/pantryignore.md`).
//!
//! A repo's own file can't silence the checks that protect you from that
//! repo ([`PROTECTIVE`]), nor anything malicious or actively exploited,
//! nor the note that its own gitleaks config isn't obeyed
//! ([`repo_cannot_skip`]): only your file can. A repo's section for one of
//! those checks is reported, not honoured. A repo's file is read only when
//! it's a regular file, not a link to one.

use crate::checks::Scan;
use crate::finding::Finding;
use crate::utils::files::{home, read_capped, short};
use std::path::{Component as Part, Path, PathBuf};

/// A repo's ignore file, at its root.
pub const FILE: &str = ".pantryignore";
/// The checks a repo can't silence for itself: they protect you from it.
pub const PROTECTIVE: &[&str] =
    &["malware", "suspect-code", "hidden-text", "repo-hook", "clipper", "document", "mcp", "install-script"];
/// Findings no repo's file can skip, whatever their check: known malware.
const PROTECTED_IDS: &[&str] = &["MALWARE", "REPO-POLICY"];

/// Whether a finding is beyond a repo's own ignore file: its check protects
/// you from the repo, it names something malicious or actively exploited, or
/// it's the note that the repo's own policy isn't obeyed.
pub fn repo_cannot_skip(f: &Finding) -> bool {
    PROTECTIVE.contains(&f.kind.as_str())
        || f.kev
        || f.severity == "MALICIOUS"
        || f.vuln_id.starts_with("MAL-")
        || PROTECTED_IDS.contains(&f.vuln_id.as_str())
}
/// The largest ignore file read.
pub(crate) const MAX: u64 = 1 << 20;

/// Your ignore file: `ignore` in [`crate::sources::file::config_dir`].
pub fn user_file() -> PathBuf {
    crate::sources::file::config_dir().join("ignore")
}

/// One ignore file, parsed.
#[derive(Clone, Debug, Default)]
pub struct Ignore {
    sections: Vec<Section>,
    /// Lines that couldn't be used: their number, and why.
    pub problems: Vec<(usize, String)>,
}

#[derive(Clone, Debug)]
struct Section {
    /// The check it applies to; None for every check. `Some("")`, after a
    /// header that couldn't be read, applies to none.
    kind: Option<String>,
    /// The rule or advisory it applies to; None for all of the check's.
    id: Option<String>,
    /// Its header's line (0 before any header).
    line: usize,
    patterns: Vec<Pattern>,
}

#[derive(Clone, Debug)]
struct Pattern {
    negate: bool,
    dir_only: bool,
    /// Path segments, `**` among them. An unanchored pattern starts with `**`.
    segs: Vec<String>,
}

impl Ignore {
    /// A file's text: gitignore patterns, under section headers.
    pub fn parse(text: &str) -> Ignore {
        let mut out = Ignore::default();
        out.sections.push(Section { kind: None, id: None, line: 0, patterns: Vec::new() });
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(inner) = header(line) {
                let (kind, id) = match section(inner) {
                    Ok(s) => s,
                    Err(why) => {
                        out.problems.push((n, why));
                        (Some(String::new()), None)
                    }
                };
                out.sections.push(Section { kind, id, line: n, patterns: Vec::new() });
                continue;
            }
            match Pattern::parse(line) {
                Some(p) => out.sections.last_mut().expect("the first section").patterns.push(p),
                None => out.problems.push((n, format!("`{}` matches nothing", line.trim()))),
            }
        }
        out
    }

    /// A repo's file at `path`: None if there is none, an error if it can't
    /// be read or isn't a regular file (a link could point anywhere, or at a
    /// pipe that never answers).
    pub fn load(path: &Path) -> Option<std::result::Result<Ignore, String>> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_file() {
            return Some(Err("not a regular file (a link or a special file); not read".into()));
        }
        read(path).map(|r| r.map(|text| Ignore::parse(&text)))
    }

    /// Your file: like a repo's, with absolute or `~/` paths.
    pub fn parse_user(text: &str, home: &Path) -> Ignore {
        let home = escape(&home.to_string_lossy().replace('\\', "/"));
        let home = home.trim_end_matches('/');
        let text: String = text
            .lines()
            .map(|l| {
                let (bang, rest) = l.strip_prefix('!').map_or(("", l), |r| ("!", r));
                match rest.strip_prefix("~/") {
                    Some(rest) => format!("{bang}{home}/{rest}\n"),
                    None if rest == "~" => format!("{bang}{home}\n"),
                    None => format!("{l}\n"),
                }
            })
            .collect();
        Ignore::parse(&text)
    }

    /// Whether a `kind` finding under `id` at `rel` (a `/`-separated path
    /// from the file's root) is left out.
    pub fn skips(&self, kind: &str, id: &str, rel: &str) -> bool {
        let path = split(rel);
        !path.is_empty() && self.sections.iter().filter(|s| s.applies(kind, Some(id))).any(|s| s.ignores(&path))
    }

    /// Whether every `kind` finding at `rel` is left out, whatever its rule:
    /// the file needn't be read for that check.
    pub fn skips_kind(&self, kind: &str, rel: &str) -> bool {
        let path = split(rel);
        !path.is_empty() && self.sections.iter().filter(|s| s.applies(kind, None)).any(|s| s.ignores(&path))
    }

    /// The sections naming a check in [`PROTECTIVE`]: their line and check.
    pub fn protective(&self) -> Vec<(usize, &str)> {
        self.sections
            .iter()
            .filter_map(|s| s.kind.as_deref().filter(|k| PROTECTIVE.contains(k)).map(|k| (s.line, k)))
            .collect()
    }
}

impl Section {
    /// Whether it applies to a `kind` finding under `id`. With no id (the
    /// whole check), only a section with no id of its own does.
    fn applies(&self, kind: &str, id: Option<&str>) -> bool {
        self.kind.as_deref().is_none_or(|k| k == kind)
            && match (&self.id, id) {
                (None, _) => true,
                (Some(mine), Some(id)) => mine.eq_ignore_ascii_case(id),
                (Some(_), None) => false,
            }
    }

    /// git's rule: the last pattern matching a path decides, and a path in
    /// an ignored directory stays ignored, whatever comes after.
    fn ignores(&self, path: &[&str]) -> bool {
        for end in 1..=path.len() {
            let dir = end < path.len();
            let part = &path[..end];
            let last = self.patterns.iter().rev().find(|p| (!p.dir_only || dir) && matches(&p.segs, part));
            if let Some(p) = last {
                if dir && !p.negate {
                    return true;
                }
                if !dir {
                    return !p.negate;
                }
            }
        }
        false
    }
}

impl Pattern {
    fn parse(line: &str) -> Option<Pattern> {
        let mut s = trim_end(line);
        let mut negate = false;
        if let Some(rest) = s.strip_prefix('!') {
            negate = true;
            s = rest;
        } else if s.starts_with("\\!") || s.starts_with("\\#") {
            s = &s[1..];
        }
        let dir_only = s.ends_with('/');
        let s = s.trim_end_matches('/');
        // A slash at the start or in the middle anchors it to the root.
        let anchored = s.contains('/');
        let mut segs: Vec<String> = s.split('/').filter(|seg| !seg.is_empty()).map(str::to_string).collect();
        if segs.is_empty() {
            return None;
        }
        if !anchored {
            segs.insert(0, "**".into());
        }
        Some(Pattern { negate, dir_only, segs })
    }
}

/// A file's text: None if there is none, an error if it can't be read.
pub(crate) fn read(path: &Path) -> Option<std::result::Result<String, String>> {
    match read_capped(path, MAX) {
        Ok(text) => Some(Ok(text)),
        Err(_) if !path.exists() => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// A section header's inside: `[kind]`, `[kind id]` or `[*]`. A line like
/// `[Bb]uild/` is a pattern: a header is the whole line.
pub(crate) fn header(line: &str) -> Option<&str> {
    let t = line.trim();
    let inner = t.strip_prefix('[')?.strip_suffix(']')?;
    (!inner.contains(['[', ']'])).then_some(inner)
}

/// Whether a line (not blank, not a comment, not a header) is a pattern
/// the file can use, as [`Ignore::parse`] reads it.
pub(crate) fn is_pattern(line: &str) -> bool {
    Pattern::parse(line.strip_suffix('\r').unwrap_or(line)).is_some()
}

/// Whether a line is a comment (a blank line or one starting with `#`).
pub(crate) fn is_skippable(line: &str) -> bool {
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.trim().is_empty() || line.starts_with('#')
}

pub(crate) fn section(inner: &str) -> std::result::Result<(Option<String>, Option<String>), String> {
    let mut words = inner.split_whitespace();
    let (Some(kind), id, None) = (words.next(), words.next(), words.next()) else {
        return Err(format!("`[{inner}]`: a section is `[check]` or `[check id]`"));
    };
    let id = id.map(str::to_string);
    if kind == "*" {
        return Ok((None, id));
    }
    if kind == "unchecked" || !crate::reporters::view::KIND_ORDER.contains(&kind) {
        let hint = kind
            .strip_suffix('s')
            .filter(|k| crate::reporters::view::KIND_ORDER.contains(k))
            .map(|k| format!(" (did you mean `{k}`?)"))
            .unwrap_or_default();
        return Err(format!("`[{inner}]`: no check is called `{kind}`{hint}"));
    }
    Ok((Some(kind.to_string()), id))
}

/// Trailing spaces go, unless escaped with a backslash.
fn trim_end(line: &str) -> &str {
    let mut end = line.len();
    while end > 0 && line.as_bytes()[end - 1] == b' ' {
        if end >= 2 && line.as_bytes()[end - 2] == b'\\' {
            break;
        }
        end -= 1;
    }
    &line[..end]
}

/// A path's segments, `.` and empty ones dropped.
fn split(rel: &str) -> Vec<&str> {
    rel.split(['/', '\\']).filter(|s| !s.is_empty() && *s != ".").collect()
}

/// Glob characters in a literal path, escaped.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Whether pattern segments match path segments. `**` matches any number
/// of segments, and one or more when it ends the pattern (`dir/**` is what
/// is inside `dir`, not `dir`). Dynamic programming over (pattern, path)
/// positions, so a file of many `**` can't make it exponential.
fn matches(pat: &[String], path: &[&str]) -> bool {
    let (n, m) = (pat.len(), path.len());
    // ok[i][j]: pat[i..] matches path[j..].
    let mut ok = vec![vec![false; m + 1]; n + 1];
    ok[n][m] = true;
    for i in (0..n).rev() {
        for j in (0..=m).rev() {
            ok[i][j] = if pat[i] == "**" {
                if i + 1 == n { j < m } else { ok[i + 1][j] || (j < m && ok[i][j + 1]) }
            } else {
                j < m && glob(&pat[i], path[j]) && ok[i + 1][j + 1]
            };
        }
    }
    ok[0][0]
}

/// One segment against a glob: `*`, `?`, `[a-z]` (`[!a]` and `[^a]` negate)
/// and `\` escapes. Linear in practice: on a mismatch it returns to the last
/// `*` only, never to earlier ones.
fn glob(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let (mut pi, mut si) = (0, 0);
    // The last `*`'s pattern position, and where in `s` it's matched to.
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            star = Some((pi, si));
            continue;
        }
        if let Some(len) = step(&p[pi..], s[si]) {
            pi += len;
            si += 1;
            continue;
        }
        match star {
            Some((sp, ss)) => {
                pi = sp;
                si = ss + 1;
                star = Some((sp, ss + 1));
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// How much of the pattern at `p` one character `c` uses, if it matches:
/// `?`, a class, an escape or a literal.
fn step(p: &[char], c: char) -> Option<usize> {
    match p.first()? {
        '?' => Some(1),
        '[' => match class(p, Some(c)) {
            Some((hit, len)) => hit.then_some(len),
            None => (c == '[').then_some(1),
        },
        '\\' if p.len() > 1 => (p[1] == c).then_some(2),
        '*' => None,
        lit => (*lit == c).then_some(1),
    }
}

/// A `[...]` class at the start of `p`: whether `c` is in it, and its
/// length; None when it isn't closed (the `[` is then a plain character).
fn class(p: &[char], c: Option<char>) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let start = i;
    let mut hit = false;
    while let Some(&ch) = p.get(i) {
        if ch == ']' && i > start {
            let Some(c) = c else { return Some((false, i + 1)) };
            return Some((hit != negate && c != '/', i + 1));
        }
        let (lo, next) = if ch == '\\' { (*p.get(i + 1)?, i + 2) } else { (ch, i + 1) };
        if p.get(next) == Some(&'-') && p.get(next + 1).is_some_and(|h| *h != ']') {
            let hi = p[next + 1];
            hit |= c.is_some_and(|c| lo <= c && c <= hi);
            i = next + 2;
        } else {
            hit |= c == Some(lo);
            i = next;
        }
    }
    None
}

/// A path a finding names, made absolute: `~/…` under your home, or as
/// it is when it's absolute. Anything else (a line, a package name) isn't one.
pub(crate) fn absolute(s: &str, home: &Path) -> Option<PathBuf> {
    if s == "~" {
        return Some(home.to_path_buf());
    }
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        return Some(home.join(rest));
    }
    let p = Path::new(s);
    p.is_absolute().then(|| p.to_path_buf())
}

/// A path's parts, `/`-joined, with no root (a Windows drive is the first part).
pub(crate) fn joined(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            Part::Prefix(x) => Some(x.as_os_str().to_string_lossy().into_owned()),
            Part::Normal(x) => Some(x.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// One repo in scope, and its ignore file if it has one.
pub(crate) struct InScope<'r> {
    pub(crate) name: &'r str,
    pub(crate) root: &'r Path,
    pub(crate) ignore: Option<std::borrow::Cow<'r, Ignore>>,
}

/// Which file left a finding out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skip {
    /// A repo's `.pantryignore`.
    Repo,
    /// Your ignore file.
    User,
}

/// Whether the repo files in `repos` or your file `user` leave `f` out, and
/// which one does: the one decision [`apply_with`] makes for every finding,
/// shared with `wpantry ignore` so what it writes is checked by the filter
/// that will read it. `repos` are innermost first.
pub(crate) fn skipped_by(f: &Finding, repos: &[InScope], user: Option<&Ignore>, home: &Path) -> Option<Skip> {
    if f.kind == "unchecked" {
        return None;
    }
    let places = [f.component.as_str(), f.location.as_str()];
    if !repo_cannot_skip(f) {
        for place in places {
            if let Some((r, rel)) = in_repo(repos, place, home)
                && r.ignore.as_ref().is_some_and(|ig| ig.skips(&f.kind, &f.vuln_id, &rel))
            {
                return Some(Skip::Repo);
            }
        }
    }
    if let Some(u) = user {
        for place in places {
            if let Some(p) = absolute(place, home)
                && u.skips(&f.kind, &f.vuln_id, &joined(&p))
            {
                return Some(Skip::User);
            }
        }
    }
    None
}

/// The repo a path is in, innermost first, and the path from its root.
fn in_repo<'a, 'r>(repos: &'a [InScope<'r>], place: &str, home: &Path) -> Option<(&'a InScope<'r>, String)> {
    for r in repos {
        let rest =
            place.strip_prefix(r.name).and_then(|rest| rest.strip_prefix('/').or_else(|| rest.strip_prefix('\\')));
        if let Some(rest) = rest {
            return Some((r, rest.replace('\\', "/")));
        }
    }
    let p = absolute(place, home)?;
    // A verbatim (`\\?\`) root, as a canonical Windows path has, names the same folder.
    repos.iter().find_map(|r| {
        let root = PathBuf::from(crate::utils::files::strip_verbatim(&r.root.to_string_lossy()));
        p.strip_prefix(&root).ok().map(|rel| (r, joined(rel)))
    })
}

/// A note about an ignore file, in the Configuration area.
fn note(file: &str, line: usize, id: &str, status: &str, note: String, fix: String) -> Finding {
    Finding {
        kind: "config".into(),
        component: file.into(),
        location: if line > 0 { format!("line {line}") } else { String::new() },
        vuln_id: id.into(),
        status: status.into(),
        note,
        fix_cmd: fix,
        ..Default::default()
    }
}

/// A repo's ignore file and yours, for findings made of many files' hits
/// (a repo's test passwords), which [`apply`] can't match by one path: each
/// hit is checked before they are grouped.
pub(crate) struct Skipper {
    root: PathBuf,
    repo: Option<Ignore>,
    user: Option<Ignore>,
}

impl Skipper {
    pub(crate) fn new(root: &Path) -> Skipper {
        Skipper::with(root, &user_file())
    }

    pub(crate) fn with(root: &Path, user_path: &Path) -> Skipper {
        let repo = Ignore::load(&root.join(FILE)).and_then(|r| r.ok());
        let user = read(user_path).and_then(|r| r.ok()).map(|t| Ignore::parse_user(&t, &home()));
        Skipper { root: root.to_path_buf(), repo, user }
    }

    /// The count a hit of `kind` and `id` in `rel` (a path in the repo) is
    /// left out under, if an ignore file skips it.
    pub(crate) fn skips(&self, kind: &str, id: &str, rel: &str) -> Option<&'static str> {
        if self.repo.as_ref().is_some_and(|ig| ig.skips(kind, id, rel)) {
            return Some("findings skipped by a repo's .pantryignore");
        }
        let abs = joined(&self.root.join(rel));
        self.user.as_ref().is_some_and(|u| u.skips(kind, id, &abs)).then_some("findings skipped by your ignore file")
    }
}

/// The scan's findings, less what the ignore files skip; then what those
/// files ask that can't be done, and how much each left out.
pub(crate) fn apply(scan: &mut Scan) {
    apply_with(scan, &user_file());
}

/// [`apply`] with your ignore file at `user_path`.
pub(crate) fn apply_with(scan: &mut Scan, user_path: &Path) {
    let home = home();
    let mut notes = Vec::new();
    let user_name = short(&user_path.to_string_lossy());
    let user = match read(user_path) {
        None => None,
        Some(Err(e)) => {
            scan.unchecked("your ignore file", &e);
            None
        }
        Some(Ok(text)) => {
            let ig = Ignore::parse_user(&text, &home);
            for (n, why) in &ig.problems {
                notes.push(note(
                    &user_name,
                    *n,
                    "IGNORE-FILE",
                    "warn",
                    why.clone(),
                    format!("Fix line {n} of {user_name}"),
                ));
            }
            Some(ig)
        }
    };
    let mut repos: Vec<InScope> = scan.repos.iter().map(|(name, root)| InScope { name, root, ignore: None }).collect();
    for r in &mut repos {
        let file = format!("{}/{FILE}", r.name);
        match Ignore::load(&r.root.join(FILE)) {
            None => {}
            Some(Err(e)) => {
                notes.push(note(&file, 0, "IGNORE-FILE", "warn", format!("unreadable: {e}"), String::new()))
            }
            Some(Ok(ig)) => {
                for (n, why) in &ig.problems {
                    notes.push(note(&file, *n, "IGNORE-FILE", "warn", why.clone(), format!("Fix line {n} of {file}")));
                }
                for (n, kind) in ig.protective() {
                    notes.push(note(
                        &file,
                        n,
                        "IGNORE-PROTECTED",
                        "warn",
                        format!("asks to skip the {kind} check, which protects you from the repo itself, so a repo's file can't skip it; not honoured"),
                        format!("Find out why the repo wants {kind} findings skipped. To skip them yourself, list the paths under [{kind}] in {user_name}"),
                    ));
                }
                r.ignore = Some(std::borrow::Cow::Owned(ig));
            }
        }
    }
    // Innermost first: a file in a nested repo belongs to that repo.
    repos.sort_by_key(|r| std::cmp::Reverse(r.root.components().count()));
    let (mut by_repo, mut by_user) = (0, 0);
    if user.is_some() || repos.iter().any(|r| r.ignore.is_some()) {
        scan.findings.retain(|f| match skipped_by(f, &repos, user.as_ref(), &home) {
            Some(Skip::Repo) => {
                by_repo += 1;
                false
            }
            Some(Skip::User) => {
                by_user += 1;
                false
            }
            None => true,
        });
    }
    for n in notes {
        scan.add(n);
    }
    scan.count("findings skipped by a repo's .pantryignore", by_repo);
    scan.count("findings skipped by your ignore file", by_user);
}

#[cfg(test)]
#[path = "ignore_tests.rs"]
mod tests;
