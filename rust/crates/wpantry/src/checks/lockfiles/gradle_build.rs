//! Gradle builds without a `gradle.lockfile` → `Maven`: the direct
//! dependencies a build script (`build.gradle`, `build.gradle.kts`) or a
//! version catalog (`gradle/*.versions.toml`) spells out. Nothing is
//! evaluated: a script is tokenized, never run, and only a string literal
//! of the exact shape `"group:artifact:version"` given to a configuration
//! inside a `dependencies { }` block counts. Everything Gradle would have
//! to run to know (a `$variable`, a dynamic `1.+` or `latest.release`, a
//! range, a version left to a platform or plugin, map notation, a helper
//! call) is returned as [`Unresolved`] for the scan to count as not
//! checked, never dropped. A version read here is the one declared, not
//! the one Gradle resolves (the highest any declaration, BOM or constraint
//! asks for), so the scan warns on it rather than fails. Local
//! dependencies (`project(..)`, `files(..)`) and catalog accessors
//! (`libs.x`, read from the catalog itself) are skipped. `plugins { }`
//! blocks and a catalog's `[plugins]` are not read: a plugin id isn't a
//! Maven coordinate OSV knows.
//!
//! Example (`build.gradle`):
//!
//! ```text
//! dependencies {
//!     implementation 'org.apache.logging.log4j:log4j-core:2.14.1'  // Maven org.apache.logging.log4j:log4j-core 2.14.1
//!     implementation "org.x:y:$ver"                                // unresolved: version from a variable
//!     implementation project(':core')                              // skipped: local
//! }
//! ```

use super::{Package, Scope, lines, plausible};
use crate::error::{Error, Result};
use crate::utils::toml::{self, Val};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 256;

/// A declared dependency whose version can't be read without running Gradle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresolved {
    /// The declaration as written (trimmed, at most [`SHOWN`] characters).
    pub what: String,
    pub why: &'static str,
}

/// The longest declaration kept in an [`Unresolved`].
const SHOWN: usize = 80;

/// What one build file declares.
#[derive(Debug, Default, PartialEq)]
pub struct Declared {
    pub packages: Vec<Package>,
    pub unresolved: Vec<Unresolved>,
}

/// Whether the repo walk reads `name` in `dir`, given the directories the
/// walk found a `gradle.lockfile` in (which [`super::gradle`] reads): a
/// build script unless one sits beside it, a `*.versions.toml` in a
/// `gradle/` directory unless the project above it or any of its modules
/// is locked (the lockfiles already list what the catalog declares).
pub fn scanned(dir: &Path, name: &str, locked: &[PathBuf]) -> bool {
    match name {
        "build.gradle" | "build.gradle.kts" => !locked.iter().any(|l| l == dir),
        n if is_catalog(n) => {
            dir.file_name().is_some_and(|d| d == "gradle")
                && !dir
                    .parent()
                    .is_some_and(|p| locked.iter().any(|l| l.starts_with(p)) || p.join("gradle.lockfile").exists())
        }
        _ => false,
    }
}

/// Whether `path` is a build file this module reads, whose versions are
/// declared rather than resolved.
pub fn declared(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| matches!(n, "build.gradle" | "build.gradle.kts") || is_catalog(n))
}

/// How the scan qualifies an advisory matched on a declared version.
pub const DECLARED: &str = "version as declared, not resolved: Gradle uses the highest version any declaration, BOM, \
     constraint or dependency asks for; a gradle.lockfile would confirm it";

/// A version catalog's name (`libs.versions.toml`).
pub(crate) fn is_catalog(name: &str) -> bool {
    name.len() > ".versions.toml".len() && name.ends_with(".versions.toml")
}

pub fn parse_script(text: &str) -> Result<Vec<Package>> {
    Ok(script(text)?.packages)
}

pub fn parse_catalog(text: &str) -> Result<Vec<Package>> {
    Ok(catalog(text)?.packages)
}

/// The declarations of `path` that weren't checked: how many, and one line
/// naming the first for the scan's log; None when every one was read (or
/// the file isn't a Gradle build file, or can't be read: that error is the
/// extractor's to report).
pub fn unresolved_note(path: &Path) -> Option<(usize, String)> {
    let name = path.file_name()?.to_str()?;
    let text = crate::utils::files::read_capped(path, super::MAX_FILE).ok()?;
    let found = match name {
        "build.gradle" | "build.gradle.kts" => script(&text).ok()?,
        n if is_catalog(n) => catalog(&text).ok()?,
        _ => return None,
    };
    let first = found.unresolved.first()?;
    let more = found.unresolved.len() - 1;
    let tail = if more > 0 { format!(" and {more} more") } else { String::new() };
    let n = found.unresolved.len();
    Some((
        n,
        format!("{n} not checked, Gradle would have to run to know the version: {} ({}){tail}", first.what, first.why),
    ))
}

// Coordinates -------------------------------------------------------------------

/// `group:artifact:version[:classifier][@ext]` as (`group:artifact`,
/// version), or why it isn't one with an exact version.
fn coordinate(s: &str) -> std::result::Result<(String, String), &'static str> {
    if s.contains('$') {
        return Err("version from a variable");
    }
    let coords = s.split_once('@').map_or(s, |(c, _)| c);
    let parts: Vec<&str> = coords.split(':').collect();
    if parts.len() < 2 || parts.len() > 4 || parts.iter().any(|p| p.is_empty() || p.contains(char::is_whitespace)) {
        return Err("not a group:artifact:version string");
    }
    let Some(version) = parts.get(2) else { return Err("no version (left to a platform, BOM or plugin)") };
    // `1.2.3!!` is Gradle's "strictly 1.2.3".
    let version = version.strip_suffix("!!").unwrap_or(version);
    if version.contains(['+', '[', ']', '(', ')', ',']) || version.starts_with("latest.") {
        return Err("a dynamic version or a range");
    }
    if !plausible(version) {
        return Err("not a version");
    }
    Ok((format!("{}:{}", parts[0], parts[1]), version.to_string()))
}

/// `s` with its whitespace runs as one space, cut at [`SHOWN`]
/// characters. Lazy: it reads no further into `s` than the cut.
fn shown(s: &str) -> String {
    let mut flat =
        s.split_whitespace().enumerate().flat_map(|(k, w)| (k > 0).then_some(' ').into_iter().chain(w.chars()));
    let head: String = flat.by_ref().take(SHOWN).collect();
    if flat.next().is_some() { format!("{head}...") } else { head }
}

// Build scripts -----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Ident,
    /// A string literal's text, escapes left as written.
    Str(String),
    Punct(char),
    Newline,
}

#[derive(Clone, Debug)]
struct Tok {
    kind: Kind,
    /// The token's bytes in the source.
    start: usize,
    end: usize,
}

/// Groovy and Kotlin, as far as finding dependency declarations needs:
/// identifiers, string literals (single, double and triple quoted),
/// punctuation and line ends; comments dropped. A `/` is punctuation (a
/// Groovy slashy string reads as punctuation and text, which can't open a
/// `dependencies` block).
fn tokens(text: &str) -> Result<Vec<Tok>> {
    let bad = |m: &str| Error::Invalid(format!("build script: {m}"));
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        let kind = match c {
            b'\n' => {
                i += 1;
                Kind::Newline
            }
            c if c.is_ascii_whitespace() => {
                i += 1;
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = text[i..].find('\n').map_or(b.len(), |n| i + n);
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = text[i + 2..].find("*/").ok_or_else(|| bad("a comment never closes"))?;
                // The lines a comment spans still end statements.
                if text[i..i + 2 + end].contains('\n') {
                    out.push(Tok { kind: Kind::Newline, start, end: start });
                }
                i += 2 + end + 2;
                continue;
            }
            b'"' | b'\'' => {
                let triple = b.get(i + 1) == Some(&c) && b.get(i + 2) == Some(&c);
                let (open, close) = if triple {
                    let q = if c == b'"' { "\"\"\"" } else { "'''" };
                    (3, text[i + 3..].find(q).map(|n| i + 3 + n))
                } else {
                    let mut j = i + 1;
                    let mut end = None;
                    while j < b.len() {
                        match b[j] {
                            b'\\' => j += 2,
                            b'\n' => break,
                            q if q == c => {
                                end = Some(j);
                                break;
                            }
                            _ => j += 1,
                        }
                    }
                    (1, end)
                };
                let close = close.ok_or_else(|| bad("a string never closes"))?;
                i = close + open;
                Kind::Str(text[start + open..close].to_string())
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                Kind::Ident
            }
            _ => {
                // One character, however many bytes it takes.
                let ch = text[i..].chars().next().expect("in bounds");
                i += ch.len_utf8();
                Kind::Punct(ch)
            }
        };
        out.push(Tok { kind, start, end: i });
    }
    Ok(out)
}

/// What a configuration's argument turned out to be.
enum Arg {
    Dep(String, String),
    Unresolved(&'static str),
    Skip,
}

/// Arguments that are local or read elsewhere.
const LOCAL: &[&str] = &["project", "files", "fileTree", "gradleApi", "localGroovy", "gradleTestKit"];
/// Wrappers whose argument is still a coordinate.
const WRAPPERS: &[&str] = &["platform", "enforcedPlatform", "testFixtures"];
/// Control flow inside `dependencies { }`: its blocks still declare.
const CONTROL: &[&str] = &["if", "else", "for", "while", "when", "try"];
/// Statements that start with an identifier but aren't a configuration.
const KEYWORDS: &[&str] = &["val", "var", "def", "return", "throw", "import", "catch", "finally"];

struct Script<'a> {
    text: &'a str,
    toks: Vec<Tok>,
}

impl Script<'_> {
    fn ident(&self, i: usize) -> Option<&str> {
        let t = self.toks.get(i)?;
        (t.kind == Kind::Ident).then(|| &self.text[t.start..t.end])
    }

    fn punct(&self, i: usize, c: char) -> bool {
        self.toks.get(i).is_some_and(|t| t.kind == Kind::Punct(c))
    }

    fn skip_newlines(&self, mut i: usize) -> usize {
        while self.toks.get(i).is_some_and(|t| t.kind == Kind::Newline) {
            i += 1;
        }
        i
    }

    /// The index after the `)` matching the `(` at `i`.
    fn after_parens(&self, i: usize) -> usize {
        let mut depth = 0usize;
        for (j, t) in self.toks.iter().enumerate().skip(i) {
            match t.kind {
                Kind::Punct('(') => depth += 1,
                Kind::Punct(')') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return j + 1;
                    }
                }
                _ => {}
            }
        }
        self.toks.len()
    }

    /// The index of the line end (or the `)` closing an enclosing
    /// parenthesis) that ends the expression at `i`.
    fn expression_end(&self, i: usize) -> usize {
        let mut depth = 0usize;
        for (j, t) in self.toks.iter().enumerate().skip(i) {
            match t.kind {
                Kind::Punct('(') | Kind::Punct('{') | Kind::Punct('[') => depth += 1,
                Kind::Punct(')') | Kind::Punct('}') | Kind::Punct(']') if depth == 0 => return j,
                Kind::Punct(')') | Kind::Punct('}') | Kind::Punct(']') => depth -= 1,
                Kind::Newline if depth == 0 => return j,
                _ => {}
            }
        }
        self.toks.len()
    }

    fn source(&self, from: usize, to: usize) -> String {
        let (Some(a), Some(b)) = (self.toks.get(from), self.toks.get(to.saturating_sub(1))) else {
            return String::new();
        };
        shown(&self.text[a.start..b.end.max(a.start)])
    }

    /// One argument at `i`: (what it is, the index after it).
    fn arg(&self, i: usize, depth: usize) -> (Arg, usize) {
        let Some(t) = self.toks.get(i) else { return (Arg::Skip, i) };
        if depth > 8 {
            return (Arg::Unresolved("nested too deeply"), self.expression_end(i));
        }
        if let Kind::Str(s) = &t.kind {
            // `"g:a:" + v` or `"g:a:1" + suffix` is an expression, not a literal.
            let ends = match self.toks.get(i + 1).map(|t| &t.kind) {
                None | Some(Kind::Newline) => true,
                Some(Kind::Punct(c)) => matches!(c, ',' | ')' | ';' | '{' | '}'),
                Some(_) => false,
            };
            if !ends {
                return (Arg::Unresolved("an expression"), self.expression_end(i));
            }
            return match coordinate(s) {
                Ok((name, version)) => (Arg::Dep(name, version), i + 1),
                Err(why) => (Arg::Unresolved(why), i + 1),
            };
        }
        let Some(word) = self.ident(i) else { return (Arg::Unresolved("not a string"), self.expression_end(i)) };
        if self.punct(i + 1, ':') || self.punct(i + 1, '=') {
            return (Arg::Unresolved("map or named-argument notation"), self.expression_end(i));
        }
        if self.punct(i + 1, '(') {
            let end = self.after_parens(i + 1);
            if WRAPPERS.contains(&word) {
                let (inner, _) = self.arg(self.skip_newlines(i + 2), depth + 1);
                return (inner, end);
            }
            if LOCAL.contains(&word) {
                return (Arg::Skip, end);
            }
            return (Arg::Unresolved("a helper call"), end);
        }
        // A property path: `libs.x.y` is the catalog's, read there.
        let mut j = i + 1;
        while self.punct(j, '.') && self.ident(j + 1).is_some() {
            j += 2;
        }
        if word == "libs" && j > i + 1 {
            return (Arg::Skip, j);
        }
        (Arg::Unresolved("version from a variable"), self.expression_end(i))
    }

    /// The declaration starting with configuration `conf` at `i`, pushed
    /// to `out`; the index to continue from. An unresolved argument after
    /// the first is shown from its own tokens (the first with the
    /// configuration as written), so a long list costs its length once.
    fn declaration(&self, i: usize, out: &mut Declared) -> usize {
        // `implementation …`, or Kotlin's `"implementation"(…)`.
        let conf = match &self.toks[i].kind {
            Kind::Str(s) => s.as_str(),
            _ => self.ident(i).unwrap_or(""),
        };
        let mut j = i + 1;
        let parens = self.punct(j, '(');
        if parens {
            j = self.skip_newlines(j + 1);
        }
        let scope = if conf.to_ascii_lowercase().contains("test") { Scope::Dev } else { Scope::Unknown };
        let first = j;
        loop {
            let (arg, next) = self.arg(j, 0);
            let close = if parens && self.punct(next, ')') { next + 1 } else { next };
            match arg {
                Arg::Dep(name, version) => {
                    out.packages.push(Package::new("Maven", &name, &version).scoped(scope).direct(true))
                }
                Arg::Unresolved(why) => {
                    let what = if j == first {
                        self.source(i, close)
                    } else if parens {
                        shown(&format!("{conf}({})", self.source(j, next)))
                    } else {
                        shown(&format!("{conf} {}", self.source(j, next)))
                    };
                    out.unresolved.push(Unresolved { what, why })
                }
                Arg::Skip => {}
            }
            // Groovy lists several: `implementation 'a:b:1', 'c:d:2'`.
            if !self.punct(next, ',') {
                return close.max(i + 1);
            }
            j = self.skip_newlines(next + 1);
        }
    }
}

/// Whether the identifier at `i` starts a configuration call: followed by
/// `(`, a string or another identifier on the same line. A string followed
/// by `(` is Kotlin's quoted configuration name.
fn is_declaration(s: &Script, i: usize) -> bool {
    if matches!(s.toks[i].kind, Kind::Str(_)) {
        return s.punct(i + 1, '(');
    }
    let Some(word) = s.ident(i) else { return false };
    if KEYWORDS.contains(&word) || CONTROL.contains(&word) || word == "dependencies" {
        return false;
    }
    // `implementation(…)`, `implementation '…'`, `implementation libs.x`;
    // not `a.b`, `a = b` or `a {`.
    matches!(s.toks.get(i + 1).map(|t| &t.kind), Some(Kind::Punct('(') | Kind::Str(_) | Kind::Ident))
}

#[derive(Clone, Copy, PartialEq)]
enum Block {
    Dependencies,
    Other,
}

fn script(text: &str) -> Result<Declared> {
    let _ = lines(text)?; // the line cap
    let s = Script { text, toks: tokens(text)? };
    let mut out = Declared::default();
    let mut stack: Vec<Block> = Vec::new();
    // Whether the last token ends a statement (a line end, `;`, a brace).
    let mut at_start = true;
    // The last token that wasn't a line end, to name the block a `{` opens.
    let mut last: Option<usize> = None;
    // A control-flow keyword in a dependencies block, until its `{`.
    let mut control = false;
    let mut i = 0;
    while i < s.toks.len() {
        let in_deps = stack.last() == Some(&Block::Dependencies);
        match &s.toks[i].kind {
            Kind::Newline => {
                at_start = true;
                i += 1;
                continue;
            }
            Kind::Punct('{') => {
                let opens_deps = last.and_then(|l| s.ident(l)) == Some("dependencies");
                let kind = if opens_deps || (in_deps && control) { Block::Dependencies } else { Block::Other };
                if stack.len() >= MAX_DEPTH {
                    return Err(Error::Invalid("build script: nested too deeply".into()));
                }
                stack.push(kind);
                control = false;
                at_start = true;
            }
            Kind::Punct('}') => {
                stack.pop();
                at_start = true;
            }
            Kind::Punct(';') => at_start = true,
            Kind::Ident if in_deps && at_start && CONTROL.contains(&s.ident(i).unwrap_or("")) => {
                control = true;
                // `if (…)`: the condition isn't evaluated, both branches count.
                let next = s.skip_newlines(i + 1);
                if s.punct(next, '(') {
                    last = Some(next);
                    i = s.after_parens(next);
                    continue;
                }
            }
            Kind::Str(_) | Kind::Ident if in_deps && at_start && is_declaration(&s, i) => {
                i = s.declaration(i, &mut out);
                last = Some(i.saturating_sub(1));
                at_start = false;
                continue;
            }
            _ => at_start = false,
        }
        last = Some(i);
        i += 1;
    }
    Ok(out)
}

// Version catalogs --------------------------------------------------------------

/// A `[versions]` entry, or a library's inline `version = { … }`: a plain
/// string, or `strictly`/`require` (an exact one, the coordinate check
/// says); `prefer`/`reject` alone pin nothing.
fn catalog_version(v: &Val) -> Option<String> {
    match v {
        Val::Str(s) => Some(s.clone()),
        Val::Raw(raw) => {
            let fields = toml::inline(raw);
            let get = |k: &str| fields.iter().find(|(f, _)| f == k).and_then(|(_, v)| v.as_str());
            get("strictly").or_else(|| get("require")).map(str::to_string)
        }
    }
}

fn catalog(text: &str) -> Result<Declared> {
    let tables = toml::parse(text)?;
    let known = ["versions", "libraries", "plugins", "bundles"];
    if !tables.iter().any(|t| !t.array && known.contains(&t.name.as_str())) {
        return Err(Error::Invalid(
            "a version catalog has a [versions], [libraries], [plugins] or [bundles] table".into(),
        ));
    }
    let versions: BTreeMap<&str, &Val> = tables
        .iter()
        .filter(|t| t.name == "versions" && !t.array)
        .flat_map(|t| &t.entries)
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let mut out = Declared::default();
    for (alias, val) in tables.iter().filter(|t| t.name == "libraries" && !t.array).flat_map(|t| &t.entries) {
        let unresolved = |why| Unresolved { what: shown(&format!("[libraries] {alias}")), why };
        // A coordinate string, or a table naming `module` (or `group` and
        // `name`) and the version (inline, `version.ref`, or a rich table).
        let coords = match val {
            Val::Str(s) => s.clone(),
            Val::Raw(raw) => {
                let fields = toml::inline(raw);
                let get = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v);
                let module = match (get("module").and_then(Val::as_str), get("group"), get("name")) {
                    (Some(m), _, _) => m.to_string(),
                    (None, Some(Val::Str(g)), Some(Val::Str(n))) => format!("{g}:{n}"),
                    _ => {
                        out.unresolved.push(unresolved("not a module or group and name"));
                        continue;
                    }
                };
                let version = match (get("version"), get("version.ref").and_then(Val::as_str)) {
                    (Some(v), _) => catalog_version(v).or_else(|| {
                        // `version = { ref = "x" }`
                        let Val::Raw(raw) = v else { return None };
                        let fields = toml::inline(raw);
                        let r = fields.iter().find(|(f, _)| f == "ref").and_then(|(_, v)| v.as_str())?;
                        versions.get(r).and_then(|v| catalog_version(v))
                    }),
                    (None, Some(r)) => match versions.get(r) {
                        Some(v) => catalog_version(v),
                        None => {
                            out.unresolved.push(unresolved("version.ref names no [versions] entry"));
                            continue;
                        }
                    },
                    (None, None) => None,
                };
                match version {
                    Some(v) => format!("{module}:{v}"),
                    None if get("version").is_some() || get("version.ref").is_some() => {
                        out.unresolved.push(unresolved("a dynamic version or a range"));
                        continue;
                    }
                    None => module,
                }
            }
        };
        match coordinate(&coords) {
            Ok((name, version)) => out.packages.push(Package::new("Maven", &name, &version).direct(true)),
            Err(why) => out.unresolved.push(unresolved(why)),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "gradle_build_tests.rs"]
mod tests;
