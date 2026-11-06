//! `requirements*.txt` → `PyPI`. Only exact pins count (`name==version`,
//! `name===version`, optionally with extras, an environment marker or
//! `--hash` options); ranges, wildcards, URLs, paths, editables and other
//! options have no single version to look up. Lines continue with a
//! trailing backslash; comments start at a `#` after whitespace. `-r FILE`
//! (`--requirement`) includes are followed relative to the including file,
//! once each, and only while they stay inside the repository root; an
//! include that is missing or leads outside it is skipped, as osv-scalibr
//! skips includes it can't open. Names are normalized (PEP 503).

use super::{MAX_FILE, Package, lines, plausible};
use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// At most this many files are read for one requirements file.
pub const MAX_INCLUDES: usize = 64;

pub fn is_requirements(name: &str) -> bool {
    name.starts_with("requirements") && name.ends_with(".txt")
}

/// What a requirements file's name says about its pins: `requirements-dev.txt`,
/// `requirements_test.txt` and `requirements-docs.txt` are tooling, not what
/// ships; a plain `requirements.txt` says nothing either way (it may be a
/// `pip freeze` of everything).
pub fn scope_of_file(name: &str) -> super::Scope {
    let stem = name.to_ascii_lowercase();
    let stem = stem.strip_suffix(".txt").unwrap_or(&stem);
    let tooling = ["dev", "test", "tests", "testing", "docs", "lint", "ci"];
    let dev = stem.split(['-', '_', '.']).skip(1).any(|part| tooling.contains(&part));
    if dev { super::Scope::Dev } else { super::Scope::Unknown }
}

/// PEP 503: lowercase, runs of `-`, `_` and `.` as one `-`.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

/// The pin on one logical line, if it is one.
fn pin(line: &str) -> Option<(String, String)> {
    // Per-requirement options (--hash, --config-settings, …) end the requirement.
    let line = match line.find(" --").or_else(|| line.find("\t--")) {
        Some(i) => &line[..i],
        None => line,
    };
    let req = line.split(';').next().unwrap_or("").trim();
    if req.contains('@') || req.contains("://") {
        return None; // a direct reference
    }
    let name_end =
        req.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))).unwrap_or(req.len());
    let name = &req[..name_end];
    if !valid_name(name) {
        return None;
    }
    let mut rest = req[name_end..].trim_start();
    if let Some(extras) = rest.strip_prefix('[') {
        rest = extras.split_once(']')?.1.trim_start();
    }
    let rest = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')).unwrap_or(rest).trim();
    if rest.contains(',') {
        return None; // more than one specifier
    }
    let version = rest.strip_prefix("===").or_else(|| rest.strip_prefix("=="))?.trim();
    if version.contains(['*', ' ', '\t', '$']) || !plausible(version) {
        return None;
    }
    Some((normalize(name), version.to_string()))
}

/// The pins in one file and the files it includes, as written.
pub fn parse(text: &str) -> Result<(Vec<Package>, Vec<String>)> {
    let mut pkgs = Vec::new();
    let mut includes = Vec::new();
    let mut logical = String::new();
    let mut all = lines(text)?.peekable();
    while let Some(raw) = all.next() {
        // A comment (a `#` first or after whitespace) ends the line, and
        // any continuation inside it.
        let line = match raw.match_indices('#').find(|(i, _)| *i == 0 || raw[..*i].ends_with([' ', '\t'])) {
            Some((i, _)) => &raw[..i],
            None => raw,
        };
        if let Some(head) = line.strip_suffix('\\')
            && all.peek().is_some()
        {
            logical.push_str(head);
            continue;
        }
        logical.push_str(line.strip_suffix('\\').unwrap_or(line));
        if logical.len() > super::MAX_LINE {
            return Err(Error::Invalid(format!("a requirement of {} bytes (cap {})", logical.len(), super::MAX_LINE)));
        }
        let l = logical.trim();
        let include = l
            .strip_prefix("--requirement")
            .map(|r| r.trim_start_matches(['=', ' ', '\t']))
            .or_else(|| l.strip_prefix("-r").map(|r| r.trim_start_matches(['=', ' ', '\t'])));
        if let Some(file) = include {
            if !file.is_empty() {
                includes.push(file.trim().to_string());
            }
        } else if !l.starts_with('-')
            && let Some((name, version)) = pin(l)
        {
            pkgs.push(Package::new("PyPI", &name, &version));
        }
        logical.clear();
    }
    Ok((pkgs, includes))
}

/// The pins of a requirements file and of everything it includes under `root`.
pub fn parse_file(path: &Path, root: &Path) -> Result<Vec<Package>> {
    let root = root.canonicalize()?;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut queue = vec![path.to_path_buf()];
    let mut out = Vec::new();
    let mut first = true;
    while let Some(p) = queue.pop() {
        let real = match p.canonicalize() {
            Ok(r) => r,
            Err(e) if first => return Err(e.into()),
            Err(_) => continue,
        };
        if !first && (!real.starts_with(&root) || !real.is_file()) {
            continue;
        }
        first = false;
        if !seen.insert(real.clone()) {
            continue;
        }
        if seen.len() > MAX_INCLUDES {
            return Err(Error::Invalid(format!("more than {MAX_INCLUDES} included requirements files")));
        }
        let (pkgs, includes) = parse(&crate::utils::files::read_capped(&real, MAX_FILE)?)?;
        let scope = scope_of_file(real.file_name().and_then(|n| n.to_str()).unwrap_or(""));
        out.extend(pkgs.into_iter().map(|p| p.scoped(scope)));
        let dir = p.parent().unwrap_or(Path::new("."));
        // Depth first, in the order written.
        queue.extend(includes.iter().rev().map(|inc| dir.join(inc)));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "requirements_tests.rs"]
mod tests;
