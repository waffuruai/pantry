//! `yarn.lock` → `npm`, read line by line. Each unindented line opens an
//! entry keyed by its descriptors (`"a@^1, a@^1.1":`); its two-space
//! indented fields hold the version. Yarn 1 writes `version "1.2.3"` and
//! `resolved "<tarball>"`; Yarn 2+ (berry, recognized by `__metadata:`)
//! writes YAML, `version: 1.2.3` and `resolution: "name@npm:1.2.3"`.
//!
//! Yarn 1: the name comes from the first descriptor, through `npm:`
//! aliases; `file:`, `link:`, git, GitHub and tarball-URL descriptors and
//! git-resolved entries are skipped. Berry: only `npm:` resolutions count,
//! and `patch:` resolutions of `npm:` packages (Yarn's built-in patches of
//! typescript, resolve, fsevents); workspaces, portals, links, files, execs
//! and git are skipped.

use super::{Package, lines, plausible, unquote};
use crate::error::{Error, Result};

/// (name, rest) of `name@rest`, the name possibly scoped.
fn split_at_name(desc: &str) -> Option<(&str, &str)> {
    let i = desc.get(1..)?.find('@')? + 1;
    Some((&desc[..i], &desc[i + 1..]))
}

/// Ranges that aren't registry ranges.
fn local_range(range: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "file:",
        "link:",
        "portal:",
        "workspace:",
        "exec:",
        "patch:",
        "git",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http:",
        "https:",
    ];
    PREFIXES.iter().any(|p| range.starts_with(p)) || (range.contains('/') && !range.starts_with("npm:")) // user/repo shorthand, paths
}

fn classic(header: &str, fields: &[(&str, &str)]) -> Option<(String, String)> {
    let first = header.split(", ").next()?;
    let first = unquote(first.trim());
    let (mut name, mut range) = split_at_name(first)?;
    if let Some(alias) = range.strip_prefix("npm:")
        && let Some((real, r)) = split_at_name(alias)
    {
        (name, range) = (real, r);
    }
    if local_range(range) {
        return None;
    }
    let field = |k: &str| fields.iter().find(|(f, _)| *f == k).map(|(_, v)| unquote(v));
    let resolved = field("resolved").unwrap_or("");
    if resolved.starts_with("git") || resolved.starts_with("file:") || resolved.contains("codeload.github.com") {
        return None;
    }
    Some((name.to_string(), field("version")?.to_string()))
}

/// `%3A` and friends in a berry `patch:` locator.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn berry(fields: &[(&str, &str)]) -> Option<(String, String)> {
    let field = |k: &str| fields.iter().find(|(f, _)| *f == k).map(|(_, v)| unquote(v));
    let resolution = field("resolution")?;
    let (name, rest) = split_at_name(resolution)?;
    let registry = if rest.starts_with("npm:") {
        true
    } else if let Some(inner) = rest.strip_prefix("patch:") {
        let inner = percent_decode(inner.split('#').next().unwrap_or(""));
        split_at_name(&inner).is_some_and(|(_, r)| r.starts_with("npm:"))
    } else {
        false
    };
    registry.then(|| (name.to_string(), field("version").unwrap_or("").to_string()))
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let all: Vec<&str> = lines(text)?.collect();
    let is_berry = all.iter().any(|l| l.trim_end() == "__metadata:");
    let mut out = Vec::new();
    let mut header: Option<&str> = None;
    let mut fields: Vec<(&str, &str)> = Vec::new();
    let mut flush = |header: Option<&str>, fields: &[(&str, &str)]| {
        let Some(h) = header else { return };
        if h == "__metadata" {
            return;
        }
        let found = if is_berry { berry(fields) } else { classic(h, fields) };
        if let Some((name, version)) = found
            && plausible(&version)
        {
            out.push(Package::new("npm", &name, &version));
        }
    };
    for line in all {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            flush(header.take(), &fields);
            fields.clear();
            header = Some(line.trim_end().strip_suffix(':').unwrap_or(line.trim_end()));
            continue;
        }
        if header.is_none() {
            return Err(Error::Invalid("yarn.lock: a field before any entry".into()));
        }
        // Only the entry's own fields (two spaces), not its dependency lists.
        if line.len() > 2 && !line[2..].starts_with(' ') {
            let item = line.trim();
            let (k, v) = if is_berry {
                item.split_once(':').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((item, ""))
            } else {
                item.split_once(' ').map(|(k, v)| (k.trim_end_matches(':'), v.trim())).unwrap_or((item, ""))
            };
            fields.push((unquote(k), v));
        }
    }
    flush(header.take(), &fields);
    Ok(out)
}

#[cfg(test)]
#[path = "yarn_tests.rs"]
mod tests;
