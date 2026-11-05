//! `bun.lock` (Bun's text lockfile, JSONC) → `npm`. Comments and trailing
//! commas are dropped before the JSON is read. Each `packages` entry is a
//! tuple whose first element is `name@version`; workspace, file, link, git,
//! GitHub and tarball entries have no registry version and are skipped. The
//! binary `bun.lockb` isn't read.

use super::{Package, plausible};
use crate::error::Result;
use crate::utils::json;
use serde_json::Value;

/// JSONC → JSON: `//` and `/* */` comments and commas before `}` or `]`
/// removed, outside strings.
pub fn strip_jsonc(text: &str) -> String {
    let b = text.as_bytes();
    let mut no_comments = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            no_comments.push(c);
            if c == b'\\' && i + 1 < b.len() {
                no_comments.push(b[i + 1]);
                i += 2;
                continue;
            }
            in_str = c != b'"';
            i += 1;
        } else if c == b'"' {
            in_str = true;
            no_comments.push(c);
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i += 2;
            no_comments.push(b' ');
        } else {
            no_comments.push(c);
            i += 1;
        }
    }
    let b = no_comments;
    let mut out = Vec::with_capacity(b.len());
    let mut in_str = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            in_str = c != b'"';
        } else if c == b'"' {
            in_str = true;
            out.push(c);
        } else if c == b',' {
            let next = b[i + 1..].iter().find(|x| !x.is_ascii_whitespace());
            if !matches!(next, Some(b'}' | b']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(strip_jsonc(text).as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    for entry in data.get("packages").and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
        let Some(id) = entry.get(0).and_then(Value::as_str) else { continue };
        let Some(at) = id.get(1..).and_then(|r| r.find('@')).map(|i| i + 1) else { continue };
        let (name, version) = (&id[..at], &id[at + 1..]);
        if plausible(version) {
            out.push(Package::new("npm", name, version));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "bun_tests.rs"]
mod tests;
