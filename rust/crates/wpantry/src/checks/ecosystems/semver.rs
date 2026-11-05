//! Semantic Versioning 2.0.0 precedence (semver.org §11), for crates.io,
//! npm, SwiftURL, Pub, Hex and NuGet. Lenient where lockfiles are: a leading
//! "v", and any number of numeric core parts (NuGet's four), missing parts
//! counting as 0.

use crate::checks::ecosystems::versions::num_cmp;
use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
pub struct Version<'a> {
    pub core: Vec<&'a str>,
    pub pre: Vec<&'a str>,
}

fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn parse(v: &str) -> Option<Version<'_>> {
    let v = v.trim();
    let v = v.strip_prefix('v').or_else(|| v.strip_prefix('V')).unwrap_or(v);
    let v = match v.split_once('+') {
        Some((head, build)) => {
            if !build.split('.').all(ident) {
                return None;
            }
            head
        }
        None => v,
    };
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let core: Vec<&str> = core.split('.').collect();
    if !core.iter().all(|p| numeric(p)) {
        return None;
    }
    let pre: Vec<&str> = match pre {
        Some(p) => {
            let ids: Vec<&str> = p.split('.').collect();
            if !ids.iter().all(|i| ident(i)) {
                return None;
            }
            ids
        }
        None => Vec::new(),
    };
    Some(Version { core, pre })
}

pub fn cmp_parsed(a: &Version, b: &Version) -> Ordering {
    let n = a.core.len().max(b.core.len());
    for i in 0..n {
        let x = a.core.get(i).copied().unwrap_or("0");
        let y = b.core.get(i).copied().unwrap_or("0");
        match num_cmp(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    cmp_pre(&a.pre, &b.pre)
}

/// Pre-release precedence: none beats any; identifiers compare numerically
/// when both are numeric, numeric below alphanumeric, ASCII otherwise; a
/// shorter set of equal identifiers is lower.
pub fn cmp_pre(a: &[&str], b: &[&str]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    for (x, y) in a.iter().zip(b) {
        let o = match (numeric(x), numeric(y)) {
            (true, true) => num_cmp(x, y),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => cmp_parsed(&x, &y),
        _ => crate::checks::ecosystems::versions::cmp(a, b),
    }
}

#[cfg(test)]
#[path = "semver_tests.rs"]
mod tests;
