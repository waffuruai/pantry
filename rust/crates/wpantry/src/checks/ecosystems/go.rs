//! Go module versions, as `golang.org/x/mod/semver.Compare` orders them:
//! semver with shorthands (v1, v1.2), pseudo-versions as pre-releases,
//! `+incompatible` as ignored build metadata, and every invalid version
//! equal to every other and below every valid one. OSV writes Go versions
//! without the "v", so it is optional here.

use super::semver::cmp_pre;
use crate::checks::ecosystems::versions::num_cmp;
use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
struct Version<'a> {
    core: [&'a str; 3],
    pre: Vec<&'a str>,
}

fn num(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn parse(v: &str) -> Option<Version<'_>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let (head, build) = match v.split_once('+') {
        Some((h, b)) => (h, Some(b)),
        None => (v, None),
    };
    if let Some(b) = build
        && (b.is_empty()
            || !b.split('.').all(|i| !i.is_empty() && i.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')))
    {
        return None;
    }
    let (core, pre) = match head.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (head, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 || !parts.iter().all(|p| num(p)) {
        return None;
    }
    // Shorthands (v1, v1.2) take no pre-release or build suffix.
    if parts.len() < 3 && (pre.is_some() || build.is_some()) {
        return None;
    }
    let pre: Vec<&str> = match pre {
        Some(p) => {
            let ids: Vec<&str> = p.split('.').collect();
            let ok = ids.iter().all(|i| {
                !i.is_empty()
                    && i.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    && (!i.bytes().all(|c| c.is_ascii_digit()) || num(i))
            });
            if !ok {
                return None;
            }
            ids
        }
        None => Vec::new(),
    };
    Some(Version { core: [parts[0], parts.get(1).copied().unwrap_or("0"), parts.get(2).copied().unwrap_or("0")], pre })
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    match (parse(a), parse(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => {
            for (p, q) in x.core.iter().zip(y.core.iter()) {
                match num_cmp(p, q) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            cmp_pre(&x.pre, &y.pre)
        }
    }
}

#[cfg(test)]
#[path = "go_tests.rs"]
mod tests;
