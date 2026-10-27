//! Semantic Versioning 2.0.0 precedence (semver.org §11), for crates.io,
//! npm, SwiftURL, Pub, Hex and NuGet. Lenient where lockfiles are: a leading
//! "v", and any number of numeric core parts (NuGet's four), missing parts
//! counting as 0.

use crate::versions::num_cmp;
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
        _ => crate::versions::cmp(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::assert_sorted;

    #[test]
    fn semver_org_precedence() {
        // semver.org §11, in order.
        assert_sorted(cmp, &["1.0.0", "2.0.0", "2.1.0", "2.1.1"]);
        assert_sorted(
            cmp,
            &[
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.beta",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.11",
                "1.0.0-rc.1",
                "1.0.0",
            ],
        );
    }

    #[test]
    fn build_metadata_and_leniency() {
        assert_eq!(cmp("1.0.0+20130313144700", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp("1.0.0-beta+exp.sha.5114f85", "1.0.0-beta"), Ordering::Equal);
        assert_eq!(cmp("v1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(cmp("4.0.0.1", "4.0.0"), Ordering::Greater);
        assert_eq!(cmp("1.9.0", "1.10.0"), Ordering::Less);
        assert_eq!(cmp("0.0.0-20230101", "0.0.0"), Ordering::Less);
        assert!(parse("1.0.0-").is_none() && parse("1.a.0").is_none() && parse("1.0.0+").is_none());
        assert_eq!(cmp("not a version", "1.0.0"), Ordering::Less, "falls back to the generic order");
    }
}
