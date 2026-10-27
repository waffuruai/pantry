//! Go module versions, as `golang.org/x/mod/semver.Compare` orders them:
//! semver with shorthands (v1, v1.2), pseudo-versions as pre-releases,
//! `+incompatible` as ignored build metadata, and every invalid version
//! equal to every other and below every valid one. OSV writes Go versions
//! without the "v", so it is optional here.

use super::semver::cmp_pre;
use crate::versions::num_cmp;
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
mod tests {
    use super::*;

    /// x/mod/semver's semver_test.go `tests`, in its order: each entry is
    /// (version, canonical form, "" when invalid). The test asserts that
    /// Compare follows the list order, with equal canonical forms equal.
    const TESTS: &[(&str, &str)] = &[
        ("bad", ""),
        ("v1-alpha.beta.gamma", ""),
        ("v1-pre", ""),
        ("v1+meta", ""),
        ("v1-pre+meta", ""),
        ("v1.2-pre", ""),
        ("v1.2+meta", ""),
        ("v1.2-pre+meta", ""),
        ("v1.0.0-alpha", "v1.0.0-alpha"),
        ("v1.0.0-alpha.1", "v1.0.0-alpha.1"),
        ("v1.0.0-alpha.beta", "v1.0.0-alpha.beta"),
        ("v1.0.0-beta", "v1.0.0-beta"),
        ("v1.0.0-beta.2", "v1.0.0-beta.2"),
        ("v1.0.0-beta.11", "v1.0.0-beta.11"),
        ("v1.0.0-rc.1", "v1.0.0-rc.1"),
        ("v1", "v1.0.0"),
        ("v1.0", "v1.0.0"),
        ("v1.0.0", "v1.0.0"),
        ("v1.2", "v1.2.0"),
        ("v1.2.0", "v1.2.0"),
        ("v1.2.3-456", "v1.2.3-456"),
        ("v1.2.3-456.789", "v1.2.3-456.789"),
        ("v1.2.3-456-789", "v1.2.3-456-789"),
        ("v1.2.3-456a", "v1.2.3-456a"),
        ("v1.2.3-pre", "v1.2.3-pre"),
        ("v1.2.3-pre+meta", "v1.2.3-pre"),
        ("v1.2.3-pre.1", "v1.2.3-pre.1"),
        ("v1.2.3-zzz", "v1.2.3-zzz"),
        ("v1.2.3", "v1.2.3"),
        ("v1.2.3+meta", "v1.2.3"),
        ("v1.2.3+meta-pre", "v1.2.3"),
        ("v1.2.3+meta-pre.sha.256a", "v1.2.3"),
    ];

    #[test]
    fn x_mod_semver_order() {
        for (i, (a, ca)) in TESTS.iter().enumerate() {
            for (j, (b, cb)) in TESTS.iter().enumerate() {
                let want = if ca == cb { Ordering::Equal } else { i.cmp(&j) };
                assert_eq!(cmp(a, b), want, "{a} vs {b}");
            }
        }
    }

    #[test]
    fn osv_forms() {
        assert_eq!(cmp("1.2.3", "v1.2.3"), Ordering::Equal);
        assert_eq!(cmp("0.0.0-20191109021931-daa7c04131f5", "0.1.0"), Ordering::Less);
        assert_eq!(cmp("2.0.0+incompatible", "2.0.0"), Ordering::Equal);
        assert_eq!(cmp("1.21.3", "1.21.10"), Ordering::Less);
        assert_eq!(cmp("v1.02.0", "v0.1.0"), Ordering::Less, "leading zeros are invalid");
    }
}
