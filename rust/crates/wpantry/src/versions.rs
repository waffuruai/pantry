//! Ecosystem-agnostic version ordering, good enough to pick a fixed version
//! (Python: `versions.py`, which this matches case for case).
//!
//! OSV does the authoritative "is this version affected" matching server
//! side; this only orders candidate fixed versions and compares app versions
//! to the latest ones, so it favours being predictable over being exact. The
//! per-ecosystem comparators are in [`crate::compare`].

use std::cmp::Ordering;

/// One token of a version: a word sorts before the end of the version (a
/// pre-release), which sorts before a number.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    End,
    Num(String), // digits without leading zeros ("0" for zero)
}

impl Tok {
    fn rank(&self) -> u8 {
        match self {
            Tok::Word(_) => 0,
            Tok::End => 1,
            Tok::Num(_) => 2,
        }
    }
}

impl Ord for Tok {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Tok::Num(a), Tok::Num(b)) => num_cmp(a, b),
            (Tok::Word(a), Tok::Word(b)) => a.cmp(b),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

impl PartialOrd for Tok {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare two digit strings numerically, whatever their length.
pub fn num_cmp(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn norm_num(d: &str) -> String {
    let t = d.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// The sort key: numbers compare numerically, a pre-release word (rc, beta)
/// sorts before the release it precedes, and build metadata is ignored.
fn key(version: &str) -> Vec<Tok> {
    let mut v = version.trim();
    // A "v", "version-", "release-" or "r" prefix before a digit.
    for prefix in ["version-", "release-", "v", "r"] {
        if v.len() > prefix.len()
            && v[..prefix.len()].eq_ignore_ascii_case(prefix)
            && v.as_bytes()[prefix.len()].is_ascii_digit()
        {
            v = &v[prefix.len()..];
            break;
        }
    }
    v = v.split('+').next().unwrap_or("");
    // A dpkg epoch.
    if let Some((epoch, rest)) = v.split_once(':')
        && !epoch.is_empty()
        && epoch.bytes().all(|b| b.is_ascii_digit())
    {
        v = rest;
    }
    let mut out = Vec::new();
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i].is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            out.push(Tok::Num(norm_num(&v[start..i])));
        } else if b[i].is_ascii_alphabetic() {
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Tok::Word(v[start..i].to_ascii_lowercase()));
        } else {
            i += 1;
        }
    }
    out.push(Tok::End);
    out
}

/// Generic order of two versions.
pub fn cmp(a: &str, b: &str) -> Ordering {
    key(a).cmp(&key(b))
}

pub fn lt(a: &str, b: &str) -> bool {
    cmp(a, b) == Ordering::Less
}

/// The numbers in a version (before any build metadata), without leading zeros.
pub fn numbers(version: &str) -> Vec<String> {
    let v = version.split('+').next().unwrap_or("");
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in v.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(norm_num(&cur));
            cur.clear();
        }
    }
    if !cur.is_empty() {
        out.push(norm_num(&cur));
    }
    out
}

/// How many leading numbers two versions share.
pub fn common_prefix(a: &str, b: &str) -> usize {
    numbers(a).iter().zip(numbers(b).iter()).take_while(|(x, y)| x == y).count()
}

/// The fixed version to recommend: newer than installed, on the closest
/// release line (most leading numbers in common), lowest on that line,
/// ordered by `order` (the ecosystem's comparator, or [`cmp`]).
pub fn pick_safe_by<S: AsRef<str>>(
    installed: &str,
    candidates: &[S],
    order: impl Fn(&str, &str) -> Ordering,
) -> Option<String> {
    let mut newer: Vec<&str> = candidates
        .iter()
        .map(AsRef::as_ref)
        .filter(|c| !c.is_empty() && order(installed, c) == Ordering::Less)
        .collect();
    newer.sort_unstable();
    newer.dedup();
    newer.sort_by(|a, b| {
        common_prefix(installed, b).cmp(&common_prefix(installed, a)).then_with(|| order(a, b)).then_with(|| a.cmp(b))
    });
    newer.first().map(|s| s.to_string())
}

/// [`pick_safe_by`] with the generic order (Python: `versions.pick_safe`).
pub fn pick_safe<S: AsRef<str>>(installed: &str, candidates: &[S]) -> Option<String> {
    pick_safe_by(installed, candidates, cmp)
}

/// True when installed is at least latest. Compares only as many numbers as
/// both carry, so app version "2026.1" equals catalog "2026.1.0".
pub fn same_or_newer(installed: &str, latest: &str) -> bool {
    let (a, b) = (numbers(installed), numbers(latest));
    let n = a.len().min(b.len());
    if n == 0 {
        return true;
    }
    for (x, y) in a[..n].iter().zip(&b[..n]) {
        match num_cmp(x, y) {
            Ordering::Equal => continue,
            o => return o == Ordering::Greater,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Python test vectors (python/test_wscanner.py `Versions`).
    #[test]
    fn order() {
        assert!(lt("1.2.3", "1.2.10"));
        assert!(lt("1.2.3rc1", "1.2.3"));
        assert!(lt("v3.12.13", "v3.12.14"));
        assert!(lt("curl-8_7_1", "curl-8_11_1"));
        assert!(!lt("2.0.0", "2.0.0"));
        assert!(lt("1:1.0", "2.0"), "the epoch is dropped");
        assert!(lt("1.0+build9", "1.0.1"));
        assert_eq!(cmp("V1.0", "1.0"), Ordering::Equal);
        assert!(lt("99999999999999999999999", "100000000000000000000000"));
    }

    #[test]
    fn pick_safe_prefers_same_line() {
        assert_eq!(pick_safe("24.22.1", &["26.12.2", "24.22.2", "22.23.5"]).as_deref(), Some("24.22.2"));
        assert_eq!(pick_safe("1.0.9", &["1.0.10", "1.0.11"]).as_deref(), Some("1.0.10"));
        assert_eq!(pick_safe("2.0.0", &["1.9.0"]), None);
        assert_eq!(pick_safe("2.0.0", &["", "2.0.0"]), None);
    }

    #[test]
    fn same_or_newer_ignores_extra_digits() {
        assert!(same_or_newer("2026.1", "2026.1.0"));
        assert!(!same_or_newer("3.0.20", "3.0.24"));
        assert!(same_or_newer("x", "1.0"));
    }

    #[test]
    fn common_prefix_counts_leading_numbers() {
        assert_eq!(common_prefix("v3.12.13", "v3.12.15"), 2);
        assert_eq!(common_prefix("1.02", "1.2.0"), 2);
        assert_eq!(numbers("v1.2.3+meta.4"), ["1", "2", "3"]);
    }
}
