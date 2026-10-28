//! RubyGems ordering, as `Gem::Version#<=>` sorts (rubygems
//! `lib/rubygems/version.rb`): a "-" reads as ".pre.", trailing zero
//! segments and zeros before the first letter of a pre-release are dropped,
//! then the version splits into runs of digits and runs of letters; numbers
//! compare numerically, words as strings, a word sorts below any number, and
//! a version with leftover segments is lower only if they hold a word. A
//! version `Gem::Version` rejects falls back to the generic order.

use crate::versions::num_cmp;
use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
enum Seg<'a> {
    Num(&'a str),
    Word(&'a str),
}

fn alnum_run(s: &[u8], i: usize, extra: u8) -> usize {
    let mut j = i;
    while j < s.len() && (s[j].is_ascii_alphanumeric() || s[j] == extra) {
        j += 1;
    }
    j
}

/// `Gem::Version.correct?`: `\s*([0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)?\s*`.
fn correct(v: &str) -> bool {
    let s = v.as_bytes();
    if s.is_empty() {
        return true;
    }
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return false;
    }
    while i < s.len() && s[i] == b'.' {
        let j = alnum_run(s, i + 1, 0);
        if j == i + 1 {
            return false;
        }
        i = j;
    }
    if i < s.len() && s[i] == b'-' {
        loop {
            let j = alnum_run(s, i + 1, b'-');
            if j == i + 1 {
                return false;
            }
            i = j;
            if i == s.len() || s[i] != b'.' {
                break;
            }
        }
    }
    i == s.len()
}

/// The canonical segments of a version `correct` accepted, already
/// stripped and with "-" read as ".pre.".
fn canonical(v: &str) -> Vec<Seg<'_>> {
    let b = v.as_bytes();
    // Trailing [.0]+ after a letter or a dot.
    let mut end = b.len();
    if let Some(i) = (1..b.len()).find(|&i| {
        (b[i - 1].is_ascii_alphabetic() || b[i - 1] == b'.') && b[i..].iter().all(|c| *c == b'.' || *c == b'0')
    }) {
        end = i;
    }
    let v = &v[..end];
    let b = v.as_bytes();
    // Zeros before the first letter of a pre-release: the first run of
    // [0.] at the start or after a dot that a letter follows.
    let mut cut = (0, 0);
    if b.iter().any(u8::is_ascii_alphabetic) {
        for i in 0..b.len() {
            if i > 0 && b[i - 1] != b'.' {
                continue;
            }
            let mut j = i;
            while j < b.len() && (b[j] == b'0' || b[j] == b'.') {
                j += 1;
            }
            if j > i && j < b.len() && b[j].is_ascii_alphabetic() {
                cut = (i, j);
                break;
            }
        }
    }
    let mut out = Vec::new();
    for part in [&v[..cut.0], &v[cut.1..]] {
        let p = part.as_bytes();
        let mut i = 0;
        while i < p.len() {
            let start = i;
            if p[i].is_ascii_digit() {
                while i < p.len() && p[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Seg::Num(&part[start..i]));
            } else if p[i].is_ascii_alphabetic() {
                while i < p.len() && p[i].is_ascii_alphabetic() {
                    i += 1;
                }
                out.push(Seg::Word(&part[start..i]));
            } else {
                i += 1;
            }
        }
    }
    // Two parts can meet mid-run ("1." + "a" is fine; digits never meet).
    out
}

fn zero(n: &str) -> bool {
    n.bytes().all(|b| b == b'0')
}

fn cmp_canonical(l: &[Seg], r: &[Seg]) -> Ordering {
    let limit = l.len().min(r.len());
    for i in 0..limit {
        match (&l[i], &r[i]) {
            (Seg::Num(a), Seg::Num(b)) => match num_cmp(a, b) {
                Ordering::Equal => {}
                o => return o,
            },
            (Seg::Word(a), Seg::Word(b)) => match a.cmp(b) {
                Ordering::Equal => {}
                o => return o,
            },
            (Seg::Word(_), Seg::Num(_)) => return Ordering::Less,
            (Seg::Num(_), Seg::Word(_)) => return Ordering::Greater,
        }
    }
    // Leftover segments: a word makes that side lower, a non-zero number higher.
    for s in &l[limit..] {
        match s {
            Seg::Word(_) => return Ordering::Less,
            Seg::Num(n) if !zero(n) => return Ordering::Greater,
            _ => {}
        }
    }
    for s in &r[limit..] {
        match s {
            Seg::Word(_) => return Ordering::Greater,
            Seg::Num(n) if !zero(n) => return Ordering::Less,
            _ => {}
        }
    }
    Ordering::Equal
}

/// The version as `Gem::Version.new` stores it, or None if it rejects it.
fn normalize(v: &str) -> Option<String> {
    let t = v.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r'));
    if !correct(t) {
        return None;
    }
    Some(if t.is_empty() { "0".to_string() } else { t.replace('-', ".pre.") })
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    match (normalize(a), normalize(b)) {
        (Some(x), Some(y)) if x == y => Ordering::Equal,
        (Some(x), Some(y)) => cmp_canonical(&canonical(&x), &canonical(&y)),
        _ => crate::versions::cmp(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(v: &str) -> Vec<Seg<'static>> {
        let n: &'static str = Box::leak(normalize(v).unwrap().into_boxed_str());
        canonical(n)
    }

    // The vectors of rubygems' test/rubygems/test_gem_version.rb (MIT).
    #[test]
    fn rubygems_test_gem_version() {
        use Ordering::*;
        // test_initialize, test_empty_version, test_class_correct
        for good in ["1.0", "1.0 ", " 1.0 ", "1.0\n", "\n1.0\n"] {
            assert_eq!(cmp("1.0", good), Equal, "{good:?}");
        }
        for empty in ["", "   ", " "] {
            assert_eq!(normalize(empty).as_deref(), Some("0"));
        }
        assert!(normalize("5.1").is_some() && normalize("an incorrect version").is_none());
        // test_initialize_invalid
        for bad in ["junk", "1.0\n2.0", "1..2", "1.2 3.4", "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e."]
        {
            assert!(normalize(bad).is_none(), "{bad:?}");
        }
        // test_equals2, test_hash, test_eql_eh (== ignores eql?)
        assert_eq!(cmp("1.2", "1.2"), Equal);
        assert_ne!(cmp("1.2", "1.3"), Equal);
        assert_eq!(cmp("1.2.b1", "1.2.b.1"), Equal);
        assert_eq!(cmp("1.2", "1.2.0"), Equal);
        assert_eq!(cmp("1.2.pre.1", "1.2.0.pre.1.0"), Equal);
        // test_spaceship
        let spaceship = [
            ("1.0", "1.0.0", Equal),
            ("1.0", "1.0.a", Greater),
            ("1.8.2", "0.0.0", Greater),
            ("1.8.2", "1.8.2.a", Greater),
            ("1.8.2.b", "1.8.2.a", Greater),
            ("1.8.2.a", "1.8.2", Less),
            ("1.8.2.a10", "1.8.2.a9", Greater),
            ("", "0", Equal),
            ("0.beta.1", "0.0.beta.1", Equal),
            ("0.0.beta", "0.0.beta.1", Less),
            ("0.0.beta", "0.beta.1", Less),
            ("5.a", "5.0.0.rc2", Less),
            ("5.x", "5.0.0.rc2", Greater),
            ("1.9.3", "1.9.3", Equal),
            ("1.9.3", "1.9.2.99", Greater),
            ("1.9.3", "1.9.3.1", Less),
        ];
        for (a, b, want) in spaceship {
            assert_eq!(cmp(a, b), want, "{a} <=> {b}");
            assert_eq!(cmp(b, a), want.reverse(), "{b} <=> {a}");
        }
        // test_semver
        for (a, b) in [
            ("1.0.0-alpha", "1.0.0-alpha.1"),
            ("1.0.0-alpha.1", "1.0.0-beta.2"),
            ("1.0.0-beta.2", "1.0.0-beta.11"),
            ("1.0.0-beta.11", "1.0.0-rc.1"),
            ("1.0.0-rc1", "1.0.0"),
            ("1.0.0-1", "1"),
        ] {
            assert_eq!(cmp(a, b), Less, "{a} < {b}");
        }
        // test_sort_key_*: timestamps, segments over the radix, many segments
        assert_eq!(cmp("1.0.0", "0.0.1.20220404083012"), Greater);
        assert_eq!(cmp("0.7.0", "0.6.63000"), Greater);
        assert_eq!(cmp("18.0.1", "18.0.2"), Less);
        assert_eq!(cmp("2.30.1.250000", "2.30.1.249999"), Greater);
        assert_eq!(cmp("1.1.1.1.1.1.1", "1.1.1.1.1.1"), Greater);
        // test_canonical_segments
        assert_eq!(segs("1.0.0"), [Seg::Num("1")]);
        assert_eq!(segs("1.0.0.a.1.0"), [Seg::Num("1"), Seg::Word("a"), Seg::Num("1")]);
        assert_eq!(segs("1.2.3-1"), [Seg::Num("1"), Seg::Num("2"), Seg::Num("3"), Seg::Word("pre"), Seg::Num("1")]);
        // test_prerelease ordering against its release
        for pre in ["1.2.0.a", "2.9.b", "22.1.50.0.d", "1.2.d.42", "1.A", "1-1", "1-a"] {
            assert!(normalize(pre).unwrap().bytes().any(|b| b.is_ascii_alphabetic()), "{pre}");
        }
    }

    #[test]
    fn never_panics_and_falls_back() {
        assert_eq!(cmp("junk", "1.0"), crate::versions::cmp("junk", "1.0"));
        assert_eq!(cmp("99999999999999999999999.0", "99999999999999999999998.9"), Ordering::Greater);
        assert_eq!(cmp("1.0.0-x86_64-linux", "1.0.0"), crate::versions::cmp("1.0.0-x86_64-linux", "1.0.0"));
    }
}
