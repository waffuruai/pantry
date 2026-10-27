//! RPM version ordering for openSUSE and SUSE: [epoch:]version[-release],
//! epoch first, then `rpmvercmp` on version and release (alternating alpha
//! and numeric segments, numbers newer than letters, `~` before everything
//! and `^` after the base version).

use crate::versions::num_cmp;
use std::cmp::Ordering;

/// rpm's `rpmvercmp`.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let (ca, cb) = (a.get(i).copied(), b.get(j).copied());
        // The tilde sorts before everything else.
        if ca == Some(b'~') || cb == Some(b'~') {
            if ca != Some(b'~') {
                return Ordering::Greater;
            }
            if cb != Some(b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        // The caret is like the tilde, except that a version that ends
        // first (the base version) is the lower one.
        if ca == Some(b'^') || cb == Some(b'^') {
            if ca.is_none() {
                return Ordering::Less;
            }
            if cb.is_none() {
                return Ordering::Greater;
            }
            if ca != Some(b'^') {
                return Ordering::Greater;
            }
            if cb != Some(b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca.is_none() || cb.is_none() {
            break;
        }
        let isnum = a[i].is_ascii_digit();
        let class = |c: u8| if isnum { c.is_ascii_digit() } else { c.is_ascii_alphabetic() };
        let (si, sj) = (i, j);
        while i < a.len() && class(a[i]) {
            i += 1;
        }
        while j < b.len() && class(b[j]) {
            j += 1;
        }
        // Segments of different types: numbers are newer than letters.
        if sj == j {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }
        let x = std::str::from_utf8(&a[si..i]).unwrap_or("");
        let y = std::str::from_utf8(&b[sj..j]).unwrap_or("");
        let o = if isnum { num_cmp(x, y) } else { x.cmp(y) };
        if o != Ordering::Equal {
            return o;
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

fn split(v: &str) -> (&str, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e, r),
        _ => ("0", v),
    };
    match rest.rfind('-') {
        Some(i) => (epoch, &rest[..i], &rest[i + 1..]),
        None => (epoch, rest, ""),
    }
}

/// EVR comparison. A missing release compares equal to any release, as
/// rpm does when one side doesn't name one.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let ((ea, va, ra), (eb, vb, rb)) = (split(a), split(b));
    num_cmp(ea, eb)
        .then_with(|| rpmvercmp(va, vb))
        .then_with(|| if ra.is_empty() || rb.is_empty() { Ordering::Equal } else { rpmvercmp(ra, rb) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpmvercmp_at() {
        // rpm's tests/rpmvercmp.at, every RPMVERCMP(a, b, result) case.
        let cases: &[(&str, &str, i32)] = &[
            ("1.0", "1.0", 0),
            ("1.0", "2.0", -1),
            ("2.0", "1.0", 1),
            ("2.0.1", "2.0.1", 0),
            ("2.0", "2.0.1", -1),
            ("2.0.1", "2.0", 1),
            ("2.0.1a", "2.0.1a", 0),
            ("2.0.1a", "2.0.1", 1),
            ("2.0.1", "2.0.1a", -1),
            ("5.5p1", "5.5p1", 0),
            ("5.5p1", "5.5p2", -1),
            ("5.5p2", "5.5p1", 1),
            ("5.5p10", "5.5p10", 0),
            ("5.5p1", "5.5p10", -1),
            ("5.5p10", "5.5p1", 1),
            ("10xyz", "10.1xyz", -1),
            ("10.1xyz", "10xyz", 1),
            ("xyz10", "xyz10", 0),
            ("xyz10", "xyz10.1", -1),
            ("xyz10.1", "xyz10", 1),
            ("xyz.4", "xyz.4", 0),
            ("xyz.4", "8", -1),
            ("8", "xyz.4", 1),
            ("xyz.4", "2", -1),
            ("2", "xyz.4", 1),
            ("5.5p2", "5.6p1", -1),
            ("5.6p1", "5.5p2", 1),
            ("5.6p1", "6.5p1", -1),
            ("6.5p1", "5.6p1", 1),
            ("6.0.rc1", "6.0", 1),
            ("6.0", "6.0.rc1", -1),
            ("10b2", "10a1", 1),
            ("10a2", "10b2", -1),
            ("1.0aa", "1.0aa", 0),
            ("1.0a", "1.0aa", -1),
            ("1.0aa", "1.0a", 1),
            ("10.0001", "10.0001", 0),
            ("10.0001", "10.1", 0),
            ("10.1", "10.0001", 0),
            ("10.0001", "10.0039", -1),
            ("10.0039", "10.0001", 1),
            ("4.999.9", "5.0", -1),
            ("5.0", "4.999.9", 1),
            ("20101121", "20101121", 0),
            ("20101121", "20101122", -1),
            ("20101122", "20101121", 1),
            ("2_0", "2_0", 0),
            ("2.0", "2_0", 0),
            ("2_0", "2.0", 0),
            ("a", "a", 0),
            ("a+", "a+", 0),
            ("a+", "a_", 0),
            ("a_", "a+", 0),
            ("+a", "+a", 0),
            ("+a", "_a", 0),
            ("_a", "+a", 0),
            ("+_", "+_", 0),
            ("_+", "+_", 0),
            ("_+", "_+", 0),
            ("+", "_", 0),
            ("_", "+", 0),
            ("1.0~rc1", "1.0~rc1", 0),
            ("1.0~rc1", "1.0", -1),
            ("1.0", "1.0~rc1", 1),
            ("1.0~rc1", "1.0~rc2", -1),
            ("1.0~rc2", "1.0~rc1", 1),
            ("1.0~rc1~git123", "1.0~rc1~git123", 0),
            ("1.0~rc1~git123", "1.0~rc1", -1),
            ("1.0~rc1", "1.0~rc1~git123", 1),
            ("1.0^", "1.0^", 0),
            ("1.0^", "1.0", 1),
            ("1.0", "1.0^", -1),
            ("1.0^git1", "1.0^git1", 0),
            ("1.0^git1", "1.0", 1),
            ("1.0", "1.0^git1", -1),
            ("1.0^git1", "1.0^git2", -1),
            ("1.0^git2", "1.0^git1", 1),
            ("1.0^git1", "1.01", -1),
            ("1.01", "1.0^git1", 1),
            ("1.0^20160101", "1.0^20160101", 0),
            ("1.0^20160101", "1.0.1", -1),
            ("1.0.1", "1.0^20160101", 1),
            ("1.0^20160101^git1", "1.0^20160101^git1", 0),
            ("1.0^20160102", "1.0^20160101^git1", 1),
            ("1.0^20160101^git1", "1.0^20160102", -1),
            ("1.0~rc1^git1", "1.0~rc1^git1", 0),
            ("1.0~rc1^git1", "1.0~rc1", 1),
            ("1.0~rc1", "1.0~rc1^git1", -1),
            ("1.0^git1~pre", "1.0^git1~pre", 0),
            ("1.0^git1", "1.0^git1~pre", 1),
            ("1.0^git1~pre", "1.0^git1", -1),
        ];
        for (a, b, want) in cases {
            assert_eq!(rpmvercmp(a, b), want.cmp(&0), "rpmvercmp({a}, {b})");
        }
    }

    #[test]
    fn evr() {
        assert_eq!(cmp("1:1.0-1", "2.0-1"), Ordering::Greater);
        assert_eq!(cmp("0:3.1.4-150600.3.3.1", "3.1.4-150600.3.6.1"), Ordering::Less);
        assert_eq!(cmp("1.0-1", "1.0"), Ordering::Equal);
    }
}
