//! RPM version ordering for openSUSE and SUSE: [epoch:]version[-release],
//! epoch first, then `rpmvercmp` on version and release (alternating alpha
//! and numeric segments, numbers newer than letters, `~` before everything
//! and `^` after the base version).

use crate::checks::ecosystems::versions::num_cmp;
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
#[path = "rpm_tests.rs"]
mod tests;
