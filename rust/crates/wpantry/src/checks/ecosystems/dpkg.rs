//! Debian version ordering (`dpkg --compare-versions`, deb-version(7)):
//! [epoch:]upstream[-revision], compared epoch first, then upstream and
//! revision by dpkg's `verrevcmp`, where `~` sorts before everything, even
//! the end of the string.

use crate::checks::ecosystems::versions::num_cmp;
use std::cmp::Ordering;

struct Evr<'a> {
    epoch: &'a str,
    upstream: &'a str,
    revision: &'a str,
}

fn split(v: &str) -> Evr<'_> {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e, r),
        _ => ("0", v),
    };
    let (upstream, revision) = match rest.rfind('-') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    Evr { epoch, upstream, revision }
}

/// dpkg's `order()`: `~` lowest, then the end of a part, letters, then
/// everything else.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

/// dpkg's `verrevcmp`.
pub fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = order(a.get(i).copied());
            let bc = order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        let (si, sj) = (i.min(a.len()), j.min(b.len()));
        while i < a.len() && a[i].is_ascii_digit() {
            i += 1;
        }
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let x = std::str::from_utf8(&a[si..i.min(a.len())]).unwrap_or("");
        let y = std::str::from_utf8(&b[sj..j.min(b.len())]).unwrap_or("");
        match num_cmp(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    Ordering::Equal
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    let (x, y) = (split(a), split(b));
    num_cmp(x.epoch, y.epoch)
        .then_with(|| verrevcmp(x.upstream, y.upstream))
        .then_with(|| verrevcmp(x.revision, y.revision))
}

#[cfg(test)]
#[path = "dpkg_tests.rs"]
mod tests;
