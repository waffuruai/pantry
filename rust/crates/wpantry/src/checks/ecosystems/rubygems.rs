//! RubyGems ordering, as `Gem::Version#<=>` sorts (rubygems
//! `lib/rubygems/version.rb`): a "-" reads as ".pre.", trailing zero
//! segments and zeros before the first letter of a pre-release are dropped,
//! then the version splits into runs of digits and runs of letters; numbers
//! compare numerically, words as strings, a word sorts below any number, and
//! a version with leftover segments is lower only if they hold a word. A
//! version `Gem::Version` rejects falls back to the generic order.

use crate::checks::ecosystems::versions::num_cmp;
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
        _ => crate::checks::ecosystems::versions::cmp(a, b),
    }
}

#[cfg(test)]
#[path = "rubygems_tests.rs"]
mod tests;
