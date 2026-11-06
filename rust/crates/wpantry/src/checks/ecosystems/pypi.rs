//! PEP 440 version ordering for PyPI, as `packaging.version.Version` sorts:
//! epoch, release (trailing zeros ignored), pre-release, post-release,
//! development release, then the local label. Normalisation follows the
//! spec: case-insensitive, `alpha`/`beta`/`c`/`pre`/`preview` spellings,
//! `rev`/`r` and a bare `-N` for post-releases, optional separators and
//! implicit zeros.

use crate::checks::ecosystems::versions::num_cmp;
use std::cmp::Ordering;

/// A project name as PyPI compares names (PEP 503): lowercased, with each
/// run of `-`, `_` and `.` as one `-`.
pub fn normalize(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep {
                out.push('-');
                sep = false;
            }
            out.push(c.to_ascii_lowercase());
        }
    }
    if sep {
        out.push('-');
    }
    out
}

#[derive(Debug, PartialEq)]
pub struct Version {
    epoch: String,
    release: Vec<String>,
    pre: Option<(u8, String)>, // (0 a, 1 b, 2 rc, number)
    post: Option<String>,
    dev: Option<String>,
    local: Vec<String>,
}

struct Scanner<'a> {
    s: &'a [u8],
    i: usize,
}

impl Scanner<'_> {
    fn digits(&mut self) -> Option<String> {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        (self.i > start).then(|| {
            let t = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("0").trim_start_matches('0');
            if t.is_empty() { "0".to_string() } else { t.to_string() }
        })
    }

    fn sep(&mut self) -> bool {
        if self.i < self.s.len() && matches!(self.s[self.i], b'.' | b'-' | b'_') {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// One of `words` (longest first) at the cursor, case-insensitively.
    fn word(&mut self, words: &[&str]) -> Option<usize> {
        for (n, w) in words.iter().enumerate() {
            let end = self.i + w.len();
            if end <= self.s.len() && self.s[self.i..end].eq_ignore_ascii_case(w.as_bytes()) {
                self.i = end;
                return Some(n);
            }
        }
        None
    }

    fn done(&self) -> bool {
        self.i == self.s.len()
    }
}

pub fn parse(v: &str) -> Option<Version> {
    let v = v.trim();
    let (main, local) = match v.split_once('+') {
        Some((m, l)) => (m, Some(l)),
        None => (v, None),
    };
    let mut sc = Scanner { s: main.as_bytes(), i: 0 };
    if sc.i < sc.s.len() && matches!(sc.s[0], b'v' | b'V') {
        sc.i += 1;
    }
    let mut epoch = "0".to_string();
    let save = sc.i;
    if let Some(n) = sc.digits() {
        if sc.i < sc.s.len() && sc.s[sc.i] == b'!' {
            epoch = n;
            sc.i += 1;
        } else {
            sc.i = save;
        }
    }
    let mut release = vec![sc.digits()?];
    loop {
        let save = sc.i;
        if sc.i < sc.s.len() && sc.s[sc.i] == b'.' {
            sc.i += 1;
            if let Some(n) = sc.digits() {
                release.push(n);
                continue;
            }
        }
        sc.i = save;
        break;
    }
    // Pre-release: [sep](a|b|rc|alpha|beta|c|pre|preview)[sep][N]
    let mut pre = None;
    let save = sc.i;
    sc.sep();
    match sc.word(&["preview", "alpha", "beta", "pre", "rc", "a", "b", "c"]) {
        Some(w) => {
            let kind = match w {
                1 | 5 => 0,
                2 | 6 => 1,
                _ => 2,
            };
            let save_n = sc.i;
            sc.sep();
            let n = sc.digits().unwrap_or_else(|| {
                sc.i = save_n;
                "0".into()
            });
            pre = Some((kind, n));
        }
        None => sc.i = save,
    }
    // Post-release: -N, or [sep](post|rev|r)[sep][N]
    let mut post = None;
    let save = sc.i;
    if sc.i < sc.s.len() && sc.s[sc.i] == b'-' {
        sc.i += 1;
        if let Some(n) = sc.digits() {
            post = Some(n);
        } else {
            sc.i = save;
        }
    }
    if post.is_none() {
        let save = sc.i;
        sc.sep();
        if sc.word(&["post", "rev", "r"]).is_some() {
            let save_n = sc.i;
            sc.sep();
            post = Some(sc.digits().unwrap_or_else(|| {
                sc.i = save_n;
                "0".into()
            }));
        } else {
            sc.i = save;
        }
    }
    // Development release: [sep]dev[sep][N]
    let mut dev = None;
    let save = sc.i;
    sc.sep();
    if sc.word(&["dev"]).is_some() {
        let save_n = sc.i;
        sc.sep();
        dev = Some(sc.digits().unwrap_or_else(|| {
            sc.i = save_n;
            "0".into()
        }));
    } else {
        sc.i = save;
    }
    if !sc.done() {
        return None;
    }
    let local = match local {
        Some(l) => {
            let parts: Vec<String> = l.split(['.', '-', '_']).map(str::to_ascii_lowercase).collect();
            if parts.iter().any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric())) {
                return None;
            }
            parts
        }
        None => Vec::new(),
    };
    Some(Version { epoch, release, pre, post, dev, local })
}

fn cmp_release(a: &[String], b: &[String]) -> Ordering {
    let trim = |r: &[String]| r.len() - r.iter().rev().take_while(|n| *n == "0").count();
    let (a, b) = (&a[..trim(a)], &b[..trim(b)]);
    for (x, y) in a.iter().zip(b) {
        match num_cmp(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    a.len().cmp(&b.len())
}

/// An optional number where "absent" sorts below (`low`) or above every value.
fn cmp_opt(a: &Option<String>, b: &Option<String>, absent_low: bool) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => {
            if absent_low {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        (Some(_), None) => {
            if absent_low {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        (Some(x), Some(y)) => num_cmp(x, y),
    }
}

/// packaging's `_cmpkey` pre-release slot: a dev release with no pre or
/// post sorts before every pre-release; a final release after them.
fn pre_key(v: &Version) -> (i8, u8, &str) {
    match &v.pre {
        None if v.post.is_none() && v.dev.is_some() => (-1, 0, ""),
        None => (1, 0, ""),
        Some((k, n)) => (0, *k, n.as_str()),
    }
}

fn cmp_local(a: &[String], b: &[String]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    for (x, y) in a.iter().zip(b) {
        let xn = x.bytes().all(|c| c.is_ascii_digit());
        let yn = y.bytes().all(|c| c.is_ascii_digit());
        let o = match (xn, yn) {
            (true, true) => num_cmp(x, y),
            (true, false) => Ordering::Greater, // numbers sort after strings
            (false, true) => Ordering::Less,
            (false, false) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

pub fn cmp_parsed(a: &Version, b: &Version) -> Ordering {
    num_cmp(&a.epoch, &b.epoch)
        .then_with(|| cmp_release(&a.release, &b.release))
        .then_with(|| {
            let (x, y) = (pre_key(a), pre_key(b));
            x.0.cmp(&y.0).then(x.1.cmp(&y.1)).then_with(|| num_cmp(x.2, y.2))
        })
        .then_with(|| cmp_opt(&a.post, &b.post, true))
        .then_with(|| cmp_opt(&a.dev, &b.dev, false))
        .then_with(|| cmp_local(&a.local, &b.local))
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => cmp_parsed(&x, &y),
        _ => crate::checks::ecosystems::versions::cmp(a, b),
    }
}

#[cfg(test)]
#[path = "pypi_tests.rs"]
mod tests;
