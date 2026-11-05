//! Alpine (and Wolfi, Chainguard) package versions, ordered as apk-tools'
//! `apk_version_compare` does: digits, an optional letter, `_suffix[N]`
//! parts (alpha < beta < pre < rc < none < cvs < svn < git < hg < p) and a
//! `-rN` package revision, read by its token state machine.

use std::cmp::Ordering;

// apk-tools' token types, in its order.
const INVALID: i8 = -1;
const DIGIT_OR_ZERO: i8 = 0;
const DIGIT: i8 = 1;
const LETTER: i8 = 2;
const SUFFIX: i8 = 3;
const SUFFIX_NO: i8 = 4;
const REVISION_NO: i8 = 5;
const END: i8 = 6;

const PRE_SUFFIXES: [&str; 4] = ["alpha", "beta", "pre", "rc"];
const POST_SUFFIXES: [&str; 5] = ["cvs", "svn", "git", "hg", "p"];

struct Blob<'a> {
    s: &'a [u8],
}

fn next_token(t: &mut i8, b: &mut Blob) {
    let mut n = INVALID;
    if b.s.is_empty() || b.s[0] == 0 {
        n = END;
    } else if (*t == DIGIT || *t == DIGIT_OR_ZERO) && b.s[0].is_ascii_lowercase() {
        n = LETTER;
    } else if *t == LETTER && b.s[0].is_ascii_digit() {
        n = DIGIT;
    } else if *t == SUFFIX && b.s[0].is_ascii_digit() {
        n = SUFFIX_NO;
    } else {
        match b.s[0] {
            b'.' => n = DIGIT_OR_ZERO,
            b'_' => n = SUFFIX,
            b'-' if b.s.len() > 1 && b.s[1] == b'r' => {
                n = REVISION_NO;
                b.s = &b.s[1..];
            }
            _ => {}
        }
        b.s = &b.s[1..];
    }
    if n < *t
        && !((n == DIGIT_OR_ZERO && *t == DIGIT) || (n == SUFFIX && *t == SUFFIX_NO) || (n == DIGIT && *t == LETTER))
    {
        n = INVALID;
    }
    *t = n;
}

fn get_token(t: &mut i8, b: &mut Blob) -> i64 {
    if b.s.is_empty() {
        *t = END;
        return 0;
    }
    let mut v: i64 = 0;
    let mut i = 0usize;
    let mut nt = INVALID;
    match *t {
        DIGIT_OR_ZERO if b.s[0] == b'0' => {
            // Leading zeros get a special treatment: all but the last one
            // count against the part, the last is read as a digit.
            while i + 1 < b.s.len() && b.s[i + 1] == b'0' {
                i += 1;
            }
            nt = DIGIT;
            v = -(i as i64);
        }
        DIGIT_OR_ZERO | DIGIT | SUFFIX_NO | REVISION_NO => {
            while i < b.s.len() && b.s[i].is_ascii_digit() {
                v = v.wrapping_mul(10).wrapping_add((b.s[i] - b'0') as i64);
                i += 1;
            }
            if i >= 18 {
                *t = INVALID;
                return -1;
            }
        }
        LETTER => {
            v = b.s[0] as i64;
            i = 1;
        }
        SUFFIX => {
            let pre = PRE_SUFFIXES.iter().position(|p| b.s.starts_with(p.as_bytes()));
            let post = POST_SUFFIXES.iter().position(|p| b.s.starts_with(p.as_bytes()));
            if let Some(n) = pre {
                v = n as i64 - PRE_SUFFIXES.len() as i64;
                i = PRE_SUFFIXES[n].len();
            } else if let Some(n) = post {
                v = n as i64;
                i = POST_SUFFIXES[n].len();
            } else {
                *t = INVALID;
                return -1;
            }
        }
        _ => {
            *t = INVALID;
            return -1;
        }
    }
    b.s = &b.s[i..];
    if b.s.is_empty() {
        *t = END;
    } else if nt != INVALID {
        *t = nt;
    } else {
        next_token(t, b);
    }
    v
}

/// apk-tools' comparison; versions it can't read compare by their tokens up
/// to the bad one, as apk itself does.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (mut x, mut y) = (Blob { s: a.trim().as_bytes() }, Blob { s: b.trim().as_bytes() });
    let (mut at, mut bt) = (DIGIT, DIGIT);
    let (mut av, mut bv) = (0i64, 0i64);
    while at == bt && at != END && at != INVALID && av == bv {
        av = get_token(&mut at, &mut x);
        bv = get_token(&mut bt, &mut y);
    }
    if av != bv {
        return av.cmp(&bv);
    }
    if at == bt {
        return Ordering::Equal;
    }
    // The leading parts are equal; the longer version is greater unless what
    // follows is a pre-release suffix.
    let mut tt = at;
    if at == SUFFIX && get_token(&mut tt, &mut x) < 0 {
        return Ordering::Less;
    }
    tt = bt;
    if bt == SUFFIX && get_token(&mut tt, &mut y) < 0 {
        return Ordering::Greater;
    }
    bt.cmp(&at)
}

#[cfg(test)]
#[path = "apk_tests.rs"]
mod tests;
