//! Whether a candidate secret reads as text rather than a key: betterleaks
//! asks a tokenizer (cl100k: text compresses to few tokens), Pantry asks two
//! plainer questions, which on the corpora we measured drop what betterleaks'
//! check drops and never a random key:
//!
//! - **A word:** it holds a dictionary word of [`MIN_WORD`] to [`MAX_WORD`]
//!   letters, cased as a word (`config`, `CONFIG`, `Config`; not `cOnFiG`,
//!   which random keys are made of). The words are web2's
//!   (`assets/secrets/words.txt.gz`, `scripts/secret_words.py`).
//! - **A run:** [`RUN`] or more characters climbing or falling one at a time
//!   (`0123456789`, `abcdefgh`), as placeholders are written.
//!
//! betterleaks' `failsTokenEfficiency` and its token-ratio limits both read
//! as this check.

use std::collections::HashSet;
use std::sync::OnceLock;

pub const MIN_WORD: usize = 5;
pub const MAX_WORD: usize = 12;
pub const RUN: usize = 8;
/// The word list's largest decompressed size, a bound for the inflater.
const MAX_WORDS_BYTES: usize = 4 << 20;

const WORDS_GZ: &[u8] = include_bytes!("../../../assets/secrets/words.txt.gz");

fn words() -> &'static HashSet<Box<[u8]>> {
    static WORDS: OnceLock<HashSet<Box<[u8]>>> = OnceLock::new();
    WORDS.get_or_init(|| {
        let text =
            crate::utils::archive::gzip::gunzip(WORDS_GZ, MAX_WORDS_BYTES).expect("the bundled word list inflates");
        text.split(|&b| b == b'\n').filter(|w| !w.is_empty()).map(Box::from).collect()
    })
}

/// Lowercase, UPPERCASE or Capitalized: how a word is written, not a key.
fn cased(w: &[u8]) -> bool {
    let lower = |b: &[u8]| b.iter().all(u8::is_ascii_lowercase);
    lower(w) || w.iter().all(u8::is_ascii_uppercase) || (w[0].is_ascii_uppercase() && lower(&w[1..]))
}

/// Whether `s` holds a dictionary word, cased as a word.
pub fn has_word(s: &[u8]) -> bool {
    let words = words();
    (0..s.len()).any(|i| {
        (MIN_WORD..=MAX_WORD).filter(|n| i + n <= s.len()).any(|n| {
            let w = &s[i..i + n];
            w.iter().all(u8::is_ascii_alphabetic) && cased(w) && words.contains(w.to_ascii_lowercase().as_slice())
        })
    })
}

/// Whether `s` has [`RUN`] characters climbing or falling by one.
pub fn has_run(s: &[u8]) -> bool {
    let run = |step: i16| {
        let mut n = 1;
        s.windows(2).any(|w| {
            n = if w[1] as i16 - w[0] as i16 == step { n + 1 } else { 1 };
            n >= RUN
        })
    };
    run(1) || run(-1)
}

/// Whether `secret` reads as text.
pub fn readable(secret: &[u8]) -> bool {
    has_run(secret) || has_word(secret)
}

#[cfg(test)]
#[path = "readable_tests.rs"]
mod tests;
