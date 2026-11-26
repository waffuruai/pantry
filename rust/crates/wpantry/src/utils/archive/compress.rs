//! DEFLATE out (RFC 1951), without a crate: one fixed-Huffman block, the
//! matches found through hash chains in the 32 KiB window, greedily. Fixed
//! codes need no tables in the stream and come within a few tens of percent
//! of zlib on repetitive text, which is what it packs: the HTML report's
//! bundle, and the deflated zips the tests build. [`super::deflate::inflate`]
//! (and any browser's `DecompressionStream('deflate-raw')`) reads it back.
//!
//! ```
//! use wpantry::utils::archive::{compress::deflate, deflate::inflate};
//! let text = b"hello hello hello hello";
//! assert_eq!(inflate(&deflate(text), 1 << 20).as_deref(), Some(&text[..]));
//! ```
use super::deflate::{DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA};

const WINDOW: usize = 1 << 15;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const HASH: usize = 1 << 15;
/// How many earlier positions one match search tries (zlib's default level
/// tries up to 128): enough for rows that repeat, bounded for text that
/// doesn't.
const CHAIN: usize = 64;
const NONE: usize = usize::MAX;

struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    /// Header fields and extra bits, least significant first.
    fn put(&mut self, v: u32, count: u32) {
        self.acc |= u64::from(v) << self.n;
        self.n += count;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// A Huffman code, most significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        self.put(code.reverse_bits() >> (32 - len), len);
    }

    /// A literal/length symbol in the fixed code (RFC 1951 3.2.6).
    fn sym(&mut self, sym: u32) {
        match sym {
            0..=143 => self.code(0x30 + sym, 8),
            144..=255 => self.code(0x190 + sym - 144, 9),
            256..=279 => self.code(sym - 256, 7),
            _ => self.code(0xC0 + sym - 280, 8),
        }
    }
}

/// The slot of `v` in a base table: the last base not above it.
fn slot(base: &[u16], v: usize) -> usize {
    base.iter().rposition(|&b| usize::from(b) <= v).expect("a base of 1 or 3 starts each table")
}

/// `data` as raw DEFLATE.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut w = Bits { out: Vec::with_capacity(data.len() / 4 + 16), acc: 0, n: 0 };
    w.put(0b011, 3); // the last block, fixed Huffman
    let hash = |i: usize| {
        ((usize::from(data[i]) << 10) ^ (usize::from(data[i + 1]) << 5) ^ usize::from(data[i + 2])) & (HASH - 1)
    };
    // head: the latest position per hash; prev: the one before it, per
    // position in the window. A position within the window still has its
    // own prev slot: the next one to reuse it is a window later.
    let (mut head, mut prev) = (vec![NONE; HASH], vec![NONE; WINDOW]);
    let mut i = 0;
    while i < data.len() {
        let max = (data.len() - i).min(MAX_MATCH);
        let (mut best, mut dist) = (0, 0);
        if max >= MIN_MATCH {
            let mut cand = head[hash(i)];
            for _ in 0..CHAIN {
                if cand == NONE || i - cand > WINDOW {
                    break;
                }
                let len = (0..max).take_while(|&k| data[cand + k] == data[i + k]).count();
                if len > best {
                    (best, dist) = (len, i - cand);
                    if len == max {
                        break;
                    }
                }
                cand = prev[cand % WINDOW];
            }
        }
        if best >= MIN_MATCH {
            let l = slot(&LEN_BASE, best);
            w.sym(257 + l as u32);
            w.put((best - usize::from(LEN_BASE[l])) as u32, u32::from(LEN_EXTRA[l]));
            let d = slot(&DIST_BASE, dist);
            w.code(d as u32, 5);
            w.put((dist - usize::from(DIST_BASE[d])) as u32, u32::from(DIST_EXTRA[d]));
        } else {
            best = 1;
            w.sym(u32::from(data[i]));
        }
        for k in (i..i + best).filter(|k| k + MIN_MATCH <= data.len()) {
            let h = hash(k);
            prev[k % WINDOW] = head[h];
            head[h] = k;
        }
        i += best;
    }
    w.sym(256);
    if w.n > 0 {
        w.put(0, 8 - w.n);
    }
    w.out
}

#[cfg(test)]
#[path = "compress_tests.rs"]
mod tests;
