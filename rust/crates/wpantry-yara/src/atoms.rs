//! Every atom of every rule in one table, probed once per input position.
//!
//! Atoms are at most four bytes, so instead of an Aho-Corasick automaton the
//! table hashes them directly: a 2^24-bit prefilter (2 MB) indexed by the
//! first three bytes at a position answers "could any atom start here?" with
//! one load and one bit test, and only on a yes are the per-length maps
//! consulted. Text, where the prefilter is densest, still rejects most
//! positions; binary data rejects nearly all of them. It needs no pointer
//! chasing and no per-state memory, and building it is linear in the atoms.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Where an atom leads: the string, its variant, and the atom's offset into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub string: u32,
    pub variant: u32,
    pub offset: u32,
}

/// A small multiplicative hasher for integer keys (the FxHash scheme).
#[derive(Default)]
pub struct FxHasher(u64);

impl Hasher for FxHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.write_u64(u64::from(*b));
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }

    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }

    fn write_u16(&mut self, n: u16) {
        self.write_u64(u64::from(n));
    }
}

type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

const PREFILTER_BITS: usize = 1 << 24;

pub struct AtomTable {
    prefilter: Vec<u64>,
    by_len: [FxMap<u32, Vec<Target>>; 4],
}

impl Default for AtomTable {
    fn default() -> Self {
        AtomTable { prefilter: vec![0; PREFILTER_BITS / 64], by_len: Default::default() }
    }
}

/// The first (up to) four bytes at a position as a little-endian integer.
fn key(bytes: &[u8]) -> u32 {
    bytes.iter().take(4).enumerate().fold(0, |k, (i, b)| k | u32::from(*b) << (8 * i))
}

impl AtomTable {
    pub fn add(&mut self, atom: &[u8], target: Target) {
        assert!((1..=4).contains(&atom.len()), "atoms are 1 to 4 bytes");
        let k = key(atom);
        self.by_len[atom.len() - 1].entry(k).or_default().push(target);
        // Mark every three-byte prefix this atom can start: a shorter atom
        // matches whatever follows it.
        let known = atom.len().min(3);
        let free = 3 - known;
        for tail in 0..1u32 << (8 * free) {
            let bit = (k & ((1 << (8 * known)) - 1)) | tail << (8 * known);
            self.prefilter[(bit >> 6) as usize] |= 1 << (bit & 63);
        }
    }

    pub fn len(&self) -> usize {
        self.by_len.iter().map(|m| m.values().map(Vec::len).sum::<usize>()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Call `hit(position, target)` for every atom occurrence in `data`.
    pub fn scan(&self, data: &[u8], mut hit: impl FnMut(usize, &Target)) {
        let n = data.len();
        for pos in 0..n {
            let window = &data[pos..n.min(pos + 4)];
            let k = key(window);
            let bit = k & 0xFF_FFFF;
            // Past the end the missing bytes read as zero, which can only add
            // false prefilter hits, never lose one; the lengths below check.
            if self.prefilter[(bit >> 6) as usize] & (1 << (bit & 63)) == 0 {
                continue;
            }
            for len in 1..=window.len() {
                let masked = if len == 4 { k } else { k & ((1 << (8 * len)) - 1) };
                if let Some(targets) = self.by_len[len - 1].get(&masked) {
                    for t in targets {
                        hit(pos, t);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "atoms_tests.rs"]
mod tests;
