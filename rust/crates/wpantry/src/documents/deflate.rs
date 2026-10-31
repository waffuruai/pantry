//! DEFLATE (RFC 1951), enough to read an Office part or a PDF object
//! stream without a crate: stored, fixed and dynamic blocks, decoded a bit
//! at a time with puff's canonical-Huffman algorithm. Bounded: it gives up
//! past the caller's output cap and on any malformed input, so a zip bomb
//! or a truncated stream is `None`, not a panic or a gigabyte.

use super::u16le;

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    n: u32,
}

impl Bits<'_> {
    fn bits(&mut self, count: u32) -> Option<u32> {
        while self.n < count {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.acc |= (b as u32) << self.n;
            self.n += 8;
        }
        let v = self.acc & ((1u32 << count) - 1);
        self.acc >>= count;
        self.n -= count;
        Some(v)
    }

    fn align(&mut self) {
        self.acc = 0;
        self.n = 0;
    }
}

/// A canonical Huffman code, decoded a bit at a time (puff's algorithm).
struct Huff {
    count: [u16; 16],
    symbol: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Option<Huff> {
        let mut count = [0u16; 16];
        for &l in lengths {
            if l as usize >= 16 {
                return None;
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[l as usize];
                *symbol.get_mut(*o as usize)? = sym as u16;
                *o += 1;
            }
        }
        Some(Huff { count, symbol })
    }

    fn decode(&self, bits: &mut Bits) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= bits.bits(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return self.symbol.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// Raw DEFLATE to bytes, giving up past `max` output or on any malformed
/// input.
pub fn inflate(data: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut bits = Bits { data, pos: 0, acc: 0, n: 0 };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let len = u16le(data, bits.pos)?;
                let nlen = u16le(data, bits.pos + 2)?;
                if len != (!nlen) & 0xFFFF {
                    return None;
                }
                let start = bits.pos + 4;
                out.extend_from_slice(data.get(start..start + len)?);
                bits.pos = start + len;
            }
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                let lit = Huff::new(&lengths)?;
                let dist = Huff::new(&[5u8; 30])?;
                codes(&mut bits, &lit, &dist, &mut out, max)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut bits)?;
                codes(&mut bits, &lit, &dist, &mut out, max)?;
            }
            _ => return None,
        }
        if out.len() > max {
            return None;
        }
        if last {
            return Some(out);
        }
    }
}

/// The literal/length and distance codes a dynamic block carries in its
/// header, themselves written with a third code (RFC 1951 3.2.7).
fn dynamic_tables(bits: &mut Bits) -> Option<(Huff, Huff)> {
    let nlen = bits.bits(5)? as usize + 257;
    let ndist = bits.bits(5)? as usize + 1;
    let ncode = bits.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return None;
    }
    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut cl = [0u8; 19];
    for &o in ORDER.iter().take(ncode) {
        cl[o] = bits.bits(3)? as u8;
    }
    let clh = Huff::new(&cl)?;
    let mut lengths = vec![0u8; nlen + ndist];
    let mut i = 0;
    while i < nlen + ndist {
        let sym = clh.decode(bits)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return None;
                }
                let prev = lengths[i - 1];
                let rep = 3 + bits.bits(2)? as usize;
                if i + rep > lengths.len() {
                    return None;
                }
                lengths[i..i + rep].fill(prev);
                i += rep;
            }
            17 | 18 => {
                let rep = if sym == 17 { 3 + bits.bits(3)? as usize } else { 11 + bits.bits(7)? as usize };
                if i + rep > lengths.len() {
                    return None;
                }
                i += rep;
            }
            _ => return None,
        }
    }
    if lengths[256] == 0 {
        return None;
    }
    Some((Huff::new(&lengths[..nlen])?, Huff::new(&lengths[nlen..])?))
}

fn codes(bits: &mut Bits, lit: &Huff, dist: &Huff, out: &mut Vec<u8>, max: usize) -> Option<()> {
    loop {
        let sym = lit.decode(bits)? as usize;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Some(()),
            257..=285 => {
                let i = sym - 257;
                let len = LEN_BASE[i] as usize + bits.bits(LEN_EXTRA[i] as u32)? as usize;
                let d = dist.decode(bits)? as usize;
                if d >= 30 {
                    return None;
                }
                let distance = DIST_BASE[d] as usize + bits.bits(DIST_EXTRA[d] as u32)? as usize;
                if distance > out.len() {
                    return None;
                }
                let start = out.len() - distance;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return None,
        }
        if out.len() > max {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zlib's dynamic-block encoding of a sentence with repeats.
    const DYNAMIC: &[u8] = &[
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x8a, 0x13, 0x33, 0x53, 0x14, 0x4a, 0x32,
        0x52, 0x15, 0x52, 0xf2, 0x93, 0x4b, 0x73, 0x53, 0xf3, 0x4a, 0x14, 0x4a, 0xf2, 0xc1, 0xfc, 0xe2, 0xe4, 0xc4,
        0xbc, 0xbc, 0xd4, 0x22, 0x6b, 0xa8, 0xf2, 0xc4, 0xf4, 0xc4, 0xcc, 0x3c, 0x3d, 0x00,
    ];
    const DYNAMIC_TEXT: &[u8] = b"hello hello hello hello, said the document to the scanner; hello again.";

    #[test]
    fn inflate_reads_the_three_block_types() {
        assert_eq!(inflate(DYNAMIC, 1 << 20).as_deref(), Some(DYNAMIC_TEXT));
        let fixed: &[u8] = &[0x4b, 0x4c, 0x4a, 0x4e, 0x84, 0x21, 0x85, 0x8a, 0xca, 0x2a, 0x00];
        assert_eq!(inflate(fixed, 1 << 20).as_deref(), Some(b"abcabcabcabc xyz" as &[u8]));
        let stored: &[u8] = &[0x01, 0x07, 0x00, 0xf8, 0xff, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x21];
        assert_eq!(inflate(stored, 1 << 20).as_deref(), Some(b"stored!" as &[u8]));
    }

    #[test]
    fn inflate_gives_up_rather_than_guessing() {
        assert_eq!(inflate(DYNAMIC, 10), None, "the output cap holds");
        assert_eq!(inflate(&DYNAMIC[..20], 1 << 20), None, "truncated input is an error, not a panic");
        assert_eq!(inflate(&[0xff; 64], 1 << 20), None, "garbage");
        assert_eq!(inflate(&[], 1 << 20), None, "nothing");
        let bad_stored: &[u8] = &[0x01, 0x07, 0x00, 0x00, 0x00, b'x'];
        assert_eq!(inflate(bad_stored, 1 << 20), None, "a stored block whose length check fails");
        let reserved_type: &[u8] = &[0x07];
        assert_eq!(inflate(reserved_type, 1 << 20), None, "block type 3 is reserved");
    }

    /// Real streams against zlib's answer: `WPANTRY_INFLATE_FIXTURES=<dir>`
    /// holding `*.raw` (zlib-wrapped or raw deflate) and `*.out` pairs.
    #[test]
    #[ignore]
    fn inflate_matches_zlib_on_real_streams() {
        let Ok(dir) = std::env::var("WPANTRY_INFLATE_FIXTURES") else { return };
        let mut n = 0;
        for e in std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()) {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("raw") {
                continue;
            }
            let raw = std::fs::read(&path).unwrap();
            let want = std::fs::read(path.with_extension("out")).unwrap();
            // a zlib header (0x78 …) wraps raw deflate: skip the two bytes
            let body = if raw.first() == Some(&0x78) { &raw[2..] } else { &raw[..] };
            let got = inflate(body, 64 << 20);
            assert_eq!(got.as_deref().map(|g| g.len()), Some(want.len()), "{}: length", path.display());
            assert!(got.as_deref() == Some(&want[..]), "{}: content differs", path.display());
            n += 1;
        }
        assert!(n > 0);
    }
}
