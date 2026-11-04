//! YARA's `hash` module, and the digests themselves (MD5, SHA-1, SHA-256,
//! CRC-32), written here so the engine has no dependencies. `pe.imphash` and
//! the signature thumbprints use them too.

use super::{Module, hex, window};
use crate::value::{FnCtx, StructType, Type, Value};
use std::sync::Arc;

pub struct Hash(Arc<StructType>);

impl Hash {
    pub fn new() -> Self {
        let t = StructType::new()
            .func("md5", "ii", Type::Str, |c, a| range(c, a, |d| hex_value(&md5(d))))
            .func("md5", "s", Type::Str, |_, a| string(a, |d| hex_value(&md5(d))))
            .func("sha1", "ii", Type::Str, |c, a| range(c, a, |d| hex_value(&sha1(d))))
            .func("sha1", "s", Type::Str, |_, a| string(a, |d| hex_value(&sha1(d))))
            .func("sha256", "ii", Type::Str, |c, a| range(c, a, |d| hex_value(&sha256(d))))
            .func("sha256", "s", Type::Str, |_, a| string(a, |d| hex_value(&sha256(d))))
            .func("crc32", "ii", Type::Int, |c, a| range(c, a, |d| Value::Int(i64::from(crc32(d)))))
            .func("crc32", "s", Type::Int, |_, a| string(a, |d| Value::Int(i64::from(crc32(d)))))
            .func("checksum32", "ii", Type::Int, |c, a| range(c, a, |d| Value::Int(i64::from(checksum32(d)))))
            .func("checksum32", "s", Type::Int, |_, a| string(a, |d| Value::Int(i64::from(checksum32(d)))));
        Hash(Arc::new(t))
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Hash {
    fn name(&self) -> &'static str {
        "hash"
    }

    fn schema(&self) -> Arc<StructType> {
        self.0.clone()
    }

    fn parse(&self, _: &[u8]) -> Value {
        self.0.value().build()
    }
}

fn range(c: &FnCtx, a: &[Value], f: impl Fn(&[u8]) -> Value) -> Value {
    window(c.data, &a[0], &a[1]).map_or(Value::Undef, f)
}

fn string(a: &[Value], f: impl Fn(&[u8]) -> Value) -> Value {
    a[0].as_bytes().map_or(Value::Undef, f)
}

fn hex_value(digest: &[u8]) -> Value {
    Value::str(hex(digest))
}

/// The byte sum, as a 32-bit integer.
pub fn checksum32(d: &[u8]) -> u32 {
    d.iter().fold(0u32, |s, b| s.wrapping_add(u32::from(*b)))
}

pub fn crc32(d: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in d {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Pad a message the way MD5 and SHA do: `0x80`, zeros, then the bit
/// length (little-endian for MD5, big-endian for SHA).
fn padded(d: &[u8], big_endian: bool) -> Vec<u8> {
    let mut m = d.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    let bits = (d.len() as u64).wrapping_mul(8);
    m.extend_from_slice(&if big_endian { bits.to_be_bytes() } else { bits.to_le_bytes() });
    m
}

pub fn md5(d: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
        20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
        10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32).collect();
    let mut h = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in padded(d, false).chunks_exact(64) {
        let w: Vec<u32> = block.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().expect("4"))).collect();
        let [mut a, mut b, mut c, mut dd] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & dd), i),
                1 => ((dd & b) | (!dd & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ dd, (3 * i + 5) % 16),
                _ => (c ^ (b | !dd), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(w[g]);
            a = dd;
            dd = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        for (x, y) in h.iter_mut().zip([a, b, c, dd]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 16];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn sha1(d: &[u8]) -> [u8; 20] {
    let mut h = [0x6745_2301u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    for block in padded(d, true).chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(c.try_into().expect("4"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut dd, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & dd), 0x5A82_7999),
                1 => (b ^ c ^ dd, 0x6ED9_EBA1),
                2 => ((b & c) | (b & dd) | (c & dd), 0x8F1B_BCDC),
                _ => (b ^ c ^ dd, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = dd;
            dd = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, dd, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256(d: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for block in padded(d, true).chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(c.try_into().expect("4"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for (x, y) in h.iter_mut().zip(v) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::FieldKind;

    #[test]
    fn known_digests() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let long = vec![b'a'; 1000];
        assert_eq!(hex(&sha256(&long)), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(checksum32(b"\x01\x02"), 3);
    }

    #[test]
    fn module_functions() {
        let m = Hash::default();
        assert_eq!(m.name(), "hash");
        let schema = m.schema();
        let this = m.parse(b"");
        let call = |name: &str, args: &str, data: &[u8], a: &[Value]| {
            let Some(FieldKind::Func(overloads)) = schema.lookup(name) else { panic!() };
            let f = overloads.iter().find(|f| f.args == args).unwrap();
            (f.f)(&FnCtx { data, this: &this }, a)
        };
        assert_eq!(
            call("md5", "ii", b"xabc", &[Value::Int(1), Value::Int(3)]).as_bytes(),
            Some(&b"900150983cd24fb0d6963f7d28e17f72"[..])
        );
        assert_eq!(
            call("sha1", "s", b"", &[Value::str("abc")]).as_bytes(),
            Some(&b"a9993e364706816aba3e25717850c26c9cd0d89d"[..])
        );
        assert!(call("sha256", "ii", b"ab", &[Value::Int(1), Value::Int(3)]).is_undef());
        assert!(call("md5", "s", b"", &[Value::Undef]).is_undef());
        assert_eq!(call("crc32", "s", b"", &[Value::str("123456789")]).as_int(), Some(0xCBF4_3926));
        assert_eq!(call("checksum32", "ii", b"\x01\x02", &[Value::Int(0), Value::Int(2)]).as_int(), Some(3));
        for (name, args) in [("sha1", "ii"), ("sha256", "s"), ("crc32", "ii"), ("checksum32", "s"), ("md5", "s")] {
            let a = if args == "ii" { vec![Value::Int(0), Value::Int(0)] } else { vec![Value::str("")] };
            assert!(!call(name, args, b"", &a).is_undef(), "{name}");
        }
    }
}
