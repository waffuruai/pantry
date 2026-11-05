use super::*;

/// zlib's dynamic-block encoding of a sentence with repeats.
const DYNAMIC: &[u8] = &[
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x8a, 0x13, 0x33, 0x53, 0x14, 0x4a, 0x32, 0x52,
    0x15, 0x52, 0xf2, 0x93, 0x4b, 0x73, 0x53, 0xf3, 0x4a, 0x14, 0x4a, 0xf2, 0xc1, 0xfc, 0xe2, 0xe4, 0xc4, 0xbc, 0xbc,
    0xd4, 0x22, 0x6b, 0xa8, 0xf2, 0xc4, 0xf4, 0xc4, 0xcc, 0x3c, 0x3d, 0x00,
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

/// Writes a DEFLATE stream a bit at a time: header fields LSB first,
/// Huffman codes MSB first (RFC 1951 3.1.1).
struct Writer {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl Writer {
    fn new() -> Writer {
        Writer { out: Vec::new(), acc: 0, n: 0 }
    }

    fn bits(&mut self, v: u32, count: u32) {
        self.acc |= v << self.n;
        self.n += count;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.bits((code >> i) & 1, 1);
        }
    }

    fn align(&mut self) {
        if self.n > 0 {
            self.bits(0, 8 - self.n);
        }
    }

    fn stored(&mut self, last: bool, data: &[u8]) {
        self.bits(last as u32, 1);
        self.bits(0, 2);
        self.align();
        let len = data.len() as u16;
        self.out.extend(len.to_le_bytes());
        self.out.extend((!len).to_le_bytes());
        self.out.extend(data);
    }

    /// A literal/length symbol in the fixed code.
    fn fixed(&mut self, sym: u32) {
        match sym {
            0..=143 => self.code(0x30 + sym, 8),
            144..=255 => self.code(0x190 + sym - 144, 9),
            256..=279 => self.code(sym - 256, 7),
            _ => self.code(0xC0 + sym - 280, 8),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

#[test]
fn stored_blocks_chain_and_the_cap_holds_across_blocks() {
    let mut w = Writer::new();
    w.stored(false, b"ab");
    w.stored(true, b"c");
    let data = w.finish();
    assert_eq!(inflate(&data, 1 << 20).as_deref(), Some(b"abc" as &[u8]));
    assert_eq!(inflate(&data, 2), None);
}

#[test]
fn fixed_blocks_check_their_symbols_and_distances() {
    let mut w = Writer::new();
    w.bits(1, 1);
    w.bits(1, 2);
    w.fixed(b'a' as u32);
    w.fixed(257); // length 3 ...
    w.code(0, 5); // ... at distance 1
    w.fixed(256);
    assert_eq!(inflate(&w.finish(), 1 << 20).as_deref(), Some(b"aaaa" as &[u8]));
    let mut w = Writer::new();
    w.bits(1, 1);
    w.bits(1, 2);
    w.fixed(b'a' as u32);
    w.fixed(257);
    w.code(1, 5); // distance 2, with one byte written
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "a distance before the start");
    let mut w = Writer::new();
    w.bits(1, 1);
    w.bits(1, 2);
    w.fixed(286); // a code the fixed table has, that means nothing
    assert_eq!(inflate(&w.finish(), 1 << 20), None);
}

/// The header of a dynamic block whose code-length code has the symbols
/// 0, 3, 16 and 18, each two bits (codes 00, 01, 10, 11), for 257
/// literal/length and one distance length.
fn dynamic_header(w: &mut Writer) {
    w.bits(1, 1);
    w.bits(2, 2);
    w.bits(0, 5);
    w.bits(0, 5);
    w.bits(15, 4);
    for sym in [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15] {
        w.bits(if matches!(sym, 0 | 3 | 16 | 18) { 2 } else { 0 }, 3);
    }
}

fn code_length(w: &mut Writer, sym: u32) {
    w.code(
        match sym {
            0 => 0,
            3 => 1,
            16 => 2,
            _ => 3,
        },
        2,
    );
}

#[test]
fn dynamic_blocks_read_repeated_lengths() {
    let mut w = Writer::new();
    dynamic_header(&mut w);
    code_length(&mut w, 18);
    w.bits(86, 7); // 97 zero lengths
    code_length(&mut w, 3); // 'a'
    code_length(&mut w, 16);
    w.bits(0, 2); // 'b' 'c' 'd' the same
    code_length(&mut w, 18);
    w.bits(127, 7);
    code_length(&mut w, 18);
    w.bits(5, 7); // zeros up to the end code ...
    code_length(&mut w, 0); // ... and one more
    code_length(&mut w, 3); // 256
    code_length(&mut w, 3); // the one distance code
    for code in [0, 1, 2, 4] {
        w.code(code, 3); // a b c end
    }
    assert_eq!(inflate(&w.finish(), 1 << 20).as_deref(), Some(b"abc" as &[u8]));
}

#[test]
fn dynamic_headers_that_do_not_add_up() {
    let mut w = Writer::new();
    w.bits(1, 1);
    w.bits(2, 2);
    w.bits(31, 5);
    w.bits(0, 5);
    w.bits(0, 4);
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "288 literal codes");

    let mut w = Writer::new();
    dynamic_header(&mut w);
    code_length(&mut w, 16);
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "nothing to repeat");

    let mut w = Writer::new();
    dynamic_header(&mut w);
    code_length(&mut w, 3);
    code_length(&mut w, 18);
    w.bits(127, 7);
    code_length(&mut w, 18);
    w.bits(106, 7);
    code_length(&mut w, 16);
    w.bits(0, 2);
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "a repeat past the end");

    let mut w = Writer::new();
    dynamic_header(&mut w);
    code_length(&mut w, 18);
    w.bits(127, 7);
    code_length(&mut w, 18);
    w.bits(127, 7);
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "zeros past the end");

    let mut w = Writer::new();
    dynamic_header(&mut w);
    code_length(&mut w, 18);
    w.bits(127, 7);
    code_length(&mut w, 18);
    w.bits(109, 7);
    assert_eq!(inflate(&w.finish(), 1 << 20), None, "no end-of-block code");
}

#[test]
fn huffman_tables_reject_what_they_cannot_hold() {
    assert!(Huff::new(&[16]).is_none(), "lengths stop at 15");
    let one = Huff::new(&[1]).unwrap();
    let mut bits = Bits { data: &[0xff; 4], pos: 0, acc: 0, n: 0 };
    assert_eq!(one.decode(&mut bits), None, "a code the table never assigned");
}

/// `*.raw` (zlib-wrapped or raw deflate) in `dir` against its `*.out`:
/// how many pairs were checked.
fn check_fixtures(dir: &std::path::Path) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
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
    n
}

#[test]
fn fixture_pairs_are_checked_with_or_without_the_zlib_header() {
    let d = crate::utils::temp::TempDir::new("inflate").unwrap();
    let wrapped: Vec<u8> = [0x78, 0x9c].iter().chain(DYNAMIC).copied().collect();
    std::fs::write(d.path().join("a.raw"), wrapped).unwrap();
    std::fs::write(d.path().join("a.out"), DYNAMIC_TEXT).unwrap();
    std::fs::write(d.path().join("b.raw"), DYNAMIC).unwrap();
    std::fs::write(d.path().join("b.out"), DYNAMIC_TEXT).unwrap();
    std::fs::write(d.path().join("notes.txt"), "not a pair").unwrap();
    assert_eq!(check_fixtures(d.path()), 2);
}

/// Real streams against zlib's answer: `WPANTRY_INFLATE_FIXTURES=<dir>`
/// holding `*.raw` (zlib-wrapped or raw deflate) and `*.out` pairs.
#[test]
#[ignore]
fn inflate_matches_zlib_on_real_streams() {
    let Ok(dir) = std::env::var("WPANTRY_INFLATE_FIXTURES") else { return };
    assert!(check_fixtures(std::path::Path::new(&dir)) > 0);
}
