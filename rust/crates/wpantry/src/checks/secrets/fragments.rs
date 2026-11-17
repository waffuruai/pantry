//! A file as betterleaks reads it: fragments of about [`READ`] bytes, each
//! extended to a blank line when one comes within [`PEEK`] bytes, through a
//! [`BUFFER`]-byte read buffer (Go's `bufio.Reader`, whose leftovers start
//! the next fragment). Fragments don't overlap: a secret across a cut is
//! missed, as betterleaks misses it.

/// What one read asks for (betterleaks' `defaultBufferSize`).
pub const READ: usize = 100_000;
/// How far past a read the cut may move to find a blank line.
pub const PEEK: usize = 25_000;
/// Go's `bufio.Reader` default size.
pub const BUFFER: usize = 4096;
/// How much of a file is sniffed for a NUL byte, as git does.
pub const SNIFF: usize = 8000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub range: std::ops::Range<usize>,
    /// The 1-based line its first byte is on.
    pub start_line: usize,
}

/// Go's `bufio.Reader` over bytes already in memory: `[r, w)` is buffered.
struct Reader<'a> {
    data: &'a [u8],
    r: usize,
    w: usize,
}

impl Reader<'_> {
    fn buffered(&self) -> usize {
        self.w - self.r
    }

    /// `Read(p)` with `len(p) == READ`: the buffered bytes if any, else a
    /// read straight from the file.
    fn read(&mut self) -> std::ops::Range<usize> {
        let start = self.r;
        let n = if self.buffered() > 0 { self.buffered().min(READ) } else { READ.min(self.data.len() - self.w) };
        self.r += n;
        self.w = self.w.max(self.r);
        start..self.r
    }

    /// Fill an empty buffer; false at the end of the file.
    fn fill(&mut self) -> bool {
        if self.w == self.data.len() {
            return false;
        }
        self.w += BUFFER.min(self.data.len() - self.w);
        true
    }
}

fn whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// betterleaks' `readUntilSafeBoundary`: extend the fragment `start..r.r`
/// (`n` bytes read) to two newlines with only whitespace between, reading at
/// most [`PEEK`] more bytes.
fn safe_boundary(r: &mut Reader, start: usize, n: usize) {
    let frag = &r.data[start..r.r];
    let Some(&last) = frag.last() else { return };
    if whitespace(last) {
        let mut newlines = 0;
        for &b in frag.iter().rev() {
            if b == b'\n' {
                newlines += 1;
                if newlines >= 2 {
                    return;
                }
            } else if !whitespace(b) {
                break;
            }
        }
    }
    let mut newlines = usize::from(last == b'\n');
    let mut remaining = PEEK as isize - (r.r - start - n) as isize;
    while remaining > 0 {
        if r.buffered() == 0 && !r.fill() {
            return;
        }
        let block = (remaining as usize).min(r.buffered());
        let mut consumed = block;
        for (i, &b) in r.data[r.r..r.r + block].iter().enumerate() {
            if b == b'\n' {
                newlines += 1;
                if newlines >= 2 {
                    consumed = i + 1;
                    break;
                }
            } else if !whitespace(b) {
                newlines = 0;
            }
        }
        r.r += consumed;
        remaining -= consumed as isize;
        if newlines >= 2 {
            return;
        }
    }
}

/// The fragments of `data`, in order.
pub fn split(data: &[u8]) -> Vec<Fragment> {
    let mut r = Reader { data, r: 0, w: 0 };
    let mut out = Vec::new();
    let mut end_line = 0;
    loop {
        let read = r.read();
        if read.is_empty() {
            return out;
        }
        safe_boundary(&mut r, read.start, read.len());
        let range = read.start..r.r;
        let start_line = end_line + 1;
        end_line += data[range.clone()].iter().filter(|&&b| b == b'\n').count();
        out.push(Fragment { range, start_line });
    }
}

/// Signatures of the files betterleaks skips as binary (h2non/filetype's
/// `application/…` types it sniffs): `(offset, bytes)`.
const BINARY: &[(usize, &[u8])] = &[
    (0, b"PK\x03\x04"),
    (0, b"PK\x05\x06"),
    (0, b"PK\x07\x08"),
    (0, b"\x1f\x8b\x08"),
    (0, b"BZh"),
    (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"\xfd7zXZ\x00"),
    (0, b"\x28\xb5\x2f\xfd"),
    (0, b"Rar!\x1a\x07"),
    (0, b"LZIP"),
    (0, b"\x1f\x9d"),
    (0, b"\x1f\xa0"),
    (257, b"ustar"),
    (0, b"%PDF"),
    (0, b"%!"),
    (0, b"{\\rtf"),
    (0, b"MZ"),
    (0, b"\x7fELF"),
    (0, b"\xca\xfe\xba\xbe"),
    (0, b"\xfe\xed\xfa\xce"),
    (0, b"\xfe\xed\xfa\xcf"),
    (0, b"\xce\xfa\xed\xfe"),
    (0, b"\xcf\xfa\xed\xfe"),
    (0, b"\x00asm"),
    (0, b"dex\n"),
    (0, b"dey\n"),
    (0, b"FWS"),
    (0, b"CWS"),
    (0, b"NES\x1a"),
    (0, b"Cr24"),
    (0, b"MSCF"),
    (0, b"ISc("),
    (0, b"SQLite format 3\x00"),
    (0, b"!<arch>"),
    (0, b"\xed\xab\xee\xdb"),
    (128, b"DICM"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    (0, b"wOFF"),
    (0, b"wOF2"),
    (0, b"\x00\x01\x00\x00\x00"),
    (0, b"OTTO"),
];

/// Whether a file is skipped as binary: a signature betterleaks skips, or (as
/// Pantry adds, and git decides) a NUL byte in its first [`SNIFF`] bytes, so
/// model weights, images and other data no one types a secret into aren't
/// read through.
pub fn binary(data: &[u8]) -> bool {
    BINARY.iter().any(|(at, sig)| data.get(*at..at + sig.len()) == Some(*sig))
        || data[..data.len().min(SNIFF)].contains(&0)
}

#[cfg(test)]
#[path = "fragments_tests.rs"]
mod tests;
