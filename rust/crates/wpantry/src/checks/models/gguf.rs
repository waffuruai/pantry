//! A GGUF file's structure, read by seeking and bounded everywhere: the
//! header, the key-value metadata (only the chat templates, the alignment
//! and the split count are kept; everything else, big vocabulary arrays
//! included, is skipped by seeking), and the tensor table. From the table,
//! where the tensor data must end; then a look at what lies past that end.
//! Tensor data is never read, only the bytes past its end.
//!
//! The expected end is the data section's start (the tensor table's end,
//! rounded up to `general.alignment`, default 32) plus the farthest
//! `offset + size` of any tensor, a tensor's size from its ggml type's
//! block size ([`block`]). A type not in that table, a cut-short file, a
//! header past a cap or malformed: not checked, never clean (local files
//! with custom quantization types exist).
//!
//! Inside the data section, a hole no tensor covers (the first tensor not
//! at offset 0, or a gap between two tensors of at least the alignment,
//! more than a writer's padding) is a finding too, `MODEL-DATA-GAP`: a
//! warning, or a failure when a bounded window of the hole holds a program
//! or archive. At most [`MAX_GAPS`] holes are read, [`WINDOW`] bytes each.
//! Padding is read, not trusted: a writer zeroes it, so the padding before
//! the data section and between tensors must be all zero, and non-zero
//! padding is a hole too (at most [`MAX_PADDING`] bytes of it are read).
//! Non-zero padding after the last tensor is part of the tail. An alignment
//! over [`MAX_ALIGN`] is not checked.
//! What remains out of reach: bytes inside a tensor the model never uses
//! can't be told from weights by a static check.
//!
//! ```
//! use wpantry::checks::models::gguf;
//! assert!(gguf::looks_like(b"GGUF\x03\0\0\0"));
//! assert_eq!(gguf::block(2), Some((32, 18))); // Q4_0
//! assert_eq!(gguf::block(99), None);
//! ```

use super::{FileResult, Issue, Level, What, ids};
use std::collections::HashSet;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"GGUF";
/// The magic read as a big-endian u32 written little-endian: a file whose
/// writer swapped every word.
const SWAPPED: &[u8; 4] = b"FUGG";

/// The bounds: past any of them the file is not checked.
pub const MAX_TENSORS: u64 = 1 << 16;
pub const MAX_KV: u64 = 1 << 16;
pub const MAX_KEY: u64 = 1 << 16;
/// A string value skipped by seeking.
pub const MAX_STRING: u64 = 64 << 20;
/// A chat template kept to be read.
pub const MAX_TEMPLATE: u64 = 1 << 20;
/// Elements in one array (a vocabulary is a few hundred thousand).
pub const MAX_ARRAY: u64 = 1 << 24;
/// Where the tensor table may end at the latest.
pub const MAX_META: u64 = 512 << 20;
/// Dimensions of one tensor (ggml has 4).
const MAX_DIMS: u64 = 8;
/// Arrays inside arrays.
const MAX_NESTING: u32 = 2;
/// Trailing bytes under this, all zero, are padding.
pub const SHORT_TAIL: u64 = 4 << 10;
/// How much of the trailing bytes is looked at, after the expected end and
/// at the very end of the file.
pub const WINDOW: u64 = 64 << 10;
/// Holes in the data section read; more is itself a warning.
pub const MAX_GAPS: usize = 8;
/// The largest `general.alignment` read. Writers use 32 (the format's
/// default); 64 KiB covers every page size a writer could align to (4 KiB,
/// 16 KiB, 64 KiB) and keeps each padding stretch inside one [`WINDOW`].
pub const MAX_ALIGN: u64 = WINDOW;
/// At most this many padding bytes, in all, are read to see they are zero;
/// past it, not checked. Real files pad a few bytes per tensor at most.
pub const MAX_PADDING: u64 = 16 << 20;

/// A file that starts like a GGUF (either byte order).
pub fn looks_like(head: &[u8]) -> bool {
    head.starts_with(MAGIC) || head.starts_with(SWAPPED)
}

/// A ggml tensor type's (elements per block, bytes per block), from
/// ggml's type traits; types ggml removed and unknown ones are None.
pub fn block(t: u32) -> Option<(u64, u64)> {
    Some(match t {
        0 => (1, 4),     // F32
        1 => (1, 2),     // F16
        2 => (32, 18),   // Q4_0
        3 => (32, 20),   // Q4_1
        6 => (32, 22),   // Q5_0
        7 => (32, 24),   // Q5_1
        8 => (32, 34),   // Q8_0
        9 => (32, 36),   // Q8_1
        10 => (256, 84), // Q2_K
        11 => (256, 110),
        12 => (256, 144),
        13 => (256, 176),
        14 => (256, 210),
        15 => (256, 292), // Q8_K
        16 => (256, 66),  // IQ2_XXS
        17 => (256, 74),  // IQ2_XS
        18 => (256, 98),  // IQ3_XXS
        19 => (256, 50),  // IQ1_S
        20 => (32, 18),   // IQ4_NL
        21 => (256, 110), // IQ3_S
        22 => (256, 82),  // IQ2_S
        23 => (256, 136), // IQ4_XS
        24 => (1, 1),     // I8
        25 => (1, 2),     // I16
        26 => (1, 4),     // I32
        27 => (1, 8),     // I64
        28 => (1, 8),     // F64
        29 => (256, 56),  // IQ1_M
        30 => (1, 2),     // BF16
        34 => (256, 54),  // TQ1_0
        35 => (256, 66),  // TQ2_0
        39 => (32, 17),   // MXFP4
        _ => return None,
    })
}

/// A metadata value type's fixed size; strings (8) and arrays (9) vary.
fn scalar(t: u32) -> Option<u64> {
    match t {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

/// Why the structure couldn't be judged.
#[derive(Debug)]
enum Stop {
    Truncated,
    Cap(&'static str),
    Malformed(String),
}

impl Stop {
    fn reason(&self) -> String {
        match self {
            Stop::Truncated => "the file ends inside its header or tensor table (cut short)".into(),
            Stop::Cap(what) => format!("{what} past this reader's cap"),
            Stop::Malformed(why) => format!("malformed header: {why}"),
        }
    }
}

/// A reader that knows where it is and refuses to step past the file's
/// end or the metadata cap.
struct Cursor<R> {
    r: BufReader<R>,
    pos: u64,
    size: u64,
    /// GGUF v1 wrote counts and lengths as u32.
    wide: bool,
}

impl<R: Read + Seek> Cursor<R> {
    fn room(&self, n: u64) -> Result<(), Stop> {
        let end = self.pos.checked_add(n).ok_or(Stop::Truncated)?;
        if end > MAX_META {
            return Err(Stop::Cap("metadata"));
        }
        if end > self.size {
            return Err(Stop::Truncated);
        }
        Ok(())
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Stop> {
        self.room(N as u64)?;
        let mut b = [0u8; N];
        self.r.read_exact(&mut b).map_err(|_| Stop::Truncated)?;
        self.pos += N as u64;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32, Stop> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, Stop> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    /// A count or length: u64, or u32 in v1.
    fn len(&mut self) -> Result<u64, Stop> {
        if self.wide { self.u64() } else { self.u32().map(u64::from) }
    }

    fn skip(&mut self, n: u64) -> Result<(), Stop> {
        self.room(n)?;
        let n = i64::try_from(n).map_err(|_| Stop::Truncated)?;
        self.r.seek_relative(n).map_err(|_| Stop::Truncated)?;
        self.pos += n as u64;
        Ok(())
    }

    fn bytes(&mut self, n: u64) -> Result<Vec<u8>, Stop> {
        self.room(n)?;
        let mut v = vec![0u8; n as usize];
        self.r.read_exact(&mut v).map_err(|_| Stop::Truncated)?;
        self.pos += n;
        Ok(v)
    }

    /// A string kept when it is at most `keep` bytes; `Err(len)` when it
    /// was longer and skipped.
    fn string(&mut self, keep: u64) -> Result<Result<String, u64>, Stop> {
        let n = self.len()?;
        if n > MAX_STRING {
            return Err(Stop::Cap("a string"));
        }
        if n > keep {
            self.skip(n)?;
            return Ok(Err(n));
        }
        Ok(Ok(String::from_utf8_lossy(&self.bytes(n)?).into_owned()))
    }

    /// Skip a value of type `t`; an unsigned integer is returned.
    fn value(&mut self, t: u32, depth: u32) -> Result<Option<u64>, Stop> {
        if let Some(n) = scalar(t) {
            let b = self.bytes(n)?;
            let mut w = [0u8; 8];
            w[..b.len()].copy_from_slice(&b);
            let unsigned = matches!(t, 0 | 2 | 4 | 10);
            return Ok(unsigned.then(|| u64::from_le_bytes(w)));
        }
        match t {
            8 => {
                self.string(0)?.ok();
                Ok(None)
            }
            9 => {
                if depth >= MAX_NESTING {
                    return Err(Stop::Cap("array nesting"));
                }
                let et = self.u32()?;
                let n = self.len()?;
                if n > MAX_ARRAY {
                    return Err(Stop::Cap("an array"));
                }
                if let Some(size) = scalar(et) {
                    self.skip(n.checked_mul(size).ok_or(Stop::Cap("an array"))?)?;
                } else if et == 8 || et == 9 {
                    for _ in 0..n {
                        self.value(et, depth + 1)?;
                    }
                } else {
                    return Err(Stop::Malformed(format!("an array of unknown type {et}")));
                }
                Ok(None)
            }
            _ => Err(Stop::Malformed(format!("unknown value type {t}"))),
        }
    }
}

/// What the structure says.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// `(key, text)` of each chat template.
    pub templates: Vec<(String, String)>,
    pub issues: Vec<Issue>,
    pub split: u64,
}

/// The file at `path`, opened once and read by seeking.
pub fn check_path(path: &Path) -> FileResult {
    let opened = std::fs::File::open(path).and_then(|f| {
        let m = f.metadata()?;
        Ok((f, m))
    });
    let result = match opened {
        Ok((f, m)) if m.is_file() => check(f, m.len()),
        Ok(_) => Parsed {
            issues: vec![Issue::new(ids::NOT_CHECKED, Level::Unchecked, "not a regular file")],
            ..Parsed::default()
        },
        Err(e) => Parsed {
            issues: vec![Issue::new(ids::NOT_CHECKED, Level::Unchecked, format!("can't be read: {e}"))],
            ..Parsed::default()
        },
    };
    let mut issues = result.issues;
    for (key, text) in &result.templates {
        issues.extend(super::template::check(key, text));
    }
    FileResult { what: What::Gguf, issues: super::sorted(issues), split: result.split }
}

/// A GGUF of `size` bytes from `r`: its templates, and what its structure
/// and its tail say.
pub fn check<R: Read + Seek>(r: R, size: u64) -> Parsed {
    let mut c = Cursor { r: BufReader::with_capacity(64 << 10, r), pos: 0, size, wide: true };
    let mut p = Parsed::default();
    match parse(&mut c, &mut p) {
        Ok(Some(layout)) => {
            gaps(&mut c, &layout, &mut p);
            tail(&mut c, layout.end, layout.align, &mut p);
        }
        Ok(None) => {}
        Err(stop) => p.issues.push(Issue::new(ids::NOT_CHECKED, Level::Unchecked, stop.reason())),
    }
    p
}

/// Where the tensor data lies.
#[derive(Debug)]
struct Layout {
    /// The tensor table's end in the file: padding follows, up to `data`.
    table_end: u64,
    /// The data section's start in the file.
    data: u64,
    /// The expected end of the data, in the file.
    end: u64,
    align: u64,
    /// Each tensor's `(offset, end)` in the data section, sorted.
    spans: Vec<(u64, u64)>,
}

/// The header and tables; the layout, or None when it can't be told
/// (said in `p`).
fn parse<R: Read + Seek>(c: &mut Cursor<R>, p: &mut Parsed) -> Result<Option<Layout>, Stop> {
    let magic: [u8; 4] = c.take()?;
    if &magic == SWAPPED {
        p.issues.push(Issue::new(ids::HEADER, Level::Warn, "byte-swapped GGUF magic"));
        p.issues.push(Issue::new(ids::NOT_CHECKED, Level::Unchecked, "a byte-swapped file's structure isn't read"));
        return Ok(None);
    }
    if &magic != MAGIC {
        return Err(Stop::Malformed("no GGUF magic".into()));
    }
    let version = c.u32()?;
    if !(1..=3).contains(&version) {
        let swapped = version.swap_bytes();
        let why = if (1..=3).contains(&swapped) {
            format!("version {swapped} written big-endian")
        } else {
            format!("unknown GGUF version {version}")
        };
        p.issues.push(Issue::new(ids::HEADER, Level::Warn, why.clone()));
        p.issues.push(Issue::new(ids::NOT_CHECKED, Level::Unchecked, format!("{why}: its structure isn't read")));
        return Ok(None);
    }
    c.wide = version >= 2;
    let tensors = c.len()?;
    let kvs = c.len()?;
    if tensors > MAX_TENSORS {
        return Err(Stop::Cap("the tensor count"));
    }
    if kvs > MAX_KV {
        return Err(Stop::Cap("the metadata count"));
    }
    let mut align: u64 = 32;
    let mut seen: HashSet<String> = HashSet::new();
    let mut dupes = 0usize;
    for _ in 0..kvs {
        let key = match c.string(MAX_KEY)? {
            Ok(k) => k,
            Err(_) => return Err(Stop::Cap("a metadata key")),
        };
        if !seen.insert(key.clone()) {
            dupes += 1;
        }
        let t = c.u32()?;
        let is_template = key == "tokenizer.chat_template" || key.starts_with("tokenizer.chat_template.");
        if is_template && t == 8 {
            match c.string(MAX_TEMPLATE)? {
                Ok(text) => p.templates.push((key, text)),
                Err(n) => p.issues.push(Issue::new(
                    ids::NOT_CHECKED,
                    Level::Unchecked,
                    format!("{key}: {n} bytes, over the {} MiB template cap: not read", MAX_TEMPLATE >> 20),
                )),
            }
            continue;
        }
        let v = c.value(t, 0)?;
        match key.as_str() {
            "general.alignment" => {
                align = v.ok_or_else(|| Stop::Malformed("general.alignment isn't an unsigned integer".into()))?;
                if align == 0 || !align.is_power_of_two() {
                    return Err(Stop::Malformed(format!("general.alignment {align} isn't a power of two")));
                }
                if align > MAX_ALIGN {
                    return Err(Stop::Cap("general.alignment"));
                }
            }
            "split.count" => p.split = v.unwrap_or(0),
            _ => {}
        }
    }
    if dupes > 0 {
        p.issues.push(Issue::new(ids::HEADER, Level::Warn, format!("{dupes} duplicate metadata key(s)")));
    }
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(tensors as usize);
    let mut unknown: Vec<u32> = Vec::new();
    for _ in 0..tensors {
        // The name is skipped.
        let _ = c.string(0)?;
        let dims = u64::from(c.u32()?);
        if dims > MAX_DIMS {
            return Err(Stop::Malformed(format!("a tensor with {dims} dimensions")));
        }
        let mut elems: u64 = 1;
        for _ in 0..dims {
            let d = c.len()?;
            elems = elems.checked_mul(d).ok_or_else(|| Stop::Malformed("a tensor's size overflows".into()))?;
        }
        let t = c.u32()?;
        let offset = c.u64()?;
        match block(t) {
            Some((per, bytes)) => {
                let size = elems
                    .div_ceil(per)
                    .checked_mul(bytes)
                    .ok_or_else(|| Stop::Malformed("a tensor's size overflows".into()))?;
                let end = offset.checked_add(size).ok_or_else(|| Stop::Malformed("a tensor's end overflows".into()))?;
                spans.push((offset, end));
            }
            None => {
                if !unknown.contains(&t) {
                    unknown.push(t);
                }
            }
        }
    }
    let table_end = c.pos;
    let data = table_end.checked_next_multiple_of(align).ok_or(Stop::Truncated)?;
    if !unknown.is_empty() {
        unknown.sort_unstable();
        let list: Vec<String> = unknown.iter().map(u32::to_string).collect();
        p.issues.push(Issue::new(
            ids::NOT_CHECKED,
            Level::Unchecked,
            format!("tensor type(s) {} unknown to this reader: where the data ends can't be told", list.join(", ")),
        ));
        return Ok(None);
    }
    spans.sort_unstable();
    if spans.windows(2).any(|w| w[1].0 < w[0].1) {
        p.issues.push(Issue::new(ids::HEADER, Level::Warn, "tensors overlap in the data section"));
    }
    let last = spans.iter().map(|s| s.1).max().unwrap_or(0);
    let end = data.checked_add(last).ok_or(Stop::Truncated)?;
    if end > c.size {
        return Err(Stop::Truncated);
    }
    Ok(Some(Layout { table_end, data, end, align, spans }))
}

/// The holes in the data section no tensor covers: before the first
/// tensor, and between tensors when wider than a writer's padding (less
/// than the alignment). `(start, end)` in the data section.
fn holes(spans: &[(u64, u64)], align: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = 0u64;
    for (i, &(start, end)) in spans.iter().enumerate() {
        let gap = start.saturating_sub(at);
        if (i == 0 && gap > 0) || (i > 0 && gap >= align) {
            out.push((at, start));
        }
        at = at.max(end);
    }
    out
}

/// The gaps between tensors a writer's padding fills (narrower than the
/// alignment), `(start, end)` in the data section: they must be zero.
fn pads(spans: &[(u64, u64)], align: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = 0u64;
    for (i, &(start, end)) in spans.iter().enumerate() {
        let gap = start.saturating_sub(at);
        if i > 0 && gap > 0 && gap < align {
            out.push((at, start));
        }
        at = at.max(end);
    }
    out
}

/// How far `at` is from the next multiple of `align`: a writer's padding.
fn pad_to(at: u64, align: u64) -> u64 {
    at.checked_next_multiple_of(align).map_or(0, |n| n - at)
}

/// Bytes `from..from + n` of the file, or None.
fn read_at<R: Read + Seek>(c: &mut Cursor<R>, from: u64, n: u64) -> Option<Vec<u8>> {
    c.r.seek(SeekFrom::Start(from)).ok()?;
    let mut v = vec![0u8; n as usize];
    c.r.read_exact(&mut v).ok()?;
    Some(v)
}

/// What the holes in the data section hold, read in bounded windows.
fn gaps<R: Read + Seek>(c: &mut Cursor<R>, l: &Layout, p: &mut Parsed) {
    let mut budget = MAX_PADDING;
    let mut unread = false;
    // Padding is read, not trusted: what isn't zero is a hole.
    let mut zero = |c: &mut Cursor<R>, from: u64, n: u64| -> Option<bool> {
        if n > budget {
            unread = true;
            return None;
        }
        budget -= n;
        let w = read_at(c, from, n);
        if w.is_none() {
            unread = true;
        }
        w.map(|w| w.iter().all(|b| *b == 0))
    };
    if l.data > l.table_end && zero(c, l.table_end, l.data - l.table_end) == Some(false) {
        header_padding(c, l, p);
    }
    let mut holes = holes(&l.spans, l.align);
    for (start, end) in pads(&l.spans, l.align) {
        if zero(c, l.data + start, end - start) == Some(false) {
            holes.push((start, end));
        }
    }
    holes.sort_unstable();
    if unread {
        p.issues.push(Issue::new(
            ids::NOT_CHECKED,
            Level::Unchecked,
            format!("the padding between tensors past {} MiB isn't read", MAX_PADDING >> 20),
        ));
    }
    let Some(&(first, _)) = holes.first() else { return };
    let total: u64 = holes.iter().map(|(s, e)| e - s).sum();
    let mut found: Option<String> = None;
    let mut starts = String::new();
    for (n, &(start, end)) in holes.iter().take(MAX_GAPS).enumerate() {
        let Some(w) = read_at(c, l.data + start, (end - start).min(WINDOW)) else {
            p.issues.push(Issue::new(ids::NOT_CHECKED, Level::Unchecked, "a hole in the tensor data can't be read"));
            return;
        };
        // A writer's zero padding up to the alignment comes first.
        let pad = pad_to(start, l.align) as usize;
        let lead = w.iter().take(pad).take_while(|b| **b == 0).count();
        let body = &w[lead..];
        if n == 0 {
            starts = hex(&body[..body.len().min(16)]);
        }
        if found.is_none()
            && let Some(what) = program_or_archive(body).or_else(|| program_inside(&w))
        {
            found = Some(format!(
                "{} bytes at data offset {start}, starting {}: {what}",
                end - start,
                hex(&body[..body.len().min(16)])
            ));
        }
    }
    let more = if holes.len() > MAX_GAPS {
        format!("; {} holes, only the first {MAX_GAPS} read", holes.len())
    } else {
        String::new()
    };
    let shown = format!(
        "{} hole(s) no tensor covers in the data section, {total} bytes, the first at data offset {first}",
        holes.len()
    );
    match found {
        Some(what) => p.issues.push(Issue::new(ids::DATA_GAP, Level::Fail, format!("{shown}; one holds {what}{more}"))),
        None => p.issues.push(Issue::new(
            ids::DATA_GAP,
            Level::Warn,
            format!("{shown}, starting {starts}: data no loader reads{more}"),
        )),
    }
}

/// Non-zero bytes in the padding between the tensor table and the data
/// section (narrower than the alignment, so one read).
fn header_padding<R: Read + Seek>(c: &mut Cursor<R>, l: &Layout, p: &mut Parsed) {
    let n = l.data - l.table_end;
    let Some(w) = read_at(c, l.table_end, n) else { return };
    let lead = w.iter().take_while(|b| **b == 0).count();
    let body = &w[lead..];
    let shown = format!(
        "{n} bytes of padding before the tensor data, at file offset {}, aren't zero, starting {}",
        l.table_end,
        hex(&body[..body.len().min(16)])
    );
    match program_or_archive(body).or_else(|| program_inside(&w)) {
        Some(what) => p.issues.push(Issue::new(ids::DATA_GAP, Level::Fail, format!("{shown}: {what}"))),
        None => p.issues.push(Issue::new(ids::DATA_GAP, Level::Warn, format!("{shown}: data no loader reads"))),
    }
}

/// What the first bytes of some data say it is, when that is a program
/// or an archive.
pub fn program_or_archive(b: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"MZ", "a Windows program (MZ)"),
        (b"\x7fELF", "an ELF program"),
        (b"\xfe\xed\xfa\xce", "a Mach-O program"),
        (b"\xce\xfa\xed\xfe", "a Mach-O program"),
        (b"\xfe\xed\xfa\xcf", "a Mach-O program"),
        (b"\xcf\xfa\xed\xfe", "a Mach-O program"),
        (b"\xca\xfe\xba\xbe", "a Mach-O universal program"),
        (b"PK\x03\x04", "a ZIP archive"),
        (b"PK\x05\x06", "a ZIP archive"),
        (b"\x1f\x8b", "a gzip stream"),
        (b"#!", "a script (shebang)"),
        (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
        (b"\xfd7zXZ\x00", "an xz stream"),
        (b"BZh", "a bzip2 stream"),
        (b"\x28\xb5\x2f\xfd", "a zstd stream"),
        (b"Rar!\x1a\x07", "a RAR archive"),
    ];
    if let Some((_, what)) = MAGICS.iter().find(|(m, _)| b.starts_with(m)) {
        return Some(what);
    }
    // Python's pickle: PROTO and a protocol number.
    if b.len() >= 2 && b[0] == 0x80 && (2..=5).contains(&b[1]) {
        return Some("a Python pickle");
    }
    None
}

/// A program's header anywhere in `b`: a PE (`MZ` whose `e_lfanew` points
/// at `PE\0\0`), an ELF or a ZIP local header.
fn program_inside(b: &[u8]) -> Option<&'static str> {
    for i in 0..b.len().saturating_sub(3) {
        let w = &b[i..];
        if w.starts_with(b"\x7fELF") {
            return Some("an ELF program");
        }
        if w.starts_with(b"PK\x03\x04") {
            return Some("a ZIP archive");
        }
        if w.starts_with(b"MZ") && w.len() >= 0x40 {
            let lfanew = u32::from_le_bytes([w[0x3c], w[0x3d], w[0x3e], w[0x3f]]) as usize;
            if w.get(lfanew..lfanew + 4) == Some(b"PE\0\0") {
                return Some("a Windows program (PE)");
            }
        }
    }
    None
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What lies past the expected end, read in two bounded windows.
fn tail<R: Read + Seek>(c: &mut Cursor<R>, end: u64, align: u64, p: &mut Parsed) {
    let size = c.size;
    let extra = size - end;
    if extra == 0 {
        return;
    }
    let mut window = |from: u64, n: u64| read_at(c, from, n);
    let first_n = extra.min(WINDOW);
    let Some(first) = window(end, first_n) else {
        p.issues.push(Issue::new(ids::NOT_CHECKED, Level::Unchecked, "the bytes past the last tensor can't be read"));
        return;
    };
    let last = if extra > WINDOW { window(size - WINDOW, WINDOW) } else { None };
    if extra < SHORT_TAIL && first.iter().all(|b| *b == 0) {
        return;
    }
    // A writer pads the last tensor to the alignment: what follows starts
    // past the zeros.
    let pad = pad_to(end, align) as usize;
    let lead = first.iter().take(pad).take_while(|b| **b == 0).count();
    let extra = extra - lead as u64;
    if extra == 0 {
        return;
    }
    let body = &first[lead..];
    let starts = &body[..body.len().min(16)];
    let at_start = program_or_archive(body);
    let inside = at_start.or_else(|| program_inside(&first)).or_else(|| last.as_deref().and_then(program_inside));
    let shown = format!("{extra} bytes after the last tensor, starting {}", hex(starts));
    match (at_start, inside) {
        (Some(what), _) => {
            p.issues.push(Issue::new(ids::APPENDED_PROGRAM, Level::Fail, format!("{shown}: {what}")));
        }
        (None, Some(what)) => {
            p.issues.push(Issue::new(ids::APPENDED_PROGRAM, Level::Fail, format!("{shown}, with {what} inside them")))
        }
        (None, None) if extra >= SHORT_TAIL => p.issues.push(Issue::new(
            ids::TRAILING_DATA,
            Level::Fail,
            format!("{shown}: data no loader reads, where a payload can hide"),
        )),
        (None, None) => {
            p.issues.push(Issue::new(ids::TRAILING_DATA, Level::Warn, format!("{shown}: data no loader reads")))
        }
    }
}

#[cfg(test)]
#[path = "gguf_tests.rs"]
mod tests;
