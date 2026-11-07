//! betterleaks' decoding (its `detect/codec`): each pass finds the percent,
//! unicode (`U+0041`, `A`, `\\u0041`), hex and base64 runs in the last
//! pass's text, decodes those whose result is printable ASCII, and the rules
//! run again on the new text. A match counts only where it overlaps text
//! this pass decoded, and is reported at the encoded text it came from.

use std::collections::HashMap;

/// Decoding passes after the first (betterleaks' `--max-decode-depth`).
pub const MAX_DEPTH: usize = 5;
/// The shortest base64 run decoded, and the shortest all-hex run read as hex.
const MIN_BASE64: usize = 16;
const MIN_HEX: usize = 32;

const PERCENT: u8 = 1;
const UNICODE: u8 = 2;
const HEX: u8 = 4;
const BASE64: u8 = 8;
const NAMES: [(u8, &str); 4] = [(PERCENT, "percent"), (UNICODE, "unicode"), (HEX, "hex"), (BASE64, "base64")];

/// A half-open span; [`Span::overlaps`] counts touching spans, as betterleaks does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    fn new(start: usize, end: usize) -> Span {
        Span { start, end }
    }
    fn overlaps(self, o: Span) -> bool {
        o.start <= self.end && o.end >= self.start
    }
    fn contains(self, o: Span) -> bool {
        self.start <= o.start && o.end <= self.end
    }
    fn merge(self, o: Span) -> Span {
        Span::new(self.start.min(o.start), self.end.max(o.end))
    }
    /// How far `o` runs past this span on each side (betterleaks' `overflow`),
    /// added to `base`.
    fn shift(base: Span, s: Span, o: Span) -> Span {
        let m = s.merge(o);
        Span::new(base.start.saturating_sub(s.start - m.start), base.end + (m.end - s.end))
    }
}

/// One decoded run in a pass.
#[derive(Clone, Debug)]
pub struct Segment {
    /// Where it is in the fragment as read.
    pub original: Span,
    /// Where its encoded text is in the previous pass's text.
    pub encoded: Span,
    /// Where its decoding is in this pass's text.
    pub decoded: Span,
    encodings: u8,
    depth: usize,
}

/// A fragment's passes: its text, then each decoding of the last.
pub struct Decoder {
    texts: Vec<Vec<u8>>,
    passes: Vec<Vec<Segment>>,
    cache: HashMap<Vec<u8>, Vec<u8>>,
}

impl Decoder {
    pub fn new(frag: &[u8]) -> Decoder {
        Decoder { texts: vec![frag.to_vec()], passes: vec![Vec::new()], cache: HashMap::new() }
    }

    /// The text the current pass scans.
    pub fn text(&self) -> &[u8] {
        self.texts.last().expect("a pass")
    }

    /// The segments the current pass decoded (none on the first).
    pub fn segments(&self) -> &[Segment] {
        self.passes.last().expect("a pass")
    }

    /// Decode the current text; false when nothing in it decodes.
    pub fn decode_next(&mut self) -> bool {
        let data = self.text().to_vec();
        let depth = self.passes.len() - 1;
        let mut segments = Vec::new();
        let mut shift: isize = 0;
        for (kind, span) in matches(&data) {
            let encoded = &data[span.start..span.end];
            let decoded = match self.cache.get(encoded) {
                Some(d) => d.clone(),
                None => {
                    let d = decode(kind, encoded);
                    self.cache.insert(encoded.to_vec(), d.clone());
                    d
                }
            };
            if decoded.is_empty() {
                continue;
            }
            let start = (span.start as isize + shift) as usize;
            let mut encodings = kind;
            for p in self.segments() {
                if span.overlaps(p.decoded) {
                    encodings |= p.encodings;
                }
            }
            let grow = decoded.len() as isize - encoded.len() as isize;
            segments.push((
                Segment {
                    original: self.original(depth, span),
                    encoded: span,
                    decoded: Span::new(start, start + decoded.len()),
                    encodings,
                    depth: depth + 1,
                },
                decoded,
            ));
            shift += grow;
        }
        if segments.is_empty() {
            return false;
        }
        let mut text = Vec::with_capacity(data.len());
        let mut at = 0;
        for (s, d) in &segments {
            text.extend_from_slice(&data[at..s.encoded.start]);
            text.extend_from_slice(d);
            at = s.encoded.end;
        }
        text.extend_from_slice(&data[at..]);
        self.texts.push(text);
        self.passes.push(segments.into_iter().map(|(s, _)| s).collect());
        true
    }

    /// `span` of pass `pass`'s text, in the fragment as read (betterleaks'
    /// `toOriginal` over that pass's segments).
    fn original(&self, pass: usize, span: Span) -> Span {
        let mut pass = pass;
        let mut span = span;
        loop {
            let preds = &self.passes[pass];
            if preds.is_empty() {
                return span;
            }
            let mut encoded: Option<Span> = None;
            for p in preds.iter().filter(|p| p.decoded.overlaps(span)) {
                if p.decoded.contains(span) {
                    return p.original;
                }
                let e = Span::shift(p.encoded, p.decoded, span);
                encoded = Some(encoded.map_or(e, |x| x.merge(e)));
            }
            match encoded {
                Some(e) if e.end != 0 => span = e,
                _ => return span,
            }
            pass -= 1;
        }
    }

    /// For a match at `start..end` of the current pass: where it is in the
    /// fragment as read and its tags, or None when it overlaps nothing this
    /// pass decoded.
    pub fn map(&self, start: usize, end: usize) -> Option<((usize, usize), Vec<String>)> {
        let m = Span::new(start, end);
        let over: Vec<&Segment> = self.segments().iter().filter(|s| s.decoded.overlaps(m)).collect();
        let first = over.first()?;
        let kinds = over.iter().fold(0, |k, s| k | s.encodings);
        let mut tags: Vec<String> =
            NAMES.iter().filter(|(k, _)| kinds & k != 0).map(|(_, n)| format!("decoded:{n}")).collect();
        tags.push(format!("decode-depth:{}", first.depth));
        // toOriginal over just the overlapping segments, then up the passes.
        let pass = self.passes.len() - 1;
        let mut encoded: Option<Span> = None;
        for p in &over {
            if p.decoded.contains(m) {
                return Some(((p.original.start, p.original.end), tags));
            }
            let e = Span::shift(p.encoded, p.decoded, m);
            encoded = Some(encoded.map_or(e, |x| x.merge(e)));
        }
        let orig = match encoded {
            Some(e) if e.end != 0 => self.original(pass - 1, e),
            _ => m,
        };
        Some(((orig.start, orig.end), tags))
    }

    /// betterleaks' `CurrentLine`: the current text from the newline before
    /// the decoded segments the match overlaps (that newline included) to
    /// the newline after them.
    pub fn line(&self, start: usize, end: usize) -> &[u8] {
        let text = self.text();
        let m = Span::new(start, end);
        let mut over = self.segments().iter().filter(|s| s.decoded.overlaps(m)).map(|s| s.decoded);
        let Some(first) = over.next() else { return text };
        let d = over.fold(first, Span::merge);
        let from = text[..=d.start.min(text.len().saturating_sub(1))].iter().rposition(|&b| b == b'\n').unwrap_or(0);
        let to = text.get(d.end..).and_then(|t| t.iter().position(|&b| b == b'\n')).map_or(text.len(), |i| d.end + i);
        &text[from..to.max(from)]
    }
}

fn hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'/' | b'+' | b'-')
}

fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
}

fn hex4(d: &[u8], at: usize) -> bool {
    d.get(at..at + 4).is_some_and(|h| h.iter().all(|&b| hex(b)))
}

fn precedence(kind: u8) -> u8 {
    match kind {
        PERCENT => 4,
        UNICODE => 3,
        HEX => 2,
        _ => 1,
    }
}

/// The encoded runs in `d`, in order (betterleaks' `findEncodingMatches`).
fn matches(d: &[u8]) -> Vec<(u8, Span)> {
    let n = d.len();
    let mut all = Vec::new();
    let mut i = 0;
    while i < n {
        let c = d[i];
        if c == b'%' && i + 2 < n && hex(d[i + 1]) && hex(d[i + 2]) {
            let mut last = i + 3;
            let mut j = i + 3;
            while j < n && d[j] != b'\n' {
                if d[j] == b'%' && j + 2 < n && hex(d[j + 1]) && hex(d[j + 2]) {
                    last = j + 3;
                }
                j += 1;
            }
            all.push((PERCENT, Span::new(i, last)));
            i = last;
            continue;
        }
        if c == b'U' && i + 5 < n && d[i + 1] == b'+' && hex4(d, i + 2) && (i + 6 >= n || space(d[i + 6])) {
            let mut end = i + 6;
            let mut j = end;
            while j < n && space(d[j]) {
                let mut ws = j;
                while ws < n && space(d[ws]) {
                    ws += 1;
                }
                if ws + 5 < n
                    && d[ws] == b'U'
                    && d[ws + 1] == b'+'
                    && hex4(d, ws + 2)
                    && (ws + 6 >= n || space(d[ws + 6]))
                {
                    end = ws + 6;
                    j = end;
                    continue;
                }
                break;
            }
            all.push((UNICODE, Span::new(i, end)));
            i = end;
            continue;
        }
        if c == b'\\' {
            let escape_at = |j: usize| -> Option<usize> {
                if j + 6 < n && d[j] == b'\\' && d[j + 1] == b'\\' && matches!(d[j + 2], b'u' | b'U') && hex4(d, j + 3)
                {
                    return Some(j + 7);
                }
                if j + 5 < n && d[j] == b'\\' && matches!(d[j + 1], b'u' | b'U') && hex4(d, j + 2) {
                    return Some(j + 6);
                }
                None
            };
            // The opening `\\u` needs one byte more than a following one does.
            let open = if i + 7 < n && d[i + 1] == b'\\' && matches!(d[i + 2], b'u' | b'U') && hex4(d, i + 3) {
                Some(i + 7)
            } else if i + 5 < n && matches!(d[i + 1], b'u' | b'U') && hex4(d, i + 2) {
                Some(i + 6)
            } else {
                None
            };
            if let Some(mut end) = open {
                while let Some(e) = escape_at(end) {
                    end = e;
                }
                all.push((UNICODE, Span::new(i, end)));
                i = end;
                continue;
            }
        }
        if b64(c) {
            let start = i;
            let mut all_hex = hex(c);
            i += 1;
            while i < n && b64(d[i]) {
                all_hex &= hex(d[i]);
                i += 1;
            }
            let run = i - start;
            let mut end = i;
            let mut eq = 0;
            while eq < 2 && end < n && d[end] == b'=' {
                eq += 1;
                end += 1;
            }
            if all_hex && run >= MIN_HEX {
                all.push((HEX, Span::new(start, start + run)));
            } else if run >= MIN_BASE64 {
                all.push((BASE64, Span::new(start, end)));
            }
            continue;
        }
        i += 1;
    }
    if all.len() <= 1 {
        return all;
    }
    let mut out = Vec::with_capacity(all.len());
    for (k, &(kind, span)) in all.iter().enumerate() {
        let beaten =
            |o: Option<&(u8, Span)>| o.is_some_and(|&(ok, os)| span.overlaps(os) && precedence(ok) > precedence(kind));
        if beaten(k.checked_sub(1).and_then(|p| all.get(p))) || beaten(all.get(k + 1)) {
            continue;
        }
        out.push((kind, span));
    }
    out
}

fn printable(b: u8) -> bool {
    (0x09..0x7f).contains(&b)
}

fn nibble(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|v| v as u8)
}

fn decode(kind: u8, s: &[u8]) -> Vec<u8> {
    match kind {
        PERCENT => percent(s),
        UNICODE => unicode(s),
        HEX => hex_decode(s),
        _ => base64(s),
    }
}

fn percent(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%'
            && i + 2 < s.len()
            && let (Some(a), Some(b)) = (nibble(s[i + 1]), nibble(s[i + 2]))
        {
            let v = a << 4 | b;
            if !printable(v) {
                return Vec::new();
            }
            out.push(v);
            i += 3;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

fn hex_decode(s: &[u8]) -> Vec<u8> {
    if !s.len().is_multiple_of(2) || !s.iter().any(u8::is_ascii_digit) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        let (Some(a), Some(b)) = (nibble(pair[0]), nibble(pair[1])) else { return Vec::new() };
        let v = a << 4 | b;
        if !printable(v) {
            return Vec::new();
        }
        out.push(v);
    }
    out
}

fn push_char(out: &mut Vec<u8>, v: u32) {
    let c = char::from_u32(v).unwrap_or('\u{FFFD}');
    let mut buf = [0; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

fn hex4_value(s: &[u8], at: usize) -> Option<u32> {
    let h = s.get(at..at + 4)?;
    h.iter().try_fold(0u32, |v, &b| nibble(b).map(|n| v << 4 | n as u32))
}

fn unicode(s: &[u8]) -> Vec<u8> {
    let n = s.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    if super::contains(s, b"U+") {
        while i < n {
            if i + 5 < n
                && s[i] == b'U'
                && s[i + 1] == b'+'
                && let Some(v) = hex4_value(s, i + 2)
            {
                push_char(&mut out, v);
                i += 6;
                if i < n && matches!(s[i], b' ' | b'\t') && i + 6 < n && s[i + 1] == b'U' && s[i + 2] == b'+' {
                    i += 1;
                }
                continue;
            }
            out.push(s[i]);
            i += 1;
        }
        return out;
    }
    if !super::contains(s, b"\\u") && !super::contains(s, b"\\U") {
        return s.to_vec();
    }
    while i < n {
        if s[i] == b'\\' {
            if i + 6 < n
                && s[i + 1] == b'\\'
                && matches!(s[i + 2], b'u' | b'U')
                && let Some(v) = hex4_value(s, i + 3)
            {
                push_char(&mut out, v);
                i += 7;
                continue;
            }
            if i + 5 < n
                && matches!(s[i + 1], b'u' | b'U')
                && let Some(v) = hex4_value(s, i + 2)
            {
                push_char(&mut out, v);
                i += 6;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Go's base64 decoding of `s` with `alphabet`'s last two characters, padded
/// (`StdEncoding`) or not (`RawURLEncoding`); None where Go returns an error.
fn base64_with(s: &[u8], extra: [u8; 2], padded: bool) -> Option<Vec<u8>> {
    let value = |b: u8| -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            _ if b == extra[0] => 62,
            _ if b == extra[1] => 63,
            _ => return None,
        } as u32)
    };
    let body = if padded {
        if !s.len().is_multiple_of(4) {
            return None;
        }
        let pad = s.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        &s[..s.len() - pad]
    } else {
        s
    };
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut acc = 0u32;
        for &b in chunk {
            acc = acc << 6 | value(b)?;
        }
        let bits = chunk.len() * 6;
        acc <<= 24 - bits;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..1 + (bits / 8)]);
    }
    Some(out)
}

fn base64(s: &[u8]) -> Vec<u8> {
    if !s.iter().any(|&b| b.is_ascii_digit() || matches!(b, b'+' | b'/' | b'-' | b'_')) {
        return Vec::new();
    }
    for (extra, padded) in [(*b"+/", true), (*b"-_", false)] {
        if let Some(d) = base64_with(s, extra, padded)
            && d.iter().all(|&b| printable(b))
        {
            return d;
        }
    }
    Vec::new()
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
