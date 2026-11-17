//! The indicator store: every hash, host, IP address and URL the indicator
//! lists name ([`crate::sources::indicator_lists`]), each with what it is
//! and where it came from, looked up by key in constant time. A file is
//! matched by looking up what it contains ([`crate::checks::malware::observe`]),
//! never by scanning it once per indicator, so a million indicators cost
//! what a thousand do (spec 04, F7 and P2).
//!
//! One normaliser serves both sides: a list's line and a token from a file
//! become the same `(kind, value)`, and so the same key.

use std::path::Path;

/// What an indicator is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// An MD5, SHA-1 or SHA-256 of a file, lowercase hex.
    Hash,
    /// A domain name, lowercase, no trailing dot.
    Host,
    /// An IPv4 address, no port.
    Ip,
    /// A host and a path, `host/a/b`: no scheme, query or trailing slash.
    Url,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Hash => b'h',
            Kind::Host => b'd',
            Kind::Ip => b'i',
            Kind::Url => b'u',
        }
    }
}

/// The key `(kind, value)` is stored and looked up under: 64-bit FNV-1a,
/// never 0 (the table's empty slot).
pub fn key(kind: Kind, value: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in std::iter::once(kind.tag()).chain(value.bytes()) {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    h.max(1)
}

/// Whether `s` is an MD5, SHA-1 or SHA-256 in hex.
pub fn is_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `s` is a dotted IPv4 address.
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Whether `s` (lowercase) is a domain name: two labels or more of letters,
/// digits, `-` and `_`, ending in a top-level domain of letters (or an IDN's
/// `xn--`).
fn is_domain(s: &str) -> bool {
    if !(4..=253).contains(&s.len()) || !s.contains('.') {
        return false;
    }
    let mut labels = s.split('.').peekable();
    while let Some(label) = labels.next() {
        let ok = (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok {
            return false;
        }
        if labels.peek().is_none() {
            return label.starts_with("xn--") || (label.len() >= 2 && label.bytes().all(|b| b.is_ascii_lowercase()));
        }
    }
    false
}

/// `raw` as a host and a path: the scheme, user, port, query and fragment
/// dropped, the host lowercased, the path's trailing slashes trimmed.
fn split(raw: &str) -> (String, &str) {
    let s = raw.trim().trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | ','));
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let s = s.split(['?', '#']).next().unwrap_or_default();
    let (host, path) = s.split_once('/').unwrap_or((s, ""));
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    (host.trim_end_matches('.').to_ascii_lowercase(), path.trim_end_matches('/'))
}

/// An indicator list's entry as the store keeps it, or `None` when it is
/// none of the kinds (a regex, a CIDR range, a comment's leftovers).
pub fn normalize(raw: &str) -> Option<(Kind, String)> {
    let t = raw.trim();
    if is_hash(t) {
        return Some((Kind::Hash, t.to_ascii_lowercase()));
    }
    let (host, path) = split(t);
    let kind = if is_ipv4(&host) {
        Kind::Ip
    } else if is_domain(&host) {
        Kind::Host
    } else {
        return None;
    };
    Some(if path.is_empty() { (kind, host) } else { (Kind::Url, format!("{host}/{path}")) })
}

/// The most path segments a URL in a file is looked up by.
const MAX_SEGMENTS: usize = 8;

/// The keys a token found in a file is looked up under: its host or
/// address, every parent domain of two labels or more (`a.evil.com` is
/// also `evil.com`), and each leading part of its path (`evil.com/a/b` is
/// also `evil.com/a`). Never a hash: a file that quotes a bad hash isn't
/// that file.
pub fn lookups(token: &str, out: &mut Vec<u64>) {
    let (host, path) = split(token);
    if is_ipv4(&host) {
        out.push(key(Kind::Ip, &host));
    } else if is_domain(&host) {
        let mut rest = host.as_str();
        loop {
            out.push(key(Kind::Host, rest));
            match rest.split_once('.') {
                Some((_, parent)) if parent.contains('.') => rest = parent,
                _ => break,
            }
        }
    } else {
        return;
    }
    let mut url = host.clone();
    for segment in path.split('/').filter(|s| !s.is_empty()).take(MAX_SEGMENTS) {
        url.push('/');
        url.push_str(segment);
        out.push(key(Kind::Url, &url));
    }
}

/// Where an indicator came from: the rule a match is reported under and
/// the source's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub rule: String,
    pub source: String,
}

/// One indicator, as the store holds it.
#[derive(Clone, Copy, Debug)]
struct Entry {
    key: u64,
    kind: Kind,
    /// Its value in the store's text.
    at: u32,
    len: u32,
    /// What it is, in the store's interned text.
    what: u32,
    origin: u32,
}

/// What a lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found<'a> {
    pub kind: Kind,
    pub value: &'a str,
    pub what: &'a str,
    pub origin: &'a Origin,
}

/// Every indicator, by key. The first one added under a key is kept: ours
/// before the user's.
#[derive(Default)]
pub struct Store {
    /// Open addressing, linear probing: an index into `entries`, or `EMPTY`.
    slots: Vec<u32>,
    entries: Vec<Entry>,
    text: String,
    whats: Vec<String>,
    origins: Vec<Origin>,
    by_what: std::collections::HashMap<String, u32>,
}

const EMPTY: u32 = u32::MAX;

/// The saved store's first line, and the bytes one entry takes in it.
const MAGIC: &[u8] = b"wpantry-iocs 1\n";
const ENTRY: usize = 8 + 1 + 4 * 4;

fn put_u32(b: &mut Vec<u8>, n: u32) {
    b.extend_from_slice(&n.to_le_bytes());
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    put_u32(b, s.len() as u32);
    b.extend_from_slice(s.as_bytes());
}

/// A cursor over a saved store; every read is bounds-checked.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(out)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn str(&mut self) -> Option<&'a str> {
        let n = self.u32()? as usize;
        std::str::from_utf8(self.take(n)?).ok()
    }
}

impl Store {
    /// The indicators, built from `add` calls; [`Store::seal`] makes them
    /// searchable.
    pub fn new() -> Store {
        Store::default()
    }

    /// The origin indicators from one source are added under.
    pub fn origin(&mut self, rule: &str, source: &str) -> u32 {
        let o = Origin { rule: rule.to_string(), source: source.to_string() };
        if let Some(i) = self.origins.iter().position(|x| *x == o) {
            return i as u32;
        }
        self.origins.push(o);
        (self.origins.len() - 1) as u32
    }

    /// Add `raw` (normalized first; `false` when it is no indicator) as
    /// `what`, from `origin`.
    pub fn add(&mut self, raw: &str, what: &str, origin: u32) -> bool {
        let Some((kind, value)) = normalize(raw) else { return false };
        self.add_normalized(kind, &value, what, origin);
        true
    }

    fn add_normalized(&mut self, kind: Kind, value: &str, what: &str, origin: u32) {
        let what = match self.by_what.get(what) {
            Some(&i) => i,
            None => {
                self.whats.push(what.to_string());
                let i = (self.whats.len() - 1) as u32;
                self.by_what.insert(what.to_string(), i);
                i
            }
        };
        let at = self.text.len() as u32;
        self.text.push_str(value);
        self.entries.push(Entry { key: key(kind, value), kind, at, len: value.len() as u32, what, origin });
    }

    /// Index what was added: from here on [`Store::get`] finds it. A key
    /// added twice keeps its first entry.
    pub fn seal(&mut self) {
        let capacity = (self.entries.len() * 2).max(16).next_power_of_two();
        let mask = capacity - 1;
        let mut slots = vec![EMPTY; capacity];
        let mut kept = Vec::with_capacity(self.entries.len());
        for e in std::mem::take(&mut self.entries) {
            let mut i = (e.key as usize) & mask;
            loop {
                match slots[i] {
                    EMPTY => {
                        slots[i] = kept.len() as u32;
                        kept.push(e);
                        break;
                    }
                    j if kept[j as usize].key == e.key => break,
                    _ => i = (i + 1) & mask,
                }
            }
        }
        self.entries = kept;
        self.slots = slots;
        self.by_what = Default::default();
    }

    /// The store as one file, read back by [`Store::load`] while `digest`
    /// (what it was built from) is the same: built once per list update,
    /// not once per scan.
    pub fn save(&self, path: &Path, digest: &str) -> std::io::Result<()> {
        let mut b = Vec::with_capacity(self.text.len() + self.entries.len() * ENTRY + 4096);
        b.extend_from_slice(MAGIC);
        put_str(&mut b, digest);
        put_u32(&mut b, self.entries.len() as u32);
        for e in &self.entries {
            b.extend_from_slice(&e.key.to_le_bytes());
            b.push(e.kind.tag());
            for n in [e.at, e.len, e.what, e.origin] {
                put_u32(&mut b, n);
            }
        }
        put_str(&mut b, &self.text);
        put_u32(&mut b, self.whats.len() as u32);
        for w in &self.whats {
            put_str(&mut b, w);
        }
        put_u32(&mut b, self.origins.len() as u32);
        for o in &self.origins {
            put_str(&mut b, &o.rule);
            put_str(&mut b, &o.source);
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &b)?;
        std::fs::rename(&tmp, path)
    }

    /// The store [`Store::save`] wrote for `digest`, or `None` when the file
    /// is missing, for another digest, or malformed in any way.
    pub fn load(path: &Path, digest: &str) -> Option<Store> {
        let b = std::fs::read(path).ok()?;
        let mut r = Reader { b: &b, at: 0 };
        if r.take(MAGIC.len())? != MAGIC || r.str()? != digest {
            return None;
        }
        let n = r.u32()? as usize;
        if n.checked_mul(ENTRY)? > b.len() - r.at {
            return None;
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let key = u64::from_le_bytes(r.take(8)?.try_into().ok()?);
            let kind = match r.take(1)?[0] {
                b'h' => Kind::Hash,
                b'd' => Kind::Host,
                b'i' => Kind::Ip,
                b'u' => Kind::Url,
                _ => return None,
            };
            entries.push(Entry { key, kind, at: r.u32()?, len: r.u32()?, what: r.u32()?, origin: r.u32()? });
        }
        let text = r.str()?.to_string();
        let whats = (0..r.u32()?).map(|_| r.str().map(str::to_string)).collect::<Option<Vec<_>>>()?;
        let origins = (0..r.u32()?)
            .map(|_| Some(Origin { rule: r.str()?.to_string(), source: r.str()?.to_string() }))
            .collect::<Option<Vec<_>>>()?;
        let fits = |e: &Entry| {
            let (at, end) = (e.at as usize, e.at as usize + e.len as usize);
            end <= text.len()
                && text.is_char_boundary(at)
                && text.is_char_boundary(end)
                && (e.what as usize) < whats.len()
                && (e.origin as usize) < origins.len()
        };
        if r.at != b.len() || !entries.iter().all(fits) {
            return None;
        }
        let mut store = Store { entries, text, whats, origins, ..Default::default() };
        store.seal();
        Some(store)
    }

    /// How many indicators the store holds (once sealed).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The indicator under `key`, if any.
    pub fn get(&self, key: u64) -> Option<Found<'_>> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut i = (key as usize) & mask;
        // At most half the slots are full, so an empty one ends every probe.
        loop {
            let slot = self.slots[i];
            if slot == EMPTY {
                return None;
            }
            let e = &self.entries[slot as usize];
            if e.key == key {
                return Some(Found {
                    kind: e.kind,
                    value: &self.text[e.at as usize..(e.at + e.len) as usize],
                    what: &self.whats[e.what as usize],
                    origin: &self.origins[e.origin as usize],
                });
            }
            i = (i + 1) & mask;
        }
    }

    /// Each indicator's count by origin's source, for the report.
    pub fn counts(&self) -> Vec<(String, usize)> {
        let mut n = vec![0usize; self.origins.len()];
        for e in &self.entries {
            n[e.origin as usize] += 1;
        }
        let mut by: Vec<(String, usize)> = Vec::new();
        for (o, n) in self.origins.iter().zip(n) {
            match by.iter_mut().find(|(s, _)| *s == o.source) {
                Some((_, m)) => *m += n,
                None => by.push((o.source.clone(), n)),
            }
        }
        by.retain(|(_, n)| *n > 0);
        by
    }
}

#[cfg(test)]
#[path = "indicator_store_tests.rs"]
mod tests;
