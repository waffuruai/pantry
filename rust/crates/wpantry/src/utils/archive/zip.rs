//! A zip's central directory and its members, read without a crate and
//! without touching a member until it is asked for. Enough for an Office
//! container: stored and deflated members, with zip64, encryption, other
//! methods and members over the inflated cap reported as unreadable rather
//! than guessed at.

use super::deflate::inflate;
use super::{MAX_MEMBER, rfind, u16le, u32le};

/// The end-of-central-directory record is in the last 64 KiB + 22.
const EOCD_SEARCH: usize = 66_000;
/// More entries than any document carries; a bound on a hostile count.
const MAX_ENTRIES: usize = 20_000;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const FLAG_ENCRYPTED: usize = 1;

pub(crate) struct Entry {
    pub(crate) name: String,
    method: u16,
    compressed: usize,
    uncompressed: usize,
    offset: usize,
}

/// A zip's central directory, read without touching the members.
pub(crate) struct Zip {
    pub(crate) entries: Vec<Entry>,
}

impl Zip {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Zip> {
        let tail_start = bytes.len().saturating_sub(EOCD_SEARCH);
        let eocd = tail_start + rfind(&bytes[tail_start..], b"PK\x05\x06")?;
        let total = u16le(bytes, eocd + 10)?;
        let cd_size = u32le(bytes, eocd + 12)?;
        let cd_offset = u32le(bytes, eocd + 16)?;
        if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
            return None; // zip64
        }
        let mut entries = Vec::new();
        let mut at = cd_offset;
        for _ in 0..total.min(MAX_ENTRIES) {
            if bytes.get(at..at + 4)? != b"PK\x01\x02" {
                return None;
            }
            let method = u16le(bytes, at + 10)? as u16;
            let compressed = u32le(bytes, at + 20)?;
            let uncompressed = u32le(bytes, at + 24)?;
            let n = u16le(bytes, at + 28)?;
            let e = u16le(bytes, at + 30)?;
            let c = u16le(bytes, at + 32)?;
            let offset = u32le(bytes, at + 42)?;
            let name = String::from_utf8_lossy(bytes.get(at + 46..at + 46 + n)?).into_owned();
            entries.push(Entry { name, method, compressed, uncompressed, offset });
            at = at + 46 + n + e + c;
        }
        Some(Zip { entries })
    }

    /// One member's bytes (stored or deflated), or `None` when it is
    /// missing, encrypted, too large or uses another method.
    pub(crate) fn read(&self, bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        self.read_capped(bytes, name, MAX_MEMBER)
    }

    /// [`Zip::read`] with another cap on the inflated size.
    pub(crate) fn read_capped(&self, bytes: &[u8], name: &str, max: usize) -> Option<Vec<u8>> {
        let e = self.entries.iter().find(|e| e.name == name)?;
        if e.uncompressed > max {
            return None;
        }
        let at = e.offset;
        if bytes.get(at..at + 4)? != b"PK\x03\x04" {
            return None;
        }
        let flags = u16le(bytes, at + 6)?;
        if flags & FLAG_ENCRYPTED != 0 {
            return None;
        }
        let n = u16le(bytes, at + 26)?;
        let x = u16le(bytes, at + 28)?;
        let start = at + 30 + n + x;
        let data = bytes.get(start..start + e.compressed)?;
        match e.method {
            STORED => Some(data.to_vec()),
            DEFLATED => inflate(data, max),
            _ => None,
        }
    }
}

/// A member of a test zip: `data` as written, `uncompressed` as declared.
#[cfg(test)]
pub(crate) struct Member<'a> {
    pub(crate) name: &'a str,
    pub(crate) method: u16,
    pub(crate) flags: u16,
    pub(crate) data: &'a [u8],
    pub(crate) uncompressed: u32,
}

/// A zip with these members and no extra fields, as `zipfile` would write
/// it (the CRCs are zero: nothing here checks them).
#[cfg(test)]
pub(crate) fn build(members: &[Member]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for m in members {
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0]); // version needed
        out.extend_from_slice(&m.flags.to_le_bytes());
        out.extend_from_slice(&m.method.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // time, date
        out.extend_from_slice(&[0, 0, 0, 0]); // crc (unchecked)
        out.extend_from_slice(&(m.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&m.uncompressed.to_le_bytes());
        out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]); // extra length
        out.extend_from_slice(m.name.as_bytes());
        out.extend_from_slice(m.data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&[20, 0, 20, 0]); // made by, needed
        central.extend_from_slice(&m.flags.to_le_bytes());
        central.extend_from_slice(&m.method.to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0]); // time, date
        central.extend_from_slice(&[0, 0, 0, 0]); // crc
        central.extend_from_slice(&(m.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&m.uncompressed.to_le_bytes());
        central.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // extra, comment, disk, attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(m.name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0]); // disks
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // comment length
    out
}

/// A zip with stored members, the usual test container.
#[cfg(test)]
pub(crate) fn stored(members: &[(&str, &[u8])]) -> Vec<u8> {
    let members: Vec<Member> = members
        .iter()
        .map(|(name, data)| Member { name, method: STORED, flags: 0, data, uncompressed: data.len() as u32 })
        .collect();
    build(&members)
}

#[cfg(test)]
#[path = "zip_tests.rs"]
mod tests;
