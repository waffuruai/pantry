//! gzip (RFC 1952): one member, inflated by [`super::deflate`] and checked
//! against its trailer's CRC-32 and length. A file that isn't gzip, is cut
//! short, inflates past `max` or fails its checks is `None`.

use super::deflate::inflate;

const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Whether `data` starts like a gzip file.
pub fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

/// The bytes `data` holds, at most `max` of them.
pub fn gunzip(data: &[u8], max: usize) -> Option<Vec<u8>> {
    if !is_gzip(data) || data.len() < 18 || data[2] != 8 {
        return None;
    }
    let flags = data[3];
    let mut i = 10;
    if flags & FEXTRA != 0 {
        i += 2 + super::u16le(data, i)?;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            i += data.get(i..)?.iter().position(|&b| b == 0)? + 1;
        }
    }
    if flags & FHCRC != 0 {
        i += 2;
    }
    let body = data.get(i..data.len().checked_sub(8)?)?;
    let out = inflate(body, max)?;
    let crc = super::u32le(data, data.len() - 8)?;
    let size = super::u32le(data, data.len() - 4)?;
    let ok = crc == wpantry_yara::modules::hash::crc32(&out) as usize && size == (out.len() as u32) as usize;
    ok.then_some(out)
}

#[cfg(test)]
#[path = "gzip_tests.rs"]
pub(crate) mod tests;
