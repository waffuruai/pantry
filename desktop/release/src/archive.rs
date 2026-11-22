//! Deterministic ZIP and gzipped tar writers, and the ZIP reader signing and
//! the Setup payload need.
//!
//! The layouts are the ones Python's `zipfile` and `tarfile` (GNU format)
//! write for the same entries, field for field: ZIP entries made on Unix
//! (version 20, made by 3), dated 1980-01-01 00:00, deflated, no extra
//! fields; tar headers owned by 0 with mtime 0 and empty user and group
//! names, gzip header mtime 0. Only the deflate streams differ from a
//! Python-built archive, since miniz_oxide and zlib encode differently.
//!
//! Example:
//!
//! ```text
//! let mut entries = Entries::new();
//! entries.insert("LICENSE.txt".into(), (0o644, b"MIT".to_vec()));
//! let zip = write_zip(&entries)?;
//! ```

use std::collections::BTreeMap;

/// Archive entries: name to (Unix permission bits, contents). A BTreeMap so
/// the names come out sorted by code point, as Python's `sorted()` gives.
pub type Entries = BTreeMap<String, (u32, Vec<u8>)>;

/// Python's ZIP64_LIMIT: past it zipfile would switch to ZIP64 records,
/// which this writer does not produce.
const ZIP64_LIMIT: u64 = (1 << 31) - 1;
const S_IFREG: u32 = 0o100000;
/// MS-DOS date 1980-01-01 (day 1, month 1, year 0), time 00:00:00.
const DOS_DATE: u16 = (1 << 5) | 1;
const DEFLATE_LEVEL: u8 = 9;

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// CRC-32 (IEEE 802.3), as zip and gzip use.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn small(n: usize, what: &str, name: &str) -> Result<u32, String> {
    if n as u64 > ZIP64_LIMIT {
        return Err(format!(
            "{name}: {what} is too large for a ZIP without ZIP64"
        ));
    }
    Ok(n as u32)
}

/// A ZIP of `entries`, each deflated, in name order.
pub fn write_zip(entries: &Entries) -> Result<Vec<u8>, String> {
    if entries.len() > 0xFFFF {
        return Err("too many entries for a ZIP without ZIP64".to_string());
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, (mode, body)) in entries {
        let data = miniz_oxide::deflate::compress_to_vec(body, DEFLATE_LEVEL);
        let crc = crc32(body);
        let offset = small(out.len(), "the archive", name)?;
        // zipfile's own test: past ZIP64_LIMIT / 1.05 it would write ZIP64.
        if body.len() as f64 * 1.05 > ZIP64_LIMIT as f64 {
            return Err(format!(
                "{name}: the file is too large for a ZIP without ZIP64"
            ));
        }
        let compressed = small(data.len(), "the compressed file", name)?;
        let size = body.len() as u32;
        let name_len = u16::try_from(name.len()).map_err(|_| format!("{name}: name too long"))?;
        // Bit 11: the name is UTF-8 (zipfile sets it for non-ASCII names).
        let flags: u16 = if name.is_ascii() { 0 } else { 0x800 };

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // deflate
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 3]); // made by: version 2.0, Unix
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&DOS_DATE.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&((S_IFREG | (mode & 0o7777)) << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = small(out.len(), "the archive", "ZIP")?;
    let central_size = small(central.len(), "the central directory", "ZIP")?;
    out.extend_from_slice(&central);
    let count = entries.len() as u16;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // central directory disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    Ok(out)
}

/// One member of a ZIP, as read back.
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub name: String,
    /// The central directory's external attributes (Unix mode in the top
    /// 16 bits).
    pub external_attr: u32,
    pub body: Vec<u8>,
}

impl Member {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| "truncated ZIP".to_string())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "truncated ZIP".to_string())
}

/// The members of a ZIP in central-directory order (zipfile's `infolist()`
/// order). Stored and deflated members are supported; encrypted and ZIP64
/// archives are refused.
pub fn read_zip(bytes: &[u8]) -> Result<Vec<Member>, String> {
    // The end record is the last 22 bytes, or earlier by its comment's length.
    let floor = bytes.len().saturating_sub(22 + 0xFFFF);
    let end = (floor..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&at| bytes[at..].starts_with(&0x0605_4b50u32.to_le_bytes()))
        .ok_or("not a ZIP: no end of central directory record")?;
    let count = u16_at(bytes, end + 10)? as usize;
    let central = u32_at(bytes, end + 16)?;
    if count == 0xFFFF || central == 0xFFFF_FFFF {
        return Err("ZIP64 archives are not supported".to_string());
    }
    let mut at = central as usize;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(bytes, at)? != 0x0201_4b50 {
            return Err("bad central directory entry".to_string());
        }
        let flags = u16_at(bytes, at + 8)?;
        let method = u16_at(bytes, at + 10)?;
        let crc = u32_at(bytes, at + 16)?;
        let compressed = u32_at(bytes, at + 20)? as usize;
        let size = u32_at(bytes, at + 24)? as usize;
        let name_len = u16_at(bytes, at + 28)? as usize;
        let extra_len = u16_at(bytes, at + 30)? as usize;
        let comment_len = u16_at(bytes, at + 32)? as usize;
        let external_attr = u32_at(bytes, at + 38)?;
        let offset = u32_at(bytes, at + 42)? as usize;
        let raw_name = bytes
            .get(at + 46..at + 46 + name_len)
            .ok_or("truncated ZIP")?;
        at += 46 + name_len + extra_len + comment_len;

        let name = if flags & 0x800 != 0 || raw_name.is_ascii() {
            String::from_utf8(raw_name.to_vec())
                .map_err(|_| "a ZIP name is not UTF-8".to_string())?
        } else {
            return Err("a ZIP name is neither ASCII nor marked UTF-8".to_string());
        };
        if flags & 1 != 0 {
            return Err(format!("{name}: encrypted ZIP members are not supported"));
        }
        if compressed == 0xFFFF_FFFF || size == 0xFFFF_FFFF || offset == 0xFFFF_FFFF {
            return Err(format!("{name}: ZIP64 members are not supported"));
        }
        if u32_at(bytes, offset)? != 0x0403_4b50 {
            return Err(format!("{name}: bad local file header"));
        }
        let local_name_len = u16_at(bytes, offset + 26)? as usize;
        let local_extra_len = u16_at(bytes, offset + 28)? as usize;
        let local_name = bytes
            .get(offset + 30..offset + 30 + local_name_len)
            .ok_or("truncated ZIP")?;
        if local_name != raw_name {
            return Err(format!("{name}: the local header names a different file"));
        }
        let start = offset + 30 + local_name_len + local_extra_len;
        let data = bytes
            .get(start..start + compressed)
            .ok_or("truncated ZIP")?;
        let body = match method {
            0 => data.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, size)
                .map_err(|e| format!("{name}: bad deflate data: {e:?}"))?,
            other => {
                return Err(format!(
                    "{name}: compression method {other} is not supported"
                ));
            }
        };
        if body.len() != size || crc32(&body) != crc {
            return Err(format!("{name}: size or CRC does not match"));
        }
        members.push(Member {
            name,
            external_attr,
            body,
        });
    }
    Ok(members)
}

const BLOCK: usize = 512;
const RECORD: usize = BLOCK * 20;

/// tarfile's `itn` for small numbers: zero-padded octal, then NUL.
fn octal(field: &mut [u8], n: u64, name: &str) -> Result<(), String> {
    let digits = field.len() - 1;
    let text = format!("{n:0digits$o}");
    if text.len() > digits {
        return Err(format!("{name}: {n} does not fit a tar header field"));
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

/// A GNU tar header for a regular file, as `tarfile.TarInfo.tobuf(GNU_FORMAT)`
/// writes it with uid, gid and mtime 0 and empty user and group names.
fn tar_header(name: &str, mode: u32, size: usize) -> Result<[u8; BLOCK], String> {
    if name.len() > 100 {
        // tarfile would add a GNU long-name record, which this writer omits.
        return Err(format!(
            "{name}: tar names over 100 bytes are not supported"
        ));
    }
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], u64::from(mode & 0o7777), name)?;
    octal(&mut h[108..116], 0, name)?; // uid
    octal(&mut h[116..124], 0, name)?; // gid
    octal(&mut h[124..136], size as u64, name)?;
    octal(&mut h[136..148], 0, name)?; // mtime
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0'; // regular file
    h[257..265].copy_from_slice(b"ustar  \0"); // GNU magic and version
    // uname, gname, devmajor, devminor and prefix stay NUL.
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    Ok(h)
}

/// A gzipped GNU tar of `entries` in name order. Python's
/// `gzip.GzipFile(filename="", mtime=0)` header: no name, mtime 0, XFL 2
/// (best compression), OS 255.
pub fn write_tar_gz(entries: &Entries) -> Result<Vec<u8>, String> {
    let mut tar = Vec::new();
    for (name, (mode, body)) in entries {
        tar.extend_from_slice(&tar_header(name, *mode, body.len())?);
        tar.extend_from_slice(body);
        let rest = body.len() % BLOCK;
        if rest > 0 {
            tar.resize(tar.len() + BLOCK - rest, 0);
        }
    }
    tar.resize(tar.len() + 2 * BLOCK, 0);
    let rest = tar.len() % RECORD;
    if rest > 0 {
        tar.resize(tar.len() + RECORD - rest, 0);
    }

    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 0xff];
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(&tar, DEFLATE_LEVEL));
    out.extend_from_slice(&crc32(&tar).to_le_bytes());
    out.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    Ok(out)
}

/// The uncompressed tar inside `write_tar_gz` output, for tests and checks.
pub fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 18 || bytes[..4] != [0x1f, 0x8b, 8, 0] {
        return Err("not a gzip stream without optional fields".to_string());
    }
    let body = &bytes[10..bytes.len() - 8];
    let data = miniz_oxide::inflate::decompress_to_vec(body)
        .map_err(|e| format!("bad gzip data: {e:?}"))?;
    let crc = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap());
    if crc32(&data) != crc {
        return Err("gzip CRC does not match".to_string());
    }
    Ok(data)
}
