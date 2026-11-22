//! Just enough ZIP, gzip and tar reading to unpack the release downloads
//! the way a person would (`--bundle`, `--setup`), with miniz_oxide (already
//! a dependency) for the deflate streams. Names that would land outside the
//! target folder are refused.
//!
//! ```text
//! archive::unzip(Path::new("wpantry-desktop-x86_64-unknown-linux-gnu.zip"), &folder);
//! let entries = archive::untar_gz(Path::new("wpantry-setup-....tar.gz"), &folder);
//! ```

use std::path::{Component, Path, PathBuf};

fn u16_at(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

/// `name` under `into`, or a panic for an absolute or `..` name.
fn inside(into: &Path, name: &str) -> PathBuf {
    let relative = Path::new(name);
    assert!(
        relative
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "archive entry escapes its folder: {name}"
    );
    into.join(relative)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("chmod an extracted file");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn inflate(raw: &[u8]) -> Vec<u8> {
    miniz_oxide::inflate::decompress_to_vec(raw)
        .unwrap_or_else(|e| panic!("bad deflate stream: {e:?}"))
}

/// Extract every entry of `zip` into `into`, with the permission bits each
/// entry records (Python's `extractall` plus `chmod`).
pub fn unzip(zip: &Path, into: &Path) {
    let b = std::fs::read(zip).unwrap_or_else(|e| panic!("{}: {e}", zip.display()));
    let eocd = (0..b.len().saturating_sub(21))
        .rev()
        .find(|&i| b[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
        .unwrap_or_else(|| panic!("{} is not a ZIP", zip.display()));
    let (count, mut at) = (u16_at(&b, eocd + 10), u32_at(&b, eocd + 16));
    std::fs::create_dir_all(into).expect("create the extract folder");
    for _ in 0..count {
        assert_eq!(
            b[at..at + 4],
            [0x50, 0x4b, 0x01, 0x02],
            "bad central directory"
        );
        let method = u16_at(&b, at + 10);
        let size = u32_at(&b, at + 20);
        let (name_len, extra_len, comment_len) = (
            u16_at(&b, at + 28),
            u16_at(&b, at + 30),
            u16_at(&b, at + 32),
        );
        let mode = (u32_at(&b, at + 38) >> 16) as u32 & 0o777;
        let local = u32_at(&b, at + 42);
        let name =
            String::from_utf8(b[at + 46..at + 46 + name_len].to_vec()).expect("UTF-8 entry name");
        at += 46 + name_len + extra_len + comment_len;
        let path = inside(into, &name);
        if name.ends_with('/') {
            std::fs::create_dir_all(&path).expect("create an extracted folder");
            continue;
        }
        let start = local + 30 + u16_at(&b, local + 26) + u16_at(&b, local + 28);
        let raw = &b[start..start + size];
        let data = match method {
            0 => raw.to_vec(),
            8 => inflate(raw),
            other => panic!("{name}: ZIP method {other} is not supported"),
        };
        std::fs::create_dir_all(path.parent().unwrap()).expect("create an extracted folder");
        std::fs::write(&path, data).expect("write an extracted file");
        set_mode(&path, mode);
    }
}

/// One tar member's header fields the suite checks.
pub struct TarEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
}

fn octal(field: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(field);
    let digits = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if digits.is_empty() {
        0
    } else {
        u64::from_str_radix(digits, 8).unwrap_or_else(|_| panic!("bad octal {digits:?}"))
    }
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).expect("UTF-8 tar name")
}

/// Extract a gzipped tar into `into` and return its members' headers.
pub fn untar_gz(tgz: &Path, into: &Path) -> Vec<TarEntry> {
    let gz = std::fs::read(tgz).unwrap_or_else(|e| panic!("{}: {e}", tgz.display()));
    assert!(
        gz.len() > 18 && gz[..3] == [0x1f, 0x8b, 8],
        "{} is not gzip",
        tgz.display()
    );
    let flags = gz[3];
    let mut at = 10;
    if flags & 4 != 0 {
        at += 2 + u16_at(&gz, at);
    }
    for bit in [8, 16] {
        if flags & bit != 0 {
            at += gz[at..]
                .iter()
                .position(|&c| c == 0)
                .expect("terminated gzip field")
                + 1;
        }
    }
    if flags & 2 != 0 {
        at += 2;
    }
    let tar = inflate(&gz[at..]);
    std::fs::create_dir_all(into).expect("create the extract folder");
    let (mut entries, mut long_name, mut at) = (Vec::new(), None, 0);
    while at + 512 <= tar.len() && tar[at..at + 512].iter().any(|&c| c != 0) {
        let h = &tar[at..at + 512];
        let size = octal(&h[124..136]) as usize;
        let body = &tar[at + 512..at + 512 + size];
        at += 512 + size.div_ceil(512) * 512;
        match h[156] {
            b'L' => long_name = Some(cstr(body)),
            kind @ (b'0' | 0 | b'5') => {
                let name = long_name.take().unwrap_or_else(|| cstr(&h[..100]));
                let entry = TarEntry {
                    mode: octal(&h[100..108]) as u32 & 0o7777,
                    uid: octal(&h[108..116]),
                    gid: octal(&h[116..124]),
                    mtime: octal(&h[136..148]),
                    name,
                };
                let path = inside(into, entry.name.trim_end_matches('/'));
                if kind == b'5' {
                    std::fs::create_dir_all(&path).expect("create an extracted folder");
                } else {
                    std::fs::create_dir_all(path.parent().unwrap())
                        .expect("create an extracted folder");
                    std::fs::write(&path, body).expect("write an extracted file");
                    // As tarfile's "data" filter: keep the permission bits,
                    // drop set-id and sticky.
                    set_mode(&path, entry.mode & 0o777);
                }
                entries.push(entry);
            }
            other => panic!("tar member type {:?} is not supported", other as char),
        }
    }
    entries
}
