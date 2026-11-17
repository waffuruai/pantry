//! Documents and images read for the shapes document malware takes, without
//! opening them: a PDF that runs JavaScript when opened or launches a
//! program, an Office file carrying macros in a format that shouldn't,
//! Excel 4.0 macro sheets, a template or OLE object fetched from a remote
//! host, DDE fields, RTF with embedded objects, an image that is really a
//! program or carries one after its last byte, an SVG with a script, and
//! a program wearing a document's name. ClamAV runs over the same files
//! when it is installed. Nothing is executed, rendered or fetched; every
//! parser here is bounded and returns "can't be read" rather than guessing.
//!
//! A clean result is not a clean file: these are the shapes, and ClamAV
//! knows the signatures it has.
//!
//! One file per format: [`pdf`], [`ooxml`] (over the [`zip`] reader and the
//! [`deflate`](crate::utils::archive::deflate) inflater), [`ole`], [`rtf`],
//! [`image`], [`svg`] and the [`clamav`] call. This file is the index: what
//! is read, the size limits, the walk, the dispatch by extension and first
//! bytes, and the byte helpers the readers share.

use std::path::{Path, PathBuf};

mod clamav;
mod image;
mod ole;
mod ooxml;
mod pdf;
mod rtf;
mod svg;

use crate::checks::files::{Contents, Read, Stats, When};
pub use crate::utils::archive::deflate::inflate;
use crate::utils::archive::zip;
use crate::utils::archive::{MAX_MEMBER, rfind};
use crate::utils::walk::walk;
pub use clamav::clamav;

/// The members of a zip whose names end in `suffix`, each inflated up to
/// `max` bytes: `(name, bytes)`. Members that can't be read are left out.
pub fn zip_members(bytes: &[u8], suffix: &str, max: usize) -> Vec<(String, Vec<u8>)> {
    let Some(z) = zip::Zip::parse(bytes) else { return Vec::new() };
    z.entries
        .iter()
        .filter(|e| e.name.ends_with(suffix))
        .filter_map(|e| z.read_capped(bytes, &e.name, max).map(|b| (e.name.clone(), b)))
        .collect()
}

/// One finding about one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Doc {
    /// Relative to the root scanned.
    pub file: String,
    pub id: &'static str,
    pub note: String,
    /// Fails the scan.
    pub hard: bool,
}

const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlt", "xltx", "xltm", "xlam", "ppt",
    "pptx", "pptm", "pot", "potx", "potm", "ppam", "ppsx", "ppsm", "rtf", "odt", "ods", "odp",
];
const IMG_EXTS: &[&str] =
    &["png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "heic", "heif", "avif", "svg"];

/// The most of one file read, and of one root.
const MAX_FILE: u64 = 32 << 20;
const MAX_ROOT: u64 = 512 << 20;

fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Whether a name is a document or image this module reads.
pub fn wanted(name: &str) -> bool {
    let e = ext_of(name);
    DOC_EXTS.contains(&e.as_str()) || IMG_EXTS.contains(&e.as_str())
}

/// Every finding under `root`, `depth` levels down (6 for a repo, 1 for
/// `~/Downloads`), one per (file, id). Build output and dependency
/// directories are skipped as everywhere else. Files are read smallest
/// first, so a directory over the 512 MiB budget loses its largest files,
/// which one finding names, not its many small ones. One job of the files
/// pass ([`crate::checks::files::pass`]).
pub fn scan_dir(root: &Path, depth: usize) -> Vec<Doc> {
    crate::checks::files::Results::default().documents(root, depth)
}

/// The documents and images a root's check reads (smallest first, at most
/// [`MAX_FILE`] each and [`MAX_ROOT`] in all), and the ones it leaves.
#[derive(Debug)]
pub struct Plan {
    pub reads: Vec<Read>,
    skipped: Vec<(String, u64)>,
}

pub fn plan(root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for (dir, names) in walk {
        for name in names {
            if !wanted(name) {
                continue;
            }
            let path = dir.join(name);
            if let Some(s) = stat(&path).filter(|s| s.file) {
                files.push((path, s.size));
            }
        }
    }
    files.sort_by_key(|(_, size)| *size);
    let mut budget = MAX_ROOT;
    let mut plan = Plan { reads: Vec::new(), skipped: Vec::new() };
    for (path, size) in files {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if size > MAX_FILE || size > budget {
            plan.skipped.push((rel, size));
            continue;
        }
        budget -= size;
        plan.reads.push(Read { path, rel, cap: MAX_FILE, role: 0, when: When::Always });
    }
    plan
}

/// One file's findings.
pub fn file(read: &Read, c: &Contents) -> Vec<Doc> {
    c.bytes.map(|b| scan_bytes(&read.rel, b)).unwrap_or_default()
}

/// The root's findings, one per (file, id).
pub fn finish(plan: &Plan, files: &[Option<&Vec<Doc>>]) -> Vec<Doc> {
    let mut out: Vec<Doc> = files.iter().flatten().flat_map(|f| f.iter().cloned()).collect();
    let skipped = &plan.skipped;
    if !skipped.is_empty() {
        let total: u64 = skipped.iter().map(|(_, s)| s).sum();
        let shown: Vec<&str> = skipped.iter().take(3).map(|(r, _)| r.as_str()).collect();
        push(
            &mut out,
            &skipped[0].0,
            "DOC-UNREADABLE",
            format!(
                "{} file(s), {} MiB, not read: over {} MiB each or past this directory's {} MiB budget ({}{})",
                skipped.len(),
                total >> 20,
                MAX_FILE >> 20,
                MAX_ROOT >> 20,
                shown.join(", "),
                if skipped.len() > 3 { ", …" } else { "" }
            ),
            false,
        );
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out.dedup_by(|a, b| a.file == b.file && a.id == b.id);
    out
}

/// The findings for one file's bytes, by what its name says it is and
/// what its first bytes say it really is.
pub fn scan_bytes(file: &str, bytes: &[u8]) -> Vec<Doc> {
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }
    let ext = ext_of(file);
    if let Some(what) = program_header(bytes) {
        push(
            &mut out,
            file,
            "DISGUISED-PROGRAM",
            format!("named .{ext} but it is {what}: a program dressed as a document"),
            true,
        );
        return out;
    }
    let is_zip = bytes.starts_with(b"PK\x03\x04");
    let is_cfb = bytes.starts_with(&ole::CFB);
    let is_rtf = bytes.starts_with(b"{\\rt");
    match ext.as_str() {
        "pdf" => pdf::scan(file, bytes, &mut out),
        "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam" | "pptx" | "pptm" | "potx"
        | "potm" | "ppam" | "ppsx" | "ppsm" | "odt" | "ods" | "odp" => {
            if is_zip {
                ooxml::scan(file, &ext, bytes, &mut out);
            } else if is_cfb {
                ole::scan(file, &ext, bytes, &mut out);
            } else if is_rtf {
                rtf::scan(file, bytes, &mut out);
            } else {
                push(
                    &mut out,
                    file,
                    "DOC-UNREADABLE",
                    "not a zip container: can't be read as an Office document",
                    false,
                );
            }
        }
        "doc" | "dot" | "xls" | "xlt" | "ppt" | "pot" => {
            if is_cfb {
                ole::scan(file, &ext, bytes, &mut out);
            } else if is_zip {
                ooxml::scan(file, &ext, bytes, &mut out);
            } else if is_rtf {
                rtf::scan(file, bytes, &mut out);
            } else if looks_like_text(bytes) {
                push(&mut out, file, "DOC-UNREADABLE", "a text file with a document's extension", false);
            }
        }
        "rtf" => {
            if is_rtf {
                rtf::scan(file, bytes, &mut out);
            } else if is_cfb {
                ole::scan(file, &ext, bytes, &mut out);
            } else if is_zip {
                ooxml::scan(file, &ext, bytes, &mut out);
            }
        }
        "svg" => svg::scan(file, bytes, &mut out),
        _ if IMG_EXTS.contains(&ext.as_str()) => image::scan(file, &ext, bytes, &mut out),
        _ => {}
    }
    out
}

/// Every document and image under `root` (for ClamAV), `depth` levels down.
pub fn files_under(root: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (dir, files) in walk(root, depth) {
        for name in files {
            if wanted(&name) {
                out.push(dir.join(name));
            }
        }
    }
    out
}

// --- Shared by the readers ------------------------------------------------

/// One finding appended for `file`.
fn push(out: &mut Vec<Doc>, file: &str, id: &'static str, note: impl Into<String>, hard: bool) {
    out.push(Doc { file: file.into(), id, note: note.into(), hard });
}

fn looks_like_text(bytes: &[u8]) -> bool {
    bytes.iter().take(512).all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || *b >= 0x80)
}

/// What the first bytes say when they say "program".
fn program_header(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"MZ") {
        Some("a Windows executable (MZ)")
    } else if b.starts_with(b"\x7fELF") {
        Some("an ELF executable")
    } else if [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
    ]
    .iter()
    .any(|m| b.starts_with(m))
    {
        Some("a Mach-O executable")
    } else if b.starts_with(b"#!") {
        Some("a script (shebang)")
    } else {
        None
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

/// The (id, hard) pairs of some findings, for the readers' tests.
#[cfg(test)]
fn ids(v: &[Doc]) -> Vec<(&str, bool)> {
    v.iter().map(|d| (d.id, d.hard)).collect()
}

#[cfg(test)]
mod tests;
