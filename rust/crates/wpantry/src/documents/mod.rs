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
//! [`deflate`] inflater), [`ole`], [`rtf`], [`image`], [`svg`] and the
//! [`clamav`] call. This file is the index: what is read, the size limits,
//! the walk, the dispatch by extension and first bytes, and the byte
//! helpers the readers share.

use crate::repos;
use std::path::{Path, PathBuf};

mod clamav;
mod deflate;
mod image;
mod ole;
mod ooxml;
mod pdf;
mod rtf;
mod svg;
mod zip;

pub use clamav::clamav;
pub use deflate::inflate;

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
/// A zip member is read only up to this much once inflated (a bomb guard);
/// RTF and SVG text is lowercased up to the same bound.
const MAX_MEMBER: usize = 16 << 20;

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
/// which one finding names, not its many small ones.
pub fn scan_dir(root: &Path, depth: usize) -> Vec<Doc> {
    let mut out = Vec::new();
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for (dir, names) in repos::walk(root, depth) {
        for name in names {
            if !wanted(&name) {
                continue;
            }
            let path = dir.join(&name);
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.is_file() {
                files.push((path, meta.len()));
            }
        }
    }
    files.sort_by_key(|(_, size)| *size);
    let mut budget = MAX_ROOT;
    let mut skipped: Vec<(String, u64)> = Vec::new();
    for (path, size) in files {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if size > MAX_FILE || size > budget {
            skipped.push((rel, size));
            continue;
        }
        budget -= size;
        let Ok(bytes) = std::fs::read(&path) else { continue };
        out.extend(scan_bytes(&rel, &bytes));
    }
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
    for (dir, files) in repos::walk(root, depth) {
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

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

fn u16le(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

fn u32le(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_le_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]) as usize)
}

/// The (id, hard) pairs of some findings, for the readers' tests.
#[cfg(test)]
fn ids(v: &[Doc]) -> Vec<(&str, bool)> {
    v.iter().map(|d| (d.id, d.hard)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wanted_goes_by_extension_in_any_case() {
        assert!(wanted("Report.PDF"));
        assert!(wanted("deck.pptx"));
        assert!(wanted("logo.SVG"));
        assert!(!wanted("notes.md"));
        assert!(!wanted("Makefile"));
        assert!(!wanted("archive.pdf.zip"));
    }

    #[test]
    fn a_program_wearing_a_documents_name_fails_whatever_the_name() {
        let heads: [(&[u8], &str); 4] = [
            (b"MZ\x90\x00abc", "MZ"),
            (b"\x7fELF\x02\x01", "ELF"),
            (b"\xcf\xfa\xed\xfe\x07", "Mach-O"),
            (b"#!/bin/sh\n", "shebang"),
        ];
        for (bytes, what) in heads {
            for name in ["invoice.pdf", "a.png", "old.doc", "letter.docx", "x.rtf", "logo.svg"] {
                let got = scan_bytes(name, bytes);
                assert_eq!(ids(&got), [("DISGUISED-PROGRAM", true)], "{name} {what}: {got:?}");
                assert!(got[0].note.contains(what), "{}", got[0].note);
            }
        }
        assert!(scan_bytes("x.pdf", b"MZ").is_empty(), "under four bytes there is nothing to read");
        assert_eq!(
            ids(&scan_bytes("x.txt", b"MZ\x90\x00abc")),
            [("DISGUISED-PROGRAM", true)],
            "the walker filters names; the bytes are read for whatever name is given"
        );
    }

    #[test]
    fn dispatch_follows_the_bytes_not_the_name() {
        let mut cfb = ole::CFB.to_vec();
        cfb.extend_from_slice(&[0u8; 64]);
        cfb.extend(ole::utf16("_VBA_PROJECT"));
        assert_eq!(ids(&scan_bytes("old.docx", &cfb)), [("DOC-MACRO", true)], "a compound file named .docx");
        assert_eq!(ids(&scan_bytes("old.rtf", &cfb)), [("DOC-MACRO", true)], "a compound file named .rtf");
        let zipped = zip::stored(&[("xl/macrosheets/sheet1.xml", b"<macrosheet/>")]);
        assert_eq!(ids(&scan_bytes("book.xls", &zipped)), [("DOC-XL4-MACRO", true)], "a zip named .xls");
        assert_eq!(ids(&scan_bytes("book.rtf", &zipped)), [("DOC-XL4-MACRO", true)], "a zip named .rtf");
        let rtf = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}}}";
        assert_eq!(ids(&scan_bytes("letter.docx", rtf)), [("DOC-RTF-OBJECT", true)], "RTF named .docx");
        assert_eq!(ids(&scan_bytes("letter.doc", rtf)), [("DOC-RTF-OBJECT", true)], "RTF named .doc");
        let text = b"not a zip at all, just text";
        assert_eq!(ids(&scan_bytes("letter.docx", text)), [("DOC-UNREADABLE", false)]);
        let got = scan_bytes("letter.doc", text);
        assert_eq!(ids(&got), [("DOC-UNREADABLE", false)]);
        assert!(got[0].note.contains("a text file"), "{}", got[0].note);
        assert!(scan_bytes("letter.doc", &[0u8, 1, 2, 3, 0xff, 0xfe]).is_empty(), "unknown binary named .doc");
        assert!(scan_bytes("x.rtf", text).is_empty(), "text named .rtf is read as nothing");
    }

    #[test]
    fn walks_and_skips_output_dirs() {
        let d = crate::system::TempDir::new("documents").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/x")).unwrap();
        std::fs::create_dir_all(d.path().join("docs")).unwrap();
        std::fs::write(d.path().join("node_modules/x/a.pdf"), b"MZ\x90\x00").unwrap();
        std::fs::write(d.path().join("docs/a.pdf"), b"%PDF-1.4\n<< /S /Launch >>\n%%EOF").unwrap();
        std::fs::write(
            d.path().join("docs/ok.png"),
            [0x89, b'P', b'N', b'G', 0, 0, 0, 0, b'I', b'E', b'N', b'D', 0, 0, 0, 0],
        )
        .unwrap();
        std::fs::write(d.path().join("notes.md"), "MZ not a document").unwrap();
        let got = scan_dir(d.path(), 6);
        assert_eq!(ids(&got), [("DOC-LAUNCH", true)], "{got:?}");
        assert_eq!(got[0].file, "docs/a.pdf");
        assert_eq!(files_under(d.path(), 6).len(), 2);
    }

    #[test]
    fn files_over_the_size_limit_are_named_not_read() {
        let d = crate::system::TempDir::new("documents-big").unwrap();
        // A sparse file: the size is what matters, and nothing reads it.
        let big = std::fs::File::create(d.path().join("big.pdf")).unwrap();
        big.set_len(MAX_FILE + 1).unwrap();
        std::fs::write(d.path().join("small.pdf"), b"%PDF-1.4\n%%EOF\n").unwrap();
        let got = scan_dir(d.path(), 1);
        assert_eq!(ids(&got), [("DOC-UNREADABLE", false)], "{got:?}");
        assert_eq!(got[0].file, "big.pdf");
        assert!(got[0].note.contains("1 file(s), 32 MiB"), "{}", got[0].note);
        assert!(got[0].note.contains("big.pdf"), "{}", got[0].note);
    }

    #[test]
    fn byte_helpers() {
        assert_eq!(find(b"abcabc", b"ca"), Some(2));
        assert_eq!(rfind(b"abcabc", b"ab"), Some(3));
        assert_eq!(find(b"ab", b"abc"), None, "a needle longer than the hay");
        assert_eq!(find(b"abc", b""), None, "an empty needle matches nothing");
        assert_eq!(find_ci(b"<HTML>", b"<html"), Some(0));
        assert_eq!(u16le(&[0x34, 0x12], 0), Some(0x1234));
        assert_eq!(u32le(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x1234_5678));
        assert_eq!(u32le(&[0x78, 0x56, 0x34], 0), None, "short reads are None, not panics");
        assert!(looks_like_text(b"plain words\n"));
        assert!(!looks_like_text(b"\x00\x01binary"));
        assert_eq!(program_header(b"PK\x03\x04"), None);
    }
}
