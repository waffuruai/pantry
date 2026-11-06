//! Raster images: what the bytes are by magic against what the name says,
//! a payload after the image's last byte (a zip, a program, a script
//! riding on a picture), and code in the metadata (a web shell in EXIF
//! waiting for an include). SVG is XML and goes to [`super::svg`].

use super::{Doc, find, find_ci, looks_like_text, push, rfind};

/// Data after the last byte is a trailer worth a warning past this much.
const MAX_TRAILER: usize = 1024;

/// What the trailer or metadata holds when it holds something that runs.
const PAYLOAD_MARKS: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "a zip archive"),
    (b"MZ", "a Windows executable"),
    (b"\x7fELF", "an ELF executable"),
    (b"#!/", "a script"),
    (b"<?php", "PHP code"),
    (b"<script", "a script tag"),
    (b"eval(", "an eval call"),
    (b"base64_decode(", "a base64 decoder"),
    (b"powershell", "a PowerShell command"),
];

/// Code in metadata (EXIF, text chunks): the marks that are code, not
/// just data.
const METADATA_MARKS: &[(&[u8], &str)] = &[
    (b"<?php", "PHP code"),
    (b"base64_decode(", "a base64 decoder"),
    (b"eval(", "an eval call"),
    (b"<script", "a script tag"),
];

/// What the bytes are, by magic.
fn image_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if b.starts_with(b"GIF8") {
        Some("gif")
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        Some("webp")
    } else if b.starts_with(b"BM") {
        Some("bmp")
    } else if b.starts_with(&[0, 0, 1, 0]) {
        Some("ico")
    } else if b.starts_with(b"II*\0") || b.starts_with(b"MM\0*") {
        Some("tiff")
    } else if b.get(4..8) == Some(b"ftyp") {
        Some("heif")
    } else {
        None
    }
}

/// The type an extension claims, in [`image_type`]'s names.
fn claimed_type(ext: &str) -> &str {
    match ext {
        "jpg" | "jpeg" => "jpeg",
        "tif" | "tiff" => "tiff",
        "heic" | "heif" | "avif" => "heif",
        e => e,
    }
}

pub(super) fn scan(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let actual = image_type(bytes);
    match actual {
        None => {
            wrong_type(file, ext, bytes, out);
            return;
        }
        Some(t) if t != claimed_type(ext) => {
            push(
                out,
                file,
                "IMG-WRONG-TYPE",
                format!("named .{ext} but the bytes are {t}: the extension doesn't match the file"),
                false,
            );
        }
        _ => {}
    }
    // Data after the image's last byte.
    let end = match actual {
        Some("png") => rfind(bytes, b"IEND").map(|i| i + 8),
        Some("jpeg") => rfind(bytes, &[0xFF, 0xD9]).map(|i| i + 2),
        Some("gif") => Some(bytes.iter().rposition(|b| *b == 0x3B).map_or(bytes.len(), |i| i + 1)),
        _ => None,
    };
    if let Some(end) = end
        && end < bytes.len()
    {
        let trailer = &bytes[end..];
        if let Some((_, what)) = PAYLOAD_MARKS.iter().find(|(m, _)| find(trailer, m).is_some()) {
            push(
                out,
                file,
                "IMG-PAYLOAD",
                format!(
                    "{} KiB after the image's last byte, holding {what}: a payload riding on a picture",
                    trailer.len() >> 10
                ),
                true,
            );
            return;
        }
        if trailer.len() > MAX_TRAILER {
            push(
                out,
                file,
                "IMG-TRAILER",
                format!(
                    "{} KiB after the image's last byte: data no viewer shows (steganography or a container)",
                    trailer.len() >> 10
                ),
                false,
            );
        }
    }
    if let Some((_, what)) = METADATA_MARKS.iter().find(|(m, _)| find(bytes, m).is_some()) {
        push(
            out,
            file,
            "IMG-PAYLOAD",
            format!("{what} inside the image's metadata: a web shell or loader waiting for an include"),
            true,
        );
    }
}

/// Bytes with no image magic under an image's name: a zip or HTML fails,
/// an SVG is read as one, text and unknown binary warn.
fn wrong_type(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let what = if bytes.starts_with(b"PK\x03\x04") {
        "a zip archive"
    } else if looks_like_text(bytes) && (find_ci(bytes, b"<html").is_some() || find_ci(bytes, b"<script").is_some()) {
        "an HTML page"
    } else if looks_like_text(bytes) && find(bytes, b"<svg").is_some() {
        "an SVG"
    } else if looks_like_text(bytes) {
        "text"
    } else {
        "no image format"
    };
    let hard = what != "text" && what != "no image format" && what != "an SVG";
    push(out, file, "IMG-WRONG-TYPE", format!("named .{ext} but the bytes are {what}"), hard);
    if what == "an SVG" {
        super::svg::scan(file, bytes, out);
    }
}

#[cfg(test)]
#[path = "image_tests.rs"]
mod tests;
