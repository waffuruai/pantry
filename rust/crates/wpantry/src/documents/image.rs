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
mod tests {
    use super::*;
    use crate::documents::{ids, scan_bytes};

    /// A PNG signature and an IEND chunk: the smallest thing that ends.
    fn png() -> Vec<u8> {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(b"\0\0\0\0IEND\xaeB`\x82");
        png
    }

    #[test]
    fn a_clean_image_is_nothing() {
        assert!(scan_bytes("a.png", &png()).is_empty());
        assert!(scan_bytes("a.jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9]).is_empty());
        assert!(scan_bytes("a.gif", b"GIF89a\x01\x00\x01\x00\x00\x00\x00;").is_empty());
        let mut webp = b"RIFF\x04\x00\x00\x00WEBP".to_vec();
        webp.extend_from_slice(b"VP8 ");
        assert!(scan_bytes("a.webp", &webp).is_empty());
        assert!(scan_bytes("a.heic", b"\x00\x00\x00\x18ftypheic").is_empty());
        assert!(scan_bytes("a.avif", b"\x00\x00\x00\x18ftypavif").is_empty(), "avif shares the box format");
        assert!(scan_bytes("a.tif", b"II*\0\x08\x00\x00\x00").is_empty());
    }

    #[test]
    fn a_payload_after_the_last_byte_fails_and_a_trailer_warns() {
        let mut payload = png();
        payload.extend_from_slice(b"PK\x03\x04 a whole zip follows");
        let got = scan_bytes("a.png", &payload);
        assert_eq!(ids(&got), [("IMG-PAYLOAD", true)]);
        assert!(got[0].note.contains("a zip archive"), "{}", got[0].note);
        let mut gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;".to_vec();
        gif.extend_from_slice(b"MZ\x90\x00 program");
        assert_eq!(ids(&scan_bytes("a.gif", &gif)), [("IMG-PAYLOAD", true)], "after a GIF's trailer byte");
        let mut trailer = png();
        trailer.extend(std::iter::repeat_n(0u8, 4096));
        assert_eq!(ids(&scan_bytes("a.png", &trailer)), [("IMG-TRAILER", false)]);
        let mut small = png();
        small.extend_from_slice(&[0u8; 100]);
        assert!(scan_bytes("a.png", &small).is_empty(), "a little padding is not a trailer");
    }

    #[test]
    fn code_in_metadata_fails() {
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10];
        jpg.extend_from_slice(b"Exif\0\0<?php system($_GET['c']); ?>");
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        let got = scan_bytes("shell.jpg", &jpg);
        assert_eq!(ids(&got), [("IMG-PAYLOAD", true)]);
        assert!(got[0].note.contains("PHP code inside the image's metadata"), "{}", got[0].note);
        let mut png_text = png();
        png_text.splice(8..8, b"\0\0\0\x10tEXtComment\0eval(atob(x))".iter().copied());
        assert_eq!(ids(&scan_bytes("a.png", &png_text)), [("IMG-PAYLOAD", true)], "an eval in a text chunk");
    }

    #[test]
    fn the_name_and_the_bytes_disagree() {
        assert_eq!(ids(&scan_bytes("a.jpg", &png())), [("IMG-WRONG-TYPE", false)], "a png named jpg");
        assert_eq!(ids(&scan_bytes("a.png", b"MZ\x90\x00\x03")), [("DISGUISED-PROGRAM", true)]);
        let got = scan_bytes("a.png", b"<html><script>x</script></html>");
        assert_eq!(ids(&got), [("IMG-WRONG-TYPE", true)]);
        assert!(got[0].note.contains("an HTML page"), "{}", got[0].note);
        let got = scan_bytes("a.png", b"PK\x03\x04\x14\x00\x00\x00");
        assert_eq!(ids(&got), [("IMG-WRONG-TYPE", true)]);
        assert!(got[0].note.contains("a zip archive"), "{}", got[0].note);
        let got = scan_bytes("a.png", b"just some text\n");
        assert_eq!(ids(&got), [("IMG-WRONG-TYPE", false)]);
        assert!(got[0].note.contains("text"), "{}", got[0].note);
        let got = scan_bytes("a.png", &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(ids(&got), [("IMG-WRONG-TYPE", false)]);
        assert!(got[0].note.contains("no image format"), "{}", got[0].note);
        let got = scan_bytes("a.png", b"<svg onload=\"alert(1)\"></svg>");
        assert_eq!(
            ids(&got),
            [("IMG-WRONG-TYPE", false), ("IMG-SVG-SCRIPT", true)],
            "an SVG named .png is read as an SVG: {got:?}"
        );
    }

    #[test]
    fn types_by_magic_and_by_name() {
        assert_eq!(image_type(b"BM\x00\x00"), Some("bmp"));
        assert_eq!(image_type(&[0, 0, 1, 0, 1, 0]), Some("ico"));
        assert_eq!(image_type(b"MM\0*\x00\x00"), Some("tiff"));
        assert_eq!(image_type(b"nothing"), None);
        assert_eq!(claimed_type("jpeg"), "jpeg");
        assert_eq!(claimed_type("tiff"), "tiff");
        assert_eq!(claimed_type("heif"), "heif");
        assert_eq!(claimed_type("png"), "png");
    }
}
