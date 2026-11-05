use super::*;
use crate::checks::documents::{ids, scan_bytes};

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
