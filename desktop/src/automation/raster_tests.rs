#[test]
fn crc_matches_the_png_reference() {
    // The CRC of "IEND" is fixed by the PNG spec: AE 42 60 82.
    assert_eq!(super::crc32(b"IEND"), 0xAE42_6082);
}
