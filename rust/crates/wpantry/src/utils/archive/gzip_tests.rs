use super::*;

/// `text` as a gzip file of stored (uncompressed) blocks, with `name` in
/// the header when given.
pub(crate) fn stored(text: &[u8], name: Option<&str>) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, if name.is_some() { FNAME } else { 0 }, 0, 0, 0, 0, 0, 3];
    if let Some(n) = name {
        out.extend_from_slice(n.as_bytes());
        out.push(0);
    }
    let chunks: Vec<&[u8]> = if text.is_empty() { vec![&[][..]] } else { text.chunks(65_535).collect() };
    for (i, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&wpantry_yara::modules::hash::crc32(text).to_le_bytes());
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out
}

#[test]
fn a_gzip_file_inflates_and_its_trailer_is_checked() {
    let text = b"evil.example,generic (malware),(static)\n".repeat(3000);
    let gz = stored(&text, Some("trails.csv"));
    assert!(is_gzip(&gz));
    assert_eq!(gunzip(&gz, 1 << 20).as_deref(), Some(&text[..]));
    assert_eq!(gunzip(&stored(b"", None), 10).as_deref(), Some(&b""[..]));
    assert_eq!(gunzip(&gz, 1000), None, "past max");
    let mut bad = gz.clone();
    let n = bad.len();
    bad[n - 6] ^= 1;
    assert_eq!(gunzip(&bad, 1 << 20), None, "a wrong CRC");
    let mut short = gz.clone();
    short.truncate(n - 3);
    assert_eq!(gunzip(&short, 1 << 20), None, "cut short");
    assert_eq!(gunzip(b"plain text, not gzip at all", 1 << 20), None);
}
