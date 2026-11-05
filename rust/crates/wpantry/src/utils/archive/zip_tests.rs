use super::*;

#[test]
fn reads_the_directory_and_stored_members() {
    let zip_bytes = stored(&[("a.txt", b"alpha"), ("dir/b.xml", b"<b/>")]);
    let zip = Zip::parse(&zip_bytes).unwrap();
    let names: Vec<&str> = zip.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["a.txt", "dir/b.xml"]);
    assert_eq!(zip.read(&zip_bytes, "a.txt").as_deref(), Some(b"alpha" as &[u8]));
    assert_eq!(zip.read(&zip_bytes, "dir/b.xml").as_deref(), Some(b"<b/>" as &[u8]));
    assert_eq!(zip.read(&zip_bytes, "missing.xml"), None);
}

#[test]
fn inflates_a_deflated_member() {
    // "abcabcabcabc xyz" as a fixed-Huffman block.
    let fixed: &[u8] = &[0x4b, 0x4c, 0x4a, 0x4e, 0x84, 0x21, 0x85, 0x8a, 0xca, 0x2a, 0x00];
    let zip_bytes =
        build(&[Member { name: "word/document.xml", method: DEFLATED, flags: 0, data: fixed, uncompressed: 16 }]);
    let zip = Zip::parse(&zip_bytes).unwrap();
    assert_eq!(zip.read(&zip_bytes, "word/document.xml").as_deref(), Some(b"abcabcabcabc xyz" as &[u8]));
}

#[test]
fn what_it_cannot_read_is_none() {
    assert!(Zip::parse(b"PK\x03\x04 no directory at all").is_none(), "no end record");
    assert!(Zip::parse(b"").is_none());
    let encrypted =
        build(&[Member { name: "a", method: STORED, flags: FLAG_ENCRYPTED as u16, data: b"x", uncompressed: 1 }]);
    assert_eq!(Zip::parse(&encrypted).unwrap().read(&encrypted, "a"), None, "encrypted");
    let other_method = build(&[Member { name: "a", method: 12, flags: 0, data: b"x", uncompressed: 1 }]);
    assert_eq!(Zip::parse(&other_method).unwrap().read(&other_method, "a"), None, "bzip2");
    let bomb =
        build(&[Member { name: "a", method: STORED, flags: 0, data: b"x", uncompressed: (MAX_MEMBER + 1) as u32 }]);
    assert_eq!(Zip::parse(&bomb).unwrap().read(&bomb, "a"), None, "declared larger than the cap");
    let mut zip64 = stored(&[("a", b"x")]);
    let eocd = zip64.len() - 22;
    zip64[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(Zip::parse(&zip64).is_none(), "zip64 markers");
    let mut damaged = stored(&[("a", b"x")]);
    let cd = damaged.len() - 22 - (46 + 1);
    damaged[cd..cd + 4].copy_from_slice(b"XXXX");
    assert!(Zip::parse(&damaged).is_none(), "a central directory that isn't one");
}
