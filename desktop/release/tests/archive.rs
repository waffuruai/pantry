//! The ZIP and tar.gz writers: field layout, round trips and determinism.

use wpantry_release::archive::{Entries, crc32, gunzip, read_zip, write_tar_gz, write_zip};

fn sample() -> Entries {
    let mut e = Entries::new();
    e.insert("b/run".into(), (0o755, b"#!/bin/sh\necho hi\n".to_vec()));
    e.insert("a.txt".into(), (0o644, b"hello hello hello hello".to_vec()));
    e.insert("empty".into(), (0o644, Vec::new()));
    e
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn zip_round_trips_in_name_order_with_modes() {
    let zip = write_zip(&sample()).unwrap();
    let members = read_zip(&zip).unwrap();
    let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["a.txt", "b/run", "empty"]);
    assert_eq!(members[1].body, b"#!/bin/sh\necho hi\n");
    assert_eq!(members[1].external_attr >> 16, 0o100755);
    assert_eq!(members[0].external_attr >> 16, 0o100644);
    assert!(members[2].body.is_empty());
}

#[test]
fn zip_headers_match_pythons_zipfile_layout() {
    let zip = write_zip(&sample()).unwrap();
    // First local header: signature, version 20, no flags, deflate, 1980-01-01.
    assert_eq!(u32_at(&zip, 0), 0x0403_4b50);
    assert_eq!(u16_at(&zip, 4), 20);
    assert_eq!(u16_at(&zip, 6), 0);
    assert_eq!(u16_at(&zip, 8), 8);
    assert_eq!(u16_at(&zip, 10), 0);
    assert_eq!(u16_at(&zip, 12), 0x21);
    assert_eq!(u16_at(&zip, 28), 0, "no extra field");
    // End record: three entries, no comment.
    let end = zip.len() - 22;
    assert_eq!(u32_at(&zip, end), 0x0605_4b50);
    assert_eq!(u16_at(&zip, end + 10), 3);
    assert_eq!(u16_at(&zip, end + 20), 0);
    // Central directory: made by Unix (3), version 2.0.
    let central = u32_at(&zip, end + 16) as usize;
    assert_eq!(&zip[central + 4..central + 6], &[20, 3]);
}

#[test]
fn non_ascii_names_carry_the_utf8_flag() {
    let mut e = Entries::new();
    e.insert("caf\u{e9}.txt".into(), (0o644, b"x".to_vec()));
    let zip = write_zip(&e).unwrap();
    assert_eq!(u16_at(&zip, 6), 0x800);
    assert_eq!(read_zip(&zip).unwrap()[0].name, "caf\u{e9}.txt");
}

#[test]
fn archives_are_the_same_bytes_every_run() {
    assert_eq!(write_zip(&sample()).unwrap(), write_zip(&sample()).unwrap());
    assert_eq!(
        write_tar_gz(&sample()).unwrap(),
        write_tar_gz(&sample()).unwrap()
    );
}

#[test]
fn read_zip_refuses_what_is_not_a_zip() {
    assert!(read_zip(b"not a zip at all, just some bytes here").is_err());
    let mut zip = write_zip(&sample()).unwrap();
    // Corrupt the first entry's stored CRC in the central directory.
    let end = zip.len() - 22;
    let central = u32_at(&zip, end + 16) as usize;
    zip[central + 16] ^= 0xff;
    assert!(read_zip(&zip).unwrap_err().contains("CRC"));
}

#[test]
fn tar_gz_is_gnu_tar_in_whole_records() {
    let gz = write_tar_gz(&sample()).unwrap();
    // gzip: no name, mtime 0, XFL 2, OS 255.
    assert_eq!(&gz[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 0xff]);
    let tar = gunzip(&gz).unwrap();
    assert_eq!(tar.len() % 10240, 0);
    let h = &tar[..512];
    assert_eq!(&h[..5], b"a.txt");
    assert_eq!(&h[100..108], b"0000644\0");
    assert_eq!(&h[108..116], b"0000000\0");
    assert_eq!(&h[124..136], b"00000000027\0", "23 bytes, in octal");
    assert_eq!(&h[136..148], b"00000000000\0");
    assert_eq!(h[156], b'0');
    assert_eq!(&h[257..265], b"ustar  \0");
    assert!(
        h[265..].iter().all(|&b| b == 0),
        "uname, gname, device fields and prefix stay NUL"
    );
    // The checksum: six octal digits, NUL, space, over the header with spaces there.
    let mut blank = h.to_vec();
    blank[148..156].copy_from_slice(b"        ");
    let sum: u32 = blank.iter().map(|&b| u32::from(b)).sum();
    assert_eq!(&h[148..156], format!("{sum:06o}\0 ").as_bytes());
    assert_eq!(&tar[512..535], b"hello hello hello hello");
    // The next header starts on the next block.
    assert_eq!(&tar[1024..1029], b"b/run");
    assert_eq!(&tar[1024 + 100..1024 + 108], b"0000755\0");
}

#[test]
fn tar_refuses_names_that_need_a_long_name_record() {
    let mut e = Entries::new();
    e.insert("x".repeat(101), (0o644, Vec::new()));
    assert!(write_tar_gz(&e).is_err());
    let mut e = Entries::new();
    e.insert("x".repeat(100), (0o644, Vec::new()));
    assert!(write_tar_gz(&e).is_ok());
}
