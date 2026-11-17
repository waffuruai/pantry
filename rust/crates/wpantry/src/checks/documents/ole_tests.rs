use super::*;
use crate::checks::documents::{ids, scan_bytes};

/// A compound file header, padding, and these directory names.
fn cfb(names: &[&str]) -> Vec<u8> {
    let mut out = CFB.to_vec();
    out.extend_from_slice(&[0u8; 64]);
    for n in names {
        out.extend(utf16(n));
        out.extend_from_slice(&[0, 0]);
    }
    out
}

#[test]
fn a_plain_compound_file_is_nothing() {
    assert!(scan_bytes("old.doc", &cfb(&["Root Entry", "WordDocument", "1Table"])).is_empty());
    assert!(scan_bytes("old.xls", &cfb(&["Workbook"])).is_empty());
}

#[test]
fn macros_warn_in_a_legacy_name_and_fail_in_a_modern_one() {
    let legacy = cfb(&["_VBA_PROJECT"]);
    assert_eq!(ids(&scan_bytes("old.doc", &legacy)), [("DOC-MACRO", false)]);
    assert_eq!(ids(&scan_bytes("old.ppt", &cfb(&["Macros"]))), [("DOC-MACRO", false)]);
    assert_eq!(ids(&scan_bytes("old.xls", &cfb(&["ThisWorkbook"]))), [("DOC-MACRO", false)]);
    assert_eq!(ids(&scan_bytes("old.docx", &legacy)), [("DOC-MACRO", true)], "a legacy file named .docx with macros");
    let got = scan_bytes("old.doc", &legacy);
    assert!(got[0].note.contains("legacy .doc"), "{}", got[0].note);
}

#[test]
fn objects_dde_and_remote_content() {
    assert_eq!(ids(&scan_bytes("old.doc", &cfb(&["\u{1}Ole10Native"]))), [("DOC-OLE-OBJECT", false)]);
    assert_eq!(ids(&scan_bytes("old.doc", &cfb(&["Package"]))), [("DOC-OLE-OBJECT", false)]);
    let mut dde = cfb(&["WordDocument"]);
    dde.extend_from_slice(b"DDEAUTO c:\\windows\\system32\\cmd.exe");
    assert_eq!(ids(&scan_bytes("old.doc", &dde)), [("DOC-DDE", true)], "an ASCII field");
    assert_eq!(ids(&scan_bytes("old.doc", &cfb(&["DDEAUTO"]))), [("DOC-DDE", true)], "a UTF-16 field");
    assert_eq!(
        ids(&scan_bytes("old.doc", &cfb(&["MsoDataStore", "http://evil.example/x"]))),
        [("DOC-REMOTE-CONTENT", false)]
    );
    assert!(scan_bytes("old.doc", &cfb(&["MsoDataStore"])).is_empty(), "a data store without a URL");
}

#[test]
fn utf16_is_little_endian() {
    assert_eq!(utf16("VBA"), [b'V', 0, b'B', 0, b'A', 0]);
}
