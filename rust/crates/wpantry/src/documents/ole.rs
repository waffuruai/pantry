//! Legacy binary Office files (`.doc`, `.xls`, `.ppt`): an OLE compound
//! file whose directory names are UTF-16 in the file, so macros, embedded
//! objects, DDE fields and remote content show without walking the FAT.

use super::{Doc, find, push};

/// The compound file header, `D0 CF 11 E0 A1 B1 1A E1`.
pub(super) const CFB: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The legacy extensions, where macros are expected and warn rather than
/// fail.
const LEGACY_EXTS: &[&str] = &["doc", "dot", "xls", "xlt", "ppt", "pot"];

/// A directory name as the file spells it: UTF-16, little-endian.
pub(super) fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A compound file (`.doc`, `.xls`, `.ppt`): the directory names are UTF-16
/// in the file, so macros and objects show without walking the FAT.
pub(super) fn scan(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let has = |s: &str| find(bytes, &utf16(s)).is_some();
    let macros = has("_VBA_PROJECT") || has("VBA") || has("Macros") || has("ThisDocument") || has("ThisWorkbook");
    if macros {
        push(
            out,
            file,
            "DOC-MACRO",
            format!(
                "VBA macros in a legacy .{ext}: code that runs when macros are enabled; the format can't be read further here"
            ),
            !LEGACY_EXTS.contains(&ext),
        );
    }
    if has("\u{1}Ole10Native") || has("\u{1}Ole") || has("Package") {
        push(out, file, "DOC-OLE-OBJECT", "embedded OLE object(s): another file or program packaged inside", false);
    }
    if find(bytes, b"DDEAUTO").is_some() || find(bytes, &utf16("DDEAUTO")).is_some() {
        push(
            out,
            file,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens",
            true,
        );
    }
    if has("MsoDataStore") && has("http://") {
        push(out, file, "DOC-REMOTE-CONTENT", "content loaded from a remote host when the document opens", false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::{ids, scan_bytes};

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
        assert_eq!(
            ids(&scan_bytes("old.docx", &legacy)),
            [("DOC-MACRO", true)],
            "a legacy file named .docx with macros"
        );
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
}
