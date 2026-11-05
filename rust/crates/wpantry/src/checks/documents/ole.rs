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
#[path = "ole_tests.rs"]
mod tests;
