//! RTF: embedded objects are the vector (the equation editor,
//! CVE-2017-11882, came this way), and a malformed header is the evasion
//! that goes with it. The control words are read lowercased, up to the
//! member cap.

use super::{Doc, MAX_MEMBER, find, push};

pub(super) fn scan(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let lower: Vec<u8> = bytes.iter().take(MAX_MEMBER).map(|b| b.to_ascii_lowercase()).collect();
    if !lower.starts_with(b"{\\rtf1") {
        push(
            out,
            file,
            "DOC-OBFUSCATED",
            "a malformed RTF header (not `{\\rtf1`): Word accepts it, scanners that key on the header don't",
            true,
        );
    }
    let has = |s: &[u8]| find(&lower, s).is_some();
    if has(b"\\objupdate") || has(b"\\objautlink") || has(b"equation.3") || has(b"equation.2") {
        push(
            out,
            file,
            "DOC-RTF-OBJECT",
            "an embedded object set to update itself on open (or an Equation Editor object): the RTF exploit shape",
            true,
        );
    } else if has(b"\\objdata") || has(b"\\objemb") || has(b"\\objclass") {
        push(
            out,
            file,
            "DOC-RTF-OBJECT",
            "an embedded OLE object (\\objdata): another file or program packaged inside",
            true,
        );
    }
    if has(b"ddeauto") || has(b"\\fldinst") && has(b" dde ") {
        push(
            out,
            file,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens",
            true,
        );
    }
    if has(b"\\pict") && has(b"\\objdata") && has(b"\\bin") {
        push(
            out,
            file,
            "DOC-OBFUSCATED",
            "binary data spliced into the object stream (\\bin): a known parser-confusion trick",
            true,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::documents::{ids, scan_bytes};

    #[test]
    fn plain_rtf_is_nothing() {
        assert!(scan_bytes("x.rtf", b"{\\rtf1\\ansi hello world}").is_empty());
        assert!(scan_bytes("x.rtf", b"{\\RTF1\\ansi upper case too}").is_empty());
    }

    #[test]
    fn embedded_objects_fail() {
        let equation = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}";
        let got = scan_bytes("x.rtf", equation);
        assert_eq!(ids(&got), [("DOC-RTF-OBJECT", true)]);
        assert!(got[0].note.contains("Equation Editor"), "{}", got[0].note);
        let autolink = b"{\\rtf1{\\object\\objautlink\\objupdate{\\*\\objdata 00}}}";
        assert!(scan_bytes("x.rtf", autolink)[0].note.contains("update itself on open"));
        let plain_object = b"{\\rtf1{\\object\\objemb{\\*\\objdata 0105000002}}}";
        let got = scan_bytes("x.rtf", plain_object);
        assert_eq!(ids(&got), [("DOC-RTF-OBJECT", true)]);
        assert!(got[0].note.contains("\\objdata"), "{}", got[0].note);
    }

    #[test]
    fn a_malformed_header_and_a_bin_splice_are_obfuscation() {
        assert_eq!(ids(&scan_bytes("x.rtf", b"{\\rtx\\ansi hello}")), [("DOC-OBFUSCATED", true)]);
        let bin = b"{\\rtf1{\\pict\\bin5 xxxxx}{\\object{\\*\\objdata 00}}}";
        let got = scan_bytes("x.rtf", bin);
        assert_eq!(ids(&got), [("DOC-RTF-OBJECT", true), ("DOC-OBFUSCATED", true)], "{got:?}");
        assert!(got[1].note.contains("\\bin"), "{}", got[1].note);
    }

    #[test]
    fn dde_fields_fail() {
        assert_eq!(ids(&scan_bytes("x.rtf", b"{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd}}}")), [("DOC-DDE", true)]);
        assert_eq!(
            ids(&scan_bytes("x.rtf", b"{\\rtf1{\\field{\\*\\fldinst { DDE cmd \"/c calc\" }}}}")),
            [("DOC-DDE", true)]
        );
        assert!(scan_bytes("x.rtf", b"{\\rtf1{\\field{\\*\\fldinst PAGE}}}").is_empty(), "an ordinary field");
    }
}
