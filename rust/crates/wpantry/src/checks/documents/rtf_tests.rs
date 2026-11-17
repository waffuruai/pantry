use crate::checks::documents::{ids, scan_bytes};

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
