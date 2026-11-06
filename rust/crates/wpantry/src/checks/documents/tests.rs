use super::*;

#[test]
fn wanted_goes_by_extension_in_any_case() {
    assert!(wanted("Report.PDF"));
    assert!(wanted("deck.pptx"));
    assert!(wanted("logo.SVG"));
    assert!(!wanted("notes.md"));
    assert!(!wanted("Makefile"));
    assert!(!wanted("archive.pdf.zip"));
}

#[test]
fn a_program_wearing_a_documents_name_fails_whatever_the_name() {
    let heads: [(&[u8], &str); 4] = [
        (b"MZ\x90\x00abc", "MZ"),
        (b"\x7fELF\x02\x01", "ELF"),
        (b"\xcf\xfa\xed\xfe\x07", "Mach-O"),
        (b"#!/bin/sh\n", "shebang"),
    ];
    for (bytes, what) in heads {
        for name in ["invoice.pdf", "a.png", "old.doc", "letter.docx", "x.rtf", "logo.svg"] {
            let got = scan_bytes(name, bytes);
            assert_eq!(ids(&got), [("DISGUISED-PROGRAM", true)], "{name} {what}: {got:?}");
            assert!(got[0].note.contains(what), "{}", got[0].note);
        }
    }
    assert!(scan_bytes("x.pdf", b"MZ").is_empty(), "under four bytes there is nothing to read");
    assert_eq!(
        ids(&scan_bytes("x.txt", b"MZ\x90\x00abc")),
        [("DISGUISED-PROGRAM", true)],
        "the walker filters names; the bytes are read for whatever name is given"
    );
}

#[test]
fn dispatch_follows_the_bytes_not_the_name() {
    let mut cfb = ole::CFB.to_vec();
    cfb.extend_from_slice(&[0u8; 64]);
    cfb.extend(ole::utf16("_VBA_PROJECT"));
    assert_eq!(ids(&scan_bytes("old.docx", &cfb)), [("DOC-MACRO", true)], "a compound file named .docx");
    assert_eq!(ids(&scan_bytes("old.rtf", &cfb)), [("DOC-MACRO", true)], "a compound file named .rtf");
    let zipped = zip::stored(&[("xl/macrosheets/sheet1.xml", b"<macrosheet/>")]);
    assert_eq!(ids(&scan_bytes("book.xls", &zipped)), [("DOC-XL4-MACRO", true)], "a zip named .xls");
    assert_eq!(ids(&scan_bytes("book.rtf", &zipped)), [("DOC-XL4-MACRO", true)], "a zip named .rtf");
    let rtf = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}}}";
    assert_eq!(ids(&scan_bytes("letter.docx", rtf)), [("DOC-RTF-OBJECT", true)], "RTF named .docx");
    assert_eq!(ids(&scan_bytes("letter.doc", rtf)), [("DOC-RTF-OBJECT", true)], "RTF named .doc");
    let text = b"not a zip at all, just text";
    assert_eq!(ids(&scan_bytes("letter.docx", text)), [("DOC-UNREADABLE", false)]);
    let got = scan_bytes("letter.doc", text);
    assert_eq!(ids(&got), [("DOC-UNREADABLE", false)]);
    assert!(got[0].note.contains("a text file"), "{}", got[0].note);
    assert!(scan_bytes("letter.doc", &[0u8, 1, 2, 3, 0xff, 0xfe]).is_empty(), "unknown binary named .doc");
    assert!(scan_bytes("x.rtf", text).is_empty(), "text named .rtf is read as nothing");
}

#[test]
fn walks_and_skips_output_dirs() {
    let d = crate::utils::temp::TempDir::new("documents").unwrap();
    std::fs::create_dir_all(d.path().join("node_modules/x")).unwrap();
    std::fs::create_dir_all(d.path().join("docs")).unwrap();
    std::fs::write(d.path().join("node_modules/x/a.pdf"), b"MZ\x90\x00").unwrap();
    std::fs::write(d.path().join("docs/a.pdf"), b"%PDF-1.4\n<< /S /Launch >>\n%%EOF").unwrap();
    std::fs::write(
        d.path().join("docs/ok.png"),
        [0x89, b'P', b'N', b'G', 0, 0, 0, 0, b'I', b'E', b'N', b'D', 0, 0, 0, 0],
    )
    .unwrap();
    std::fs::write(d.path().join("notes.md"), "MZ not a document").unwrap();
    let got = scan_dir(d.path(), 6);
    assert_eq!(ids(&got), [("DOC-LAUNCH", true)], "{got:?}");
    assert_eq!(got[0].file, "docs/a.pdf");
    assert_eq!(files_under(d.path(), 6).len(), 2);
}

#[test]
fn files_over_the_size_limit_are_named_not_read() {
    let d = crate::utils::temp::TempDir::new("documents-big").unwrap();
    // A sparse file: the size is what matters, and nothing reads it.
    let big = std::fs::File::create(d.path().join("big.pdf")).unwrap();
    big.set_len(MAX_FILE + 1).unwrap();
    std::fs::write(d.path().join("small.pdf"), b"%PDF-1.4\n%%EOF\n").unwrap();
    let got = scan_dir(d.path(), 1);
    assert_eq!(ids(&got), [("DOC-UNREADABLE", false)], "{got:?}");
    assert_eq!(got[0].file, "big.pdf");
    assert!(got[0].note.contains("1 file(s), 32 MiB"), "{}", got[0].note);
    assert!(got[0].note.contains("big.pdf"), "{}", got[0].note);
}

#[test]
fn byte_helpers() {
    assert_eq!(find(b"abcabc", b"ca"), Some(2));
    assert_eq!(find(b"ab", b"abc"), None, "a needle longer than the hay");
    assert_eq!(find(b"abc", b""), None, "an empty needle matches nothing");
    assert_eq!(find_ci(b"<HTML>", b"<html"), Some(0));
    assert!(looks_like_text(b"plain words\n"));
    assert!(!looks_like_text(b"\x00\x01binary"));
    assert_eq!(program_header(b"PK\x03\x04"), None);
}
