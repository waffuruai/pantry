//! PDFs, read the way pdfid does: count the names that make a PDF do
//! things, outside its stream data and with `#xx` escapes decoded first (a
//! name written `/J#61vaScript` is hiding). Object streams are inflated so
//! a catalog hidden in one still counts. Nothing is rendered or run.

use super::deflate::inflate;
use super::{Doc, MAX_MEMBER, find, looks_like_text, push, rfind};

/// The `%PDF-` header has to be in the first KiB.
const HEADER_WINDOW: usize = 1024;
/// Data after the last `%%EOF` is a trailer worth a warning past this much.
const MAX_TRAILER: usize = 1024;
/// An inline `/OpenAction` dictionary is read up to here when unclosed.
const INLINE_DICT_WINDOW: usize = 400;
/// A referenced object without `endobj` is read up to here.
const OBJECT_WINDOW: usize = 4000;
/// Where an object's dictionary is looked for when its `obj` is missing.
const DICT_LOOKBACK: usize = 2048;

/// The names whose hex-escaped spelling is a PDF hiding what it does.
const ACTION_NAMES: &[&str] = &[
    "/JS",
    "/JavaScript",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/XFA",
    "/RichMedia",
    "/SubmitForm",
    "/GoToR",
    "/URI",
];

/// What a `.pdf`'s bytes say, when they are not a program.
pub(super) fn scan(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let head = &bytes[..bytes.len().min(HEADER_WINDOW)];
    if find(head, b"%PDF-").is_none() {
        let what = if bytes.starts_with(b"PK\x03\x04") {
            "a zip archive"
        } else if bytes.starts_with(b"{\\rt") {
            "an RTF document"
        } else if looks_like_text(bytes) && find(head, b"<").is_some() {
            "markup (HTML or XML)"
        } else {
            "something else"
        };
        push(out, file, "DOC-POLYGLOT", format!("no %PDF header in the first KiB: the file starts as {what}"), true);
        return;
    }
    let (decoded, escaped) = decode_names(&text_outside_streams(bytes));
    let count = |name: &[u8]| count_names(&decoded, name);
    let js = count(b"/JS") + count(b"/JavaScript");
    let open = count(b"/OpenAction") + count(b"/AA");
    let launch = count(b"/Launch");
    let embedded = count(b"/EmbeddedFile");
    let xfa = count(b"/XFA");
    let rich = count(b"/RichMedia");
    let submit = count(b"/SubmitForm") + count(b"/GoToR") + count(b"/ImportData");
    let objstm = count(b"/ObjStm");
    let hidden = if objstm > 0 { format!("; {objstm} object stream(s) inflated and read") } else { String::new() };
    if launch > 0 {
        push(
            out,
            file,
            "DOC-LAUNCH",
            format!("a /Launch action: the PDF asks the viewer to start a program{hidden}"),
            true,
        );
    }
    if !escaped.is_empty() {
        push(
            out,
            file,
            "DOC-OBFUSCATED",
            format!("action names written with hex escapes ({}): a PDF hiding what it does", escaped.join(", ")),
            true,
        );
    }
    if js > 0 && js_runs_on_open(&decoded) {
        push(
            out,
            file,
            "DOC-JS-ON-OPEN",
            format!(
                "JavaScript ({js}) wired to the open action or the document's name tree: it runs when the file is opened{hidden}"
            ),
            true,
        );
    } else if js > 0 {
        push(
            out,
            file,
            "DOC-JAVASCRIPT",
            format!(
                "JavaScript inside the PDF ({js} reference(s)){}: form-field scripts look like this, so do exploits{hidden}",
                if open > 0 { " beside an open action that doesn't run it" } else { "" }
            ),
            false,
        );
    }
    if embedded > 0 {
        push(out, file, "DOC-EMBEDDED", format!("{embedded} embedded file(s): a PDF carrying another file"), false);
    }
    if xfa > 0 || rich > 0 || submit > 0 {
        let mut what = Vec::new();
        if xfa > 0 {
            what.push("an XFA form");
        }
        if rich > 0 {
            what.push("rich media (Flash-era content)");
        }
        if submit > 0 {
            what.push("a submit, remote-goto or import action");
        }
        push(out, file, "DOC-FORM", format!("{}: active content older viewers mishandle", what.join(", ")), false);
    }
    if let Some(eof) = rfind(bytes, b"%%EOF") {
        let trailer = bytes.len().saturating_sub(eof + 5);
        if trailer > MAX_TRAILER {
            push(
                out,
                file,
                "DOC-TRAILER",
                format!("{} KiB after the last %%EOF: data the PDF reader never shows", trailer >> 10),
                false,
            );
        }
    }
}

/// Whether the PDF's JavaScript runs when the file opens: a document-level
/// script (`/JavaScript` as a key of the `/Names` tree, not the value of
/// `/S`), or an `/OpenAction` that is a JavaScript action, inline or by
/// reference. Field and page scripts (`/AA`, `/A` on an annotation) run on
/// events, and a form full of them is ordinary.
fn js_runs_on_open(text: &[u8]) -> bool {
    let mut from = 0;
    while let Some(i) = find(&text[from..], b"/JavaScript") {
        let at = from + i;
        from = at + 11;
        let is_name = text.get(at + 11).is_none_or(|c| !is_name_char(*c));
        let before: Vec<u8> =
            text[..at].iter().rev().skip_while(|c| c.is_ascii_whitespace()).take(2).copied().collect();
        if is_name && before != b"S/" {
            return true; // a key, as in `/Names << /JavaScript 7 0 R >>`
        }
    }
    from = 0;
    while let Some(i) = find(&text[from..], b"/OpenAction") {
        let at = from + i + 11;
        from = at;
        let rest = &text[at..];
        let rest = &rest[rest.iter().take_while(|c| c.is_ascii_whitespace()).count()..];
        if rest.starts_with(b"<<") {
            let end = find(rest, b">>").unwrap_or(rest.len().min(INLINE_DICT_WINDOW));
            if find(&rest[..end], b"/JavaScript").is_some() || count_names(&rest[..end], b"/JS") > 0 {
                return true;
            }
        } else if let Some(obj) = referenced_object(text, rest)
            && (find(obj, b"/JavaScript").is_some() || count_names(obj, b"/JS") > 0)
        {
            return true;
        }
    }
    false
}

/// The body of object `N` when `rest` starts with `N 0 R`, up to `endobj`.
fn referenced_object<'a>(text: &'a [u8], rest: &[u8]) -> Option<&'a [u8]> {
    let digits: Vec<u8> = rest.iter().take_while(|c| c.is_ascii_digit()).copied().collect();
    if digits.is_empty() {
        return None;
    }
    let needle = format!("{} 0 obj", String::from_utf8_lossy(&digits));
    let mut from = 0;
    while let Some(i) = find(&text[from..], needle.as_bytes()) {
        let at = from + i;
        from = at + needle.len();
        if at == 0 || !text[at - 1].is_ascii_digit() {
            let start = at + needle.len();
            let end =
                find(&text[start..], b"endobj").map(|e| start + e).unwrap_or((start + OBJECT_WINDOW).min(text.len()));
            return Some(&text[start..end]);
        }
    }
    None
}

/// The PDF outside its stream data, with object streams (`/ObjStm`,
/// FlateDecode) inflated and appended: dictionaries live there, and the
/// bytes of a compressed image don't get to spell `/JS` by chance.
fn text_outside_streams(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let Some(k) = find(&bytes[i..], b"stream") else {
            out.extend_from_slice(&bytes[i..]);
            break;
        };
        let at = i + k;
        if at >= 3 && &bytes[at - 3..at] == b"end" {
            // a stray "endstream": text, not a stream start
            out.extend_from_slice(&bytes[i..at + 6]);
            i = at + 6;
            continue;
        }
        out.extend_from_slice(&bytes[i..at]);
        let mut d = at + 6;
        if bytes.get(d) == Some(&b'\r') {
            d += 1;
        }
        if bytes.get(d) == Some(&b'\n') {
            d += 1;
        }
        let end = find(&bytes[d..], b"endstream").map(|e| d + e).unwrap_or(bytes.len());
        let dict_start = rfind(&out, b" obj").unwrap_or(out.len().saturating_sub(DICT_LOOKBACK));
        let object_stream = {
            let dict = &out[dict_start..];
            find(dict, b"/ObjStm").is_some() && find(dict, b"/FlateDecode").is_some()
        };
        if object_stream && let Some(inflated) = inflate(&bytes[d..end], MAX_MEMBER) {
            out.push(b'\n');
            out.extend_from_slice(&inflated);
            out.push(b'\n');
        }
        out.extend_from_slice(b"endstream");
        i = (end + 9).min(bytes.len());
    }
    out
}

/// The bytes with `/Na#6de` written as `/Name`, and the action names that
/// needed it.
fn decode_names(bytes: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut escaped = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' {
            let start = out.len();
            out.push(b);
            i += 1;
            let mut had_escape = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'#'
                    && i + 2 < bytes.len()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit()
                {
                    let v = (hex(bytes[i + 1]) << 4) | hex(bytes[i + 2]);
                    out.push(v);
                    had_escape = true;
                    i += 3;
                } else if is_name_char(c) {
                    out.push(c);
                    i += 1;
                } else {
                    break;
                }
            }
            if had_escape {
                let name = String::from_utf8_lossy(&out[start..]).into_owned();
                if ACTION_NAMES.contains(&name.as_str()) && !escaped.contains(&name) {
                    escaped.push(name);
                }
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    (out, escaped)
}

/// A byte that continues a PDF name (anything else is a delimiter).
fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'
}

fn hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Occurrences of a PDF name followed by a delimiter (so `/JS` doesn't
/// count `/JScript`).
fn count_names(hay: &[u8], name: &[u8]) -> usize {
    let mut n = 0;
    let mut from = 0;
    while let Some(i) = find(&hay[from..], name) {
        let at = from + i;
        if hay.get(at + name.len()).is_none_or(|c| !is_name_char(*c)) {
            n += 1;
        }
        from = at + name.len();
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::{ids, scan_bytes};

    #[test]
    fn an_open_action_alone_is_a_page_to_open_at() {
        let plain = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj\n%%EOF\n";
        assert!(scan_bytes("a.pdf", plain).is_empty());
    }

    #[test]
    fn javascript_fails_on_open_and_warns_elsewhere() {
        let js =
            b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", js)), [("DOC-JS-ON-OPEN", true)]);
        let js_only = b"%PDF-1.7\n1 0 obj << /Type /Annot /A << /S /JavaScript /JS (calc()) >> >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", js_only)), [("DOC-JAVASCRIPT", false)]);
        // A fillable worksheet: field scripts and a go-to-page open action. Not on open.
        let form = b"%PDF-1.6\n1 0 obj << /Type /Catalog /OpenAction 3 0 R /AcroForm 4 0 R >> endobj\n3 0 obj << /S /GoTo /D [5 0 R /Fit] >> endobj\n6 0 obj << /FT /Tx /AA << /F << /S /JavaScript /JS (AFNumber_Format(2)) >> /K << /S /JavaScript /JS (AFNumber_Keystroke(2)) >> >> >> endobj\n%%EOF";
        let got = scan_bytes("worksheet.pdf", form);
        assert_eq!(ids(&got), [("DOC-JAVASCRIPT", false)], "{got:?}");
        assert!(got[0].note.contains("doesn't run it"), "{}", got[0].note);
        let tree = b"%PDF-1.6\n1 0 obj << /Type /Catalog /Names << /JavaScript 7 0 R >> /OpenAction 3 0 R >> endobj\n7 0 obj << /Names [(init) 8 0 R] >> endobj\n8 0 obj << /S /JavaScript /JS (this.print()) >> endobj\n%%EOF";
        assert_eq!(
            ids(&scan_bytes("tree.pdf", tree)),
            [("DOC-JS-ON-OPEN", true)],
            "a document-level script runs at open"
        );
        let by_ref = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 12 0 R >> endobj\n2 0 obj << /S /GoTo >> endobj\n12 0 obj << /S /JavaScript /JS (x()) >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("ref.pdf", by_ref)), [("DOC-JS-ON-OPEN", true)], "an open action by reference");
    }

    #[test]
    fn launch_and_escaped_names_fail() {
        let launch = b"%PDF-1.7\n1 0 obj << /S /Launch /F (cmd.exe) >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", launch)), [("DOC-LAUNCH", true)]);
        let escaped = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /J#53 (x) >> endobj\n%%EOF";
        let got = scan_bytes("a.pdf", escaped);
        assert!(ids(&got).contains(&("DOC-OBFUSCATED", true)), "{got:?}");
        assert!(
            ids(&got).contains(&("DOC-JS-ON-OPEN", true)),
            "decoded names still count, through the reference: {got:?}"
        );
        let harmless = b"%PDF-1.7\n1 0 obj << /T#79pe /Catalog >> endobj\n%%EOF";
        assert!(scan_bytes("a.pdf", harmless).is_empty(), "an escape in a name that does nothing");
    }

    #[test]
    fn embedded_files_forms_and_trailers_warn() {
        let embedded = b"%PDF-1.7\n1 0 obj << /Type /Filespec /EF << /F 2 0 R >> >> endobj\n2 0 obj << /Type /EmbeddedFile >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", embedded)), [("DOC-EMBEDDED", false)]);
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
}
