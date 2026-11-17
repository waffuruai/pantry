//! PDFs, read the way pdfid does: count the names that make a PDF do
//! things, outside its stream data and with `#xx` escapes decoded first (a
//! name written `/J#61vaScript` is hiding). Object streams are inflated so
//! a catalog hidden in one still counts. A script that runs when the file
//! opens is read (a literal, hex or UTF-16 string, or a stream, inflated)
//! and quoted, so the finding says what it does: one that reaches outside
//! the document fails, one that prints or pops up a menu warns, an empty
//! one is nothing. Embedded files are named. Nothing is rendered or run.

use super::{Doc, MAX_MEMBER, find, looks_like_text, push, rfind};
use crate::utils::archive::deflate::inflate;

/// The `%PDF-` header has to be in the first KiB.
const HEADER_WINDOW: usize = 1024;
/// Data after the last `%%EOF` is a trailer worth a warning past this much.
const MAX_TRAILER: usize = 1024;
/// A referenced object without `endobj` is read up to here.
const OBJECT_WINDOW: usize = 4000;
/// Where an object's dictionary is looked for when its `obj` is missing.
const DICT_LOOKBACK: usize = 2048;
/// The most of a script read, inflated or not.
const MAX_SCRIPT: usize = 256 << 10;
/// Scripts that run on open are followed up to this many; file
/// specifications are read up to this many.
const MAX_ACTIONS: usize = 8;
const MAX_FILESPECS: usize = 16;
/// How much of a script's first line the finding quotes.
const QUOTE_LEN: usize = 80;

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
    let actions = if js > 0 { open_actions(&decoded) } else { Vec::new() };
    if !actions.is_empty() {
        let scripts: Vec<Option<String>> =
            actions.iter().map(|a| a.and_then(|a| js_value(bytes, &decoded, a)).map(|v| text_of(&v))).collect();
        grade_open_scripts(file, &scripts, count(b"/JS"), &hidden, out);
    } else if js > 0 {
        let quoted = find_name(&decoded, b"/JS")
            .and_then(|at| js_value(bytes, &decoded, &decoded[at..]))
            .map(|v| quote(&text_of(&v)))
            .filter(|q| !q.is_empty())
            .map(|q| format!("; the first reads `{q}`"))
            .unwrap_or_default();
        push(
            out,
            file,
            "DOC-JAVASCRIPT",
            format!(
                "JavaScript inside the PDF ({js} reference(s)){}: form-field scripts look like this, so do exploits{hidden}{quoted}",
                if open > 0 { " beside an open action that doesn't run it" } else { "" }
            ),
            false,
        );
    }
    if embedded > 0 {
        let names = embedded_names(&decoded);
        let named = if names.is_empty() {
            " (name not found)".to_string()
        } else {
            format!(" ({}{})", names.join(", "), if embedded > names.len() { ", …" } else { "" })
        };
        push(
            out,
            file,
            "DOC-EMBEDDED",
            format!("{embedded} embedded file(s){named}: a PDF carrying another file"),
            false,
        );
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

/// The JavaScript actions that run when the file opens: the entries of
/// the document-level name tree (`/JavaScript` as a key of `/Names`, not
/// the value of `/S`; one level of `/Kids` followed) and an `/OpenAction`
/// that is a JavaScript action, inline or by reference. Field and page
/// scripts (`/AA`, `/A` on an annotation) run on events, and a form full
/// of them is ordinary. `None` is an action that is there but whose
/// object couldn't be found: not nothing. At most `MAX_ACTIONS`.
fn open_actions(text: &[u8]) -> Vec<Option<&[u8]>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = find(&text[from..], b"/JavaScript") {
        let at = from + i;
        from = at + 11;
        let is_name = text.get(at + 11).is_none_or(|c| !is_name_char(*c));
        let before: Vec<u8> =
            text[..at].iter().rev().skip_while(|c| c.is_ascii_whitespace()).take(2).copied().collect();
        if !is_name || before == b"S/" {
            continue;
        }
        // A key, as in `/Names << /JavaScript 7 0 R >>`: its value is the tree.
        match value_dict(text, &text[at + 11..]) {
            Some(tree) => tree_actions(text, tree, &mut out, true),
            None => out.push(None),
        }
        if out.len() >= MAX_ACTIONS {
            break;
        }
    }
    from = 0;
    while let Some(i) = find(&text[from..], b"/OpenAction") {
        let at = from + i + 11;
        from = at;
        if let Some(action) = value_dict(text, &text[at..])
            && is_js_action(action)
        {
            out.push(Some(action));
        }
        if out.len() >= MAX_ACTIONS {
            break;
        }
    }
    // A page's `/AA << /O … >>` (and an annotation's `/PO`) fires when the
    // page is shown: for the first page, that is when the file opens.
    from = 0;
    while let Some(i) = find_name(&text[from..], b"/AA") {
        let at = from + i + 3;
        from = at;
        if let Some(aa) = value_dict(text, &text[at..]) {
            for key in [&b"/O"[..], b"/PO"] {
                if let Some(k) = find_name(aa, key)
                    && let Some(action) = value_dict(text, &aa[k + key.len()..])
                    && is_js_action(action)
                {
                    out.push(Some(action));
                }
            }
        }
        if out.len() >= MAX_ACTIONS {
            break;
        }
    }
    out.truncate(MAX_ACTIONS);
    out
}

/// An action dictionary that is a JavaScript action.
fn is_js_action(action: &[u8]) -> bool {
    find(action, b"/JavaScript").is_some() || count_names(action, b"/JS") > 0
}

/// The actions a name tree holds: every reference or inline dictionary in
/// its `/Names` array, and one level of `/Kids`.
fn tree_actions<'a>(text: &'a [u8], tree: &'a [u8], out: &mut Vec<Option<&'a [u8]>>, follow_kids: bool) {
    if let Some(i) = find_name(tree, b"/Names") {
        array_entries(text, array_at(&tree[i + 6..]), out);
    }
    if follow_kids && let Some(i) = find_name(tree, b"/Kids") {
        let mut kids = Vec::new();
        array_entries(text, array_at(&tree[i + 5..]), &mut kids);
        for kid in kids {
            match kid {
                Some(kid) => tree_actions(text, kid, out, false),
                None => out.push(None),
            }
            if out.len() >= MAX_ACTIONS {
                return;
            }
        }
    }
}

/// The dictionaries an array holds, inline or by reference, strings skipped.
fn array_entries<'a>(text: &'a [u8], arr: &'a [u8], out: &mut Vec<Option<&'a [u8]>>) {
    let mut i = 0;
    while i < arr.len() && out.len() < MAX_ACTIONS {
        match arr[i] {
            b'(' => i += literal_len(&arr[i..]),
            b'<' if arr.get(i + 1) == Some(&b'<') => {
                let d = dict_at(&arr[i..]);
                out.push(Some(d));
                i += d.len().max(2);
            }
            b'0'..=b'9' if i == 0 || !is_name_char(arr[i - 1]) => {
                if is_reference(&arr[i..]) {
                    out.push(referenced_object(text, &arr[i..]));
                }
                i += arr[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            }
            _ => i += 1,
        }
    }
}

/// The dictionary a value is: inline (`<< … >>`) or the object a
/// reference points at. A bare object number is followed too (TCPDF writes
/// `/Names << /JavaScript 15 >>`, no `0 R`; a viewer that is as lenient
/// runs what it finds there). `None` for anything else, or a reference to
/// an object that isn't there.
fn value_dict<'a>(text: &'a [u8], rest: &'a [u8]) -> Option<&'a [u8]> {
    let rest = skip_ws(rest);
    if rest.starts_with(b"<<") {
        Some(dict_at(rest))
    } else if is_reference(rest) || bare_number(rest) {
        referenced_object(text, rest)
    } else {
        None
    }
}

/// `rest` starts with an integer and then a delimiter: an object number
/// written without its `0 R`.
fn bare_number(rest: &[u8]) -> bool {
    let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    digits > 0 && rest.get(digits).is_none_or(|c| !is_name_char(*c))
}

/// `rest` starts with an indirect reference, `N G R`.
fn is_reference(rest: &[u8]) -> bool {
    let mut i = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    if i == 0 {
        return false;
    }
    let ws = rest[i..].iter().take_while(|c| c.is_ascii_whitespace()).count();
    i += ws;
    let generation = rest[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if ws == 0 || generation == 0 {
        return false;
    }
    i += generation;
    let ws = rest[i..].iter().take_while(|c| c.is_ascii_whitespace()).count();
    i += ws;
    ws > 0 && rest.get(i) == Some(&b'R') && rest.get(i + 1).is_none_or(|c| !is_name_char(*c))
}

fn skip_ws(s: &[u8]) -> &[u8] {
    &s[s.iter().take_while(|c| c.is_ascii_whitespace()).count()..]
}

/// `s` from its leading `<<` to the matching `>>`, nesting counted, or up
/// to `OBJECT_WINDOW` when unclosed.
fn dict_at(s: &[u8]) -> &[u8] {
    let mut depth = 0usize;
    let mut i = 0;
    let end = s.len().min(OBJECT_WINDOW);
    while i < end {
        if s[i..].starts_with(b"<<") {
            depth += 1;
            i += 2;
        } else if s[i..].starts_with(b">>") {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                return &s[..i];
            }
        } else if s[i] == b'(' {
            i += literal_len(&s[i..]);
        } else {
            i += 1;
        }
    }
    &s[..end]
}

/// The array that starts `s` (after whitespace), `[` to its matching `]`;
/// empty when there is none.
fn array_at(s: &[u8]) -> &[u8] {
    let s = skip_ws(s);
    if !s.starts_with(b"[") {
        return &[];
    }
    let mut depth = 0usize;
    let mut i = 0;
    let end = s.len().min(OBJECT_WINDOW);
    while i < end {
        match s[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return &s[1..i];
                }
            }
            b'(' => {
                i += literal_len(&s[i..]);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    &s[1..end]
}

/// The first occurrence of a PDF name followed by a delimiter.
fn find_name(hay: &[u8], name: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = find(&hay[from..], name) {
        let at = from + i;
        if hay.get(at + name.len()).is_none_or(|c| !is_name_char(*c)) {
            return Some(at);
        }
        from = at + name.len();
    }
    None
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

// --- What a script says ----------------------------------------------------

/// The `/JS` value of an action dictionary, as bytes: a literal string with
/// its escapes undone, a hex string decoded, or the object a reference
/// points at (a string, or a stream read from `raw`, inflated when it is
/// FlateDecode). `None` when it can't be read, which is not the same as
/// empty.
fn js_value(raw: &[u8], text: &[u8], dict: &[u8]) -> Option<Vec<u8>> {
    let at = find_name(dict, b"/JS")?;
    let rest = skip_ws(&dict[at + 3..]);
    if let Some(s) = string_at(rest) {
        return Some(s);
    }
    if !is_reference(rest) {
        return None;
    }
    if let Some(obj) = referenced_object(text, rest)
        && let Some(s) = string_at(skip_ws(obj))
    {
        return Some(s);
    }
    stream_data(raw, rest)
}

/// The string `rest` starts with, `(…)` or `<hex>`, decoded; `None` when
/// it starts with something else.
fn string_at(rest: &[u8]) -> Option<Vec<u8>> {
    match rest.first()? {
        b'(' => Some(literal_string(rest)),
        b'<' if rest.get(1) != Some(&b'<') => Some(hex_string(rest)),
        _ => None,
    }
}

/// The first string value of `key` in `dict`: a reference or a dictionary
/// under the same key is skipped (`/EF << /F 5 0 R >>` beside `/F (name)`).
fn string_value(dict: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut from = 0;
    while let Some(i) = find_name(&dict[from..], key) {
        let at = from + i + key.len();
        from = at;
        if let Some(s) = string_at(skip_ws(&dict[at..])) {
            return Some(s);
        }
    }
    None
}

/// The length of the literal string `s` starts with, parens and all:
/// nesting balanced, escapes skipped, the whole of `s` when unclosed.
fn literal_len(s: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s.len()
}

/// The bytes of the literal string `s` starts with, escapes undone (`\n`,
/// `\(`, `\\`, octal `\ddd`, a backslash-newline continuation), at most
/// `MAX_SCRIPT` of them.
fn literal_string(s: &[u8]) -> Vec<u8> {
    let body = &s[1..literal_len(s).saturating_sub(1).max(1)];
    let mut out = Vec::with_capacity(body.len().min(MAX_SCRIPT));
    let mut i = 0;
    while i < body.len() && out.len() < MAX_SCRIPT {
        let c = body[i];
        i += 1;
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let Some(&e) = body.get(i) else { break };
        i += 1;
        match e {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'\n' => {}
            b'\r' => {
                if body.get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'0'..=b'7' => {
                let mut v = (e - b'0') as u32;
                for _ in 0..2 {
                    match body.get(i) {
                        Some(d @ b'0'..=b'7') => {
                            v = (v << 3) | (d - b'0') as u32;
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push(v as u8);
            }
            other => out.push(other),
        }
    }
    out
}

/// The bytes of the hex string `s` starts with (`<48656C6C6F>`), whitespace
/// ignored, an odd last digit padded, at most `MAX_SCRIPT` of them.
fn hex_string(s: &[u8]) -> Vec<u8> {
    let end = find(s, b">").unwrap_or(s.len());
    let digits: Vec<u8> = s[1..end].iter().filter(|c| c.is_ascii_hexdigit()).take(MAX_SCRIPT * 2).copied().collect();
    digits.chunks(2).map(|pair| (hex(pair[0]) << 4) | pair.get(1).map(|d| hex(*d)).unwrap_or(0)).collect()
}

/// The data of stream object `N` in the raw file when `rest` starts with
/// `N 0 R`: inflated when its filter is FlateDecode, as is when it has no
/// filter, `None` for any other filter or a missing object.
fn stream_data(raw: &[u8], rest: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = rest.iter().take_while(|c| c.is_ascii_digit()).copied().collect();
    let needle = format!("{} 0 obj", String::from_utf8_lossy(&digits));
    let mut from = 0;
    while let Some(i) = find(&raw[from..], needle.as_bytes()) {
        let at = from + i;
        from = at + needle.len();
        if at > 0 && raw[at - 1].is_ascii_digit() {
            continue;
        }
        let start = at + needle.len();
        let window = &raw[start..(start + OBJECT_WINDOW).min(raw.len())];
        let stream_at = find(window, b"stream")?;
        if find(&window[..stream_at], b"endobj").is_some() {
            return None;
        }
        let dict = &window[..stream_at];
        let mut d = start + stream_at + 6;
        if raw.get(d) == Some(&b'\r') {
            d += 1;
        }
        if raw.get(d) == Some(&b'\n') {
            d += 1;
        }
        let end = find(&raw[d..], b"endstream").map(|e| d + e).unwrap_or(raw.len());
        let data = &raw[d..end];
        return if find(dict, b"/FlateDecode").is_some() {
            inflate_stream(data, MAX_SCRIPT)
        } else if find(dict, b"/Filter").is_some() {
            None
        } else {
            Some(data[..data.len().min(MAX_SCRIPT)].to_vec())
        };
    }
    None
}

/// A PDF text string as text: UTF-16 with a byte-order mark either way
/// round, UTF-8 with or without one, or bytes taken as they are.
fn text_of(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units = bytes[2..].chunks(2).map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]));
        char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..].chunks(2).map(|p| u16::from_le_bytes([p[0], *p.get(1).unwrap_or(&0)]));
        char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    } else {
        String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).into_owned()
    }
}

/// The first line of a script with something on it, whitespace collapsed,
/// about `QUOTE_LEN` characters: enough to recognize it.
fn quote(script: &str) -> String {
    let line = script.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    let one: String = line.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut q: String = one.chars().filter(|c| !c.is_control()).take(QUOTE_LEN).collect();
    if one.chars().count() > QUOTE_LEN {
        q.push('…');
    }
    q
}

/// The calls that take a script outside the document: a URL, a server, a
/// mail client, the disk, another document, the exploit-era objects. Bare
/// method names, so `app['launchURL']` counts too.
const REACHES_OUT: &[(&str, &str)] = &[
    ("launchURL", "opens a URL (app.launchURL)"),
    ("submitForm", "sends form data to a server (submitForm)"),
    ("exportDataObject", "writes an embedded file to disk (exportDataObject)"),
    ("openDoc", "opens another document (app.openDoc)"),
    ("getURL", "fetches a URL (getURL)"),
    ("Net.HTTP", "makes HTTP requests (Net.HTTP)"),
    ("mailMsg", "sends mail (app.mailMsg)"),
    ("Collab.", "calls the Collab object, an exploit's usual door"),
    ("util.printf", "calls util.printf, the CVE-2008-2992 overflow"),
];
/// A decoder (`eval`, `unescape`, `String.fromCharCode`) over this many
/// `%u`, `\x` or `\u` escapes, or a hex run this long, is a payload.
const ESCAPES_IN_A_PAYLOAD: usize = 16;
const HEX_RUN_IN_A_PAYLOAD: usize = 200;

/// Why a script reaches outside the document, when it does.
fn reaches_out(script: &str) -> Option<&'static str> {
    if let Some((_, why)) = REACHES_OUT.iter().find(|(call, _)| script.contains(call)) {
        return Some(why);
    }
    let decodes = ["eval(", "unescape(", "fromCharCode("].iter().any(|d| script.contains(d));
    if !decodes {
        return None;
    }
    let escapes = script.matches("%u").count() + script.matches("\\x").count() + script.matches("\\u").count();
    let mut hex_run = 0usize;
    let mut longest = 0usize;
    for c in script.chars() {
        hex_run = if c.is_ascii_hexdigit() { hex_run + 1 } else { 0 };
        longest = longest.max(hex_run);
    }
    (escapes >= ESCAPES_IN_A_PAYLOAD || longest >= HEX_RUN_IN_A_PAYLOAD)
        .then_some("decodes a long escaped payload with eval, unescape or String.fromCharCode")
}

/// The script with its string literals emptied and its comments removed,
/// so braces and keywords in them don't count.
fn code_only(script: &str) -> String {
    let cs: Vec<char> = script.chars().collect();
    let mut out = String::with_capacity(cs.len());
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c == '"' || c == '\'' || c == '`' {
            i += 1;
            while i < cs.len() && cs[i] != c {
                i += if cs[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.push_str("\"\"");
        } else if c == '/' && cs.get(i + 1) == Some(&'/') {
            while i < cs.len() && cs[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && cs.get(i + 1) == Some(&'*') {
            i += 2;
            while i < cs.len() && !(cs[i] == '*' && cs.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The names of the functions a script defines, when defining them is all
/// it does at its top level (KiCad's `ShM`, a form's helpers): nothing runs
/// until a link or a field calls one. `None` when anything else runs at
/// the top level, or the braces don't balance.
fn defined_functions(script: &str) -> Option<Vec<String>> {
    let cs: Vec<char> = code_only(script).chars().collect();
    let mut names = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < cs.len() && cs[*i].is_whitespace() {
            *i += 1;
        }
    };
    while i < cs.len() {
        let c = cs[i];
        if depth > 0 {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            i += 1;
            continue;
        }
        if c.is_whitespace() || c == ';' {
            i += 1;
            continue;
        }
        if !cs[i..].starts_with(&['f', 'u', 'n', 'c', 't', 'i', 'o', 'n'])
            || !cs.get(i + 8).is_some_and(|c| c.is_whitespace())
        {
            return None;
        }
        i += 8;
        ws(&mut i);
        let name: String = cs[i..].iter().take_while(|c| c.is_alphanumeric() || **c == '_' || **c == '$').collect();
        if name.is_empty() {
            return None;
        }
        i += name.chars().count();
        ws(&mut i);
        if cs.get(i) != Some(&'(') {
            return None;
        }
        let mut parens = 0usize;
        while i < cs.len() {
            match cs[i] {
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            i += 1;
            if parens == 0 {
                break;
            }
        }
        ws(&mut i);
        if cs.get(i) != Some(&'{') {
            return None;
        }
        depth = 1;
        i += 1;
        names.push(name);
    }
    (depth == 0).then_some(names)
}

/// The finding for the scripts that run when the file opens: a fail when
/// one can't be read or reaches outside the document, or only defines
/// functions that do and another open-time script calls one; nothing when
/// every one is empty (TCPDF writes an empty names-tree entry) and no
/// other `/JS` is left unread; otherwise a warning with the script quoted.
fn grade_open_scripts(file: &str, scripts: &[Option<String>], js_keys: usize, hidden: &str, out: &mut Vec<Doc>) {
    if scripts.iter().any(Option::is_none) {
        push(
            out,
            file,
            "DOC-JS-ON-OPEN",
            format!(
                "JavaScript wired to the open action or the document's name tree runs when the file is opened, and its script could not be read (an object that isn't there, or a filter this reader doesn't inflate){hidden}"
            ),
            true,
        );
        return;
    }
    let texts: Vec<&str> = scripts.iter().flatten().map(String::as_str).collect();
    // Functions defined at open that reach out when called: (name, why, script).
    let mut defined: Vec<(String, &str, &str)> = Vec::new();
    for text in &texts {
        let Some(why) = reaches_out(text) else { continue };
        match defined_functions(text) {
            Some(names) => defined.extend(names.into_iter().map(|n| (n, why, *text))),
            None => {
                push(
                    out,
                    file,
                    "DOC-JS-ON-OPEN",
                    format!("JavaScript runs when the file is opened and {why}: `{}`{hidden}", quote(text)),
                    true,
                );
                return;
            }
        }
    }
    for text in &texts {
        if let Some((name, why, _)) =
            defined.iter().find(|(name, _, from)| from != text && text.contains(&format!("{name}(")))
        {
            push(
                out,
                file,
                "DOC-JS-ON-OPEN",
                format!(
                    "JavaScript runs when the file is opened and calls {name}(), defined at open, which {why}: `{}`{hidden}",
                    quote(text)
                ),
                true,
            );
            return;
        }
    }
    if let Some((name, why, text)) = defined.first() {
        push(
            out,
            file,
            "DOC-JAVASCRIPT",
            format!(
                "JavaScript runs when the file is opened and only defines functions for links and fields to call; {name}() {why} when called: `{}`{hidden}",
                quote(text)
            ),
            false,
        );
        return;
    }
    match texts.iter().find(|t| !t.trim().is_empty()) {
        Some(text) => push(
            out,
            file,
            "DOC-JAVASCRIPT",
            format!(
                "JavaScript runs when the file is opened but stays inside the document (prints, alerts, pop-ups, field formatting): `{}`{hidden}",
                quote(text)
            ),
            false,
        ),
        None if js_keys > scripts.len() => push(
            out,
            file,
            "DOC-JAVASCRIPT",
            format!(
                "the script that runs when the file is opened is empty, and {} other /JS reference(s) were not read: form-field scripts look like this, so do exploits{hidden}",
                js_keys - scripts.len()
            ),
            false,
        ),
        None => {} // an empty script does nothing
    }
}

/// The names of the files a PDF carries: the `/UF` (Unicode) or `/F`
/// string of the file specification around each `/EF` entry, at most
/// three, so the reader can judge a `.joboptions` from a `.exe`.
fn embedded_names(text: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    let mut seen = 0;
    while let Some(i) = find_name(&text[from..], b"/EF") {
        let at = from + i;
        from = at + 3;
        seen += 1;
        let start = rfind(&text[..at], b" obj").map(|o| o + 4).unwrap_or(at.saturating_sub(DICT_LOOKBACK));
        let end = find(&text[at..], b"endobj").map(|e| at + e).unwrap_or((at + OBJECT_WINDOW).min(text.len()));
        let spec = &text[start..end];
        if let Some(name) = string_value(spec, b"/UF").or_else(|| string_value(spec, b"/F")) {
            let name = quote(&text_of(&name));
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
        if names.len() >= 3 || seen >= MAX_FILESPECS {
            break;
        }
    }
    names
}

/// A FlateDecode stream inflated: zlib-wrapped (RFC 1950, as every PDF
/// writer emits it: a two-byte header whose check passes) or raw DEFLATE.
/// The Adler-32 trailer is left to the inflater to stop before.
fn inflate_stream(data: &[u8], max: usize) -> Option<Vec<u8>> {
    let zlib = data.len() >= 2 && data[0] & 0x0F == 8 && u16::from_be_bytes([data[0], data[1]]).is_multiple_of(31);
    inflate(if zlib { &data[2..] } else { data }, max)
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
        if object_stream && let Some(inflated) = inflate_stream(&bytes[d..end], MAX_MEMBER) {
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
#[path = "pdf_tests.rs"]
mod tests;
