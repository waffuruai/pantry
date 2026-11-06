//! Office Open XML (`.docx`, `.xlsx`, `.pptx` and their macro-enabled and
//! template siblings) and OpenDocument: a zip whose table of contents and a
//! few small parts say what the document carries. Macros in a format meant
//! to carry none, Excel 4.0 macro sheets, OLE objects, ActiveX, templates
//! and objects fetched from a remote host on open, and DDE fields.

use super::{Doc, find, push};
use crate::utils::archive::zip::Zip;

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
#[path = "ooxml_tests.rs"]
mod tests;
