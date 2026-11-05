//! File names that hide what a file is: an executable dressed as a
//! document.

use crate::checks::hidden::Hidden;
use crate::checks::hidden::unicode::{BLACK_FLAG, mixed_script, without_subdivision_flags};

// --- Names ---------------------------------------------------------------

const EXEC_EXTS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "msi", "hta", "lnk",
    "jar", "sh", "command",
];
const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "zip", "rtf", "odt",
    "mp4", "mp3", "html", "htm",
];

/// What a file or directory name hides: invisible or direction-changing
/// characters, or a document's extension in front of a program's (fail);
/// Latin letters mixed with look-alikes (warn).
pub fn name_findings(rel: &str) -> Option<Hidden> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let flags_removed;
    let name = if name.contains(BLACK_FLAG) {
        flags_removed = without_subdivision_flags(name);
        flags_removed.as_str()
    } else {
        name
    };
    if name.chars().any(|c| {
        matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{E0000}'..='\u{E007F}' | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}')
    }) {
        return Some(Hidden::new(
            rel,
            "HIDDEN-FILENAME",
            0,
            "the name contains invisible or direction-changing characters: it shows as something it isn't".into(),
        ));
    }
    let lower = name.to_ascii_lowercase();
    if let Some((stem, ext)) = lower.rsplit_once('.')
        && EXEC_EXTS.contains(&ext)
        && stem.rsplit_once('.').is_some_and(|(_, e2)| DOC_EXTS.contains(&e2))
    {
        return Some(Hidden::new(
            rel,
            "HIDDEN-FILENAME",
            0,
            format!(
                "looks like a .{} but runs as a .{ext}: a program dressed as a document",
                stem.rsplit('.').next().unwrap_or("")
            ),
        ));
    }
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    if mixed_script(stem) {
        return Some(Hidden::new(
            rel,
            "CONFUSABLE-NAME",
            0,
            format!("`{name}` mixes Latin with look-alike letters from another script: two names can look like one"),
        ));
    }
    None
}
