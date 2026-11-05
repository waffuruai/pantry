//! Commit messages carrying hidden text.

use crate::checks::hidden::instructions::{Mode, first_agent_instruction};
use crate::checks::hidden::unicode::excerpt;
use crate::checks::hidden::{Hidden, scan_text};
use std::path::Path;

// --- Commit messages -----------------------------------------------------

/// Hidden characters and agent-directed text in the last 500 commit
/// messages: an agent summarizing the log reads them too.
pub fn commit_messages(root: &Path) -> Vec<Hidden> {
    use std::ffi::OsStr;
    use std::time::Duration;
    let mut out = Vec::new();
    let log = crate::utils::process::run(
        &[
            OsStr::new("git"),
            OsStr::new("-C"),
            root.as_os_str(),
            OsStr::new("log"),
            OsStr::new("-n"),
            OsStr::new("500"),
            OsStr::new("--format=%H%x00%B%x01"),
        ],
        Duration::from_secs(30),
    );
    for entry in log.split('\u{1}') {
        let Some((hash, body)) = entry.trim_start().split_once('\0') else { continue };
        let file = format!(".git (commit {})", hash.chars().take(12).collect::<String>());
        for mut h in scan_text(&file, body) {
            if matches!(h.id, "HIDDEN-BIDI" | "HIDDEN-TAGS" | "HIDDEN-ZERO-WIDTH") {
                h.note.push_str(", in a commit message");
                out.push(h);
            }
        }
        if let Some((_, what, line)) = first_agent_instruction(body, Mode::Prose) {
            out.push(Hidden::new(
                &file,
                "AGENT-INSTRUCTIONS",
                0,
                format!("a commit message addresses an AI agent rather than the reader ({what}): `{}`", excerpt(&line)),
            ));
        }
        if out.len() >= 20 {
            break;
        }
    }
    out
}
