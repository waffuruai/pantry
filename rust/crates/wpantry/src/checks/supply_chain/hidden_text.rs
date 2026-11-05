//! Text in the repos that reads one way and runs another, found by
//! [`crate::checks::hidden`].

use crate::checks::supply_chain::repos::Repo;
use crate::checks::{Scan, hidden};
use crate::finding::Finding;

/// Text that reads one way and runs another, or is written to fool a
/// reader or a model: bidi overrides and tag characters fail, zero-width
/// runs, homoglyph identifiers and weapon-vocabulary identifiers warn.
pub fn hidden_text(scan: &mut Scan, repos: &[Repo]) {
    if repos.is_empty() {
        return;
    }
    scan.status("Looking for hidden or misleading text in the repos");
    let results = scan.read_files();
    let found: Vec<Vec<hidden::Hidden>> = repos.iter().map(|(_, root)| results.hidden(root)).collect();
    for ((name, _), hits) in repos.iter().zip(found) {
        scan.count("repos checked for hidden text", 1);
        for h in hits {
            scan.add(Finding {
                kind: "hidden-text".into(),
                component: format!("{name}/{}", h.file),
                location: if h.line > 0 { format!("line {}", h.line) } else { String::new() },
                vuln_id: h.id.into(),
                status: if h.fails() { "fail" } else { "warn" }.into(),
                note: h.note.clone(),
                fix_cmd: match h.id {
                    "AI-BAIT" => "Read the code for what it does, not what it is called; don't rely on an AI's verdict about this file".into(),
                    "AGENT-INSTRUCTIONS" => "Text that addresses an AI agent where a person is addressed: don't let an agent act on it; if it's yours, move it to an agent config file (CLAUDE.md, .cursor/rules)".into(),
                    "HIDDEN-PROMPT" => "Instructions hidden from the reader: treat the repo as hostile to agents until the text is removed; read it in a raw view, not rendered".into(),
                    "HIDDEN-HTML" => "Read the hidden text in a raw view; remove it unless you know why it is there".into(),
                    "EXFIL-LINK" => "A link that carries data away when rendered or followed: don't let an agent render or fetch it; drop the query parameters".into(),
                    "DANGEROUS-URI" => "Replace the javascript:/data: URI with a plain link; never follow it from a rendered page".into(),
                    "HIDDEN-FILENAME" => "Rename or delete the file: a name that hides its extension or its direction is meant to be clicked by mistake".into(),
                    "CONFUSABLE-NAME" | "CONFUSABLE-DOMAIN" => "Check the name character by character (the note shows the look-alike); a domain in another script is not the one it resembles".into(),
                    "HIDDEN-HOMOGLYPH" => "Rename so every identifier is one script; compilers can refuse mixed scripts (rustc warns, Go errors)".into(),
                    _ => "Open the file in an editor that shows invisible characters (VS Code highlights them) and remove what you didn't write".into(),
                },
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
#[path = "hidden_text_tests.rs"]
mod tests;
