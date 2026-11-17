//! PDFs, Office documents, RTF and images in the repos, read by
//! [`crate::checks::documents`], and ClamAV over the same files when it is
//! installed.

use crate::checks::supply_chain::repos::Repo;
use crate::checks::{Scan, documents};
use crate::finding::Finding;
use crate::utils::files::short;
use std::path::PathBuf;

/// PDFs, Office documents, RTF and images in the repos, read for the shapes
/// document malware takes (`documents`), and ClamAV over the same files
/// when it is installed.
pub fn documents_pass(scan: &mut Scan, repos: &[Repo]) {
    if repos.is_empty() {
        return;
    }
    scan.status("Reading documents and images for the shapes malware takes");
    let results = scan.read_files();
    let found: Vec<Vec<documents::Doc>> = repos.iter().map(|(_, root)| results.documents(root, 6)).collect();
    let mut files: Vec<PathBuf> = Vec::new();
    for ((name, root), docs) in repos.iter().zip(found) {
        scan.count("repos checked for documents and images", 1);
        for d in docs {
            add_doc(scan, &format!("{name}/{}", d.file), d);
        }
        files.extend(documents::files_under(root, 6));
    }
    clamav(scan, &files, "the repos' documents and images");
}

/// One `document` finding.
pub fn add_doc(scan: &mut Scan, component: &str, d: documents::Doc) {
    scan.add(Finding {
        kind: "document".into(),
        component: component.into(),
        vuln_id: d.id.into(),
        status: if d.hard { "fail" } else { "warn" }.into(),
        note: d.note,
        fix_cmd: doc_fix(d.id).into(),
        ..Default::default()
    });
}

fn doc_fix(id: &str) -> &'static str {
    match id {
        "DISGUISED-PROGRAM" => {
            "Don't open it. Delete it, and if it came by mail or chat, tell the sender their account may be compromised"
        }
        "DOC-POLYGLOT" | "DOC-OBFUSCATED" => {
            "Don't open it in a viewer that runs scripts; if you must read it, open it in a sandbox or convert it with a tool that drops active content"
        }
        "DOC-LAUNCH"
        | "DOC-JS-ON-OPEN"
        | "DOC-DDE"
        | "DOC-REMOTE-TEMPLATE"
        | "DOC-REMOTE-OBJECT"
        | "DOC-XL4-MACRO"
        | "DOC-RTF-OBJECT" => {
            "Don't open it with Office or a scripting PDF viewer; use Protected View, Preview or a sandbox, or ask the sender for a plain export"
        }
        "DOC-MACRO" => "Keep macros disabled when you open it; if it is yours, save it in a format without them",
        "DOC-UNREADABLE" => "Not checked: read it in a sandbox, or ask for an unencrypted copy to scan",
        "IMG-WRONG-TYPE" | "IMG-PAYLOAD" => {
            "Don't serve or include it; delete it and check how it got there (an upload form, a dependency, a download)"
        }
        "IMG-TRAILER" => {
            "Look at what follows the image (a hex editor, binwalk); re-encode it with an image tool if it isn't yours"
        }
        "IMG-SVG-SCRIPT" | "IMG-SVG-EXTERNAL" => {
            "Serve SVGs through <img> (no script runs there) or sanitize them (DOMPurify, svgo) before inlining"
        }
        "MALWARE" => {
            "Delete or quarantine the file and check where it came from; if it was opened, treat the machine as compromised and rotate what it could reach"
        }
        _ => {
            "Open it with scripting off (Preview, a browser's viewer, Protected View), not a viewer with JavaScript or macros enabled"
        }
    }
}

/// ClamAV over `files`, when it is installed: `MALWARE` per hit; a run that
/// couldn't happen is "not checked".
pub fn clamav(scan: &mut Scan, files: &[PathBuf], what: &str) {
    if files.is_empty() {
        return;
    }
    report_clamav(scan, files, what, documents::clamav(files));
}

/// What a ClamAV run over `files` found (None: not installed).
fn report_clamav(
    scan: &mut Scan,
    files: &[PathBuf],
    what: &str,
    found: Option<std::result::Result<Vec<(PathBuf, String)>, String>>,
) {
    scan.status(&format!("ClamAV over {} files", files.len()));
    match found {
        None => {}
        Some(Err(e)) => scan.unchecked(&format!("ClamAV over {what}"), &e),
        Some(Ok(hits)) => {
            scan.count("files scanned by ClamAV", files.len().min(5000) as i64);
            for (path, sig) in hits {
                scan.add(Finding {
                    kind: "document".into(),
                    component: short(&path.to_string_lossy()),
                    vuln_id: "MALWARE".into(),
                    status: "fail".into(),
                    note: format!("ClamAV: {sig}"),
                    fix_cmd: doc_fix("MALWARE").into(),
                    ..Default::default()
                });
            }
        }
    }
}

#[cfg(test)]
#[path = "documents_tests.rs"]
mod tests;
