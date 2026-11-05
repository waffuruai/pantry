//! PDFs, Office documents, RTF and images in the repos, read by
//! [`crate::checks::documents`], and ClamAV over the same files when it is
//! installed.

use crate::checks::supply_chain::repos::Repo;
use crate::checks::{Scan, documents};
use crate::finding::Finding;
use crate::utils::files::short;
use crate::utils::parallel;
use std::path::PathBuf;

/// PDFs, Office documents, RTF and images in the repos, read for the shapes
/// document malware takes (`documents`), and ClamAV over the same files
/// when it is installed.
pub fn documents_pass(scan: &mut Scan, repos: &[Repo]) {
    if repos.is_empty() {
        return;
    }
    scan.status("Reading documents and images for the shapes malware takes");
    let found: Vec<Vec<documents::Doc>> =
        parallel::par_map(repos, parallel::PROBES, |(_, root)| documents::scan_dir(root, 6));
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
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::utils::net::Fake;
    use crate::utils::temp::TempDir;

    /// A document finding per shape found, with the advice for its id, and
    /// ClamAV's hits (when it ran) as `MALWARE`.
    #[test]
    fn documents_are_read_and_clamav_hits_are_malware() {
        let d = TempDir::new("documents").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d, Options::default());
        let (name, root) = testing::repo(&d, "app");
        // A script on open that opens a URL fails; one that only alerts warns, quoted.
        testing::write(
            &root,
            "docs/a.pdf",
            "%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL(\"https://evil.example/x\", true)) >> >> endobj\n%%EOF",
        );
        testing::write(
            &root,
            "docs/b.pdf",
            "%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF",
        );
        documents_pass(&mut s, &[]);
        assert!(s.findings.is_empty());
        documents_pass(&mut s, &[(name, root.clone())]);
        assert!(s.counts.contains(&("repos checked for documents and images".to_string(), 1)));
        let js = testing::by_id(&s, "DOC-JS-ON-OPEN");
        assert_eq!(js.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (js[0].kind.as_str(), js[0].component.as_str(), js[0].status.as_str()),
            ("document", "app/docs/a.pdf", "fail")
        );
        assert!(js[0].note.contains("opens a URL"), "{}", js[0].note);
        assert_eq!(js[0].fix_cmd, doc_fix("DOC-JS-ON-OPEN"));
        let alert = testing::by_id(&s, "DOC-JAVASCRIPT");
        assert_eq!(alert.len(), 1, "{:?}", s.findings);
        assert_eq!((alert[0].component.as_str(), alert[0].status.as_str()), ("app/docs/b.pdf", "warn"));
        assert!(alert[0].note.contains("`app.alert(1)`"), "{}", alert[0].note);
        // What a ClamAV run found: hits fail, a run that couldn't happen is unchecked, none installed is nothing.
        let files = vec![root.join("docs/a.pdf")];
        let before = s.findings.len();
        report_clamav(&mut s, &files, "the repos' documents and images", None);
        assert_eq!(s.findings.len(), before);
        report_clamav(
            &mut s,
            &files,
            "the repos' documents and images",
            Some(Err("clamscan exited 2: no database".into())),
        );
        assert_eq!(testing::unchecked(&s), ["ClamAV over the repos' documents and images"]);
        report_clamav(
            &mut s,
            &files,
            "the repos' documents and images",
            Some(Ok(vec![(root.join("docs/a.pdf"), "Pdf.Exploit.X".into())])),
        );
        let mal = testing::by_id(&s, "MALWARE");
        assert_eq!(mal.len(), 1);
        assert_eq!(
            (mal[0].component.as_str(), mal[0].status.as_str(), mal[0].note.as_str()),
            (short(&root.join("docs/a.pdf").to_string_lossy()).as_str(), "fail", "ClamAV: Pdf.Exploit.X")
        );
        assert_eq!(mal[0].fix_cmd, doc_fix("MALWARE"));
        assert!(s.counts.contains(&("files scanned by ClamAV".to_string(), 1)));
        clamav(&mut s, &[], "nothing");
    }

    #[test]
    fn every_document_id_has_advice() {
        let ids = [
            "DISGUISED-PROGRAM",
            "DOC-POLYGLOT",
            "DOC-OBFUSCATED",
            "DOC-LAUNCH",
            "DOC-JS-ON-OPEN",
            "DOC-DDE",
            "DOC-REMOTE-TEMPLATE",
            "DOC-REMOTE-OBJECT",
            "DOC-XL4-MACRO",
            "DOC-RTF-OBJECT",
            "DOC-MACRO",
            "DOC-UNREADABLE",
            "IMG-WRONG-TYPE",
            "IMG-PAYLOAD",
            "IMG-TRAILER",
            "IMG-SVG-SCRIPT",
            "IMG-SVG-EXTERNAL",
            "MALWARE",
            "DOC-JAVASCRIPT",
        ];
        let advice: Vec<&str> = ids.iter().map(|id| doc_fix(id)).collect();
        assert!(advice.iter().all(|a| a.len() > 40));
        assert!(doc_fix("DOC-JAVASCRIPT").starts_with("Open it with scripting off"), "the default");
        assert!(doc_fix("DISGUISED-PROGRAM").starts_with("Don't open it. Delete it"));
        assert!(doc_fix("DOC-MACRO").starts_with("Keep macros disabled"));
        assert!(doc_fix("IMG-TRAILER").starts_with("Look at what follows the image"));
        assert!(doc_fix("DOC-UNREADABLE").starts_with("Not checked"));
    }
}
