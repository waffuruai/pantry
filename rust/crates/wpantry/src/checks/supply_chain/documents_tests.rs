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
