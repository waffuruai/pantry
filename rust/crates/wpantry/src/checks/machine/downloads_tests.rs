use super::*;
use crate::checks::machine::testing;
use crate::utils::net::Fake;

#[test]
fn downloads_and_desktop_are_read_when_present() {
    let home = crate::utils::files::test_home();
    let d = crate::utils::temp::TempDir::new("dl").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    downloads(&mut s);
    assert!(s.findings.is_empty() && s.counts.is_empty(), "no folders, nothing read");
    let dl = crate::utils::files::home().join("Downloads");
    std::fs::create_dir_all(&dl).unwrap();
    std::fs::write(
        dl.join("invoice.pdf"),
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF",
    )
    .unwrap();
    std::fs::write(dl.join("notes.txt"), "plain").unwrap();
    downloads(&mut s);
    drop(home);
    assert!(
        s.counts.iter().any(|(k, n)| k == "documents and images in Downloads, Desktop and Documents" && *n == 1),
        "{:?}",
        s.counts
    );
    let doc = s.findings.iter().find(|f| f.kind == "document").expect("the PDF's script is a finding");
    assert_eq!(doc.component, "~/Downloads/invoice.pdf");
}

#[test]
fn personal_files_are_explicitly_unchecked_in_background_mode() {
    let home = crate::utils::files::test_home();
    let d = crate::utils::temp::TempDir::new("no-personal-files").unwrap();
    let dl = crate::utils::files::home().join("Downloads");
    std::fs::create_dir_all(&dl).unwrap();
    std::fs::write(
        dl.join("invoice.pdf"),
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF",
    )
    .unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    s.opts.no_personal_files = true;
    downloads(&mut s);
    drop(home);
    assert_eq!(s.findings.len(), 1);
    assert_eq!(s.findings[0].kind, "unchecked");
    assert!(s.findings[0].note.contains("--no-personal-files"));
    assert!(s.counts.is_empty());
}
