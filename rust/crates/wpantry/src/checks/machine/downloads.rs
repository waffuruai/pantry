//! The top of `~/Downloads`, `~/Desktop` and `~/Documents`: the documents
//! and images people are sent, read for the shapes malware takes, and ClamAV
//! over the same files.

use crate::checks::Scan;

/// `~/Downloads`, `~/Desktop` and `~/Documents`, those that exist.
pub(crate) fn dirs() -> Vec<std::path::PathBuf> {
    let home = crate::utils::files::home();
    ["Downloads", "Desktop", "Documents"].iter().map(|d| home.join(d)).filter(|d| d.is_dir()).collect()
}

/// The top of `~/Downloads`, `~/Desktop` and `~/Documents`: the documents and images
/// people are sent, read for the shapes malware takes, and ClamAV over
/// them when it is installed.
pub(crate) fn downloads(scan: &mut Scan) {
    let dirs = dirs();
    if dirs.is_empty() {
        return;
    }
    let results = scan.read_files();
    let found: Vec<Vec<crate::checks::documents::Doc>> = dirs.iter().map(|d| results.documents(d, 1)).collect();
    scan.status("Reading the documents and images in Downloads, Desktop and Documents");
    let mut files = Vec::new();
    for (dir, docs) in dirs.iter().zip(found) {
        for d in docs {
            let component = crate::utils::files::short(&dir.join(&d.file).to_string_lossy());
            crate::checks::supply_chain::documents::add_doc(scan, &component, d);
        }
        files.extend(crate::checks::documents::files_under(dir, 1));
    }
    scan.count("documents and images in Downloads, Desktop and Documents", files.len() as i64);
    crate::checks::supply_chain::documents::clamav(scan, &files, "Downloads, Desktop and Documents");
}

#[cfg(test)]
mod tests {
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
}
