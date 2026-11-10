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
    if scan.opts.no_personal_files {
        scan.unchecked(
            "Personal documents and images",
            "Downloads, Desktop and Documents are excluded from this background scan's document and malware passes (--no-personal-files); an interactive scan can check them with the user's permission.",
        );
        return;
    }
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
#[path = "downloads_tests.rs"]
mod tests;
