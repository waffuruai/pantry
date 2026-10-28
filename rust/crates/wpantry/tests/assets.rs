//! The crate's copies of the default policy files and the distrusted CA
//! certificates match the Python implementation's, while both exist (until
//! phase 3 removes python/), allowing for the name: the Python reference is
//! still `wscanner`, the Rust product `wpantry`. The agent skill is not
//! compared: each describes its own binary. Skipped where python/ isn't
//! there, as in the published crate.

use std::path::Path;

#[test]
fn assets_match_the_python_originals() {
    let python = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../python");
    if !python.is_dir() {
        return;
    }
    for (copy, original) in [
        ("assets/defaults/gitleaks.toml", "wscanner/defaults/gitleaks.toml"),
        ("assets/defaults/licenses.txt", "wscanner/defaults/licenses.txt"),
        ("assets/defaults/install-scripts.txt", "wscanner/defaults/install-scripts.txt"),
        ("assets/distrusted-ca/intermediates.pem", "distrusted-ca/intermediates.pem"),
        ("assets/distrusted-ca/issuers.pem", "distrusted-ca/issuers.pem"),
        ("assets/distrusted-ca/roots.pem", "distrusted-ca/roots.pem"),
    ] {
        let ours = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(copy)).unwrap();
        let theirs = std::fs::read_to_string(python.join(original)).unwrap();
        let theirs = theirs.replace("wscanner", "wpantry").replace("WSCANNER", "WPANTRY");
        assert_eq!(ours, theirs, "{copy} differs from python/{original}: copy it over (with the name changed)");
    }
}

/// Each crate carries the license text (MIT asks for it in every copy, and a
/// published crate holds only its own directory); the copies match the
/// repository's LICENSE.
#[test]
fn crates_carry_the_repository_license() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../LICENSE");
    let Ok(license) = std::fs::read_to_string(root) else { return };
    for krate in ["wpantry", "wpantry-cli"] {
        let copy = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../{krate}/LICENSE"));
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), license, "copy LICENSE to rust/crates/{krate}/");
    }
}
