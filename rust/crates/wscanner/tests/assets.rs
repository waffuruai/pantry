//! The crate's copies of the agent skill and the default policy files match
//! the Python implementation's, while both exist (until phase 3 removes
//! python/). Skipped where python/ isn't there, as in the published crate.

use std::path::Path;

#[test]
fn assets_match_the_python_originals() {
    let python = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../python");
    if !python.is_dir() {
        return;
    }
    for (copy, original) in [
        ("assets/SKILL.md", "skill/wscanner/SKILL.md"),
        ("assets/defaults/gitleaks.toml", "wscanner/defaults/gitleaks.toml"),
        ("assets/defaults/licenses.txt", "wscanner/defaults/licenses.txt"),
        ("assets/defaults/install-scripts.txt", "wscanner/defaults/install-scripts.txt"),
    ] {
        let ours = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(copy)).unwrap();
        let theirs = std::fs::read_to_string(python.join(original)).unwrap();
        assert_eq!(ours, theirs, "{copy} differs from python/{original}: copy it over");
    }
}
