//! What the published crates must carry with them.

use std::path::Path;

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
