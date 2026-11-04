//! The library's tree says what the code does (`specs/design/source-layout.md`):
//! the five folders, and only the core files beside them.

use std::path::Path;

/// What may sit directly in `src/`.
const FOLDERS: &[&str] = &["checks", "remediation", "reporters", "sources", "utils"];
const CORE: &[&str] = &[
    "component.rs",
    "db.rs",
    "error.rs",
    "external.rs",
    "finding.rs",
    "guard.rs",
    "history.rs",
    "lib.rs",
    "selfinstall.rs",
    "sync.rs",
    "watch.rs",
];

#[test]
fn src_holds_only_the_five_folders_and_the_core_files() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stray = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let allowed = if entry.file_type().unwrap().is_dir() {
            FOLDERS.contains(&name.as_str())
        } else {
            CORE.contains(&name.as_str())
        };
        if !allowed {
            stray.push(name);
        }
    }
    stray.sort();
    assert!(
        stray.is_empty(),
        "{stray:?} in src/: put each under checks/, sources/, reporters/, remediation/ or utils/ \
         (specs/design/source-layout.md), or add it to CORE here if it is what wpantry is"
    );
    for folder in FOLDERS {
        assert!(src.join(folder).join("mod.rs").is_file(), "src/{folder}/mod.rs is the folder's index");
    }
}
