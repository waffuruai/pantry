//! The library's tree says what the code does (`specs/design/source-layout.md`):
//! the five folders, and only the core files beside them, each with its
//! tests in a sibling `<name>_tests.rs`.

use std::path::Path;

/// What may sit directly in `src/`.
const FOLDERS: &[&str] = &["checks", "remediation", "reporters", "sources", "utils"];
const CORE: &[&str] = &[
    "component.rs",
    "db.rs",
    "error.rs",
    "external.rs",
    "finding.rs",
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
            let core = name.strip_suffix("_tests.rs").map_or(name.clone(), |stem| format!("{stem}.rs"));
            CORE.contains(&core.as_str())
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

/// Tests live beside the code they test (`foo.rs` and `foo_tests.rs`, or
/// `foo/mod.rs` and `foo/tests.rs`), never inline: a source file stays the
/// code, and its tests are one file away.
#[test]
fn tests_sit_in_sibling_files_not_inline() {
    let mut inline = Vec::new();
    let mut orphans = Vec::new();
    for krate in ["wpantry", "wpantry-cli", "wpantry-yara"] {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(krate).join("src");
        walk(&src, &mut |p| {
            let text = std::fs::read_to_string(p).unwrap();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if text
                .lines()
                .any(|l| l.trim_start().starts_with("mod tests {") || l.trim_start().contains(" mod tests {"))
            {
                inline.push(p.display().to_string());
            }
            let owner = match name.strip_suffix("_tests.rs") {
                Some(stem) => Some(p.with_file_name(format!("{stem}.rs"))),
                None if name == "tests.rs" => Some(p.with_file_name("mod.rs")),
                None => None,
            };
            if let Some(owner) = owner
                && !owner.is_file()
            {
                orphans.push(p.display().to_string());
            }
        });
    }
    assert!(inline.is_empty(), "inline test modules; move each to its sibling file: {inline:?}");
    assert!(orphans.is_empty(), "test files with no source file beside them: {orphans:?}");
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            walk(&p, f);
        } else if p.extension().is_some_and(|e| e == "rs") {
            f(&p);
        }
    }
}
