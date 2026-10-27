//! Golden files (F4): each extractor against real lockfiles, with the
//! expected packages taken from the tool that wrote them
//! (tests/lockfiles/README.md).

use std::path::Path;

fn golden(case: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lockfiles").join(case);
    let lock = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().is_some_and(|n| n != "expected.txt"))
        .unwrap();
    let got: Vec<String> = wscanner::lockfiles::extract(&lock)
        .unwrap()
        .expect("a supported lockfile")
        .iter()
        .map(|p| format!("{} {} {}", p.ecosystem, p.name, p.version))
        .collect();
    let mut want: Vec<String> =
        std::fs::read_to_string(dir.join("expected.txt")).unwrap().lines().map(str::to_string).collect();
    want.sort();
    assert_eq!(got, want, "{case}");
}

#[test]
fn cargo_v4() {
    golden("cargo-v4");
}

#[test]
fn cargo_workspace() {
    golden("cargo-workspace");
}

#[test]
fn npm_v3() {
    golden("npm-v3");
}

#[test]
fn npm_v1() {
    golden("npm-v1");
}

#[test]
fn pnpm_v9() {
    golden("pnpm-v9");
}

#[test]
fn pnpm_v6() {
    golden("pnpm-v6");
}

#[test]
fn go_mod() {
    golden("go");
}

#[test]
fn uv_lock() {
    golden("uv");
}

#[test]
fn swift_v1() {
    golden("swift-v1");
}

#[test]
fn swift_v2() {
    golden("swift-v2");
}

#[test]
fn unsupported_kinds_are_none_not_empty() {
    let d = std::env::temp_dir().join(format!("wscanner-golden-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    assert_eq!(wscanner::lockfiles::extract(&d.join("yarn.lock")).unwrap(), None);
    std::fs::write(d.join("Cargo.lock"), "x".repeat(2 << 20)).unwrap();
    assert!(wscanner::lockfiles::extract(&d.join("Cargo.lock")).is_err(), "a line over the cap is refused");
    std::fs::remove_dir_all(&d).unwrap();
}
