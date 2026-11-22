//! The wpantry-release binary: arguments, exit codes, and the same bytes
//! from two runs into different folders (what release.yml compares).

use std::process::Command;
use wpantry_release::temp::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_wpantry-release");

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn package_and_setup_are_byte_reproducible_across_runs_and_folders() {
    let work = TempDir::new("release-test-").unwrap();
    let w = |name: &str| work.path().join(name).to_string_lossy().into_owned();
    std::fs::write(w("app"), b"APP").unwrap();
    std::fs::write(w("scan"), b"SCAN").unwrap();
    std::fs::write(w("notices"), b"N").unwrap();
    std::fs::write(w("setup"), b"SETUP").unwrap();
    std::fs::create_dir(w("one")).unwrap();
    std::fs::create_dir(w("two")).unwrap();
    for target in [
        "universal-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        for dir in ["one", "two"] {
            let out = |name: &str| w(&format!("{dir}/{target}-{name}"));
            assert_eq!(
                run(&[
                    "package",
                    target,
                    &w("app"),
                    &w("scan"),
                    &w("notices"),
                    &out("desktop.zip")
                ])
                .0,
                0
            );
            assert_eq!(
                run(&[
                    "setup",
                    "payload",
                    &out("desktop.zip"),
                    &out("payload.zlib")
                ])
                .0,
                0
            );
            assert_eq!(
                run(&[
                    "setup",
                    "bundle",
                    target,
                    &w("setup"),
                    &out("payload.zlib"),
                    &out("setup")
                ])
                .0,
                0
            );
        }
        for name in ["desktop.zip", "payload.zlib", "setup"] {
            let one = std::fs::read(w(&format!("one/{target}-{name}"))).unwrap();
            let two = std::fs::read(w(&format!("two/{target}-{name}"))).unwrap();
            assert_eq!(one, two, "{target} {name}");
        }
    }
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["frobnicate"]).0, 2);
    assert_eq!(run(&["package", "x86_64-unknown-linux-gnu"]).0, 2);
    assert_eq!(run(&["sign", "macos", "a.zip", "--bogus", "x"]).0, 2);
    let (code, err) = Command::new(BIN)
        .args(["sign", "windows", "a.exe"])
        .env_remove("WINDOWS_CERT_THUMBPRINT")
        .output()
        .map(|o| {
            (
                o.status.code().unwrap(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        })
        .unwrap();
    assert_eq!(code, 2);
    assert!(
        err.contains("windows signing needs --thumbprint or WINDOWS_CERT_THUMBPRINT"),
        "{err}"
    );
    assert_eq!(run(&["--help"]).0, 0);
}

#[test]
fn failures_name_the_file_and_exit_1() {
    let (code, err) = run(&[
        "setup",
        "payload",
        "/nonexistent/pantry.zip",
        "/nonexistent/out",
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("/nonexistent/pantry.zip"), "{err}");
}
