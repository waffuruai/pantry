//! Golden files (F4): each extractor against real lockfiles, with the
//! expected packages taken from the tool that wrote them
//! (tests/lockfiles/README.md).

use std::path::Path;

/// The case's lockfile (its only file besides expected.txt, or `file`)
/// against expected.txt.
fn golden_file(case: &str, file: Option<&str>) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lockfiles").join(case);
    let lock = match file {
        Some(f) => dir.join(f),
        None => {
            let mut others: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_name().is_some_and(|n| n != "expected.txt"))
                .collect();
            assert_eq!(others.len(), 1, "{case}: name the lockfile when a case has several files");
            others.remove(0)
        }
    };
    let got: Vec<String> = wpantry::lockfiles::extract(&lock)
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

fn golden(case: &str) {
    golden_file(case, None);
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
fn requirements_with_an_include() {
    golden_file("requirements", Some("requirements-dev.txt"));
}

#[test]
fn yarn_v1() {
    golden("yarn-v1");
}

#[test]
fn yarn_berry() {
    golden("yarn-berry");
}

#[test]
fn bun_lock() {
    golden("bun");
}

#[test]
fn deno_v3() {
    golden("deno-v3");
}

#[test]
fn deno_v4() {
    golden("deno-v4");
}

#[test]
fn deno_v5() {
    golden("deno-v5");
}

#[test]
fn poetry_v1() {
    golden("poetry-v1");
}

#[test]
fn poetry_v2() {
    golden("poetry-v2");
}

#[test]
fn pipfile_lock() {
    golden("pipenv");
}

#[test]
fn gemfile_lock() {
    golden("gem");
}

#[test]
fn composer_lock() {
    golden("composer");
}

#[test]
fn pubspec_lock() {
    golden("pub");
}

#[test]
fn mix_lock() {
    golden("mix");
}

#[test]
fn gradle_lockfile() {
    golden("gradle");
}

#[test]
fn pom_xml() {
    golden("maven");
}

#[test]
fn nuget_v1() {
    golden("nuget-v1");
}

#[test]
fn nuget_v2() {
    golden("nuget-v2");
}

#[test]
fn conan_v04() {
    golden("conan-v04");
}

#[test]
fn conan_v05() {
    golden("conan-v05");
}

#[test]
fn every_case_has_a_test() {
    let src = include_str!("lockfiles.rs");
    for e in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lockfiles")).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            let case = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(src.contains(&format!("(\"{case}\"")), "tests/lockfiles/{case} has no test");
        }
    }
}

/// Every golden lockfile cut short at many points (and with its bytes
/// mangled) reads as packages or an error, never a panic.
#[test]
fn truncated_and_mangled_lockfiles_never_panic() {
    let tmp = std::env::temp_dir().join(format!("wpantry-truncated-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for e in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lockfiles")).unwrap() {
        let dir = e.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let f = f.unwrap().path();
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            if name == "expected.txt" {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let step = (text.len() / 40).max(1);
            let target = tmp.join(&name);
            for cut in (0..text.len()).step_by(step) {
                let cut = (cut..=text.len()).find(|i| text.is_char_boundary(*i)).unwrap();
                for variant in [text[..cut].to_string(), text[..cut].replace(['"', ':', '\n'], " ")] {
                    std::fs::write(&target, variant).unwrap();
                    let _ = wpantry::lockfiles::extract(&target);
                }
            }
        }
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn unknown_kinds_are_none_not_empty() {
    let d = std::env::temp_dir().join(format!("wpantry-golden-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("bun.lockb"), "\0binary").unwrap();
    assert_eq!(wpantry::lockfiles::extract(&d.join("bun.lockb")).unwrap(), None);
    std::fs::write(d.join("Cargo.lock"), "x".repeat(2 << 20)).unwrap();
    assert!(wpantry::lockfiles::extract(&d.join("Cargo.lock")).is_err(), "a line over the cap is refused");
    std::fs::write(d.join("yarn.lock"), format!("a@1:\n  version \"{}\"\n", "1".repeat(2 << 20))).unwrap();
    assert!(wpantry::lockfiles::extract(&d.join("yarn.lock")).is_err(), "a line over the cap is refused");
    std::fs::remove_dir_all(&d).unwrap();
}
