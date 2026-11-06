//! Prebuilt binaries (`.node`, `.wasm`, `.so`, `.dylib`, `.dll`, `.exe`)
//! with nothing to build them from: committed to the repo's own tree, or
//! shipped by an npm dependency. You run what was uploaded, so they warn;
//! a file named like a binary whose first bytes are not an executable or
//! WebAssembly header is a payload, and fails. Well-known native
//! publishers (build tools, image, database and crypto bindings) are
//! skipped.

use super::{Policy, Suspect, apply_policy};
use crate::checks::files::{Contents, Read, When};
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
pub(super) fn wrong_magic_in(name: &str, head: &[u8]) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let ext = blob_ext(&name)?;
    let head = &head[..head.len().min(HEAD)];
    if head.len() < MIN_HEAD {
        return None;
    }
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
/// `blobs` are each file's path in the repo and, when its first bytes
/// aren't a binary's, why ([`wrong_magic_in`]).
pub(super) fn findings(blobs: &[(String, Option<String>)], sources: bool, verb: &str) -> Vec<Suspect> {
    let mut out = Vec::new();
    for (rel, why) in blobs {
        if let Some(why) = why {
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
/// a binary that isn't one fails. One job of the files pass
/// ([`crate::checks::files::pass`]).
pub fn dependency_blobs(root: &Path, policy: &Policy) -> Vec<Suspect> {
    let mut out = crate::checks::files::Results::default().blobs(root);
    apply_policy(&mut out, policy);
    out
}

/// The first bytes a repo's dependency check reads: each package's files
/// named like binaries, and whether the package has sources to build them.
#[derive(Debug)]
pub struct Plan {
    pub reads: Vec<Read>,
    /// Per package: its reads (a range of `reads`) and whether it has sources.
    packages: Vec<(std::ops::Range<usize>, bool)>,
}

/// The packages under `root`'s `node_modules` and their files, walked here
/// rather than on the shared walk: prebuilt binaries live in `build/`,
/// `prebuilds/` and `dist/`, which that walk prunes as output.
pub fn plan(root: &Path) -> Plan {
    let mut plan = Plan { reads: Vec::new(), packages: Vec::new() };
    let nm = root.join("node_modules");
    let pkgs: Vec<PathBuf> = packages(&nm)
        .into_iter()
        .take(MAX_PACKAGES)
        .filter(|pkg| !known_native(&pkg.strip_prefix(&nm).unwrap_or(pkg).to_string_lossy().replace('\\', "/")))
        .collect();
    // Listed side by side: a large node_modules is tens of thousands of directories.
    let listed = crate::utils::parallel::par_map(&pkgs, crate::utils::parallel::cores(), |pkg| {
        let mut files = Vec::new();
        package_files(pkg, 0, &mut files);
        files
    });
    for files in listed {
        let (start, mut sources) = (plan.reads.len(), false);
        for path in files {
            let f = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if is_blob_name(&f) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                plan.reads.push(Read { path, rel, cap: 0, role: 0, when: When::Always });
            }
            if native_source_name(&f) {
                sources = true;
            }
        }
        plan.packages.push((start..plan.reads.len(), sources));
    }
    plan
}

/// Why one file named like a binary isn't one.
pub fn file(read: &Read, c: &Contents) -> Option<String> {
    let name = read.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    wrong_magic_in(&name, c.head)
}

/// The repo's dependency findings, before the policy, sorted.
pub fn finish(plan: &Plan, files: &[Option<&Option<String>>]) -> Vec<Suspect> {
    let mut out = Vec::new();
    for (range, sources) in &plan.packages {
        let blobs: Vec<(String, Option<String>)> =
            range.clone().map(|i| (plan.reads[i].rel.clone(), files[i].cloned().flatten())).collect();
        out.extend(findings(&blobs, *sources, "ships"));
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out
}

#[cfg(test)]
#[path = "blobs_tests.rs"]
mod tests;
