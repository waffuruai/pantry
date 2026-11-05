//! Code that behaves like an attack: strings decoded at run time and fed
//! to `eval`, payloads kept as arrays of numbers, hand-rolled decoders,
//! privilege escalation and persistence in scripts, reads of credential
//! stores sent over the network, code that asks a crypto wallet to sign or
//! approve, clippers that swap the wallet address on the clipboard, pages that load third-party scripts without a pinned hash
//! (the supply-chain drainer pattern), traffic to raw IP addresses, and
//! prebuilt binaries with nothing to build them from.
//!
//! None of these is wrong on its own, so the verdict depends on where it
//! sits: hex tables are normal in a shader or a kernel and a colour in CSS,
//! out of place in a web page's script; `sudo` is normal in an installer
//! and alarming in an npm install script; asking a wallet to sign is what
//! a dapp does, and what a drainer hidden in a dependency does. A finding
//! fails where the pattern is out of place for its language and context,
//! warns elsewhere, and a policy file (`--suspect-policy`) turns any id or
//! path into a warning for good. It always warns: an override never
//! silences.
//!
//! One file per group of rules: [`obfuscation`] (decoded `eval`, numeric
//! payloads, string decoders, escaped source), [`escalation`] (privilege
//! and persistence), [`credentials`] (credential stores and the network),
//! [`wallet`] (signing, approvals and account takeovers on every chain),
//! [`clipper`] (clipboard reads and writes with wallet addresses in hand),
//! [`network`] (raw IP addresses),
//! [`scripts`] (unpinned third-party scripts on a page), [`blobs`]
//! (binaries without sources), [`profiling`] (an info-stealer prompt aimed
//! at an AI), [`cardholder`] (card numbers and fields in the clear),
//! [`secrets_weak`] (hardcoded and weak passwords) and [`keylogger`]
//! (keystroke capture). This file is the index: the finding, the
//! contexts a path falls into, the policy, the size limits, the walk and
//! the dispatch over one file's text, and the helpers the rules share.

use crate::checks::files::{Contents, Read, Stats, When};
use std::path::{Path, PathBuf};

pub(crate) mod blobs;
mod cardholder;
mod clipper;
mod credentials;
mod escalation;
mod keylogger;
mod network;
mod obfuscation;
mod profiling;
mod scripts;
mod secrets_weak;
mod wallet;

pub use blobs::dependency_blobs;
pub(crate) use clipper::PATTERNS as ADDRESS_PATTERNS;
pub use scripts::third_party_scripts;

/// One suspicious thing in one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Suspect {
    /// Relative to the target.
    pub file: String,
    pub id: &'static str,
    pub line: usize,
    pub note: String,
    /// Fails the scan (before the policy is applied).
    pub hard: bool,
}

/// Where a file sits, which decides what is out of place in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// JavaScript, TypeScript and the templates that embed them.
    Web,
    /// Pages: HTML and the component formats that carry `<script>` tags.
    Markup,
    Shell,
    Python,
    /// C-family, Rust, Swift, assembly, GPU shaders: numeric tables live here.
    Native,
    Style,
    /// package.json, binding.gyp, Makefiles: install-time commands.
    Manifest,
    /// Prose and agent-instruction files: Markdown, reStructuredText, and
    /// the dotfiles that carry prompts for a coding agent.
    Prompt,
    /// Structured data and config: JSON, CSV, YAML, `.env`, logs, where a
    /// leaked card number or a hardcoded password sits at rest.
    Data,
    Other,
}

pub fn context(file: &str) -> Context {
    let lower = file.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if ["package.json", "binding.gyp", "makefile", "justfile", "composer.json", "setup.py", "pyproject.toml"]
        .contains(&name)
    {
        return Context::Manifest;
    }
    // CI workflows and container builds run their steps like a shell script.
    if lower.contains(".github/workflows/")
        || lower.contains(".circleci/")
        || name == ".gitlab-ci.yml"
        || name == "bitbucket-pipelines.yml"
        || name.starts_with("azure-pipelines")
        || name == "jenkinsfile"
        || name == "dockerfile"
        || name == "containerfile"
        || name.starts_with("dockerfile.")
    {
        return Context::Shell;
    }
    // Agent-instruction dotfiles and `.env` files have no useful extension.
    if [".cursorrules", ".windsurfrules", ".clinerules"].contains(&name) {
        return Context::Prompt;
    }
    if name == ".env" || name.starts_with(".env.") {
        return Context::Data;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "vue" | "svelte" | "astro" => Context::Web,
        "html" | "htm" | "xhtml" | "mdx" => Context::Markup,
        "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" | "command" => Context::Shell,
        "py" | "pyw" | "rb" | "pl" | "php" | "lua" => Context::Python,
        "c" | "h" | "cc" | "cpp" | "hpp" | "m" | "mm" | "rs" | "swift" | "go" | "java" | "kt" | "cs" | "zig" | "s"
        | "asm" | "cu" | "cuh" | "cl" | "metal" | "glsl" | "wgsl" | "hlsl" | "frag" | "vert" => Context::Native,
        "css" | "scss" | "sass" | "less" => Context::Style,
        "md" | "markdown" | "mdc" | "rst" => Context::Prompt,
        "json" | "jsonc" | "csv" | "tsv" | "yaml" | "yml" | "ini" | "conf" | "env" | "log" | "properties" => {
            Context::Data
        }
        _ => Context::Other,
    }
}

/// Built output: not a person's source, and read elsewhere (the bundle a
/// page serves is what the page's own source becomes).
fn generated_path(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    ["/_site/", "/out/", "/.next/", "/dist/", "/build/", "/coverage/", "/target/", "/.cache/"]
        .iter()
        .any(|p| l.contains(p))
}

/// Tests and fixtures: what they contain is the thing under test.
fn test_path(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    [".test.", ".spec.", "_test.", "/tests/", "/test/", "/__tests__/", "/spec/", "/fixtures/", "/testdata/"]
        .iter()
        .any(|p| l.contains(p))
}

/// Exemptions: an id, or `path:<substring>`; a finding matching one is
/// never a failure, only a warning.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub ids: Vec<String>,
    pub paths: Vec<String>,
}

impl Policy {
    pub fn parse(text: &str) -> Policy {
        let mut p = Policy::default();
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            match l.strip_prefix("path:") {
                Some(path) => p.paths.push(path.trim().to_string()),
                None => p.ids.push(l.trim_start_matches("SUSPECT-").to_ascii_uppercase()),
            }
        }
        p
    }

    pub fn exempt(&self, s: &Suspect) -> bool {
        self.ids.iter().any(|i| i == s.id.trim_start_matches("SUSPECT-"))
            || self.paths.iter().any(|p| s.file.contains(p.as_str()))
    }
}

/// The most of one file read, and of one target.
const MAX_FILE: u64 = 1 << 20;
const MAX_TARGET: u64 = 64 << 20;
/// How deep a target is walked.
pub const DEPTH: usize = 6;

/// What was scanned: a repo (its own source, every rule) or code installed
/// from elsewhere (an extension or plugin: the rules about behaviour, not
/// about style).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Repo,
    Installed,
}

/// Every suspicious thing under `root`, one per (file, id), after the
/// policy. One job of the files pass ([`crate::checks::files::pass`]).
pub fn scan_dir(root: &Path, kind: Kind, policy: &Policy) -> Vec<Suspect> {
    let mut out = crate::checks::files::Results::default().suspects(root, kind);
    apply_policy(&mut out, policy);
    out
}

/// What a check of `root` reads: its code files (at most [`MAX_FILE`] each
/// and [`MAX_TARGET`] in all, in walk order) and, in a repo, the first
/// bytes of the files named like binaries.
#[derive(Debug)]
pub struct Plan {
    pub reads: Vec<Read>,
    kind: Kind,
    /// The repo has the sources a native addon is built from.
    native_sources: bool,
}

/// A code file, read whole.
const CODE: u8 = 0;
/// A file named like a binary: its first bytes.
const BLOB: u8 = 1;

pub fn plan(root: &Path, kind: Kind, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    let mut plan = Plan { reads: Vec::new(), kind, native_sources: false };
    let mut budget = MAX_TARGET;
    for (dir, files) in walk {
        for name in files {
            let rel_path = dir.join(name);
            let rel = rel_path.strip_prefix(root).unwrap_or(&rel_path).to_string_lossy().into_owned();
            if kind == Kind::Repo {
                if blobs::is_blob_name(name) && !generated_path(&rel) && !test_path(&rel) {
                    plan.reads.push(Read {
                        path: rel_path.clone(),
                        rel: rel.clone(),
                        cap: 0,
                        role: BLOB,
                        when: When::Always,
                    });
                }
                if blobs::native_source_name(name) {
                    plan.native_sources = true;
                }
            }
            let ctx = context(&rel);
            if ctx == Context::Other || (kind == Kind::Repo && generated_path(&rel)) {
                continue;
            }
            let Some(s) = stat(&rel_path) else { continue };
            if !s.file || s.size > MAX_FILE || s.size > budget {
                continue;
            }
            budget -= s.size;
            plan.reads.push(Read { path: rel_path, rel, cap: MAX_FILE, role: CODE, when: When::Always });
        }
    }
    plan
}

/// What one file holds: its findings, whether it signs with a wallet, and
/// for a page the unpinned third-party scripts it loads (as findings when
/// a wallet signs somewhere in the target, and when none does); for a file
/// named like a binary, why it isn't one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileResult {
    pub found: Vec<Suspect>,
    pub wallet: bool,
    pub scripts: Option<(Vec<Suspect>, Vec<Suspect>)>,
    pub not_binary: Option<String>,
}

pub fn file(kind: Kind, read: &Read, c: &Contents) -> FileResult {
    if read.role == BLOB {
        let name = read.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        return FileResult { not_binary: blobs::wrong_magic_in(&name, c.head), ..Default::default() };
    }
    let Some(text) = c.text() else { return FileResult::default() };
    let found = scan_text(&read.rel, &text, kind);
    let ctx = context(&read.rel);
    FileResult {
        wallet: found.iter().any(|s| s.id == wallet::ID),
        // A page that signs transactions and loads an unpinned third-party
        // script is the drainer pattern: the script decides what gets signed.
        scripts: (ctx == Context::Markup || ctx == Context::Web)
            .then(|| (third_party_scripts(&read.rel, &text, false), third_party_scripts(&read.rel, &text, true))),
        found,
        not_binary: None,
    }
}

/// The target's findings, one per (file, id), before the policy.
pub fn finish(plan: &Plan, files: &[Option<&FileResult>]) -> Vec<Suspect> {
    let code = || plan.reads.iter().zip(files).filter(|(r, _)| r.role == CODE).filter_map(|(_, f)| *f);
    let mut out: Vec<Suspect> = code().flat_map(|f| f.found.iter().cloned()).collect();
    let wallet_anywhere = code().any(|f| f.wallet);
    for (without, with) in code().filter_map(|f| f.scripts.as_ref()) {
        out.extend(if wallet_anywhere { with } else { without }.iter().cloned());
    }
    if plan.kind == Kind::Repo {
        let tree_blobs: Vec<(String, Option<String>)> = plan
            .reads
            .iter()
            .zip(files)
            .filter(|(r, _)| r.role == BLOB)
            .map(|(r, f)| (r.rel.clone(), f.and_then(|f| f.not_binary.clone())))
            .collect();
        out.extend(blobs::findings(&tree_blobs, plan.native_sources, "commits"));
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out
}

/// The policy's exemptions: a hard finding it names becomes a warning that says so.
pub fn apply_policy(out: &mut [Suspect], policy: &Policy) {
    for s in out {
        if s.hard && policy.exempt(s) {
            s.hard = false;
            s.note.push_str(" (exempted by the suspect policy: still a warning)");
        }
    }
}

/// The rules over one file, in the order the later ones depend on: a
/// wallet call in obfuscated code and a raw address beside a hard finding
/// read what the earlier rules found.
pub fn scan_text(file: &str, text: &str, kind: Kind) -> Vec<Suspect> {
    let ctx = context(file);
    let mut out = Vec::new();
    obfuscation::scan(file, text, ctx, &mut out);
    escalation::scan(file, text, ctx, kind, &mut out);
    credentials::scan(file, text, ctx, kind, &mut out);
    wallet::scan(file, text, ctx, kind, &mut out);
    clipper::scan(file, text, ctx, kind, &mut out);
    network::scan(file, text, ctx, &mut out);
    profiling::scan(file, text, ctx, kind, &mut out);
    cardholder::scan(file, text, ctx, &mut out);
    secrets_weak::scan(file, text, ctx, &mut out);
    keylogger::scan(file, text, ctx, kind, &mut out);
    out
}

// --- Shared by the rules --------------------------------------------------

/// One finding appended for `file`.
fn push(out: &mut Vec<Suspect>, file: &str, id: &'static str, line: usize, note: impl Into<String>, hard: bool) {
    out.push(Suspect { file: file.into(), id, line, note: note.into(), hard });
}

/// The 1-based line where `needle` first appears, or 0 when it doesn't.
fn line_of(text: &str, needle: &str) -> usize {
    text.find(needle).map(|i| text[..i].matches('\n').count() + 1).unwrap_or(0)
}

/// The line where byte offset `at` falls.
fn line_at(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

fn has_any(text: &str, needles: &[&'static str]) -> Option<&'static str> {
    needles.iter().copied().find(|n| text.contains(n))
}

/// The (id, hard) pairs of some findings, for the rules' tests.
#[cfg(test)]
fn ids(v: &[Suspect]) -> Vec<(&str, bool)> {
    v.iter().map(|s| (s.id, s.hard)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts() {
        assert_eq!(context("a/b/package.json"), Context::Manifest);
        assert_eq!(context("x.tsx"), Context::Web);
        assert_eq!(context("k.metal"), Context::Native);
        assert_eq!(context("s.scss"), Context::Style);
        assert_eq!(context("README.md"), Context::Prompt);
        assert_eq!(context("rules/.cursorrules"), Context::Prompt);
        assert_eq!(context("config/.env"), Context::Data);
        assert_eq!(context("data/events.log"), Context::Data);
        assert_eq!(context("conf/app.yaml"), Context::Data);
        assert_eq!(context("x.bin"), Context::Other);
        assert_eq!(context(".github/workflows/ci.yml"), Context::Shell);
        assert_eq!(context("Dockerfile"), Context::Shell);
        assert_eq!(context("docker/Dockerfile.ci"), Context::Shell);
        assert_eq!(context("site/index.html"), Context::Markup);
        assert_eq!(context("tool.py"), Context::Python);
        assert_eq!(context("Makefile"), Context::Manifest);
    }

    #[test]
    fn paths_that_are_output_or_tests() {
        assert!(generated_path("dist/app.js"));
        assert!(generated_path("site/.next/static/a.js"));
        assert!(!generated_path("src/distribute.js"), "a name that merely contains `dist`");
        assert!(test_path("src/__tests__/a.js"));
        assert!(test_path("a/b.spec.ts"));
        assert!(!test_path("src/attestation.ts"), "a name that merely contains `test`");
    }

    #[test]
    fn line_helpers() {
        assert_eq!(line_of("a\nb\nc", "c"), 3);
        assert_eq!(line_of("a\nb", "z"), 0, "absent is 0, not a panic");
        assert_eq!(line_at("a\nb\nc", 4), 3);
        assert_eq!(has_any("x eval( y", &["atob(", "eval("]), Some("eval("));
        assert_eq!(has_any("plain", &["atob("]), None);
    }

    #[test]
    fn policy_parses_ids_and_paths() {
        let p = Policy::parse("# mine\nSUSPECT-PRIV-ESCALATION\n  raw-ip \npath: scripts/legacy/\n\n");
        assert_eq!(p.ids, ["PRIV-ESCALATION", "RAW-IP"]);
        assert_eq!(p.paths, ["scripts/legacy/"]);
        let hit = Suspect { file: "x.js".into(), id: "SUSPECT-RAW-IP", line: 1, note: String::new(), hard: true };
        assert!(p.exempt(&hit));
        assert!(p.exempt(&Suspect { file: "scripts/legacy/a.js".into(), id: "SUSPECT-X", ..hit.clone() }));
        assert!(!p.exempt(&Suspect { id: "SUSPECT-WALLET-SIGNING", ..hit.clone() }));
        let mut v = vec![hit.clone(), Suspect { hard: false, ..hit }];
        apply_policy(&mut v, &p);
        assert!(v.iter().all(|s| !s.hard));
        assert!(v[0].note.contains("exempted") && !v[1].note.contains("exempted"), "only a downgrade says so");
    }

    #[test]
    fn policy_downgrades_but_never_silences() {
        let p = Policy::parse("# mine\nSUSPECT-PRIV-ESCALATION\npath:scripts/legacy/\n");
        let d = crate::utils::temp::TempDir::new("suspect").unwrap();
        std::fs::create_dir_all(d.path().join("scripts/legacy")).unwrap();
        std::fs::write(d.path().join("scripts/legacy/old.js"), "eval(atob('x'))").unwrap();
        std::fs::write(d.path().join("package.json"), "{\"scripts\": {\"postinstall\": \"chmod u+s x\"}}").unwrap();
        let got = scan_dir(d.path(), Kind::Repo, &p);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.iter().all(|s| !s.hard), "{got:?}");
        assert!(got.iter().all(|s| s.note.contains("exempted")));
        let strict = scan_dir(d.path(), Kind::Repo, &Policy::default());
        assert!(strict.iter().all(|s| s.hard), "{strict:?}");
    }

    #[test]
    fn walk_skips_output_and_pairs_pages_with_signing() {
        let d = crate::utils::temp::TempDir::new("suspect-walk").unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("out")).unwrap();
        std::fs::write(root.join("out/app.js"), "eval(atob('x'))").unwrap();
        std::fs::write(root.join("README.md"), "eval(atob('x')) and sudo rm -rf /").unwrap();
        std::fs::write(root.join("src/swap.ts"), "import { ethers } from 'ethers';\nsigner.signTypedData(d, t, v);\n")
            .unwrap();
        std::fs::write(root.join("index.html"), "<script src=\"https://cdn.example/t.js\"></script>").unwrap();
        let got = scan_dir(root, Kind::Repo, &Policy::default());
        assert_eq!(
            ids(&got),
            [("SUSPECT-THIRD-PARTY-SCRIPT", true), ("SUSPECT-WALLET-SIGNING", false)],
            "sorted by file; the page fails because the project signs: {got:?}"
        );
        assert_eq!((got[0].file.as_str(), got[1].file.as_str()), ("index.html", "src/swap.ts"));
        let installed = scan_dir(root, Kind::Installed, &Policy::default());
        assert!(installed.iter().any(|s| s.file == "out/app.js"), "installed code is read wherever it sits");
    }
}
