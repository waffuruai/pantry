//! The bounded directory walk every repo check shares, and what it never
//! enters: build output and dependency directories ([`PRUNE`]), and for the
//! repo search also caches, toolchains and app data ([`skip`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const PRUNE: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".build",
    "vendor",
    ".cache",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
];
/// The repo search also skips caches, toolchains and app data that hold
/// other people's checkouts (crate sources, Go modules, npm stores) or are huge.
const DISCOVER_PRUNE: &[&str] = &["Library", ".Trash", ".rustup", ".npm", ".pnpm-store"];
/// (parent, dir)
const DISCOVER_PRUNE_PAIRS: &[(&str, &str)] =
    &[("go", "pkg"), (".cargo", "registry"), (".cargo", "git"), (".local", "share")];

/// Whether the repo search skips `name` under `parent`.
pub fn skip(parent: &str, name: &str) -> bool {
    PRUNE.contains(&name)
        || DISCOVER_PRUNE.contains(&name)
        || name.ends_with(".app")
        || DISCOVER_PRUNE_PAIRS.contains(&(parent, name))
}

/// (dir, files) under root, skipping build output and dependency dirs.
/// Memoised for the process: the lockfile, install-script and image
/// checks each want the same listing of every repo; [`forget_walks`]
/// drops the memo between scans.
pub fn walk(root: &Path, depth: usize) -> Vec<(PathBuf, Vec<String>)> {
    let key = (root.to_path_buf(), depth);
    if let Some(hit) = WALKS.lock().expect("lock").get(&key).cloned() {
        return (*hit).clone();
    }
    let out = Arc::new(walk_uncached(root, depth));
    WALKS.lock().expect("lock").insert(key, out.clone());
    (*out).clone()
}

type Walks = HashMap<(PathBuf, usize), Arc<Vec<(PathBuf, Vec<String>)>>>;
static WALKS: std::sync::LazyLock<Mutex<Walks>> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Drop the memoised listings: a new scan may see changed files.
pub fn forget_walks() {
    WALKS.lock().expect("lock").clear();
}

fn walk_uncached(root: &Path, depth: usize) -> Vec<(PathBuf, Vec<String>)> {
    fn visit(d: &Path, level: usize, depth: usize, out: &mut Vec<(PathBuf, Vec<String>)>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let (mut dirs, mut files) = (Vec::new(), Vec::new());
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(t) = e.file_type() else { continue };
            // As os.walk: a symlink to a directory is listed but not walked.
            let is_dir =
                if t.is_symlink() { std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) } else { t.is_dir() };
            if !is_dir {
                files.push(name);
            } else if !t.is_symlink() && !PRUNE.contains(&name.as_str()) && level < depth {
                dirs.push(e.path());
            }
        }
        files.sort();
        dirs.sort();
        out.push((d.to_path_buf(), files));
        for sub in dirs {
            visit(&sub, level + 1, depth, out);
        }
    }
    let mut out = Vec::new();
    visit(root, 0, depth, &mut out);
    out
}
