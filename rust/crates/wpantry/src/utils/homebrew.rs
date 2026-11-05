//! Homebrew's prefix and its installed casks, read without starting brew
//! where the Caskroom says.

use super::process::{run, which};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn brew_prefix() -> String {
    brew_prefix_of(which("brew"))
}

/// What the `brew` at `brew` says its prefix is, or "" without one.
fn brew_prefix_of(brew: Option<PathBuf>) -> String {
    match brew {
        Some(b) => run(&[b.as_os_str(), "--prefix".as_ref()], Duration::from_secs(15)).trim().to_string(),
        None => String::new(),
    }
}

/// Homebrew's prefix: HOMEBREW_PREFIX, else the folder above the `bin` the
/// `brew` on PATH is in (how brew finds its own).
pub fn homebrew_prefix(brew: &Path) -> Option<PathBuf> {
    std::env::var_os("HOMEBREW_PREFIX")
        .map(PathBuf::from)
        .or_else(|| brew.parent().and_then(Path::parent).map(Path::to_path_buf))
}

/// {cask: version} from the Caskroom, what `brew list --cask --versions`
/// says without starting Homebrew's Ruby. Symlinks are skipped, as brew
/// does: a renamed cask's old token, a cask's `latest`. None when there's
/// no Caskroom or a cask has more than one version installed (brew says
/// which it lists).
pub fn caskroom(dir: &Path) -> Option<BTreeMap<String, String>> {
    let entries = |d: &Path| -> Option<Vec<std::fs::DirEntry>> {
        Some(
            std::fs::read_dir(d)
                .ok()?
                .filter_map(|e| e.ok())
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter(|e| !e.file_type().is_ok_and(|t| t.is_symlink()))
                .collect(),
        )
    };
    let mut out = BTreeMap::new();
    for cask in entries(dir)? {
        let name = cask.file_name().to_string_lossy().into_owned();
        let versions: Vec<String> =
            entries(&cask.path())?.iter().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        let [v] = versions.as_slice() else { return None };
        out.insert(name, v.clone());
    }
    Some(out)
}

/// {cask token: installed version} for Homebrew-installed casks.
pub fn brew_casks() -> BTreeMap<String, String> {
    let brew = which("brew");
    brew_casks_in(brew.as_deref().and_then(homebrew_prefix), brew.as_deref())
}

/// [`brew_casks`] for the Homebrew at `prefix` with its `brew` command.
fn brew_casks_in(prefix: Option<PathBuf>, brew: Option<&Path>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(b) = brew {
        if let Some(casks) = prefix.and_then(|p| caskroom(&p.join("Caskroom"))) {
            return casks;
        }
        for line in
            run(&[b.as_os_str(), "list".as_ref(), "--cask".as_ref(), "--versions".as_ref()], Duration::from_secs(60))
                .lines()
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                out.insert(parts[0].to_string(), parts[parts.len() - 1].to_string());
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "homebrew_tests.rs"]
mod tests;
