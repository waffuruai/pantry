//! The folders an unattended scan (`--no-personal-files`) never opens.
//!
//! On macOS, listing or opening anything inside `~/Documents`, `~/Desktop`
//! or `~/Downloads` (and the other folders below) from a program that has
//! not been given access raises a privacy prompt, or is quietly denied. A
//! scan run by a GUI program or a scheduled job has nobody to answer it, so
//! these folders are left out by path, before anything touches them: an
//! error after the fact would come too late, since the read itself raises
//! the prompt.
//!
//! [`folders`] says which folders; [`leave_out`] makes them off limits for
//! the rest of a scan, to every walk, the repo search, the persistence
//! checks and the PATH lookup ([`is_left_out`]). Paths are compared as
//! spelled (and against the home folder's canonical spelling), never
//! resolved: resolving would open them.
//!
//! ```
//! use std::path::Path;
//! use wpantry::utils::privacy::{folders, is_left_out, leave_out};
//! let home = Path::new("/nonexistent-home-for-doctest");
//! let guard = leave_out(folders(home, false), vec![home.join("Documents/named")]);
//! assert!(is_left_out(&home.join("Documents/repo/.git")));
//! assert!(!is_left_out(&home.join("Documents/named/.git")));
//! assert!(!is_left_out(&home.join("code/repo")));
//! drop(guard);
//! assert!(!is_left_out(&home.join("Documents/repo/.git")));
//! ```

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

/// The personal folders under the home folder, on every system.
pub const PERSONAL: &[&str] = &["Downloads", "Desktop", "Documents"];

/// What else macOS guards with a prompt or a quiet denial for a program
/// without Full Disk Access, under the home folder. A scan has no use for
/// other apps' private data (mail, messages, calendars, contacts, browser
/// data, app containers), and cloud drives and media libraries hold the
/// user's files like Documents does, so an unattended scan opens none of
/// them.
pub const MACOS_GUARDED: &[&str] = &[
    "Pictures",
    "Music",
    "Movies",
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
    "Library/Calendars",
    "Library/Application Support/AddressBook",
    "Library/Containers",
    "Library/Group Containers",
];

/// The folders an unattended scan leaves out under `home`: [`PERSONAL`],
/// and on macOS (`mac`) [`MACOS_GUARDED`] too. Each is given in `home`'s
/// spelling and, when it differs, in its canonical one (resolving the home
/// folder itself raises no prompt).
pub fn folders(home: &Path, mac: bool) -> Vec<PathBuf> {
    let mut bases = vec![home.to_path_buf()];
    if let Ok(canon) = std::fs::canonicalize(home)
        && canon != home
    {
        bases.push(canon);
    }
    let names = PERSONAL.iter().chain(if mac { MACOS_GUARDED } else { &[] });
    let names: Vec<&str> = names.copied().collect();
    bases.iter().flat_map(|b| names.iter().map(move |n| b.join(n))).collect()
}

/// What one [`Guard`] leaves out: the folders, and the paths the user named
/// that stay in even when they lie inside one.
type Entry = (u64, Vec<PathBuf>, Vec<PathBuf>);

/// The folders left out now, one entry per [`Guard`] alive.
static LEFT_OUT: RwLock<Vec<Entry>> = RwLock::new(Vec::new());
static NEXT: Mutex<u64> = Mutex::new(0);

/// Keeps its folders left out until dropped. Several can be alive at once
/// (tests run scans side by side); a path is left out while any guard
/// names a folder holding it.
#[derive(Debug)]
pub struct Guard(u64);

/// Leave `dirs` and everything under them out until the guard is dropped,
/// except the paths in `named` and what lies under them: a path the user
/// named is scanned as asked, and only that subtree, so its siblings in the
/// same personal folder stay out for every pass.
pub fn leave_out(dirs: Vec<PathBuf>, named: Vec<PathBuf>) -> Guard {
    let id = {
        let mut n = NEXT.lock().expect("lock");
        *n += 1;
        *n
    };
    LEFT_OUT.write().expect("lock").push((id, dirs, named));
    Guard(id)
}

impl Drop for Guard {
    fn drop(&mut self) {
        LEFT_OUT.write().expect("lock").retain(|(id, ..)| *id != self.0);
    }
}

/// Whether `path` is a left-out folder or lies inside one, by its
/// spelling: nothing is opened or resolved to answer. A path at or under
/// one the user named is not left out by that guard.
pub fn is_left_out(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    let held = LEFT_OUT.read().expect("lock");
    held.iter()
        .any(|(_, dirs, named)| dirs.iter().any(|d| path.starts_with(d)) && !named.iter().any(|n| path.starts_with(n)))
}

/// Whether the symlink at `link` points into a left-out folder, read from
/// the link alone (a relative target is taken from the link's folder).
/// Following it, even to stat it, would open that folder.
pub fn link_left_out(link: &Path) -> bool {
    if LEFT_OUT.read().expect("lock").is_empty() {
        return false;
    }
    std::fs::read_link(link).is_ok_and(|target| {
        let target = if target.is_absolute() { target } else { link.parent().unwrap_or(link).join(target) };
        is_left_out(lexical(&target))
    })
}

/// `path` with `.` and `..` folded by spelling (`/h/code/../Documents` is
/// `/h/Documents`), without asking the file system.
fn lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[path = "privacy_tests.rs"]
mod tests;
