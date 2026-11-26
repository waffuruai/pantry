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
//! checks and the PATH lookup ([`is_left_out`]). Paths are compared by
//! their spelling (and against the home folder's canonical spelling), never
//! resolved: resolving would open them. The spelling is normalised first:
//! `.` and `..` are folded (`/h/Library/../Documents/x` is `/h/Documents/x`),
//! and on macOS and Windows, whose volumes ignore case by default, names
//! are compared without regard to case (`/h/documents/x` is in `Documents`).
//! On Linux they are compared exactly: its file systems are case-sensitive,
//! so `documents` is another folder than `Documents`. Unicode normalisation
//! is not folded.
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
/// that stay in even when they lie inside one, each as its [`names`].
type Entry = (u64, Vec<Vec<String>>, Vec<Vec<String>>);

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
    let norm = |paths: Vec<PathBuf>| paths.iter().map(|p| names(p)).collect::<Vec<_>>();
    LEFT_OUT.write().expect("lock").push((id, norm(dirs), norm(named)));
    Guard(id)
}

impl Drop for Guard {
    fn drop(&mut self) {
        LEFT_OUT.write().expect("lock").retain(|(id, ..)| *id != self.0);
    }
}

/// Whether `path` is a left-out folder or lies inside one, by its
/// spelling (see the module docs: `..` folded, case ignored on macOS and
/// Windows): nothing is opened or resolved to answer. A path at or under one
/// the user named is not left out by that guard.
pub fn is_left_out(path: impl AsRef<Path>) -> bool {
    let held = LEFT_OUT.read().expect("lock");
    if held.is_empty() {
        return false;
    }
    let path = names(path.as_ref());
    held.iter()
        .any(|(_, dirs, named)| dirs.iter().any(|d| path.starts_with(d)) && !named.iter().any(|n| path.starts_with(n)))
}

/// Whether `path` is `dir` or lies under it, compared the way
/// [`is_left_out`] does: by spelling, `.` and `..` folded, and without
/// regard to case on macOS and Windows.
pub fn within(path: impl AsRef<Path>, dir: impl AsRef<Path>) -> bool {
    names(path.as_ref()).starts_with(&names(dir.as_ref()))
}

/// The most links [`reaches_left_out`] follows before it gives up and says no
/// (a loop of links).
const MAX_LINKS: usize = 40;

/// Whether `path` is left out ([`is_left_out`]) or reaches a left-out folder
/// through a symbolic link on the way: `~/bin` that is a link to
/// `~/Documents/bin`, `~/work/link/bin` for a link to `~/Documents`, a
/// relative path from a folder that is one. Each link met is read (never
/// followed with a stat first), and its target is judged by the same
/// spelling rule, so no left-out folder is opened to find out: only the
/// links on the way, which are in folders that are not left out, are looked
/// at. A loop of links, a link that points nowhere and a path that does not
/// exist are not left out. The cheap spelling check ([`is_left_out`]) is the
/// one for a walk that does not follow links; this one is for a path a
/// program is about to be looked up, stat'ed or opened at.
///
/// ```
/// use std::path::Path;
/// use wpantry::utils::privacy::{leave_out, reaches_left_out};
/// let guard = leave_out(vec![Path::new("/nonexistent-home/Documents").to_path_buf()], vec![]);
/// assert!(reaches_left_out("/nonexistent-home/Documents/bin"));
/// assert!(!reaches_left_out("/nonexistent-home/bin"));
/// drop(guard);
/// ```
pub fn reaches_left_out(path: impl AsRef<Path>) -> bool {
    use std::path::Component;
    if LEFT_OUT.read().expect("lock").is_empty() {
        return false;
    }
    let mut path = path.as_ref().to_path_buf();
    if path.is_relative() {
        match std::env::current_dir() {
            Ok(cwd) => path = cwd.join(path),
            Err(_) => return false,
        }
    }
    'again: for _ in 0..=MAX_LINKS {
        // By spelling, the whole path first: when it is left out nothing on the way is looked at.
        // A path inside a named subtree is not, and its ancestors (the folder itself) may be
        // looked at to find the links on the way.
        if is_left_out(&path) {
            return true;
        }
        let mut so_far = PathBuf::new();
        let mut parts = path.components();
        while let Some(part) = parts.next() {
            match part {
                Component::ParentDir => {
                    // `link/..` leaves a folder the path went through.
                    if is_left_out(&so_far) {
                        return true;
                    }
                    so_far.pop();
                    continue;
                }
                Component::CurDir => continue,
                other => so_far.push(other),
            }
            if std::fs::symlink_metadata(&so_far).is_ok_and(|m| m.file_type().is_symlink())
                && let Ok(target) = std::fs::read_link(&so_far)
            {
                let base =
                    if target.is_absolute() { PathBuf::new() } else { so_far.parent().unwrap_or(&so_far).into() };
                path = base.join(target).join(parts.as_path());
                continue 'again;
            }
        }
        return false;
    }
    false
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
        is_left_out(target)
    })
}

/// The names in `path`, `.` and `..` folded by spelling (`/h/code/../Documents`
/// is `/h/Documents`) without asking the file system, and lower-cased where the
/// volumes ignore case (macOS, Windows): two spellings of one place give the
/// same list, and a folder holds a path when its list starts the path's.
fn names(path: &Path) -> Vec<String> {
    use std::path::Component;
    let mut out: Vec<String> = Vec::new();
    // `canonicalize` gives a Windows path as `\\?\C:\x`: the same place as `C:\x`.
    let plain = super::files::strip_verbatim(&path.to_string_lossy());
    for c in Path::new(&plain).components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => {
                let name = other.as_os_str().to_string_lossy();
                out.push(if cfg!(any(target_os = "macos", windows)) { name.to_lowercase() } else { name.into_owned() });
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "privacy_tests.rs"]
mod tests;
