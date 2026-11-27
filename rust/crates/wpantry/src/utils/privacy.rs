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
    FOLLOWED.lock().expect("lock").clear();
    Guard(id)
}

impl Drop for Guard {
    fn drop(&mut self) {
        LEFT_OUT.write().expect("lock").retain(|(id, ..)| *id != self.0);
        FOLLOWED.lock().expect("lock").clear();
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
/// use wpantry::utils::privacy::{leave_out, reaches_left_out};
/// // Absolute on each platform (a path with no drive is relative on Windows).
/// let home = std::path::PathBuf::from(if cfg!(windows) { r"C:\nonexistent-home" } else { "/nonexistent-home" });
/// let guard = leave_out(vec![home.join("Documents")], vec![]);
/// assert!(reaches_left_out(home.join("Documents").join("bin")));
/// assert!(!reaches_left_out(home.join("bin")));
/// drop(guard);
/// ```
pub fn reaches_left_out(path: impl AsRef<Path>) -> bool {
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
    // By spelling, the whole path first: when it is left out nothing on the way is looked at.
    if is_left_out(&path) {
        return true;
    }
    resolved(&path, &mut 0, false).is_none()
}

/// The folders [`resolved`] has already followed for the guards alive now:
/// each spelling, and where it leads with no link left in it (`None`: into a
/// left-out folder). A walk asks about every link in a folder and a PATH
/// lookup about every name in a PATH folder, so without it each would lstat
/// every folder above them again. Emptied whenever a guard comes or goes.
static FOLLOWED: std::sync::LazyLock<Mutex<std::collections::HashMap<PathBuf, Option<PathBuf>>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Forget the folders [`reaches_left_out`] followed: a new scan may see
/// changed links ([`crate::utils::walk::forget_walks`]).
pub fn forget_followed() {
    FOLLOWED.lock().expect("lock").clear();
}

/// Where the absolute `path` leads with every link on it followed, or `None`
/// when it leads into (or through) a left-out folder. Each folder above it is
/// resolved first (and remembered, `keep`), so each component is judged by
/// spelling before it is looked at, as the system meets it: a link's target
/// is taken from the link's own folder, resolved, and `..` leaves the folder
/// that folder really is. A loop of links ([`MAX_LINKS`]) answers where it
/// stopped (not left out).
fn resolved(path: &Path, links: &mut usize, keep: bool) -> Option<PathBuf> {
    use std::path::Component;
    if let Some(hit) = FOLLOWED.lock().expect("lock").get(path) {
        return hit.clone();
    }
    let (Some(parent), Some(last)) = (path.parent(), path.components().next_back()) else {
        return Some(path.to_path_buf());
    };
    let out = match last {
        Component::Prefix(_) | Component::RootDir => Some(path.to_path_buf()),
        Component::CurDir => resolved(parent, links, true),
        // `link/..` leaves a folder the path went through.
        Component::ParentDir => resolved(parent, links, true)
            .and_then(|base| (!is_left_out(&base)).then(|| base.parent().map_or(base.clone(), Path::to_path_buf))),
        Component::Normal(name) => resolved(parent, links, true).and_then(|base| {
            let here = base.join(name);
            // Nothing in a left-out folder is looked at, not even a `symlink_metadata` of the
            // first folder in it: only the folders on the way to a path the user named.
            if is_left_out(&here) && !on_the_way_to_named(&here) {
                return None;
            }
            if std::fs::symlink_metadata(&here).is_ok_and(|m| m.file_type().is_symlink())
                && let Ok(target) = std::fs::read_link(&here)
            {
                *links += 1;
                if *links > MAX_LINKS {
                    return Some(here);
                }
                let next = if target.is_absolute() { target } else { base.join(target) };
                if is_left_out(&next) && !on_the_way_to_named(&next) {
                    return None;
                }
                return resolved(&next, links, false);
            }
            Some(here)
        }),
    };
    if keep {
        FOLLOWED.lock().expect("lock").insert(path.to_path_buf(), out.clone());
    }
    out
}

/// Whether `path` is a folder above a path the user named: the walk of a
/// path to a named subtree goes through it, so it may be looked at.
fn on_the_way_to_named(path: &Path) -> bool {
    let here = names(path);
    LEFT_OUT.read().expect("lock").iter().any(|(_, _, named)| named.iter().any(|n| n.starts_with(&here)))
}

/// Whether the symlink at `link` points into a left-out folder, read from
/// the link alone (a relative target is taken from the link's folder).
/// Following it, even to stat it, would open that folder. It reads one link:
/// a link to a link (or through a linked folder) that ends in a left-out
/// folder is only seen by [`reaches_left_out`], which a walk that goes on to
/// stat the link must use.
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
