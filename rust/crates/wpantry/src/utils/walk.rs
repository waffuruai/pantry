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

/// On macOS the default repo search of `$HOME` (no `--path`) also leaves
/// out the media folders: they hold no code projects, and opening them
/// raises a privacy prompt. A `--path` inside one is walked as asked.
pub const MAC_MEDIA_FOLDERS: &[&str] = &["Pictures", "Music", "Movies"];
/// The Photos and Music library bundles, wherever the default macOS
/// search meets them (one moved out of `~/Pictures` is still a library).
const MAC_MEDIA_BUNDLES: &[&str] = &[".photoslibrary", ".musiclibrary"];

/// Whether `name` is a Photos or Music library bundle (`Photos Library.photoslibrary`).
pub fn media_bundle(name: &str) -> bool {
    MAC_MEDIA_BUNDLES.iter().any(|ext| name.len() > ext.len() && name.ends_with(ext))
}

/// Whether the repo search skips `name` under `parent`.
pub fn skip(parent: &str, name: &str) -> bool {
    PRUNE.contains(&name)
        || DISCOVER_PRUNE.contains(&name)
        || name.ends_with(".app")
        || DISCOVER_PRUNE_PAIRS.contains(&(parent, name))
}

/// How deep a root is walked, whatever depth is asked: the deepest any
/// check reads (the malware scan's repo programs). A shallower walk is
/// this one cut short, so every check of a root shares one walk.
pub const DEEPEST: usize = 12;

/// (dir, files) under root, `depth` levels down, skipping build output and
/// dependency dirs. Memoised for the process: every repo check wants the
/// same listing of every repo; [`forget_walks`] drops the memo between
/// scans.
pub fn walk(root: &Path, depth: usize) -> Vec<(PathBuf, Vec<String>)> {
    walk_seen(root, depth, &|_, _| {})
}

/// [`walk`], telling `seen` each folder as it is listed, with how many
/// files it holds (nothing when the listing is already memoised).
///
/// ```
/// let root = std::env::temp_dir();
/// let n = std::sync::atomic::AtomicUsize::new(0);
/// wpantry::utils::walk::walk_seen(&root, 0, &|_dir, _files| {
///     n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
/// });
/// ```
pub fn walk_seen(root: &Path, depth: usize, seen: &(dyn Fn(&Path, usize) + Sync)) -> Vec<(PathBuf, Vec<String>)> {
    let hit = WALKS.lock().expect("lock").get(root).cloned();
    let walked = match hit {
        Some(w) if w.0 >= depth => w,
        _ => {
            let deep = depth.max(DEEPEST);
            let w = Arc::new((deep, walk_uncached(root, deep, seen)));
            WALKS.lock().expect("lock").insert(root.to_path_buf(), w.clone());
            w
        }
    };
    walked.1.iter().filter(|(_, level, _)| *level <= depth).map(|(d, _, f)| (d.clone(), f.clone())).collect()
}

/// Leave `dirs` (and everything under them) out of every later walk of
/// `root`; an empty list walks it whole again. Set per root, so scans of
/// other roots (tests run several at once) are untouched. A changed list
/// drops the memoised walk of `root`.
///
/// Example: `exclude_under(home, vec![home.join("Documents")])` before a
/// scan of a home that is a git checkout keeps `~/Documents` unread.
pub fn exclude_under(root: &Path, dirs: Vec<PathBuf>) {
    let mut ex = EXCLUDED.lock().expect("lock");
    let changed = ex.get(root).map_or(!dirs.is_empty(), |d| *d != dirs);
    if dirs.is_empty() {
        ex.remove(root);
    } else {
        ex.insert(root.to_path_buf(), dirs);
    }
    if changed {
        WALKS.lock().expect("lock").remove(root);
    }
}

/// The directories [`exclude_under`] leaves out, per root.
static EXCLUDED: std::sync::LazyLock<Mutex<HashMap<PathBuf, Vec<PathBuf>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Each root's walk: how deep, and each directory with its level.
type Walks = HashMap<PathBuf, Arc<(usize, Vec<(PathBuf, usize, Vec<String>)>)>>;
static WALKS: std::sync::LazyLock<Mutex<Walks>> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Walk `roots` side by side into the memo, so the checks that ask next
/// find them walked.
pub fn prewalk(roots: &[PathBuf]) {
    prewalk_seen(roots, &|_, _| {});
}

/// [`prewalk`], telling `seen` each folder as it is listed ([`walk_seen`]).
pub fn prewalk_seen(roots: &[PathBuf], seen: &(dyn Fn(&Path, usize) + Sync)) {
    crate::utils::parallel::par_map(roots, crate::utils::parallel::cores(), |r| {
        walk_seen(r, DEEPEST, seen);
    });
}

/// Drop the memoised listings: a new scan may see changed files.
pub fn forget_walks() {
    WALKS.lock().expect("lock").clear();
    UNREADABLE.lock().expect("lock").clear();
    crate::checks::files::roots::forget();
}

/// The folders under each root its walk couldn't list: this user may not
/// read them (on macOS, a terminal without Full Disk Access). Never a
/// folder that went away while it was walked.
static UNREADABLE: std::sync::LazyLock<Mutex<HashMap<PathBuf, Vec<PathBuf>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Note that `dir`, under `root`, couldn't be listed.
pub fn note_unreadable(root: &Path, dir: &Path) {
    let mut u = UNREADABLE.lock().expect("lock");
    let dirs = u.entry(root.to_path_buf()).or_default();
    if !dirs.iter().any(|d| d == dir) {
        dirs.push(dir.to_path_buf());
    }
}

/// The folders under `root` this scan's walks couldn't list, in walk order.
pub fn unreadable(root: &Path) -> Vec<PathBuf> {
    UNREADABLE.lock().expect("lock").get(root).cloned().unwrap_or_default()
}

type Seen<'a> = &'a (dyn Fn(&Path, usize) + Sync);

fn walk_uncached(root: &Path, depth: usize, seen: Seen) -> Vec<(PathBuf, usize, Vec<String>)> {
    type Out = Vec<(PathBuf, usize, Vec<String>)>;
    fn visit(root: &Path, d: &Path, level: usize, depth: usize, skip: &[PathBuf], seen: Seen, out: &mut Out) {
        let rd = match std::fs::read_dir(d) {
            Ok(rd) => rd,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    note_unreadable(root, d);
                }
                return;
            }
        };
        let (mut dirs, mut files) = (Vec::new(), Vec::new());
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(t) = e.file_type() else { continue };
            // A link into a left-out folder is not followed, not even to stat it:
            // that would open the folder (`read_link` reads only the link).
            if t.is_symlink() && crate::utils::privacy::reaches_left_out(e.path()) {
                continue;
            }
            // As os.walk: a symlink to a directory is listed but not walked.
            let is_dir =
                if t.is_symlink() { std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) } else { t.is_dir() };
            if !is_dir {
                files.push(name);
            } else if !t.is_symlink()
                && !PRUNE.contains(&name.as_str())
                && level < depth
                && !skip.iter().any(|x| e.path().starts_with(x))
                && !crate::utils::privacy::is_left_out(e.path())
            {
                dirs.push(e.path());
            }
        }
        files.sort();
        dirs.sort();
        seen(d, files.len());
        out.push((d.to_path_buf(), level, files));
        for sub in dirs {
            visit(root, &sub, level + 1, depth, skip, seen, out);
        }
    }
    if crate::utils::privacy::reaches_left_out(root) {
        return Vec::new();
    }
    let skip = EXCLUDED.lock().expect("lock").get(root).cloned().unwrap_or_default();
    let mut out = Vec::new();
    visit(root, root, 0, depth, &skip, seen, &mut out);
    out
}
