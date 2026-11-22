//! What `--deep` reads: `~` first, then the rest of the computer this user
//! can read, as roots of the files pass that don't overlap.
//!
//! - **macOS:** the data volume's folders, as `/usr/share/firmlinks` names
//!   them (`/Applications`, `/Library`, `/Users`, `/opt`, `/private`,
//!   `/usr/local`, …), never the read-only system volume they sit beside;
//!   then each local volume mounted under `/Volumes`.
//! - **Linux:** `/`, less the pseudo-filesystems (`/proc`, `/sys`, `/dev`,
//!   `/run`) and every network or pseudo mount `/proc/self/mounts` lists.
//! - **Elsewhere:** `~` alone.
//!
//! A root that holds a place it must leave out (`~`, read first; a network
//! mount) is replaced by its children, down to that place, and its own
//! files are read as a root of depth 0. Network mounts are never read.

use std::path::{Path, PathBuf};

/// How deep `--deep` walks each root.
pub const DEPTH: usize = 32;

/// One root of a deep scan: where, and how many levels down (0: the
/// folder's own files only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub path: PathBuf,
    pub depth: usize,
}

/// The roots of a deep scan of this computer: `home` first. Found once
/// per scan ([`forget`] drops them).
pub fn deep(home: &Path) -> Vec<Root> {
    if let Some(r) = FOUND.lock().expect("lock").get(home) {
        return r.clone();
    }
    let mut out = vec![Root { path: home.to_path_buf(), depth: DEPTH }];
    let (bases, mut avoid) = system();
    avoid.push(home.to_path_buf());
    for base in bases {
        cover(&base, &avoid, &mut out);
    }
    FOUND.lock().expect("lock").insert(home.to_path_buf(), out.clone());
    out
}

static FOUND: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<PathBuf, Vec<Root>>>> =
    std::sync::LazyLock::new(Default::default);

/// Forget the roots found: the next scan looks again (a volume may have
/// been mounted).
pub fn forget() {
    FOUND.lock().expect("lock").clear();
}

/// The places past `~` a deep scan starts from, and those it leaves out.
#[cfg(not(test))]
fn system() -> (Vec<PathBuf>, Vec<PathBuf>) {
    if cfg!(target_os = "macos") {
        let firmlinks = std::fs::read_to_string("/usr/share/firmlinks").unwrap_or_default();
        let mounts = crate::utils::process::run(&["mount"], std::time::Duration::from_secs(10));
        (macos_bases(&firmlinks, &mounts), Vec::new())
    } else if cfg!(target_os = "linux") {
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
        (vec![PathBuf::from("/")], linux_avoid(&mounts))
    } else {
        (Vec::new(), Vec::new())
    }
}

/// In a test, the folders the test asks for, never the machine's.
#[cfg(test)]
fn system() -> (Vec<PathBuf>, Vec<PathBuf>) {
    TEST_SYSTEM.with(|s| s.borrow().clone())
}

#[cfg(test)]
thread_local! {
    static TEST_SYSTEM: std::cell::RefCell<(Vec<PathBuf>, Vec<PathBuf>)> = const { std::cell::RefCell::new((Vec::new(), Vec::new())) };
}

/// For a test: the folders past `~` this thread's deep scans read, and
/// those they leave out.
#[cfg(test)]
pub fn set_test_system(bases: Vec<PathBuf>, avoid: Vec<PathBuf>) {
    TEST_SYSTEM.with(|s| *s.borrow_mut() = (bases, avoid));
}

/// macOS: the firmlinked folders (the data volume's, at the top of `/`),
/// then the local volumes under `/Volumes`.
pub fn macos_bases(firmlinks: &str, mounts: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for line in firmlinks.lines() {
        let Some(first) = line.split('\t').next().map(str::trim).filter(|p| p.starts_with('/')) else { continue };
        // The other volumes are read below, one by one; /System's are the OS's own caches.
        if first == "/Volumes" || first.starts_with("/System/") {
            continue;
        }
        let p = PathBuf::from(first);
        // A folder under one already listed is read with it.
        if !out.iter().any(|o| p.starts_with(o)) {
            out.retain(|o| !o.starts_with(&p));
            out.push(p);
        }
    }
    for line in mounts.lines() {
        // `/dev/disk4s1 on /Volumes/Backup (apfs, local, nodev, nosuid, journaled)`
        let Some((_, rest)) = line.split_once(" on ") else { continue };
        let Some((path, opts)) = rest.rsplit_once(" (") else { continue };
        let opts: Vec<&str> = opts.trim_end_matches(')').split(", ").collect();
        // Network volumes aren't `local`; the system's own (Recovery, updates) are `nobrowse`.
        if !path.starts_with("/Volumes/") || !opts.contains(&"local") || opts.contains(&"nobrowse") {
            continue;
        }
        out.push(PathBuf::from(path));
    }
    out
}

/// Linux: what a walk of `/` leaves out: the pseudo-filesystems and every
/// network or pseudo mount.
pub fn linux_avoid(mounts: &str) -> Vec<PathBuf> {
    const NOT_FILES: &[&str] = &[
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "securityfs",
        "debugfs",
        "tracefs",
        "configfs",
        "fusectl",
        "pstore",
        "bpf",
        "mqueue",
        "hugetlbfs",
        "binfmt_misc",
        "autofs",
        "efivarfs",
        "rpc_pipefs",
        "nsfs",
    ];
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "sshfs",
        "fuse.sshfs",
        "fuse.rclone",
        "davfs",
        "fuse.davfs2",
        "afs",
        "ceph",
        "glusterfs",
        "fuse.glusterfs",
        "9p",
        "virtiofs",
        "fuse.s3fs",
        "lustre",
    ];
    let mut out: Vec<PathBuf> = ["/proc", "/sys", "/dev", "/run"].iter().map(PathBuf::from).collect();
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_), Some(at), Some(kind)) = (f.next(), f.next(), f.next()) else { continue };
        // Spaces in a mount point are written \040.
        let at = at.replace("\\040", " ");
        if NOT_FILES.contains(&kind) || NETWORK.contains(&kind) {
            let p = PathBuf::from(at);
            if p != Path::new("/") && !out.iter().any(|o| p.starts_with(o)) {
                out.push(p);
            }
        }
    }
    out
}

/// `base` as roots that leave out every place in `avoid`: itself, when
/// none is under it; nothing, when it is one; otherwise its own files
/// (depth 0) and each child folder, covered the same way.
pub fn cover(base: &Path, avoid: &[PathBuf], out: &mut Vec<Root>) {
    if avoid.iter().any(|a| base.starts_with(a)) || !base.is_dir() {
        return;
    }
    if !avoid.iter().any(|a| a.starts_with(base)) {
        out.push(Root { path: base.to_path_buf(), depth: DEPTH });
        return;
    }
    out.push(Root { path: base.to_path_buf(), depth: 0 });
    let Ok(rd) = std::fs::read_dir(base) else {
        crate::utils::walk::note_unreadable(base, base);
        return;
    };
    let mut kids: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))
        .map(|e| e.path())
        .collect();
    kids.sort();
    for k in kids {
        cover(&k, avoid, out);
    }
}

#[cfg(test)]
#[path = "roots_tests.rs"]
mod tests;
