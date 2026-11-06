//! One file as every check sees it: its path, what `stat` says, and its
//! first bytes or its contents, each read at most once however many checks
//! ask.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// How many first bytes [`FileView::head`] reads: enough for every magic
/// number a check looks at.
pub const HEAD: usize = 64;

/// How many times a [`FileView`] opened each file, in tests: the evidence
/// that each file is opened once per scan.
#[cfg(test)]
static OPENED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>> =
    std::sync::LazyLock::new(Default::default);

fn opened(_path: &Path) {
    #[cfg(test)]
    {
        *OPENED.lock().expect("lock").entry(_path.to_path_buf()).or_default() += 1;
    }
}

/// How many times a [`FileView`] has opened `path` in this process.
#[cfg(test)]
pub fn opens(path: &Path) -> usize {
    OPENED.lock().expect("lock").get(path).copied().unwrap_or(0)
}

/// What `stat` says about a file, following a symlink, and whether the
/// path itself is one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stat {
    /// A regular file, after following a symlink.
    pub file: bool,
    /// The path is a symlink.
    pub link: bool,
    pub size: u64,
    /// Device, inode, size and modification time: what a cache keys on.
    pub id: (i64, i64, i64, f64),
}

impl Stat {
    fn of(path: &Path) -> Option<Stat> {
        // One syscall for all but symlinks: lstat, then stat only to follow a link.
        let l = std::fs::symlink_metadata(path).ok()?;
        let link = l.file_type().is_symlink();
        let m = if link { std::fs::metadata(path).ok()? } else { l };
        let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs_f64();
        #[cfg(unix)]
        let id = {
            use std::os::unix::fs::MetadataExt;
            (m.dev() as i64, m.ino() as i64, m.len() as i64, mtime)
        };
        #[cfg(not(unix))]
        let id = (0, 0, m.len() as i64, mtime);
        Some(Stat { file: m.is_file(), link, size: m.len(), id })
    }
}

/// One file: stat once, and its first bytes read at most once. Its
/// contents are read by [`FileView::read`], once, by the pass that hands
/// them to every check that wants them.
pub struct FileView {
    pub path: PathBuf,
    stat: OnceLock<Option<Stat>>,
    head: OnceLock<Vec<u8>>,
}

impl FileView {
    pub fn new(path: PathBuf) -> FileView {
        FileView { path, stat: OnceLock::new(), head: OnceLock::new() }
    }

    pub fn stat(&self) -> Option<Stat> {
        *self.stat.get_or_init(|| Stat::of(&self.path))
    }

    /// The whole file, refused (None) when it is over `cap` or not a
    /// regular file ([`crate::utils::files::read_capped_bytes`]).
    pub fn read(&self, cap: u64) -> Option<Vec<u8>> {
        opened(&self.path);
        crate::utils::files::read_capped_bytes(&self.path, cap).ok()
    }

    /// The file opened once: its first bytes, then the whole of it when a
    /// check reads it whole (`always`, the most it reads) or reads it whole
    /// only when those bytes say it is a program (`programs`, judged by
    /// `program`). The whole is refused (None) over its cap or when the
    /// file isn't a regular one, as
    /// [`crate::utils::files::read_capped_bytes`] refuses.
    pub fn load(&self, always: u64, programs: u64, program: fn(&[u8]) -> bool) -> (Vec<u8>, Option<Vec<u8>>) {
        opened(&self.path);
        let Ok(mut f) = std::fs::File::open(&self.path) else { return (Vec::new(), None) };
        let Ok(meta) = f.metadata() else { return (Vec::new(), None) };
        if !meta.is_file() {
            return (Vec::new(), None);
        }
        let mut bytes = Vec::with_capacity(HEAD);
        if (&mut f).take(HEAD as u64).read_to_end(&mut bytes).is_err() {
            return (Vec::new(), None);
        }
        let head = bytes.clone();
        let cap = if program(&head) { always.max(programs) } else { always };
        if cap == 0 || meta.len() > cap {
            return (head, None);
        }
        bytes.reserve(meta.len().saturating_sub(bytes.len() as u64) as usize);
        let whole = (&mut f).take((cap + 1).saturating_sub(bytes.len() as u64)).read_to_end(&mut bytes);
        if whole.is_err() || bytes.len() as u64 > cap {
            return (head, None);
        }
        (head, Some(bytes))
    }

    /// Up to [`HEAD`] first bytes; empty when it can't be read.
    pub fn head(&self) -> &[u8] {
        self.head.get_or_init(|| {
            opened(&self.path);
            let mut head = Vec::with_capacity(HEAD);
            if let Ok(f) = std::fs::File::open(&self.path) {
                let _ = f.take(HEAD as u64).read_to_end(&mut head);
            }
            head
        })
    }
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
