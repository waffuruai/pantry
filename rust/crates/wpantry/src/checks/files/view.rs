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
mod tests {
    use super::*;
    use crate::utils::temp::TempDir;

    #[test]
    fn a_view_stats_once_and_reads_its_head_once() {
        let d = TempDir::new("view").unwrap();
        let p = d.path().join("a.sh");
        std::fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
        let v = FileView::new(p.clone());
        assert!(v.stat().is_some_and(|s| s.file && !s.link && s.size == 18));
        assert_eq!(&v.head()[..2], b"#!");
        assert_eq!(v.head().len(), 18);
        assert_eq!(opens(&p), 1, "the head is read once");
        assert_eq!(v.read(1 << 20).map(|b| b.len()), Some(18));
        assert_eq!(opens(&p), 2);
    }

    #[test]
    fn caps_links_and_missing_files() {
        let d = TempDir::new("view").unwrap();
        let big = d.path().join("big");
        std::fs::write(&big, vec![b'x'; 100]).unwrap();
        assert_eq!(FileView::new(big.clone()).read(10), None, "over the cap");
        assert_eq!(FileView::new(big.clone()).head().len(), HEAD, "the head of a file over the cap");
        let gone = FileView::new(d.path().join("gone"));
        assert_eq!((gone.stat(), gone.read(10), gone.head().len()), (None, None, 0));
        #[cfg(unix)]
        {
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&big, &link).unwrap();
            assert!(FileView::new(link).stat().is_some_and(|s| s.file && s.link));
            assert!(FileView::new(d.path().to_path_buf()).stat().is_some_and(|s| !s.file && !s.link));
        }
    }
}
