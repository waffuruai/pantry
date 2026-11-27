//! Private temporary directories, removed when dropped.

use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A directory removed (with its contents) when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Result<TempDir> {
        static N: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "wpantry-{label}-{}-{}-{}",
            std::process::id(),
            stamp,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        // Exclusive and private: a path someone else made first is an error,
        // never reused, and nothing extracted there is readable by others.
        // `mode` is unix-only, so this binding is mutable only there.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
        Ok(TempDir { path: dir })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Test helper: gives a folder its mode back when dropped, so a temp dir
/// whose folder a test set to mode 000 can be removed. Declare it after the
/// `TempDir` so it drops first.
#[cfg(all(test, unix))]
pub(crate) struct Reopen(pub(crate) PathBuf);

#[cfg(all(test, unix))]
impl Drop for Reopen {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}
