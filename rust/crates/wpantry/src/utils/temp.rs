//! Private temporary directories, removed when dropped.

use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A directory removed (with its contents) when dropped.
pub struct TempDir(PathBuf);

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
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
        Ok(TempDir(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
