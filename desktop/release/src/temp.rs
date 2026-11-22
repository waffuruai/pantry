//! A temporary directory this process created itself, removed when dropped,
//! like Python's `tempfile.TemporaryDirectory`.
//!
//! ```text
//! let work = TempDir::new("pantry-sign-")?;
//! std::fs::write(work.path().join("x"), b"y")?;
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// A new, empty directory under the system temp directory. `create_dir`
    /// fails on an existing path, so it never adopts (or later removes) a
    /// directory someone else made.
    pub fn new(prefix: &str) -> Result<TempDir, String> {
        let base = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for _ in 0..100 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{prefix}{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Err(format!(
            "could not make a temporary directory in {}",
            base.display()
        ))
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
