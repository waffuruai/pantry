//! The files the content checks read: malware, suspect code, hidden text,
//! documents. One walk lists each root, and each file is one [`FileView`]:
//! stat once, open once, whichever checks want it.

pub mod view;

pub use view::{FileView, Stat};

use std::path::{Path, PathBuf};

/// Every file under `root`, `depth` levels down, in walk order: the
/// bounded, memoised walk ([`crate::utils::walk::walk`]) every check shares.
pub fn listing(root: &Path, depth: usize) -> Vec<PathBuf> {
    crate::utils::walk::walk(root, depth)
        .into_iter()
        .flat_map(|(dir, files)| files.into_iter().map(move |f| dir.join(f)))
        .collect()
}
