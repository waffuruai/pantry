//! The files the content checks read: malware, suspect code, hidden text,
//! documents. One walk lists each root, and each file is one [`FileView`]:
//! stat once, open once, whichever checks want it.
//!
//! Each check is three steps ([`pass`]): which files it reads, decided
//! from names and sizes alone (its limits included); what it finds in one
//! file; and its findings for the root, from those. The pass reads each
//! file once and hands it to every check that wants it.

pub mod cache;
pub mod pass;
pub mod view;

pub use pass::{Check, Job, Results};
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

/// One file a check reads.
#[derive(Clone, Debug, PartialEq)]
pub struct Read {
    pub path: PathBuf,
    /// Relative to the root, as the check's findings name it.
    pub rel: String,
    /// The most of it read; 0 for its first bytes only ([`view::HEAD`]).
    pub cap: u64,
    /// What the file is to its check, in the check's own numbering.
    pub role: u8,
}

/// One file as a check's per-file step sees it.
pub struct Contents<'a> {
    /// The whole file, when the check asked for it and it was read within
    /// the check's cap.
    pub bytes: Option<&'a [u8]>,
    /// Its first bytes, when the check asked for them.
    pub head: &'a [u8],
}

impl Contents<'_> {
    /// The contents as text (invalid UTF-8 replaced), as
    /// [`crate::utils::files::read_capped`] reads it.
    pub fn text(&self) -> Option<String> {
        self.bytes.map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

/// What `stat` says about a listed file, for a check's plan.
pub type Stats<'a> = &'a dyn Fn(&Path) -> Option<Stat>;
