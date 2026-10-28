//! What can go wrong, sorted by what the caller does about it: a source that
//! can't be reached or answers nonsense is reported `unchecked` (never
//! clean); a missing tool is reported `MISSING`; the cache or the filesystem
//! failing is an internal error (exit 3).

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The source could not be reached (Python: `net.Offline`).
    Offline(String),
    /// The source answered with something malformed or over a size cap
    /// (Python: `ValueError`).
    Invalid(String),
    /// An external tool ran and failed (Python: `RuntimeError`).
    Failed(String),
    /// An external tool isn't installed, or is too old (Python: `scanners.Missing`).
    Missing(String),
    /// The cache can't be opened, read or written.
    Cache(rusqlite::Error),
    /// A file we need can't be read or written.
    Io(std::io::Error),
}

impl Error {
    /// Whether this is a source failing (reported `unchecked`), as opposed
    /// to the cache or the filesystem failing (an internal error).
    pub fn is_source(&self) -> bool {
        matches!(self, Error::Offline(_) | Error::Invalid(_) | Error::Failed(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Offline(m) | Error::Invalid(m) | Error::Failed(m) | Error::Missing(m) => f.write_str(m),
            Error::Cache(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Cache(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
