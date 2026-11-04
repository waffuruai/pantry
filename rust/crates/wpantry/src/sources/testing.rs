//! Test helpers the sources and their checks share.

use crate::db::Cache;
use crate::utils::temp::TempDir;

/// A cache in a fresh temporary directory, which lives as long as it.
pub(crate) fn cache() -> (TempDir, Cache) {
    let d = TempDir::new("feeds").unwrap();
    let c = cache_in(&d);
    (d, c)
}

/// A cache in `d`.
pub(crate) fn cache_in(d: &TempDir) -> Cache {
    Cache::open(Some(&d.path().join("w.db"))).unwrap()
}

/// Owned strings, for license ids and the like.
pub(crate) fn ids(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}
