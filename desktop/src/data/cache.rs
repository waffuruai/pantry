//! Where the scanner keeps its cache, and when it last changed.

use std::path::PathBuf;

/// Where the scanner keeps its cache. Mirrors `wpantry::db::path` in the
/// Rust workspace: WPANTRY_DB, else $XDG_CACHE_HOME/wpantry/wpantry.db,
/// else ~/.cache/wpantry/wpantry.db, else %LOCALAPPDATA% on Windows.
pub fn cache_path() -> PathBuf {
    cache_path_from(&|name| std::env::var_os(name))
}

fn cache_path_from(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let var = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(path) = var("WPANTRY_DB") {
        return path;
    }
    let base = var("XDG_CACHE_HOME")
        .or_else(|| var("HOME").map(|home| home.join(".cache")))
        .or_else(|| {
            if cfg!(windows) {
                var("LOCALAPPDATA")
            } else {
                None
            }
        })
        .unwrap_or_else(|| PathBuf::from(".cache"));
    base.join("wpantry").join("wpantry.db")
}

/// The newest modification time of the cache and its SQLite write-ahead
/// log, so a scan from the schedule or a terminal shows up in the window.
pub fn cache_stamp(path: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    [path.to_path_buf(), PathBuf::from(wal)]
        .iter()
        .filter_map(|file| file.metadata().and_then(|m| m.modified()).ok())
        .max()
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
