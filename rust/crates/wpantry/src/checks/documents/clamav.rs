//! ClamAV over a list of files, when it is installed: `clamdscan` with the
//! daemon's file descriptors passed, else `clamscan`, with a file list and
//! a ten-minute cap. The signature hits come back by path.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// More files than this go unscanned: the list is capped where it is written.
const MAX_FILES: usize = 5000;
const TIMEOUT: Duration = Duration::from_secs(600);
/// clamscan's exit codes: 0 clean, 1 infected, 2 error.
const EXIT_ERROR: i32 = 2;

/// `clamscan` (or `clamdscan`) over these files, when installed: the
/// infected ones with their signature names. `None` when no scanner is
/// installed; `Err` text when it couldn't run.
pub fn clamav(files: &[PathBuf]) -> Option<Result<Vec<(PathBuf, String)>, String>> {
    let (bin, daemon) = scanner()?;
    Some(clamav_with(&bin, daemon, files))
}

/// The installed scanner: `clamdscan` (daemon: true), else `clamscan`.
fn scanner() -> Option<(PathBuf, bool)> {
    match (crate::utils::process::which("clamdscan"), crate::utils::process::which("clamscan")) {
        (Some(d), _) => Some((d, true)),
        (None, Some(s)) => Some((s, false)),
        (None, None) => None,
    }
}

/// `bin` (clamdscan when `daemon`) over `files`: the infected ones with
/// their signature names; `Err` text when it couldn't run.
fn clamav_with(bin: &Path, daemon: bool, files: &[PathBuf]) -> Result<Vec<(PathBuf, String)>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let list = match crate::utils::temp::TempDir::new("clamav") {
        Ok(d) => d,
        Err(e) => return Err(e.to_string()),
    };
    let list_file = list.path().join("files.txt");
    let text: String = files.iter().take(MAX_FILES).map(|p| format!("{}\n", p.display())).collect();
    if let Err(e) = std::fs::write(&list_file, text) {
        return Err(e.to_string());
    }
    let mut argv: Vec<&OsStr> = vec![bin.as_os_str(), OsStr::new("--infected"), OsStr::new("--no-summary")];
    if daemon {
        argv.push(OsStr::new("--fdpass"));
    } else {
        argv.push(OsStr::new("--stdout"));
    }
    argv.push(OsStr::new("--file-list"));
    argv.push(list_file.as_os_str());
    let out = match crate::utils::process::exec(&argv, &[], TIMEOUT) {
        Ok(o) => o,
        Err(e) => return Err(e.to_string()),
    };
    if out.code == Some(EXIT_ERROR) {
        return Err(format!("{} exited 2: {}", bin.display(), out.stderr.lines().next().unwrap_or("").trim()));
    }
    Ok(hits(&out.stdout))
}

/// The `<path>: <signature> FOUND` lines of clamscan's output, as (path,
/// signature); everything else it prints is left alone.
fn hits(stdout: &str) -> Vec<(PathBuf, String)> {
    let mut hits = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_suffix(" FOUND")
            && let Some((path, sig)) = rest.rsplit_once(": ")
        {
            hits.push((PathBuf::from(path), sig.to_string()));
        }
    }
    hits
}

#[cfg(test)]
#[path = "clamav_tests.rs"]
mod tests;
