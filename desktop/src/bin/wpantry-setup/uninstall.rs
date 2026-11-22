//! Uninstalling: move the install folder aside, delete it or put it back,
//! then remove the scheduled scan and the shortcuts.

use crate::install::clean_stale_stages;
use crate::shortcuts::remove_shortcuts;
use crate::{MARKER, SCANNER, explain};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Prefix of the folder an uninstall moves the install folder to before
/// deleting it, and of the folder that holds the scanner until the
/// scheduled scan is gone. Both end in Setup's pid.
pub(super) const UNINSTALL_PREFIX: &str = ".pantry-uninstall-";
pub(super) const UNINSTALL_SCANNER_PREFIX: &str = ".pantry-uninstall-scanner-";
/// What [`uninstall`] found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Removal {
    /// Pantry's folder, shortcuts and scheduled scan are gone.
    Removed,
    /// No install folder: nothing was removed except stale shortcuts.
    NotInstalled,
    /// No install folder, but an earlier uninstall had left the scheduled
    /// scan behind with its scanner kept aside; that schedule is now gone.
    LeftoverRemoved,
}

/// Scanners an earlier, failed uninstall kept in
/// `.pantry-uninstall-scanner-<pid>` (a pid other than ours) so the
/// scheduled scan could still be removed.
fn kept_scanners(parent: &Path, own: u32) -> Vec<(PathBuf, PathBuf)> {
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let name = Path::new(SCANNER)
        .file_name()
        .unwrap_or_default()
        .to_owned();
    let mut kept: Vec<(PathBuf, PathBuf)> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix(UNINSTALL_SCANNER_PREFIX))
                .is_some_and(|pid| pid.parse::<u32>().is_ok_and(|pid| pid != own))
        })
        .map(|entry| (entry.path(), entry.path().join(&name)))
        .filter(|(_, scanner)| scanner.is_file())
        .collect();
    kept.sort();
    kept
}

/// The second uninstall after one that removed Pantry's files but not its
/// scheduled scan: retry the removal with the kept scanner (then the
/// direct route), and only once the schedule is gone remove the kept
/// folders. `Err` keeps them and gives the steps.
fn retry_leftover_schedule(
    kept: &[(PathBuf, PathBuf)],
    schedule: &mut impl FnMut(&Path) -> io::Result<()>,
    direct: &mut impl FnMut() -> Result<(), String>,
) -> io::Result<()> {
    let failures: Vec<String> = kept
        .iter()
        .filter_map(|(_, scanner)| schedule(scanner).err().map(|error| error.to_string()))
        .collect();
    if !failures.is_empty()
        && let Err(steps) = direct()
    {
        let (folder, scanner) = &kept[0];
        return Err(io::Error::other(format!(
            "Pantry is not installed, but the scheduled scan an earlier uninstall left behind is still there. {steps} Or run \"{}\" schedule uninstall, then delete the folder {}.\n\nDetails: {}",
            scanner.display(),
            folder.display(),
            failures.join("; ")
        )));
    }
    for (folder, _) in kept {
        // Only Pantry's own scanner is in this folder.
        let _ = fs::remove_dir_all(folder);
    }
    Ok(())
}

/// Uninstall, in an order that never leaves app files without the marker:
///
/// 1. Move the install folder aside to `.pantry-uninstall-<pid>` beside it
///    (one rename: if it fails, nothing changed).
/// 2. Move the scanner out to `.pantry-uninstall-scanner-<pid>`, so it can
///    still remove the scheduled scan after the folder is gone.
/// 3. Delete everything in the moved folder, the marker last. On any
///    failure put the scanner back and rename the folder back, so the
///    marker stays and Setup can repair or uninstall it later.
/// 4. Only then remove the scheduled scan: through the scanner (`schedule`),
///    or if it is missing or fails, `direct`.
/// 5. Remove the shortcuts.
///
/// A folder without Setup's marker is never touched. Scan history,
/// settings and the cache live in the state and cache folders and are
/// never touched.
pub(super) fn uninstall(
    destination: &Path,
    shortcuts: Option<&Path>,
    mut schedule: impl FnMut(&Path) -> io::Result<()>,
    mut direct: impl FnMut() -> Result<(), String>,
) -> io::Result<Removal> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("Missing Pantry installation folder."))?;
    let pid = std::process::id();
    let installed = fs::symlink_metadata(destination).is_ok();
    // A scanner an earlier uninstall kept is the way to remove the schedule
    // it left; it goes only once that worked, so clean it up first.
    let kept = if installed {
        Vec::new()
    } else {
        kept_scanners(parent, pid)
    };
    if !kept.is_empty() {
        retry_leftover_schedule(&kept, &mut schedule, &mut direct)?;
    }
    if parent.is_dir() {
        clean_stale_stages(parent, pid)?;
    }
    if !installed {
        if let Some(root) = shortcuts {
            remove_shortcuts(root)?;
        }
        return Ok(if kept.is_empty() {
            Removal::NotInstalled
        } else {
            Removal::LeftoverRemoved
        });
    }
    let Ok(marker) = fs::read_to_string(destination.join(MARKER)) else {
        return Err(io::Error::other(format!(
            "Pantry Setup did not install the folder at {} and left it in place.",
            destination.display()
        )));
    };
    let aside = parent.join(format!("{UNINSTALL_PREFIX}{pid}"));
    let keep = parent.join(format!("{UNINSTALL_SCANNER_PREFIX}{pid}"));
    fs::rename(destination, &aside)?;

    let mut held: Option<PathBuf> = None;
    let emptied = (|| -> io::Result<()> {
        let scanner = aside.join(SCANNER);
        if scanner.is_file() {
            fs::create_dir_all(&keep)?;
            let target = keep.join(scanner.file_name().unwrap_or_default());
            fs::rename(&scanner, &target)?;
            held = Some(target);
        }
        for entry in fs::read_dir(&aside)? {
            let entry = entry?;
            if entry.file_name() == MARKER {
                continue;
            }
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        fs::remove_file(aside.join(MARKER))?;
        fs::remove_dir(&aside)
    })();
    if let Err(error) = emptied {
        // Put back what is left, marker included, so the install stays ours.
        if let Some(held) = &held {
            let scanner = aside.join(SCANNER);
            if let Some(folder) = scanner.parent() {
                let _ = fs::create_dir_all(folder);
            }
            let _ = fs::rename(held, &scanner);
        }
        let _ = fs::remove_dir(&keep);
        let reason = explain(&error, Some(destination));
        return Err(match fs::rename(&aside, destination) {
            Ok(()) => {
                if !destination.join(MARKER).is_file() {
                    let _ = fs::write(destination.join(MARKER), &marker);
                }
                io::Error::other(format!(
                    "Pantry Setup could not remove every file in {}, so it put back what was left. Pantry is still installed and its scheduled scan is kept, but some files may be gone: run Pantry Setup to repair Pantry, or fix the problem below and run Pantry Setup --uninstall again.\n\n{reason}",
                    destination.display()
                ))
            }
            Err(back) => io::Error::other(format!(
                "Pantry Setup could not remove every file of Pantry, and could not move what was left back to {} ({back}). The rest is in {}. Run Pantry Setup --uninstall again once the problem below is fixed.\n\n{reason}",
                destination.display(),
                aside.display()
            )),
        });
    }

    // The folder is gone: now the scheduled scan.
    let through_scanner = held.as_deref().map(&mut schedule);
    let leftover = match &through_scanner {
        Some(Ok(())) => None,
        _ => direct().err(),
    };
    if leftover.is_none() {
        let _ = fs::remove_dir_all(&keep);
    }
    if let Some(steps) = leftover {
        let scanner_steps = held.as_ref().map_or_else(String::new, |held| {
            format!(
                " Or run \"{}\" schedule uninstall, then delete the folder {}.",
                held.display(),
                keep.display()
            )
        });
        let detail = match through_scanner {
            Some(Err(error)) => format!("\n\nDetails: {error}"),
            _ => String::new(),
        };
        let shortcuts_note = shortcuts
            .map(remove_shortcuts)
            .and_then(Result::err)
            .map_or_else(String::new, |error| {
                format!(" Its menu entry may also remain ({error}).")
            });
        return Err(io::Error::other(format!(
            "Pantry Setup removed Pantry's files, but a scheduled scan may remain.{shortcuts_note} {steps}{scanner_steps}{detail}"
        )));
    }
    if let Some(root) = shortcuts {
        remove_shortcuts(root).map_err(|error| {
            io::Error::other(format!(
                "Pantry Setup removed Pantry and its scheduled scan, but could not remove its menu entry.\n\n{}",
                explain(&error, Some(root))
            ))
        })?;
    }
    Ok(Removal::Removed)
}

#[cfg(test)]
#[path = "uninstall_tests.rs"]
mod tests;
