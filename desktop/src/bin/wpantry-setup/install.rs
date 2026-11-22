//! Installing: unpack the payload into a stage folder, swap it in, keep the
//! old copy until the new one is whole, and never downgrade.

use crate::uninstall::{UNINSTALL_PREFIX, UNINSTALL_SCANNER_PREFIX};
use crate::{APP, MARKER, PAYLOAD_LIMIT, PREVIOUS, SCANNER, STAGE_PREFIX};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::process::Command;

/// Parse `MAJOR.MINOR.PATCH`, ignoring surrounding whitespace.
///
/// ```text
/// version("0.6.0\n") == Some([0, 6, 0])
/// version("0.6")     == None
/// ```
pub(super) fn version(text: &str) -> Option<[u32; 3]> {
    let mut parts = text.trim().split('.');
    let version = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(version)
}

pub(super) fn installed_version(destination: &Path) -> Option<[u32; 3]> {
    fs::read_to_string(destination.join(MARKER))
        .ok()
        .and_then(|text| version(&text))
}

/// Read the payload a macOS Setup bundle carries in `Resources`. A missing
/// file means the download was not extracted whole, so say that and name
/// the file; the system's text stays as detail.
pub(super) fn read_payload(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::other(format!(
                "Pantry Setup is missing a file from its download: {}. Download Pantry Setup again, extract the whole ZIP, then open Pantry Setup from the extracted folder.\n\nDetails: {error}",
                path.display()
            ))
        } else {
            error
        }
    })
}

fn foreign_folder(path: &Path) -> io::Error {
    io::Error::other(format!(
        "Pantry Setup found a folder it did not create at {}. Move or delete that folder, then run Pantry Setup again.",
        path.display()
    ))
}

/// Unpack Setup's payload into `stage`.
///
/// The payload is zlib over a run of records: `u16` path length, `u32` body
/// length (both little endian), one executable flag byte, the UTF-8 path,
/// then the body. `wpantry-release setup payload` writes it. Every path
/// must be relative and made only of normal components, so no entry can
/// land outside `stage`.
fn unpack(payload: &[u8], stage: &Path, limit: usize) -> io::Result<()> {
    let decoded = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(payload, limit)
        .map_err(|_| io::Error::other("Pantry Setup could not read its bundled files."))?;
    let mut remaining = decoded.as_slice();
    while !remaining.is_empty() {
        let mut header = [0; 7];
        remaining
            .read_exact(&mut header)
            .map_err(|_| io::Error::other("Pantry Setup contains an incomplete file."))?;
        let path_length = u16::from_le_bytes([header[0], header[1]]) as usize;
        let file_length = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let path = remaining
            .get(..path_length)
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(Path::new)
            .filter(|path| {
                !path.as_os_str().is_empty()
                    && path
                        .components()
                        .all(|component| matches!(component, Component::Normal(_)))
            })
            .ok_or_else(|| io::Error::other("Pantry Setup contains an invalid file path."))?;
        let body = path_length
            .checked_add(file_length)
            .and_then(|end| remaining.get(path_length..end))
            .ok_or_else(|| io::Error::other("Pantry Setup contains an incomplete file."))?;
        let destination = stage.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination, body)?;
        #[cfg(unix)]
        if header[6] != 0 {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
        }
        remaining = &remaining[path_length + file_length..];
    }
    Ok(())
}

/// Remove staging folders left by a Setup run that was killed mid-install,
/// and the folders a killed or failed uninstall left beside the install.
///
/// Only folders named `.pantry-setup-<pid>`, `.pantry-uninstall-<pid>` or
/// `.pantry-uninstall-scanner-<pid>` with a pid other than ours qualify.
/// Setup holds both `setup.lock` and `window.lock` while it installs or
/// uninstalls, so no other Setup can be using one of them right now.
/// `.pantry-setup-previous` is not numeric and is left to the recovery step.
pub(super) fn clean_stale_stages(parent: &Path, own: u32) -> io::Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let stale = [STAGE_PREFIX, UNINSTALL_PREFIX, UNINSTALL_SCANNER_PREFIX]
            .iter()
            .filter_map(|prefix| name.to_str()?.strip_prefix(prefix))
            .any(|pid| pid.parse::<u32>().is_ok_and(|pid| pid != own));
        if stale && entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

/// What [`install`] did.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Installed {
    /// The bundled version is now installed (fresh, upgrade or repair).
    Bundled,
    /// A newer install was found and kept as it is.
    KeptNewer,
}

/// An install folder Setup made that has the app and the scanner.
fn healthy(folder: &Path) -> bool {
    folder.join(MARKER).is_file() && folder.join(APP).is_file() && folder.join(SCANNER).is_file()
}

/// Install `payload` into `destination`, replacing an older install made by
/// Setup or repairing one of the same version. A newer install is kept as
/// it is (downgrade guard). A folder without Setup's marker file is never
/// touched.
pub(super) fn install(payload: &[u8], destination: &Path, bundled: &str) -> io::Result<Installed> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("Missing Pantry installation folder."))?;
    fs::create_dir_all(parent)?;
    clean_stale_stages(parent, std::process::id())?;
    let stage = parent.join(format!("{STAGE_PREFIX}{}", std::process::id()));
    let previous = parent.join(PREVIOUS);
    // A foreign destination stops Setup before it touches anything else,
    // so a recoverable previous copy is never deleted for it.
    if destination.exists() && !destination.join(MARKER).is_file() {
        return Err(foreign_folder(destination));
    }
    // Recover the old installation if an earlier install stopped between
    // renames. The previous copy goes only once the destination is ours and
    // whole; a missing or damaged destination of ours gives way to it.
    if previous.join(MARKER).is_file() {
        if healthy(destination) {
            fs::remove_dir_all(&previous)?;
        } else {
            if destination.exists() {
                fs::remove_dir_all(destination)?;
            }
            fs::rename(&previous, destination)?;
        }
    }
    if previous.exists() {
        return Err(foreign_folder(&previous));
    }
    if let (Some(installed), Some(bundled)) = (installed_version(destination), version(bundled))
        && installed > bundled
    {
        return Ok(Installed::KeptNewer);
    }
    fs::create_dir(&stage)?;
    let result = (|| {
        unpack(payload, &stage, PAYLOAD_LIMIT)?;
        if !stage.join(APP).is_file() || !stage.join(SCANNER).is_file() {
            return Err(io::Error::other(
                "Pantry Setup is missing the desktop app or its scanner.",
            ));
        }
        fs::write(stage.join(MARKER), bundled)?;
        let replacing = destination.exists();
        if replacing {
            fs::rename(destination, &previous)?;
        }
        if let Err(error) = fs::rename(&stage, destination) {
            if replacing {
                fs::rename(&previous, destination)?;
            }
            return Err(error);
        }
        if replacing {
            let _ = fs::remove_dir_all(&previous);
        }
        Ok(Installed::Bundled)
    })();
    let _ = fs::remove_dir_all(stage);
    result
}

pub(super) fn launch(destination: &Path) -> io::Result<()> {
    if cfg!(target_os = "macos") {
        // Open the bundle through LaunchServices so the Dock shows Pantry's
        // name and icon. Exec'ing Contents/MacOS/Pantry directly would leave
        // the app attributed to Pantry Setup.
        // LaunchServices does not inherit our environment, so forward the
        // install-root override the app uses to find its state folder.
        let bundle = destination.join("Pantry.app");
        let mut open = Command::new("/usr/bin/open");
        if let Some(home) = std::env::var_os("WPANTRY_DESKTOP_HOME") {
            let mut pair = std::ffi::OsString::from("WPANTRY_DESKTOP_HOME=");
            pair.push(home);
            open.arg("--env").arg(pair);
        }
        let status = open.arg(&bundle).status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "Pantry Setup could not open {}.",
                bundle.display()
            )));
        }
    } else {
        Command::new(destination.join(APP)).spawn()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
