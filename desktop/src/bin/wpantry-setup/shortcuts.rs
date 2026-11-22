//! The Start menu shortcut on Windows and the app menu entry on Linux.

use crate::{APP, quiet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Desktop entry and icon name on Linux. The window's app id (and so its
/// X11 WM_CLASS) is `ai.waffuru.pantry.desktop`, set in `main.rs`.
pub(super) const LINUX_ENTRY: &str = "applications/ai.waffuru.pantry.desktop";
pub(super) const LINUX_ICON: &str = "icons/hicolor/256x256/apps/ai.waffuru.pantry.png";
const LINUX_WM_CLASS: &str = "ai.waffuru.pantry.desktop";
pub(super) const LINUX_ENTRY_KEY: &str = "X-Waffuru-Pantry";
const WINDOWS_SHORTCUT: &str = "Pantry.lnk";
#[cfg(target_os = "linux")]
const ICON_PNG: &[u8] = include_bytes!("../../../assets/waffuru-waffle.png");

/// Quote a path for a Desktop Entry `Exec` key: double quotes around it,
/// `"` `` ` `` `$` `\` escaped for the Exec rules, every backslash doubled
/// again for the string-value rules, and `%` doubled (field codes).
fn desktop_exec_quote(path: &str) -> io::Result<String> {
    if path.chars().any(char::is_control) {
        return Err(io::Error::other(
            "Pantry's install path contains a control character.",
        ));
    }
    let mut quoted = String::from("\"");
    for character in path.chars() {
        match character {
            '"' | '`' | '$' => {
                quoted.push_str("\\\\");
                quoted.push(character);
            }
            '\\' => quoted.push_str("\\\\\\\\"),
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn desktop_entry(app: &Path, bundled: &str) -> io::Result<String> {
    let exec = desktop_exec_quote(&app.to_string_lossy())?;
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name=Pantry\n\
         Comment=See open security findings on this computer and how to fix them\n\
         Exec={exec}\n\
         Icon=ai.waffuru.pantry\n\
         Terminal=false\n\
         Categories=Utility;System;Security;\n\
         StartupWMClass={LINUX_WM_CLASS}\n\
         {LINUX_ENTRY_KEY}={bundled}\n"
    ))
}

/// Write `body` to `path` through a temporary file in the same folder.
fn write_atomic(path: &Path, body: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing shortcut folder."))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".pantry-shortcut-{}.tmp", std::process::id()));
    fs::write(&temporary, body)?;
    fs::rename(&temporary, path)
}

fn refresh_linux_menus(root: &Path) {
    // Missing on many systems and only a cache: ignore every failure.
    let _ = Command::new("update-desktop-database")
        .arg(root.join("applications"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Create the platform launcher: a Start Menu shortcut on Windows, a
/// desktop entry and icon on Linux, nothing on macOS (the installed
/// `Pantry.app` is its own launcher).
pub(super) fn create_shortcuts(root: &Path, destination: &Path, bundled: &str) -> io::Result<()> {
    let app = destination.join(APP);
    if cfg!(windows) {
        fs::create_dir_all(root)?;
        // WScript.Shell writes the .lnk; values travel in the environment so
        // no path is ever spliced into the script.
        let script = "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:PANTRY_LNK); \
                      $s.TargetPath = $env:PANTRY_APP; $s.WorkingDirectory = $env:PANTRY_DIR; \
                      $s.IconLocation = $env:PANTRY_APP + ',0'; $s.Description = 'Pantry'; $s.Save()";
        let status = quiet(&mut Command::new("powershell.exe"))
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                script,
            ])
            .env("PANTRY_LNK", root.join(WINDOWS_SHORTCUT))
            .env("PANTRY_APP", &app)
            .env("PANTRY_DIR", destination)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(
                "Pantry Setup could not add Pantry to the Start menu.",
            ));
        }
    } else if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        write_atomic(&root.join(LINUX_ICON), ICON_PNG)?;
        write_atomic(
            &root.join(LINUX_ENTRY),
            desktop_entry(&app, bundled)?.as_bytes(),
        )?;
        refresh_linux_menus(root);
    }
    Ok(())
}

/// Remove the launchers [`create_shortcuts`] made. A desktop entry without
/// Setup's key is someone else's and stays.
pub(super) fn remove_shortcuts(root: &Path) -> io::Result<()> {
    let remove = |path: PathBuf| match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    };
    if cfg!(windows) {
        remove(root.join(WINDOWS_SHORTCUT))?;
    } else if cfg!(target_os = "linux") {
        let entry = root.join(LINUX_ENTRY);
        let ours = fs::read_to_string(&entry)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(LINUX_ENTRY_KEY)));
        if ours {
            remove(entry)?;
            remove(root.join(LINUX_ICON))?;
            refresh_linux_menus(root);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "shortcuts_tests.rs"]
mod tests;
