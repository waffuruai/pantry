#![cfg_attr(windows, windows_subsystem = "windows")]
//! Pantry Setup: installs the desktop app and its scanner for this account.
//!
//! ```text
//! Pantry Setup                    install or update, then open Pantry
//! Pantry Setup --install-only     install or update without opening Pantry
//! Pantry Setup --uninstall        remove the installed app, its shortcuts and
//!                                 its scheduled scan; keep scan history
//! ```

use crate::install::{Installed, install, installed_version, launch, read_payload, version};
use crate::schedule::{remove_schedule, remove_schedule_directly};
use crate::shortcuts::create_shortcuts;
use crate::uninstall::{Removal, uninstall};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use wpantry_desktop::instance;

mod install;
mod schedule;
mod shortcuts;
mod uninstall;

const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pantry-setup.zlib"));
const MARKER: &str = ".waffuru-pantry-desktop";
const STAGE_PREFIX: &str = ".pantry-setup-";
const PREVIOUS: &str = ".pantry-setup-previous";
/// Largest unpacked payload Setup accepts.
const PAYLOAD_LIMIT: usize = 100 * 1024 * 1024;
const APP: &str = if cfg!(target_os = "macos") {
    "Pantry.app/Contents/MacOS/Pantry"
} else if cfg!(windows) {
    "wpantry-desktop.exe"
} else {
    "wpantry-desktop"
};
const SCANNER: &str = if cfg!(target_os = "macos") {
    "Pantry.app/Contents/MacOS/wpantry"
} else if cfg!(windows) {
    "wpantry.exe"
} else {
    "wpantry"
};
const RUNNING: &str = "Pantry is open. Quit Pantry, then run Pantry Setup again to update.";
const RUNNING_UNINSTALL: &str =
    "Pantry is open. Quit Pantry, then run Pantry Setup --uninstall again.";
const IN_USE: &str = "Pantry or a scheduled scan is using Pantry's files, so Pantry Setup cannot change them. Quit Pantry, wait for any scheduled scan to finish, then try again.";
const NO_PERMISSION: &str = "Pantry Setup does not have permission to change Pantry's files.";
const WINDOWS_DENIED: &str = "Windows denied Pantry Setup access to Pantry's files. Pantry or a scheduled scan may be using them: quit Pantry, wait for any scheduled scan to finish, then try again.";
const SETUP_RUNNING: &str =
    "Pantry Setup is already running. Wait for it to finish; this copy changed nothing.";
const NEWER_INSTALLED: &str = "A newer Pantry is already installed.";
const NOT_INSTALLED: &str =
    "Pantry is not installed for this account, so Pantry Setup removed nothing.";
const REMOVED: &str = "Pantry Setup removed Pantry. Your scan history and settings are kept.";
const LEFTOVER_REMOVED: &str = "Pantry Setup removed the scheduled scan an earlier uninstall left behind. Pantry is not installed. Your scan history and settings are kept.";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Install,
    InstallOnly,
    Uninstall,
}

/// Turn an install error into words for the person running Setup. Errors
/// Setup wrote itself pass through. A system error gets one plain sentence
/// saying which problem it is and what to do, plus the system's detail:
///
/// - in use: a file is busy or locked (`EBUSY` 16, `ETXTBSY` 26, Windows
///   sharing or lock violation 32 and 33);
/// - no permission: `EPERM` 1 or `EACCES` 13, naming `folder`;
/// - Windows "access denied" (5), which Windows also returns for a running
///   program's file, so that one sentence covers both.
///
/// ```text
/// explain(&io::Error::from_raw_os_error(13), Some(dest))
///   == "Pantry Setup does not have permission ... <dest> ...\n\nDetails: Permission denied (os error 13)"
/// ```
fn explain(error: &io::Error, folder: Option<&Path>) -> String {
    let raw = error.raw_os_error();
    let windows_denied = cfg!(windows) && raw == Some(5);
    let in_use = matches!(
        error.kind(),
        io::ErrorKind::ResourceBusy | io::ErrorKind::ExecutableFileBusy
    ) || (cfg!(windows) && matches!(raw, Some(32 | 33)))
        || (cfg!(unix) && matches!(raw, Some(16 | 26)));
    let denied = !windows_denied && error.kind() == io::ErrorKind::PermissionDenied;
    let folder = folder.map_or_else(
        || "Pantry's install folder".to_owned(),
        |folder| folder.display().to_string(),
    );
    if windows_denied {
        format!(
            "{WINDOWS_DENIED} If that does not help, check that your account can change {folder} and the folder that holds it.\n\nDetails: {error}"
        )
    } else if in_use {
        format!("{IN_USE}\n\nDetails: {error}")
    } else if denied {
        format!(
            "{NO_PERMISSION} Check that your account can change {folder} and the folder that holds it, then try again.\n\nDetails: {error}"
        )
    } else {
        error.to_string()
    }
}

/// Start a helper process without a console window on Windows. Setup is a
/// GUI-subsystem program, so a console child would otherwise open one.
fn quiet(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// Why Setup did not get its locks, and what it does instead.
#[derive(Debug, PartialEq, Eq)]
enum Blocked {
    /// Another Setup holds `setup.lock`: say so and change nothing.
    SetupRunning,
    /// Pantry is open and up to date: bring its window forward.
    Activate,
    /// Pantry is open and up to date, and nothing should open.
    Current,
    /// Pantry is open and Setup would change it: refuse with this text.
    Refuse(&'static str),
}

/// Take `setup.lock`, then `window.lock` (Setup holds the window lock
/// while it works, so Pantry cannot start from a half-replaced folder).
fn take_locks(
    state: &Path,
    destination: &Path,
    mode: Mode,
    bundled: &str,
) -> io::Result<Result<(fs::File, fs::File), Blocked>> {
    let Some(setup) = instance::try_lock(state, instance::SETUP_LOCK)? else {
        return Ok(Err(Blocked::SetupRunning));
    };
    let Some(window) = instance::try_lock(state, instance::WINDOW_LOCK)? else {
        let current = installed_version(destination)
            .zip(version(bundled))
            .is_some_and(|(installed, bundled)| installed >= bundled);
        return Ok(Err(match mode {
            // A plain relaunch of an up-to-date install: show the open window.
            Mode::Install if current => Blocked::Activate,
            Mode::InstallOnly if current => Blocked::Current,
            Mode::Uninstall => Blocked::Refuse(RUNNING_UNINSTALL),
            _ => Blocked::Refuse(RUNNING),
        }));
    };
    Ok(Ok((setup, window)))
}

/// A note for the person running Setup when it worked but has news: on
/// standard output, and for a double-click (no terminal) in a dialog too.
fn notice(mode: Mode, message: &str) {
    println!("Pantry Setup: {message}");
    if mode == Mode::Install {
        tell(message);
    }
}

fn run(mode: Mode) -> io::Result<()> {
    let bundled = env!("CARGO_PKG_VERSION");
    let (state, destination) = instance::directories()?;
    let (_setup, window) = match take_locks(&state, &destination, mode, bundled)? {
        Ok(locks) => locks,
        // A second double-click while Setup runs: the first copy carries on.
        Err(Blocked::SetupRunning) => {
            notice(mode, SETUP_RUNNING);
            return Ok(());
        }
        Err(Blocked::Activate) => return instance::request_activation(&state),
        Err(Blocked::Current) => return Ok(()),
        Err(Blocked::Refuse(message)) => return Err(io::Error::other(message)),
    };
    let shortcuts = instance::shortcuts()?;
    if mode == Mode::Uninstall {
        let removal = uninstall(
            &destination,
            shortcuts.as_deref(),
            remove_schedule,
            remove_schedule_directly,
        )?;
        println!(
            "{}",
            match removal {
                Removal::Removed => REMOVED,
                Removal::NotInstalled => NOT_INSTALLED,
                Removal::LeftoverRemoved => LEFTOVER_REMOVED,
            }
        );
        return Ok(());
    }
    let installed = if cfg!(target_os = "macos") {
        let executable = std::env::current_exe()?;
        let contents = executable
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::other("Pantry Setup must be opened from its app bundle."))?;
        let payload = read_payload(&contents.join("Resources/pantry-setup.zlib"))?;
        install(&payload, &destination, bundled)?
    } else {
        install(PAYLOAD, &destination, bundled)?
    };
    if installed == Installed::KeptNewer {
        // An older Setup over a newer install: keep it, say so, and open
        // the installed Pantry the way a normal install does.
        drop(window);
        notice(mode, NEWER_INSTALLED);
        if mode == Mode::Install {
            launch(&destination)?;
        }
        return Ok(());
    }
    if let Some(root) = &shortcuts
        && let Err(error) = create_shortcuts(root, &destination, bundled)
    {
        // Pantry is installed and opens below; a missing menu entry is not
        // worth failing the install over.
        eprintln!("Pantry Setup: {}", explain(&error, Some(root)));
    }
    drop(window);
    if mode == Mode::Install {
        launch(&destination)?;
    }
    Ok(())
}

/// Show `message` in a native dialog. Each tool is tried in turn; the
/// message is always on standard error too.
fn tell(message: &str) {
    #[cfg(windows)]
    let _ = quiet(&mut Command::new("powershell.exe"))
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($env:PANTRY_SETUP_ERROR, 'Pantry Setup')",
        ])
        .env("PANTRY_SETUP_ERROR", message)
        .status();
    #[cfg(target_os = "macos")]
    let _ = Command::new("osascript")
        .args([
            "-e",
            "on run argv",
            "-e",
            "display alert \"Pantry Setup\" message (item 1 of argv)",
            "-e",
            "end run",
            "--",
            message,
        ])
        .status();
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let tools: [&[&str]; 3] = [
            &[
                "zenity",
                "--error",
                "--no-markup",
                "--title=Pantry Setup",
                "--text",
            ],
            &["kdialog", "--title", "Pantry Setup", "--error"],
            &["notify-send", "Pantry Setup"],
        ];
        for tool in tools {
            let shown = Command::new(tool[0])
                .args(&tool[1..])
                .arg(message)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if shown {
                break;
            }
        }
    }
}

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mode = match (args.next(), args.next()) {
        (None, _) => Mode::Install,
        (Some(arg), None) if arg == "--install-only" => Mode::InstallOnly,
        (Some(arg), None) if arg == "--uninstall" => Mode::Uninstall,
        _ => {
            eprintln!("Usage: wpantry-setup [--install-only | --uninstall]");
            return std::process::ExitCode::from(2);
        }
    };
    if let Err(error) = run(mode) {
        let destination = instance::directories()
            .ok()
            .map(|(_, destination)| destination);
        let message = explain(&error, destination.as_deref());
        eprintln!("Pantry Setup: {message}");
        // A double-click has no terminal to read; automation passes a flag
        // and reads standard error instead.
        if mode == Mode::Install {
            tell(&message);
        }
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests;
