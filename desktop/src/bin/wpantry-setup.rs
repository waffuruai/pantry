#![cfg_attr(windows, windows_subsystem = "windows")]
//! Pantry Setup: installs the desktop app and its scanner for this account.
//!
//! ```text
//! Pantry Setup                    install or update, then open Pantry
//! Pantry Setup --install-only     install or update without opening Pantry
//! Pantry Setup --uninstall        remove the installed app, its shortcuts and
//!                                 its scheduled scan; keep scan history
//! ```

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use wpantry_desktop::instance;

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
/// Desktop entry and icon name on Linux. The window's app id (and so its
/// X11 WM_CLASS) is `ai.waffuru.pantry.desktop`, set in `main.rs`.
const LINUX_ENTRY: &str = "applications/ai.waffuru.pantry.desktop";
const LINUX_ICON: &str = "icons/hicolor/256x256/apps/ai.waffuru.pantry.png";
const LINUX_WM_CLASS: &str = "ai.waffuru.pantry.desktop";
const LINUX_ENTRY_KEY: &str = "X-Waffuru-Pantry";
const WINDOWS_SHORTCUT: &str = "Pantry.lnk";
#[cfg(target_os = "linux")]
const ICON_PNG: &[u8] = include_bytes!("../../assets/waffuru-waffle.png");

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
/// Prefix of the folder an uninstall moves the install folder to before
/// deleting it, and of the folder that holds the scanner until the
/// scheduled scan is gone. Both end in Setup's pid.
const UNINSTALL_PREFIX: &str = ".pantry-uninstall-";
const UNINSTALL_SCANNER_PREFIX: &str = ".pantry-uninstall-scanner-";
/// The scheduled scan's launchd label and systemd/cron names. These copy
/// `rust/crates/wpantry-cli/src/schedule.rs` (`LABEL`, `CRON_MARK`) and
/// `schedule/windows.rs` (`task`).
/// TODO: share these with the CLI crate once the desktop crate depends on it.
const SCHEDULE_LABEL: &str = "ai.waffuru.wpantry";
const CRON_MARK: &str = "# wpantry schedule";
const WINDOWS_TASK_PREFIX: &str = "Waffuru-Pantry-";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Install,
    InstallOnly,
    Uninstall,
}

/// Parse `MAJOR.MINOR.PATCH`, ignoring surrounding whitespace.
///
/// ```text
/// version("0.6.0\n") == Some([0, 6, 0])
/// version("0.6")     == None
/// ```
fn version(text: &str) -> Option<[u32; 3]> {
    let mut parts = text.trim().split('.');
    let version = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(version)
}

fn installed_version(destination: &Path) -> Option<[u32; 3]> {
    fs::read_to_string(destination.join(MARKER))
        .ok()
        .and_then(|text| version(&text))
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

/// Read the payload a macOS Setup bundle carries in `Resources`. A missing
/// file means the download was not extracted whole, so say that and name
/// the file; the system's text stays as detail.
fn read_payload(path: &Path) -> io::Result<Vec<u8>> {
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
/// then the body. `desktop/release/setup.py payload` writes it. Every path
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
fn clean_stale_stages(parent: &Path, own: u32) -> io::Result<()> {
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
enum Installed {
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
fn install(payload: &[u8], destination: &Path, bundled: &str) -> io::Result<Installed> {
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
fn create_shortcuts(root: &Path, destination: &Path, bundled: &str) -> io::Result<()> {
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
fn remove_shortcuts(root: &Path) -> io::Result<()> {
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

/// Ask the scanner Setup installed to remove Pantry's scheduled scan, so no
/// job is left pointing at a deleted scanner.
fn remove_schedule(scanner: &Path) -> io::Result<()> {
    let status = quiet(&mut Command::new(scanner))
        .args(["schedule", "uninstall"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "\"{}\" schedule uninstall failed ({status}).",
            scanner.display()
        )));
    }
    Ok(())
}

/// Run a helper quietly and capture its output; `None` if it could not
/// start (for example it is not installed).
fn helper(program: &str, args: &[&str]) -> Option<std::process::Output> {
    quiet(&mut Command::new(program))
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()
}

/// Remove the scheduled scan without the scanner, the way `wpantry
/// schedule uninstall` does (see `rust/crates/wpantry-cli/src/schedule.rs`
/// `uninstall_with`), for an install whose scanner is gone or fails.
/// `Err` holds the plain steps that remove whatever may remain.
///
/// - macOS: `launchctl bootout gui/<uid>/ai.waffuru.wpantry`, then delete
///   `~/Library/LaunchAgents/ai.waffuru.wpantry.plist`.
/// - Linux: `systemctl --user disable --now wpantry.timer`, then delete
///   the user units; a cron line is left to the person, with the steps.
/// - Windows: `schtasks /Delete` on the per-user task `Waffuru-Pantry-<SID>`.
fn remove_schedule_directly() -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute());
    let delete = |path: &Path| match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(format!(
            "To remove it, delete {} ({error}).",
            path.display()
        )),
        _ => Ok(()),
    };
    if cfg!(target_os = "macos") {
        let Some(home) = home else {
            return Err(format!(
                "To remove it, delete ~/Library/LaunchAgents/{SCHEDULE_LABEL}.plist, then log out and back in."
            ));
        };
        remove_launchd_job(&home, &helper)
    } else if cfg!(windows) {
        let manual = format!(
            "To remove it, open Task Scheduler and delete the task whose name starts with {WINDOWS_TASK_PREFIX}."
        );
        // `whoami /user /fo csv /nh` prints `"DOMAIN\user","S-1-5-..."`.
        let sid = helper("whoami.exe", &["/user", "/fo", "csv", "/nh"])
            .filter(|out| out.status.success())
            .and_then(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .split('"')
                    .find(|word| word.starts_with("S-1-"))
                    .map(str::to_owned)
            })
            .ok_or_else(|| manual.clone())?;
        let task = format!("{WINDOWS_TASK_PREFIX}{sid}");
        let exists = helper("schtasks.exe", &["/Query", "/TN", &task])
            .is_some_and(|out| out.status.success());
        let deleted = !exists
            || helper("schtasks.exe", &["/Delete", "/TN", &task, "/F"])
                .is_some_and(|out| out.status.success());
        if deleted {
            Ok(())
        } else {
            Err(format!(
                "To remove it, run: schtasks /Delete /TN \"{task}\" /F"
            ))
        }
    } else {
        let Some(home) = home else {
            return Err(
                "To remove it, install the Pantry scanner and run: wpantry schedule uninstall"
                    .into(),
            );
        };
        let units = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|config| config.is_absolute())
            .unwrap_or_else(|| home.join(".config"))
            .join("systemd/user");
        let timer = units.join("wpantry.timer");
        if timer.exists() {
            let _ = helper(
                "systemctl",
                &["--user", "disable", "--now", "wpantry.timer"],
            );
        }
        delete(&timer)?;
        delete(&units.join("wpantry.service"))?;
        let cron = helper("crontab", &["-l"])
            .filter(|out| out.status.success())
            .is_some_and(|out| String::from_utf8_lossy(&out.stdout).contains(CRON_MARK));
        if cron {
            return Err(format!(
                "To remove it, run crontab -e and delete the line that ends in \"{CRON_MARK}\"."
            ));
        }
        Ok(())
    }
}

/// Remove the launchd job and its plist, then check with `launchctl
/// print` that launchd no longer has it loaded. `run` is [`helper`] for
/// real and a stand-in in tests. `Err` holds the plain steps that remove
/// what remains.
///
/// ```text
/// remove_launchd_job(home, &helper)
///   id -u                                   -> 501
///   launchctl bootout gui/501/<label>       (its answer is kept)
///   delete ~/Library/LaunchAgents/<label>.plist
///   launchctl print gui/501/<label>         -> fails once the job is gone
/// ```
fn remove_launchd_job(
    home: &Path,
    run: &dyn Fn(&str, &[&str]) -> Option<std::process::Output>,
) -> Result<(), String> {
    let plist = home
        .join("Library/LaunchAgents")
        .join(format!("{SCHEDULE_LABEL}.plist"));
    let uid = run("id", &["-u"])
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|uid| uid.trim().to_owned())
        .filter(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()));
    let target = uid.map(|uid| format!("gui/{uid}/{SCHEDULE_LABEL}"));
    let bootout = target
        .as_deref()
        .and_then(|target| run("launchctl", &["bootout", target]));
    if let Err(error) = fs::remove_file(&plist)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(format!(
            "To remove it, delete {} ({error}), then log out and back in.",
            plist.display()
        ));
    }
    let Some(target) = target else {
        return Err(
            "Pantry Setup could not check whether the scheduled scan is still loaded. To be sure it is gone, log out and back in.".into(),
        );
    };
    // `launchctl print` succeeds only while the job is loaded.
    let loaded = run("launchctl", &["print", &target]).map(|out| out.status.success());
    match loaded {
        Some(false) => Ok(()),
        Some(true) => Err(format!(
            "The scheduled scan is still loaded{}. To remove it, run: launchctl bootout {target} (or log out and back in).",
            bootout
                .filter(|out| !out.status.success())
                .map(|out| {
                    let said = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                    if said.is_empty() {
                        String::new()
                    } else {
                        format!(" (launchctl said: {said})")
                    }
                })
                .unwrap_or_default()
        )),
        None => Err(format!(
            "Pantry Setup could not run launchctl to check the scheduled scan. To remove it, run: launchctl bootout {target} (or log out and back in)."
        )),
    }
}

/// What [`uninstall`] found.
#[derive(Debug, PartialEq, Eq)]
enum Removal {
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
fn uninstall(
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

fn launch(destination: &Path) -> io::Result<()> {
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh folder under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "wpantry-setup-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Encode records the way `desktop/release/setup.py payload` does.
    fn raw(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, body, executable) in entries {
            out.extend_from_slice(&(path.len() as u16).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.push(u8::from(*executable));
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    fn payload(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(&raw(entries), 6)
    }

    fn app_payload(body: &[u8]) -> Vec<u8> {
        payload(&[(APP, body, true), (SCANNER, b"scanner", true)])
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // Oracle: the semver triple grammar. Exactly three dot-separated u32s.
    #[test]
    fn version_accepts_only_three_numbers() {
        assert_eq!(version("0.6.0"), Some([0, 6, 0]));
        assert_eq!(version(" 1.2.3\n"), Some([1, 2, 3]));
        for bad in ["", "1.2", "1.2.3.4", "a.b.c", "1.2.-3", "1..3", "v1.2.3"] {
            assert_eq!(version(bad), None, "{bad:?}");
        }
        // Numeric, not lexical, order: the downgrade guard depends on it.
        assert!(version("0.10.0") > version("0.9.9"));
    }

    // Oracle: the payload round-trips byte for byte, with the exec bit set
    // only where the record asks for it.
    #[test]
    fn unpack_writes_every_record() {
        let scratch = Scratch::new();
        let data = payload(&[("a/b.txt", b"hello", false), ("run", b"#!", true)]);
        unpack(&data, &scratch.0, PAYLOAD_LIMIT).unwrap();
        assert_eq!(fs::read(scratch.0.join("a/b.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(scratch.0.join("run")).unwrap(), b"#!");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |name: &str| {
                fs::metadata(scratch.0.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
            };
            assert_eq!(mode("run") & 0o111, 0o111);
            assert_eq!(mode("a/b.txt") & 0o111, 0);
        }
    }

    // Oracle: no entry may escape the stage. Known-bad cases: parent
    // components, absolute paths, a leading `.`, an empty path. Nothing may
    // be written beside the stage.
    #[test]
    fn unpack_rejects_paths_outside_the_stage() {
        let scratch = Scratch::new();
        let stage = scratch.0.join("stage");
        fs::create_dir(&stage).unwrap();
        let absolute = scratch.0.join("absolute.txt");
        let absolute = absolute.to_str().unwrap();
        for bad in ["../escaped.txt", "a/../../escaped.txt", absolute, "./x", ""] {
            let error = unpack(&payload(&[(bad, b"x", false)]), &stage, PAYLOAD_LIMIT).unwrap_err();
            assert!(
                error.to_string().contains("invalid file path"),
                "{bad:?}: {error}"
            );
        }
        assert_eq!(entries(&scratch.0), ["stage"]);
        assert!(entries(&stage).is_empty());
    }

    // Oracle: a body or header cut short is an error, never a short file.
    #[test]
    fn unpack_rejects_truncated_records() {
        let scratch = Scratch::new();
        let mut cut = raw(&[("file", b"0123456789", false)]);
        cut.truncate(cut.len() - 3);
        let data = miniz_oxide::deflate::compress_to_vec_zlib(&cut, 6);
        let error = unpack(&data, &scratch.0, PAYLOAD_LIMIT).unwrap_err();
        assert!(error.to_string().contains("incomplete"), "{error}");
        assert!(!scratch.0.join("file").exists());

        let header = miniz_oxide::deflate::compress_to_vec_zlib(&[4, 0, 0], 6);
        assert!(unpack(&header, &scratch.0, PAYLOAD_LIMIT).is_err());

        // A body length near u32::MAX must not wrap the bounds check.
        let mut huge = raw(&[("f", b"", false)]);
        huge[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        let data = miniz_oxide::deflate::compress_to_vec_zlib(&huge, 6);
        assert!(unpack(&data, &scratch.0, PAYLOAD_LIMIT).is_err());
    }

    // Oracle: the size limit applies to the unpacked bytes. Known-bad: a
    // payload one byte over the limit. Also corrupt and empty (the dev
    // build's payload) input fail cleanly.
    #[test]
    fn unpack_rejects_oversize_and_corrupt_payloads() {
        let scratch = Scratch::new();
        let body = vec![0; 4096];
        let data = payload(&[("big", &body, false)]);
        let size = raw(&[("big", &body, false)]).len();
        assert!(unpack(&data, &scratch.0, size - 1).is_err());
        assert!(!scratch.0.join("big").exists());
        unpack(&data, &scratch.0, size).unwrap();
        for bad in [&b""[..], b"not zlib"] {
            let error = unpack(bad, &scratch.0, PAYLOAD_LIMIT).unwrap_err();
            assert!(error.to_string().contains("could not read"), "{error}");
        }
    }

    // Oracle: a fresh install has the app, the scanner and a marker naming
    // the bundled version, and leaves no staging folder behind.
    #[test]
    fn install_fresh() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"new"), &destination, "1.2.3").unwrap();
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
        assert_eq!(
            fs::read_to_string(destination.join(MARKER)).unwrap(),
            "1.2.3"
        );
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: an older install is replaced; the same version is reinstalled
    // (repair); a newer install is left byte for byte (downgrade guard).
    #[test]
    fn install_upgrades_but_never_downgrades() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
        install(&app_payload(b"new"), &destination, "1.1.0").unwrap();
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
        install(&app_payload(b"older"), &destination, "1.0.9").unwrap();
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
        assert_eq!(
            fs::read_to_string(destination.join(MARKER)).unwrap(),
            "1.1.0"
        );
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: a folder without the marker is someone else's. Setup refuses,
    // names the folder and says what to do, and leaves its files alone.
    #[test]
    fn install_refuses_a_foreign_folder() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("notes"), b"mine").unwrap();
        let error = install(&app_payload(b"new"), &destination, "1.0.0").unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains(&destination.display().to_string()) && text.contains("Move or delete"),
            "{text}"
        );
        assert_eq!(fs::read(destination.join("notes")).unwrap(), b"mine");
        assert_eq!(entries(&destination), ["notes"]);
    }

    // Oracle: an install killed after moving the old copy aside (previous
    // has the marker, destination is gone) is rolled back, then upgraded.
    #[test]
    fn install_recovers_an_interrupted_install() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
        fs::rename(&destination, scratch.0.join(PREVIOUS)).unwrap();
        install(&app_payload(b"new"), &destination, "1.1.0").unwrap();
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
        assert_eq!(entries(&scratch.0), ["installed"]);

        // Killed after the new copy landed: the leftover previous copy
        // (ours, it has the marker) goes away.
        let previous = scratch.0.join(PREVIOUS);
        fs::create_dir(&previous).unwrap();
        fs::write(previous.join(MARKER), "1.1.0").unwrap();
        install(&app_payload(b"newer"), &destination, "1.2.0").unwrap();
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"newer");
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: a `.pantry-setup-previous` without the marker is not ours and
    // blocks the install with its path named.
    #[test]
    fn install_refuses_a_foreign_previous_folder() {
        let scratch = Scratch::new();
        let previous = scratch.0.join(PREVIOUS);
        fs::create_dir(&previous).unwrap();
        fs::write(previous.join("keep"), b"x").unwrap();
        let error =
            install(&app_payload(b"new"), &scratch.0.join("installed"), "1.0.0").unwrap_err();
        assert!(error.to_string().contains(PREVIOUS), "{error}");
        assert!(previous.join("keep").is_file());
    }

    // Oracle: only `.pantry-setup-<number>` folders of another pid go;
    // look-alikes, files and our own stage stay.
    #[test]
    fn stale_stages_are_cleaned() {
        let scratch = Scratch::new();
        for name in [
            ".pantry-setup-4242",
            ".pantry-setup-7",
            ".pantry-setup-notes",
            "Pantry",
        ] {
            fs::create_dir(scratch.0.join(name)).unwrap();
            fs::write(scratch.0.join(name).join("f"), b"x").unwrap();
        }
        fs::write(scratch.0.join(".pantry-setup-99"), b"a file").unwrap();
        clean_stale_stages(&scratch.0, 7).unwrap();
        assert_eq!(
            entries(&scratch.0),
            [
                ".pantry-setup-7",
                ".pantry-setup-99",
                ".pantry-setup-notes",
                "Pantry"
            ]
        );

        // install() runs the cleanup first.
        fs::create_dir(scratch.0.join(".pantry-setup-4243")).unwrap();
        install(&app_payload(b"new"), &scratch.0.join("installed"), "1.0.0").unwrap();
        assert!(!scratch.0.join(".pantry-setup-4243").exists());
    }

    // Oracle: install failures with no app or scanner leave the old copy.
    #[test]
    fn install_keeps_the_old_copy_when_the_payload_is_incomplete() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
        let partial = payload(&[(APP, b"new", true)]);
        assert!(install(&partial, &destination, "1.1.0").is_err());
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"old");
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: uninstall removes our folder, then asks the installed scanner
    // (its bytes intact) to remove the schedule, and leaves the state folder
    // and nothing else beside the install; a foreign folder stays and the
    // schedule is not touched.
    #[test]
    fn uninstall_removes_only_what_setup_made() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        let state = scratch.0.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(state.join("history.db"), b"keep").unwrap();
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();

        let mut called = None;
        let removal = uninstall(
            &destination,
            None,
            |scanner| {
                // The folder step is done before the schedule is touched.
                assert!(!destination.exists());
                called = Some(fs::read(scanner).unwrap());
                Ok(())
            },
            || panic!("the scanner worked"),
        )
        .unwrap();
        assert_eq!(removal, Removal::Removed);
        assert_eq!(called.as_deref(), Some(&b"scanner"[..]));
        assert!(!destination.exists());
        assert_eq!(entries(&scratch.0), ["state"]);
        assert_eq!(fs::read(state.join("history.db")).unwrap(), b"keep");

        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("mine"), b"x").unwrap();
        let error = uninstall(
            &destination,
            None,
            |_| panic!("not ours"),
            || panic!("not ours"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("left it in place"), "{error}");
        assert!(destination.join("mine").is_file());
    }

    // Oracle: a failed uninstall leaves an install Setup still owns:
    // the marker and the files it could not remove are back in place, the
    // schedule is untouched, the error says plainly what happened, and a
    // later uninstall (once the problem is gone) removes it. Known-bad: the
    // old `remove_dir_all` deleted the marker first and then failed, so
    // both install and uninstall refused with "found a folder it did not
    // create".
    #[cfg(unix)]
    #[test]
    fn failed_uninstall_keeps_the_marker() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(
            &payload(&[
                (APP, b"app", true),
                (SCANNER, b"scanner", true),
                ("zz/locked/file", b"x", false),
            ]),
            &destination,
            "1.0.0",
        )
        .unwrap();
        let locked = destination.join("zz/locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        // Root ignores the mode bits; the check needs a refusal to exist.
        if fs::write(locked.join("probe"), b"").is_ok() {
            return;
        }
        let error = uninstall(
            &destination,
            None,
            |_| panic!("schedule touched after a failed folder step"),
            || panic!("schedule touched after a failed folder step"),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("put back what was left") && text.contains(NO_PERMISSION),
            "{text}"
        );
        assert_eq!(installed_version(&destination), Some([1, 0, 0]));
        assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
        assert!(locked.join("file").is_file());
        assert_eq!(entries(&scratch.0), ["installed"]);
        // Setup still owns it: repair works, and so does a later uninstall.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            install(&app_payload(b"app"), &destination, "1.0.0").unwrap(),
            Installed::Bundled
        );
        let removal = uninstall(&destination, None, |_| Ok(()), || Ok(())).unwrap();
        assert_eq!(removal, Removal::Removed);
        assert!(scratch.0.read_dir().unwrap().next().is_none());
    }

    // Oracle: with no install folder, uninstall reports NotInstalled
    // (run() prints NOT_INSTALLED, never REMOVED) and touches no schedule.
    // Known-bad: the old code returned Ok(()) and run() said "removed".
    #[test]
    fn uninstall_with_nothing_installed_says_so() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        let removal = uninstall(
            &destination,
            None,
            |_| panic!("nothing installed"),
            || panic!("nothing installed"),
        )
        .unwrap();
        assert_eq!(removal, Removal::NotInstalled);
        assert!(!NOT_INSTALLED.contains("removed Pantry"));
    }

    // Oracle: an install whose scanner is gone, or whose scanner fails,
    // still gets its schedule removed by the direct route; if that cannot
    // finish, the error says a scheduled scan may remain and gives the
    // steps, and the kept scanner is named. Known-bad: the old code skipped
    // the schedule when the scanner was missing and said "removed Pantry".
    #[test]
    fn uninstall_without_a_scanner_still_removes_the_schedule() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
        fs::remove_file(destination.join(SCANNER)).unwrap();
        let mut direct = false;
        let removal = uninstall(
            &destination,
            None,
            |_| panic!("no scanner"),
            || {
                direct = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(direct && removal == Removal::Removed);
        assert!(scratch.0.read_dir().unwrap().next().is_none());

        // The scanner fails and the direct route cannot finish either.
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
        let error = uninstall(
            &destination,
            None,
            |_| Err(io::Error::other("scanner broke")),
            || Err("To remove it, do X.".into()),
        )
        .unwrap_err();
        let text = error.to_string();
        let keep = scratch
            .0
            .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
        assert!(
            text.contains("a scheduled scan may remain")
                && text.contains("do X")
                && text.contains("scanner broke")
                && text.contains(&keep.display().to_string()),
            "{text}"
        );
        assert!(!destination.exists());
        assert!(keep.join(Path::new(SCANNER).file_name().unwrap()).is_file());
        // A later Setup run clears the kept scanner once it is stale.
        clean_stale_stages(&scratch.0, std::process::id() + 1).unwrap();
        assert!(!keep.exists());
    }

    // Oracle: the folder an earlier failed uninstall kept is how its
    // schedule gets removed. A second uninstall retries with that scanner
    // and removes the folder only once the schedule is gone; if it is still
    // there the uninstall fails (exit 1), says so, and keeps the folder.
    // Known-bad: the old code deleted the kept folder as a stale stage,
    // touched no schedule, and printed "removed nothing" with exit 0.
    #[test]
    fn a_second_uninstall_retries_the_kept_scanner() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
        uninstall(
            &destination,
            None,
            |_| Err(io::Error::other("scanner broke")),
            || Err("To remove it, do X.".into()),
        )
        .unwrap_err();
        // That run's pid is now another process's.
        let ours = scratch
            .0
            .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
        let earlier = scratch.0.join(format!(
            "{UNINSTALL_SCANNER_PREFIX}{}",
            std::process::id() + 1
        ));
        fs::rename(&ours, &earlier).unwrap();
        let kept = earlier.join(Path::new(SCANNER).file_name().unwrap());

        // Still failing: an error, not "removed nothing", and the folder stays.
        let mut tried = Vec::new();
        let error = uninstall(
            &destination,
            None,
            |scanner| {
                tried.push(scanner.to_path_buf());
                Err(io::Error::other("still broken"))
            },
            || Err("To remove it, do Y.".into()),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("is still there")
                && text.contains("do Y")
                && text.contains("still broken"),
            "{text}"
        );
        assert!(text.contains(&kept.display().to_string()), "{text}");
        assert_eq!(tried, std::slice::from_ref(&kept));
        assert!(
            kept.is_file(),
            "the kept scanner stays until the schedule is gone"
        );

        // Now it works: the schedule goes first, then the folder.
        let removal = uninstall(
            &destination,
            None,
            |scanner| {
                assert!(scanner.is_file(), "the folder is removed only afterwards");
                Ok(())
            },
            || panic!("the kept scanner worked"),
        )
        .unwrap();
        assert_eq!(removal, Removal::LeftoverRemoved);
        assert!(!earlier.exists());
        assert!(!LEFTOVER_REMOVED.contains("removed nothing"));
        // A third run has nothing left to do.
        let removal = uninstall(&destination, None, |_| panic!("gone"), || panic!("gone")).unwrap();
        assert_eq!(removal, Removal::NotInstalled);
    }

    // Oracle: through the real `remove_schedule`, an installed scanner
    // whose `schedule uninstall` exits 1 (as it does now when launchd still
    // has the job) is a failure, never "removed Pantry". The stand-in
    // scanner only exits 1.
    #[cfg(unix)]
    #[test]
    fn a_scanner_that_cannot_remove_the_schedule_is_reported() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        let failing: &[u8] = b"#!/bin/sh\nexit 1\n";
        install(
            &payload(&[(APP, b"app", true), (SCANNER, failing, true)]),
            &destination,
            "1.0.0",
        )
        .unwrap();
        let error = uninstall(&destination, None, remove_schedule, || {
            Err("To remove it, do X.".into())
        })
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("a scheduled scan may remain")
                && text.contains("schedule uninstall failed")
                && text.contains("do X"),
            "{text}"
        );
        assert!(!text.contains(REMOVED), "{text}");
        // Positive control: when the direct route works, it is removed.
        let earlier = scratch
            .0
            .join(format!("{UNINSTALL_SCANNER_PREFIX}{}", std::process::id()));
        fs::remove_dir_all(&earlier).unwrap();
        install(
            &payload(&[(APP, b"app", true), (SCANNER, failing, true)]),
            &destination,
            "1.0.0",
        )
        .unwrap();
        let removal = uninstall(&destination, None, remove_schedule, || Ok(())).unwrap();
        assert_eq!(removal, Removal::Removed);
    }

    /// A finished helper's output, for the launchd checks.
    #[cfg(unix)]
    fn answer(code: i32, stdout: &str, stderr: &str) -> Option<std::process::Output> {
        use std::os::unix::process::ExitStatusExt;
        Some(std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    // Oracle: launchd's own answer. After the bootout and the plist delete,
    // `launchctl print` must fail; if it still lists the job, the direct
    // route fails with the bootout step, and a failed bootout's words are
    // kept. Known-bad: the old code discarded the bootout result and never
    // asked, so Setup said "removed Pantry" with exit 0. Only stand-in
    // answers are used: no real launchctl runs.
    #[cfg(unix)]
    #[test]
    fn the_direct_route_checks_launchd_let_go() {
        use std::sync::Mutex;
        let scratch = Scratch::new();
        let agents = scratch.0.join("Library/LaunchAgents");
        let plist = agents.join(format!("{SCHEDULE_LABEL}.plist"));
        let calls = Mutex::new(Vec::new());
        let stand_in = |loaded: bool, bootout_fails: bool| {
            let calls = &calls;
            move |program: &str, args: &[&str]| {
                calls
                    .lock()
                    .unwrap()
                    .push(format!("{program} {}", args.join(" ")));
                match (program, args.first().copied()) {
                    ("id", _) => answer(0, "501\n", ""),
                    ("launchctl", Some("bootout")) if bootout_fails => {
                        answer(5, "", "Boot-out failed: 5: Input/output error")
                    }
                    ("launchctl", Some("print")) if !loaded => {
                        answer(113, "", "Could not find service")
                    }
                    _ => answer(0, "", ""),
                }
            }
        };
        fs::create_dir_all(&agents).unwrap();
        fs::write(&plist, b"<plist/>").unwrap();
        let error = remove_launchd_job(&scratch.0, &stand_in(true, true)).unwrap_err();
        assert!(
            error.contains("still loaded")
                && error.contains(&format!("launchctl bootout gui/501/{SCHEDULE_LABEL}"))
                && error.contains("Boot-out failed"),
            "{error}"
        );
        assert!(!plist.exists(), "the plist goes either way");
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "id -u".to_owned(),
                format!("launchctl bootout gui/501/{SCHEDULE_LABEL}"),
                format!("launchctl print gui/501/{SCHEDULE_LABEL}"),
            ]
        );
        assert_eq!(
            remove_launchd_job(&scratch.0, &stand_in(false, false)),
            Ok(())
        );
        // launchctl that cannot run, or no user id, is not proof it is gone.
        let missing = |program: &str, _: &[&str]| {
            if program == "id" {
                answer(0, "501\n", "")
            } else {
                None
            }
        };
        assert!(remove_launchd_job(&scratch.0, &missing).is_err());
        let no_id = |_: &str, _: &[&str]| answer(1, "", "");
        assert!(
            remove_launchd_job(&scratch.0, &no_id)
                .unwrap_err()
                .contains("log out")
        );
    }

    // Oracle: with nothing installed, Setup's own menu entry and icon from
    // an earlier install still go; someone else's entry stays.
    #[cfg(target_os = "linux")]
    #[test]
    fn stale_shortcuts_go_when_nothing_is_installed() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        let root = scratch.0.join("share");
        let entry = root.join(LINUX_ENTRY);
        let icon = root.join(LINUX_ICON);
        fs::create_dir_all(entry.parent().unwrap()).unwrap();
        fs::create_dir_all(icon.parent().unwrap()).unwrap();
        fs::write(&entry, format!("[Desktop Entry]\n{LINUX_ENTRY_KEY}=1\n")).unwrap();
        fs::write(&icon, b"png").unwrap();
        let removal = uninstall(
            &destination,
            Some(&root),
            |_| panic!("none"),
            || panic!("none"),
        )
        .unwrap();
        assert_eq!(removal, Removal::NotInstalled);
        assert!(!entry.exists() && !icon.exists());
    }

    // Oracle: a recoverable previous copy (it has the marker) is never
    // deleted while the destination is not a healthy install of ours. With a
    // foreign destination Setup refuses, naming the destination, and the
    // previous copy is byte for byte intact. With a damaged destination of
    // ours, the previous copy is restored (seen through the downgrade guard
    // keeping its newer app). Known-bad: the old code deleted the previous
    // copy whenever the destination existed, then refused.
    #[test]
    fn install_never_deletes_a_recoverable_previous_copy() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        let previous = scratch.0.join(PREVIOUS);
        install(&app_payload(b"only copy"), &previous, "9.0.0").unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("theirs"), b"x").unwrap();
        let error = install(&app_payload(b"new"), &destination, "1.0.0").unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&destination.display().to_string()),
            "{error}"
        );
        assert_eq!(fs::read(previous.join(APP)).unwrap(), b"only copy");
        assert_eq!(entries(&destination), ["theirs"]);

        // Ours but damaged (no app): the previous copy comes back.
        fs::remove_file(destination.join("theirs")).unwrap();
        fs::write(destination.join(MARKER), "0.1.0").unwrap();
        assert_eq!(
            install(&app_payload(b"new"), &destination, "1.0.0").unwrap(),
            Installed::KeptNewer
        );
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"only copy");
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: a same-version run of Setup is a repair: a deleted or
    // corrupted scanner comes back byte for byte from the payload. Known-bad:
    // a mutant that skips same-version installs (`installed >= bundled`)
    // leaves the scanner missing or corrupt.
    #[test]
    fn same_version_reinstall_repairs_a_damaged_install() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
        fs::remove_file(destination.join(SCANNER)).unwrap();
        assert_eq!(
            install(&app_payload(b"app"), &destination, "1.0.0").unwrap(),
            Installed::Bundled
        );
        assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
        fs::write(destination.join(SCANNER), b"garbage").unwrap();
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
        assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
        assert_eq!(entries(&scratch.0), ["installed"]);
    }

    // Oracle: an older Setup over a newer install reports KeptNewer
    // (run() then shows NEWER_INSTALLED and opens the installed app) and
    // leaves the install byte for byte. Known-bad: the old code returned a
    // bare Ok(()), the same as a real install, so run() said nothing.
    #[test]
    fn older_setup_over_newer_install_says_so() {
        let scratch = Scratch::new();
        let destination = scratch.0.join("installed");
        install(&app_payload(b"newer"), &destination, "2.0.0").unwrap();
        assert_eq!(
            install(&app_payload(b"older"), &destination, "1.0.0").unwrap(),
            Installed::KeptNewer
        );
        assert_eq!(fs::read(destination.join(APP)).unwrap(), b"newer");
        assert_eq!(NEWER_INSTALLED, "A newer Pantry is already installed.");
    }

    // Oracle: with `setup.lock` held by another holder, Setup gets
    // SetupRunning (run() then prints SETUP_RUNNING) and installs nothing;
    // with `window.lock` held, the existing open-Pantry rules apply.
    // Known-bad: the old code returned Ok(()) with no message.
    #[test]
    fn a_second_setup_says_setup_is_running() {
        let scratch = Scratch::new();
        let state = scratch.0.join("state");
        let destination = scratch.0.join("installed");
        let held = instance::try_lock(&state, instance::SETUP_LOCK)
            .unwrap()
            .unwrap();
        for mode in [Mode::Install, Mode::InstallOnly, Mode::Uninstall] {
            assert_eq!(
                take_locks(&state, &destination, mode, "1.0.0")
                    .unwrap()
                    .err(),
                Some(Blocked::SetupRunning)
            );
        }
        assert!(SETUP_RUNNING.contains("already running"));
        drop(held);
        let window = instance::try_lock(&state, instance::WINDOW_LOCK)
            .unwrap()
            .unwrap();
        assert_eq!(
            take_locks(&state, &destination, Mode::InstallOnly, "1.0.0")
                .unwrap()
                .err(),
            Some(Blocked::Refuse(RUNNING))
        );
        drop(window);
        assert!(
            take_locks(&state, &destination, Mode::Install, "1.0.0")
                .unwrap()
                .is_ok()
        );
        assert!(!destination.exists());
    }

    // Oracle: Desktop Entry spec, "The Exec key" quoting rules, applied
    // after the string-value escapes.
    #[test]
    fn desktop_exec_quoting() {
        assert_eq!(
            desktop_exec_quote("/home/a b/x").unwrap(),
            "\"/home/a b/x\""
        );
        assert_eq!(
            desktop_exec_quote("/h/$\"`\\%").unwrap(),
            "\"/h/\\\\$\\\\\"\\\\`\\\\\\\\%%\""
        );
        assert!(desktop_exec_quote("/h/\nx").is_err());
        let entry = desktop_entry(Path::new("/opt/p/wpantry-desktop"), "1.0.0").unwrap();
        assert!(
            entry.contains("\nExec=\"/opt/p/wpantry-desktop\"\n"),
            "{entry}"
        );
        assert!(entry.contains(&format!("\nStartupWMClass={LINUX_WM_CLASS}\n")));
    }

    // Oracle: errno / Windows error tables. Busy or locked files
    // (EBUSY 16, ETXTBSY 26, Windows 32/33) read as in use; EPERM 1 and
    // EACCES 13 read as no permission and name the folder; Windows 5 gets
    // its combined sentence; the system's text stays as detail; Setup's own
    // messages pass through. Known-bad: the old code called every
    // permission error "Pantry is in use".
    #[test]
    fn errors_read_plainly() {
        let folder = Path::new("/somewhere/Pantry");
        assert_eq!(explain(&io::Error::other(RUNNING), Some(folder)), RUNNING);
        let busy = explain(&io::Error::from(io::ErrorKind::ResourceBusy), None);
        assert!(
            busy.starts_with(IN_USE) && busy.contains("Details: "),
            "{busy}"
        );
        #[cfg(unix)]
        {
            for code in [16, 26] {
                let text = explain(&io::Error::from_raw_os_error(code), Some(folder));
                assert!(text.starts_with(IN_USE), "{code}: {text}");
            }
            for code in [1, 13] {
                let error = io::Error::from_raw_os_error(code);
                let text = explain(&error, Some(folder));
                assert!(
                    text.starts_with(NO_PERMISSION)
                        && text.contains("/somewhere/Pantry")
                        && text.ends_with(&error.to_string())
                        && !text.contains(IN_USE),
                    "{code}: {text}"
                );
            }
        }
        #[cfg(windows)]
        {
            for code in [32, 33] {
                assert!(explain(&io::Error::from_raw_os_error(code), None).starts_with(IN_USE));
            }
            assert!(explain(&io::Error::from_raw_os_error(5), None).starts_with(WINDOWS_DENIED));
        }
    }

    // Oracle: a payload file missing from the extracted download names
    // that file in plain words and keeps the system text ("os error 2") as
    // detail. Known-bad: the old code showed only the raw "No such file or
    // directory (os error 2)".
    #[test]
    fn a_missing_payload_file_is_named() {
        let scratch = Scratch::new();
        let missing = scratch.0.join("Resources/pantry-setup.zlib");
        let text = explain(&read_payload(&missing).unwrap_err(), None);
        assert!(
            text.starts_with("Pantry Setup is missing a file from its download: ")
                && text.contains(&missing.display().to_string())
                && text.contains("Details: "),
            "{text}"
        );
        fs::create_dir_all(missing.parent().unwrap()).unwrap();
        fs::write(&missing, b"payload").unwrap();
        assert_eq!(read_payload(&missing).unwrap(), b"payload");
    }

    // Oracle: a desktop entry without Setup's key is the user's and stays.
    #[test]
    fn remove_shortcuts_keeps_foreign_entries() {
        let scratch = Scratch::new();
        let entry = scratch.0.join(LINUX_ENTRY);
        fs::create_dir_all(entry.parent().unwrap()).unwrap();
        fs::write(&entry, "[Desktop Entry]\nName=Mine\n").unwrap();
        remove_shortcuts(&scratch.0).unwrap();
        assert!(entry.is_file());
        if cfg!(target_os = "linux") {
            create_shortcuts(&scratch.0, Path::new("/opt/pantry"), "1.0.0").unwrap();
            assert!(scratch.0.join(LINUX_ICON).is_file());
            remove_shortcuts(&scratch.0).unwrap();
            assert!(!entry.exists() && !scratch.0.join(LINUX_ICON).exists());
        }
    }
}
