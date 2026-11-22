use std::env;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

pub fn directories() -> io::Result<(PathBuf, PathBuf)> {
    if let Some(root) = env_path("WPANTRY_DESKTOP_HOME") {
        return Ok((root.join("state"), root.join("installed")));
    }
    let variable = if cfg!(windows) {
        "LOCALAPPDATA"
    } else {
        "HOME"
    };
    let home =
        env_path(variable).ok_or_else(|| io::Error::other(format!("{variable} is unavailable")))?;
    if cfg!(windows) {
        Ok((home.join("Waffuru/Pantry"), home.join("Programs/Pantry")))
    } else if cfg!(target_os = "macos") {
        Ok((
            home.join("Library/Application Support/ai.waffuru.pantry.desktop"),
            home.join("Applications/Pantry"),
        ))
    } else {
        let state = env_path("XDG_STATE_HOME").unwrap_or_else(|| home.join(".local/state"));
        let data = env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        Ok((state.join("pantry-desktop"), data.join("pantry-desktop")))
    }
}

/// Lock file the open Pantry window holds for as long as it runs.
pub const WINDOW_LOCK: &str = "window.lock";
/// Lock file Pantry Setup holds while it installs or uninstalls. It is
/// separate from [`WINDOW_LOCK`] so Setup can tell an open Pantry window
/// apart from a second copy of Setup.
pub const SETUP_LOCK: &str = "setup.lock";
const ACTIVATION: &str = "activate";

/// Folder that holds Pantry's launcher shortcuts, or `None` where the
/// installed app is its own launcher (macOS `~/Applications`).
///
/// Windows: the per-user Start Menu `Programs` folder. Linux: the XDG data
/// folder that holds `applications/` and `icons/`. With
/// `WPANTRY_DESKTOP_HOME` set, `<root>/shortcuts` stands in for both so
/// tests never touch the real menus.
pub fn shortcuts() -> io::Result<Option<PathBuf>> {
    if let Some(root) = env_path("WPANTRY_DESKTOP_HOME") {
        return Ok((!cfg!(target_os = "macos")).then(|| root.join("shortcuts")));
    }
    if cfg!(target_os = "macos") {
        Ok(None)
    } else if cfg!(windows) {
        let roaming =
            env_path("APPDATA").ok_or_else(|| io::Error::other("APPDATA is unavailable"))?;
        Ok(Some(roaming.join("Microsoft/Windows/Start Menu/Programs")))
    } else {
        let home = env_path("HOME").ok_or_else(|| io::Error::other("HOME is unavailable"))?;
        Ok(Some(
            env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share")),
        ))
    }
}

/// Take an exclusive lock on `state/name` without waiting. `None` means
/// another process holds it. The file stays in place after the lock is
/// released, so every process always locks the same file.
///
/// ```no_run
/// # fn main() -> std::io::Result<()> {
/// let (state, _) = wpantry_desktop::instance::directories()?;
/// if wpantry_desktop::instance::try_lock(&state, wpantry_desktop::instance::SETUP_LOCK)?.is_none() {
///     println!("Pantry Setup is already running.");
/// }
/// # Ok(())
/// # }
/// ```
pub fn try_lock(state: &Path, name: &str) -> io::Result<Option<File>> {
    fs::create_dir_all(state)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join(name))?;
    match lock.try_lock() {
        Ok(()) => Ok(Some(lock)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

/// Ask the open Pantry window to come forward. The window polls the length
/// of the activation file, so each request appends one byte.
pub fn request_activation(state: &Path) -> io::Result<()> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join(ACTIVATION))?
        .write_all(b"\n")
}

pub struct Instance {
    _lock: File,
    activation: PathBuf,
    last: u64,
}

impl Instance {
    /// Claim a window or ask an existing window to come forward.
    pub fn claim(state: &Path) -> io::Result<Option<Self>> {
        let Some(lock) = try_lock(state, WINDOW_LOCK)? else {
            request_activation(state)?;
            return Ok(None);
        };
        let activation = state.join(ACTIVATION);
        File::create(&activation)?;
        Ok(Some(Self {
            _lock: lock,
            activation,
            last: 0,
        }))
    }

    pub fn activation_requested(&mut self) -> bool {
        let Ok(metadata) = self.activation.metadata() else {
            return false;
        };
        let current = metadata.len();
        current != std::mem::replace(&mut self.last, current)
    }
}
