//! Removing the scheduled scan the app and the CLI share: through the
//! installed scanner, or directly when it is missing or fails.

use crate::quiet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, io};

/// The scheduled scan's launchd label and systemd/cron names. These copy
/// `rust/crates/wpantry-cli/src/schedule.rs` (`LABEL`, `CRON_MARK`) and
/// `schedule/windows.rs` (`task`).
/// TODO: share these with the CLI crate once the desktop crate depends on it.
const SCHEDULE_LABEL: &str = "ai.waffuru.wpantry";
const CRON_MARK: &str = "# wpantry schedule";
const WINDOWS_TASK_PREFIX: &str = "Waffuru-Pantry-";

/// Ask the scanner Setup installed to remove Pantry's scheduled scan, so no
/// job is left pointing at a deleted scanner.
pub(super) fn remove_schedule(scanner: &Path) -> io::Result<()> {
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
pub(super) fn remove_schedule_directly() -> Result<(), String> {
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

// Every check here drives launchd stand-ins, so they run on Unix.
#[cfg(all(test, unix))]
#[path = "schedule_tests.rs"]
mod tests;
