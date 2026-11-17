//! Software Update, the App Store, and XProtect's definitions.

use super::read;
use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin, flag};

const SU: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// Software Update checks for and downloads updates on its own.
fn updates_check(r: Runner) -> Outcome {
    let check = flag(&read(r, SU, "AutomaticCheckEnabled"));
    let download = flag(&read(r, SU, "AutomaticDownload"));
    // Unset means macOS's default, which is on for both.
    match (check, download) {
        (Some(false), _) | (_, Some(false)) => Outcome::fail(format!(
            "AutomaticCheckEnabled={} AutomaticDownload={}",
            check.map_or("default".into(), |b| b.to_string()),
            download.map_or("default".into(), |b| b.to_string())
        )),
        _ => Outcome::pass("checks and downloads automatically"),
    }
}

/// Security responses, system data files and macOS updates install on their own.
fn updates_install(r: Runner) -> Outcome {
    let critical = flag(&read(r, SU, "CriticalUpdateInstall"));
    let config = flag(&read(r, SU, "ConfigDataInstall"));
    let macos = flag(&read(r, SU, "AutomaticallyInstallMacOSUpdates"));
    if critical != Some(false) && config != Some(false) && macos == Some(true) {
        Outcome::pass("security responses, system data and macOS updates install automatically")
    } else {
        Outcome::fail(format!(
            "CriticalUpdateInstall={} ConfigDataInstall={} AutomaticallyInstallMacOSUpdates={}",
            critical.map_or("default".into(), |b| b.to_string()),
            config.map_or("default".into(), |b| b.to_string()),
            macos.map_or("off".into(), |b| b.to_string())
        ))
    }
}

fn app_store_updates(r: Runner) -> Outcome {
    match flag(&read(r, "/Library/Preferences/com.apple.commerce", "AutoUpdate")) {
        Some(true) => Outcome::pass("App Store updates install automatically"),
        Some(false) => Outcome::fail("App Store AutoUpdate is off"),
        None => Outcome::fail("App Store AutoUpdate is not set (off)"),
    }
}

/// Where XProtect's definitions live: `/var/protected/xprotect` since
/// macOS 15 (`xprotect update` writes there), the CoreServices bundle before.
const XPROTECT_DATA: &[&str] =
    &["/var/protected/xprotect/XProtect.bundle", "/Library/Apple/System/Library/CoreServices/XProtect.bundle"];
/// XProtect Remediator, the scanner that removes what XProtect knows.
const XPROTECT_REMEDIATOR: &str = "/Library/Apple/System/Library/CoreServices/XProtect.app";

fn bundle_version(r: Runner, bundle: &str) -> Option<String> {
    let out = read(r, &format!("{bundle}/Contents/Info"), "CFBundleShortVersionString");
    let v = out.trim();
    (!v.is_empty() && !v.contains("does not exist") && !v.contains(' ')).then(|| v.to_string())
}

/// Days since XProtect's data last changed: the newest of its copies.
fn xprotect_age() -> Option<u64> {
    XPROTECT_DATA
        .iter()
        .filter_map(|b| std::fs::metadata(format!("{b}/Contents/Info.plist")).ok()?.modified().ok()?.elapsed().ok())
        .map(|d| d.as_secs() / 86400)
        .min()
}

/// XProtect's definitions version (`xprotect version` on macOS 15 and
/// later, else the bundle's), XProtect Remediator's, and the data's age.
fn xprotect(r: Runner) -> Outcome {
    let cli = r(&["xprotect", "version"]);
    let data = cli
        .lines()
        .find_map(|l| l.trim().strip_prefix("Version:"))
        .and_then(|v| v.split_whitespace().next())
        .map(str::to_string)
        .or_else(|| XPROTECT_DATA.iter().find_map(|b| bundle_version(r, b)));
    xprotect_verdict(data, bundle_version(r, XPROTECT_REMEDIATOR), xprotect_age())
}

fn xprotect_verdict(data: Option<String>, remediator: Option<String>, days: Option<u64>) -> Outcome {
    let (Some(data), Some(days)) = (data, days) else {
        return Outcome::unknown("XProtect's data isn't where macOS keeps it");
    };
    let Some(remediator) = remediator else {
        return Outcome::fail(format!(
            "XProtect {data} (updated {days} days ago), but XProtect Remediator is missing: nothing removes what XProtect finds"
        ));
    };
    Outcome::of(days <= 45, format!("XProtect {data}, updated {days} days ago; XProtect Remediator {remediator}"))
}

pub(super) const UPDATES_CHECK: Check = Check {
    id: "POSTURE-UPDATES-CHECK",
    cis: "1.2",
    title: "Software Update checks and downloads automatically",
    severity: Severity::High,
    probe: updates_check,
    fix: admin(
        "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
    ),
    explain: "Updates arrive without anyone remembering to look",
};

pub(super) const UPDATES_INSTALL: Check = Check {
    id: "POSTURE-UPDATES-INSTALL",
    cis: "1.3",
    title: "Security responses and macOS updates install automatically",
    severity: Severity::High,
    probe: updates_install,
    fix: admin(
        "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true",
    ),
    explain: "Rapid Security Responses and macOS updates apply on their own",
};

pub(super) const APPSTORE_UPDATES: Check = Check {
    id: "POSTURE-APPSTORE-UPDATES",
    cis: "1.4",
    title: "App Store updates install automatically",
    severity: Severity::Medium,
    probe: app_store_updates,
    fix: admin("sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true"),
    explain: "App Store apps get their fixes without a visit",
};

pub(super) const XPROTECT: Check = Check {
    id: "POSTURE-XPROTECT",
    cis: "5.10",
    title: "XProtect data current and XProtect Remediator present",
    severity: Severity::Medium,
    probe: xprotect,
    fix: admin("softwareupdate --background-critical  (and check that Software Update installs system data files)"),
    explain: "The built-in malware definitions are fresh",
};

#[cfg(test)]
#[path = "updates_tests.rs"]
mod tests;
