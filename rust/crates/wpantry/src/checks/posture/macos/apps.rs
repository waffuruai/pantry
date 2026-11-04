//! Settings inside Apple's own apps: Terminal's Secure Keyboard Entry and
//! Safari opening downloads on its own.

use super::super::{Check, Outcome, Runner, Severity, flag, user};
use super::read;

fn terminal_secure_input(r: Runner) -> Outcome {
    match flag(&read(r, "com.apple.Terminal", "SecureKeyboardEntry")) {
        Some(true) => Outcome::pass("Terminal's Secure Keyboard Entry is on"),
        _ => Outcome::fail("Terminal's Secure Keyboard Entry is off"),
    }
}

fn safari_safe_files(r: Runner) -> Outcome {
    let home = crate::utils::files::home();
    let container = home.join("Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari");
    let out = read(r, &container.to_string_lossy(), "AutoOpenSafeDownloads");
    match flag(&out) {
        Some(false) => Outcome::pass("Safari doesn't open \"safe\" downloads on its own"),
        Some(true) => Outcome::fail("Safari opens \"safe\" downloads on its own"),
        None if out.contains("does not exist") => Outcome::fail("Safari opens \"safe\" downloads on its own (default)"),
        None => Outcome::manual("Safari's preferences can't be read here (Full Disk Access)"),
    }
}

pub(super) const TERMINAL_SECURE_INPUT: Check = Check {
    id: "POSTURE-TERMINAL-SECURE-INPUT",
    cis: "6.4.1",
    title: "Terminal Secure Keyboard Entry",
    severity: Severity::Medium,
    probe: terminal_secure_input,
    fix: user("defaults write com.apple.Terminal SecureKeyboardEntry -bool true"),
    explain: "Other apps can't read what you type into Terminal",
};

pub(super) const SAFARI_SAFE_FILES: Check = Check {
    id: "POSTURE-SAFARI-SAFE-FILES",
    cis: "6.3.1",
    title: "Safari doesn't open downloads on its own",
    severity: Severity::Medium,
    probe: safari_safe_files,
    fix: user("Safari → Settings → General → Open \"safe\" files after downloading: off"),
    explain: "A downloaded file runs only when you open it",
};
