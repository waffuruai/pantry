//! Who can sit down at the Mac: the Guest account, automatic login,
//! password hints, the screen lock and screen saver, and whether the
//! everyday account is an administrator.

use super::super::{Check, Outcome, Runner, Severity, admin, flag, user};
use super::{read, read_host};

const LOGINWINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

fn guest(r: Runner) -> Outcome {
    match flag(&read(r, LOGINWINDOW, "GuestEnabled")) {
        Some(true) => Outcome::fail("the Guest account is enabled"),
        _ => Outcome::pass("the Guest account is disabled"),
    }
}

fn auto_login(r: Runner) -> Outcome {
    let out = read(r, LOGINWINDOW, "autoLoginUser");
    let user = out.trim();
    if user.is_empty() || user.contains("does not exist") {
        Outcome::pass("no automatic login")
    } else {
        Outcome::fail("automatic login is on for a user")
    }
}

fn password_hints(r: Runner) -> Outcome {
    let out = read(r, LOGINWINDOW, "RetriesUntilHint");
    let n = out.trim().parse::<i64>().ok();
    match n {
        Some(0) => Outcome::pass("password hints are off"),
        Some(n) => Outcome::fail(format!("a password hint shows after {n} failed attempts")),
        None => Outcome::fail("RetriesUntilHint is not set (hints after 3 attempts)"),
    }
}

fn screen_lock(r: Runner) -> Outcome {
    let out = r(&["sysadminctl", "-screenLock", "status"]);
    let line = out.lines().find(|l| l.contains("screenLock")).unwrap_or("").trim();
    if line.contains("is off") {
        Outcome::fail(line)
    } else if line.contains("delay") || line.contains("immediate") {
        Outcome::pass(line)
    } else {
        Outcome::unknown("sysadminctl gave no answer")
    }
}

fn screensaver_idle(r: Runner) -> Outcome {
    let out = read_host(r, "com.apple.screensaver", "idleTime");
    match out.trim().parse::<i64>().ok() {
        Some(0) => Outcome::fail("the screen saver never starts (idleTime 0)"),
        Some(s) if s <= 1200 => Outcome::pass(format!("the screen saver starts after {s} s")),
        Some(s) => Outcome::fail(format!("the screen saver starts after {s} s (over 20 minutes)")),
        None => Outcome::pass("the screen saver idle time is the default (20 minutes)"),
    }
}

/// The logged-in user isn't an administrator: what they run can't install
/// system-wide persistence or change security settings without a prompt
/// for another account's password.
fn not_admin(r: Runner) -> Outcome {
    let out = r(&["id", "-Gn"]);
    if out.trim().is_empty() {
        return Outcome::unknown("id -Gn gave no answer");
    }
    let admin = out.split_whitespace().any(|g| g == "admin");
    Outcome::of(
        !admin,
        if admin {
            "the everyday account is an administrator: anything it runs is one password prompt from root"
        } else {
            "the everyday account is a standard user"
        },
    )
}

pub(super) const GUEST: Check = Check {
    id: "POSTURE-GUEST",
    cis: "2.13.1",
    title: "Guest account disabled",
    severity: Severity::High,
    probe: guest,
    fix: admin("sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"),
    explain: "No login without a password",
};

pub(super) const AUTO_LOGIN: Check = Check {
    id: "POSTURE-AUTO-LOGIN",
    cis: "2.13.3",
    title: "Automatic login off",
    severity: Severity::Critical,
    probe: auto_login,
    fix: admin(
        "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser  (System Settings → Users & Groups → Automatic login: off)",
    ),
    explain: "Whoever turns the Mac on is not logged in as you",
};

pub(super) const PASSWORD_HINTS: Check = Check {
    id: "POSTURE-PASSWORD-HINTS",
    cis: "2.11.5",
    title: "Password hints off",
    severity: Severity::Medium,
    probe: password_hints,
    fix: admin("sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"),
    explain: "The login window never shows a hint",
};

pub(super) const SCREEN_LOCK: Check = Check {
    id: "POSTURE-SCREEN-LOCK",
    cis: "2.11.2",
    title: "Password required after sleep or screen saver",
    severity: Severity::High,
    probe: screen_lock,
    fix: user(
        "System Settings → Lock Screen → Require password after screen saver begins or display is turned off: immediately (or: sysadminctl -screenLock immediate -password -)",
    ),
    explain: "A sleeping Mac asks for the password",
};

pub(super) const SCREENSAVER: Check = Check {
    id: "POSTURE-SCREENSAVER",
    cis: "2.11.1",
    title: "Screen saver within 20 minutes",
    severity: Severity::Medium,
    probe: screensaver_idle,
    fix: user("defaults -currentHost write com.apple.screensaver idleTime -int 1200"),
    explain: "An unattended Mac locks itself",
};

pub(super) const NOT_ADMIN: Check = Check {
    id: "POSTURE-NOT-ADMIN",
    cis: "",
    title: "Everyday account is a standard user",
    severity: Severity::Medium,
    probe: not_admin,
    fix: admin(
        "Create a separate administrator account (System Settings → Users & Groups → Add User), log in to it, then turn off \"Allow this user to administer this computer\" for your everyday account",
    ),
    explain: "Malware run by the everyday account can't install system-wide or change security settings without another account's password",
};
