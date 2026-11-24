//! macOS: the CIS Apple macOS Benchmark items an unprivileged process can
//! read. `sudo` steps are printed, never run.
//!
//! One file per behaviour, each with its probes and their [`Check`]s:
//! [`encryption`] (FileVault), [`firewall`], [`integrity`] (Gatekeeper,
//! SIP, Secure Boot, Lockdown Mode), [`updates`] (Software Update, the App
//! Store, XProtect), [`sharing`] (remote access, sharing services,
//! AirDrop), [`accounts`] (guest, login, the screen lock, admin), [`apps`]
//! (Terminal, Safari), [`time`], [`dns`] and [`persistence`]. This file is
//! the index: the checks in report order, and the `defaults` readers
//! they share.

use super::settings::{Check, Runner};

mod accounts;
mod apps;
mod dns;
mod encryption;
mod firewall;
mod integrity;
pub mod persistence;
mod sharing;
mod time;
mod updates;

pub(super) fn read(r: Runner, domain: &str, key: &str) -> String {
    missing_key(r(&["defaults", "read", domain, key]), domain, key)
}

pub(super) fn read_host(r: Runner, domain: &str, key: &str) -> String {
    missing_key(r(&["defaults", "-currentHost", "read", domain, key]), domain, key)
}

/// macOS 27 says `Could not find key '<key>' in domain '<domain>'` for a key
/// that isn't set, where earlier releases said `The domain/default pair of
/// (<domain>, <key>) does not exist`; the checks read the older wording, so the
/// newer one is given as it. `Domain '<domain>' not found` is left alone: it is
/// also what a container without Full Disk Access answers.
fn missing_key(out: String, domain: &str, key: &str) -> String {
    if out.contains("Could not find key") {
        format!("The domain/default pair of ({domain}, {key}) does not exist")
    } else {
        out
    }
}

/// The checks, in the order the report lists them.
pub static CHECKS: &[Check] = &[
    encryption::FILEVAULT,
    firewall::FIREWALL,
    firewall::STEALTH,
    integrity::GATEKEEPER,
    integrity::SIP,
    updates::UPDATES_CHECK,
    updates::UPDATES_INSTALL,
    updates::APPSTORE_UPDATES,
    sharing::REMOTE_LOGIN,
    sharing::SCREEN_SHARING,
    sharing::REMOTE_MANAGEMENT,
    sharing::FILE_SHARING,
    sharing::REMOTE_EVENTS,
    sharing::INTERNET_SHARING,
    sharing::PRINTER_SHARING,
    accounts::GUEST,
    accounts::AUTO_LOGIN,
    accounts::PASSWORD_HINTS,
    accounts::SCREEN_LOCK,
    accounts::SCREENSAVER,
    apps::TERMINAL_SECURE_INPUT,
    apps::SAFARI_SAFE_FILES,
    sharing::BLUETOOTH_SHARING,
    updates::XPROTECT,
    integrity::SECURE_BOOT,
    accounts::NOT_ADMIN,
    time::TIME_SYNC,
    sharing::AIRDROP,
    firewall::FIREWALL_LOGGING,
    dns::DNS_ENCRYPTED,
    integrity::LOCKDOWN,
];

#[cfg(test)]
mod tests;
