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

use super::{Check, Runner};

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
    r(&["defaults", "read", domain, key])
}

pub(super) fn read_host(r: Runner, domain: &str, key: &str) -> String {
    r(&["defaults", "-currentHost", "read", domain, key])
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
mod tests {
    use super::dns::{NE_DOH, SCUTIL_PLAIN};
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn a_hardened_mac_passes() {
        let r = machine(&[
            ("fdesetup status", "FileVault is On.\n"),
            ("--getglobalstate", "Firewall is enabled. (State = 1)\n"),
            ("--getstealthmode", "Firewall stealth mode is on\n"),
            ("spctl --status", "assessments enabled\n"),
            ("csrutil status", "System Integrity Protection status: enabled.\n"),
            ("AutomaticCheckEnabled", "1\n"),
            ("AutomaticDownload", "1\n"),
            ("CriticalUpdateInstall", "1\n"),
            ("ConfigDataInstall", "1\n"),
            ("AutomaticallyInstallMacOSUpdates", "1\n"),
            ("com.apple.commerce AutoUpdate", "1\n"),
            (
                "print-disabled system",
                "disabled services = {\n\t\"com.openssh.sshd\" => disabled\n\t\"com.apple.screensharing\" => disabled\n\t\"com.apple.smbd\" => disabled\n}\n",
            ),
            ("pgrep -x ARDAgent", ""),
            ("com.apple.nat NAT", "The domain/default pair of (…) does not exist"),
            ("cupsctl", "_share_printers=0\n_debug_logging=0\n"),
            ("GuestEnabled", "0\n"),
            ("autoLoginUser", "The domain/default pair of (…) does not exist"),
            ("RetriesUntilHint", "0\n"),
            ("-screenLock status", "screenLock delay is immediate\n"),
            ("idleTime", "600\n"),
            ("SecureKeyboardEntry", "1\n"),
            ("AutoOpenSafeDownloads", "0\n"),
            ("PrefKeyServicesEnabled", "0\n"),
            ("LDMGlobalEnabled", "1\n"),
            ("plutil -p", NE_DOH),
            (
                "bputil -d",
                "Current local policy:\nOS Type                 : macOS\nSecurity Mode           : Full (smb0: absent)\n",
            ),
            ("id -Gn", "staff everyone localaccounts _appserverusr\n"),
            ("getusingnetworktime", "Network Time: On\n"),
            ("DisableAirDrop", "The domain/default pair of (…) does not exist"),
            ("DiscoverableMode", "Contacts Only\n"),
            ("--getloggingmode", "Log mode is on\n"),
        ]);
        for c in CHECKS {
            if c.id == "POSTURE-XPROTECT" {
                continue; // reads the real filesystem
            }
            let o = (c.probe)(&r);
            assert_eq!(o.status, Status::Pass, "{}: {}", c.id, o.evidence);
        }
    }

    #[test]
    fn a_fresh_mac_fails_the_right_checks() {
        let r = machine(&[
            ("fdesetup status", "FileVault is Off.\n"),
            ("--getglobalstate", "Firewall is off\n"),
            ("--getstealthmode", "Stealth mode disabled\n"),
            ("spctl --status", "assessments disabled\n"),
            ("csrutil status", "System Integrity Protection status: disabled.\n"),
            ("AutomaticCheckEnabled", "1\n"),
            ("AutomaticDownload", "0\n"),
            ("AutomaticallyInstallMacOSUpdates", "The domain/default pair of (…) does not exist"),
            ("com.apple.commerce AutoUpdate", "0\n"),
            (
                "print-disabled system",
                "disabled services = {\n\t\"com.openssh.sshd\" => enabled\n\t\"com.apple.screensharing\" => enabled\n}\n",
            ),
            ("pgrep -x ARDAgent", "812\n"),
            ("com.apple.nat NAT", "{\n    Enabled = 1;\n    PrimaryInterface = {\n    };\n}\n"),
            ("cupsctl", "_share_printers=1\n"),
            ("GuestEnabled", "1\n"),
            ("autoLoginUser", "eric\n"),
            ("RetriesUntilHint", "3\n"),
            ("-screenLock status", "screenLock is off\n"),
            ("idleTime", "0\n"),
            ("SecureKeyboardEntry", "0\n"),
            ("AutoOpenSafeDownloads", "1\n"),
            ("PrefKeyServicesEnabled", "1\n"),
            ("scutil --dns", SCUTIL_PLAIN),
            ("bputil -d", "The tool requires running as root\n"),
            ("SPiBridgeDataType", "Controller:\n      Boot Policy:\n        Secure Boot: Permissive Security\n"),
            ("id -Gn", "staff everyone admin\n"),
            ("getusingnetworktime", "Network Time: Off\n"),
            ("DiscoverableMode", "Everyone\n"),
            ("--getloggingmode", "Log mode is off\n"),
        ]);
        let fails: Vec<&str> = CHECKS
            .iter()
            .filter(|c| c.id != "POSTURE-XPROTECT")
            .filter(|c| (c.probe)(&r).status == Status::Fail)
            .map(|c| c.id)
            .collect();
        for id in [
            "POSTURE-FILEVAULT",
            "POSTURE-FIREWALL",
            "POSTURE-STEALTH",
            "POSTURE-GATEKEEPER",
            "POSTURE-SIP",
            "POSTURE-UPDATES-CHECK",
            "POSTURE-UPDATES-INSTALL",
            "POSTURE-APPSTORE-UPDATES",
            "POSTURE-REMOTE-LOGIN",
            "POSTURE-SCREEN-SHARING",
            "POSTURE-REMOTE-MANAGEMENT",
            "POSTURE-INTERNET-SHARING",
            "POSTURE-PRINTER-SHARING",
            "POSTURE-GUEST",
            "POSTURE-AUTO-LOGIN",
            "POSTURE-PASSWORD-HINTS",
            "POSTURE-SCREEN-LOCK",
            "POSTURE-SCREENSAVER",
            "POSTURE-TERMINAL-SECURE-INPUT",
            "POSTURE-SAFARI-SAFE-FILES",
            "POSTURE-BLUETOOTH-SHARING",
            "POSTURE-DNS-ENCRYPTED",
            "POSTURE-SECURE-BOOT",
            "POSTURE-NOT-ADMIN",
            "POSTURE-TIME-SYNC",
            "POSTURE-AIRDROP",
            "POSTURE-FIREWALL-LOGGING",
        ] {
            assert!(fails.contains(&id), "{id} should fail: {fails:?}");
        }
        // Never enabled is off; Lockdown off is advice, not a failure.
        assert!(!fails.contains(&"POSTURE-FILE-SHARING"));
        assert!(!fails.contains(&"POSTURE-LOCKDOWN"));
        assert_eq!((integrity::LOCKDOWN.probe)(&r).status, Status::Manual);
    }

    #[test]
    fn no_answer_is_unknown_not_a_pass() {
        let r = |_: &[&str]| String::new();
        for id in [
            "POSTURE-FILEVAULT",
            "POSTURE-FIREWALL",
            "POSTURE-GATEKEEPER",
            "POSTURE-SIP",
            "POSTURE-SCREEN-LOCK",
            "POSTURE-REMOTE-LOGIN",
            "POSTURE-PRINTER-SHARING",
            "POSTURE-DNS-ENCRYPTED",
            "POSTURE-SECURE-BOOT",
            "POSTURE-NOT-ADMIN",
        ] {
            let c = CHECKS.iter().find(|c| c.id == id).unwrap();
            assert_eq!((c.probe)(&r).status, Status::Unknown, "{id}");
        }
    }
}
