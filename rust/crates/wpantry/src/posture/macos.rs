//! macOS: the CIS Apple macOS Benchmark items an unprivileged process can
//! read. `sudo` steps are printed, never run.

use super::{Check, Fix, Outcome, Runner, Severity, flag, launchd_disabled};

const SU: &str = "/Library/Preferences/com.apple.SoftwareUpdate";
const LOGINWINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

fn read(r: Runner, domain: &str, key: &str) -> String {
    r(&["defaults", "read", domain, key])
}

fn read_host(r: Runner, domain: &str, key: &str) -> String {
    r(&["defaults", "-currentHost", "read", domain, key])
}

fn filevault(r: Runner) -> Outcome {
    let out = r(&["fdesetup", "status"]);
    let line = out.lines().next().unwrap_or("").trim();
    if line.contains("FileVault is On") {
        Outcome::pass(line)
    } else if line.contains("FileVault is Off") {
        Outcome::fail(line)
    } else {
        Outcome::unknown(if line.is_empty() { "fdesetup gave no answer" } else { line })
    }
}

/// socketfilterfw says "enabled"/"disabled" on older macOS and "is on"/"is
/// off" on newer ones.
fn on_off(line: &str, what: &str) -> Outcome {
    let l = line.to_ascii_lowercase();
    if l.contains("disabled") || l.contains(" off") {
        Outcome::fail(line)
    } else if l.contains("enabled") || l.contains(" on") {
        Outcome::pass(line)
    } else {
        Outcome::unknown(if line.is_empty() { format!("{what} gave no answer") } else { line.to_string() })
    }
}

fn firewall(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]);
    on_off(out.lines().next().unwrap_or("").trim(), "socketfilterfw")
}

fn stealth(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]);
    on_off(out.lines().next().unwrap_or("").trim(), "socketfilterfw")
}

fn gatekeeper(r: Runner) -> Outcome {
    let out = r(&["spctl", "--status"]);
    let line = out.lines().find(|l| l.contains("assessments")).unwrap_or("").trim();
    if line.contains("assessments enabled") {
        Outcome::pass(line)
    } else if line.contains("assessments disabled") {
        Outcome::fail(line)
    } else {
        Outcome::unknown("spctl gave no answer")
    }
}

fn sip(r: Runner) -> Outcome {
    let out = r(&["csrutil", "status"]);
    let line = out.lines().next().unwrap_or("").trim();
    if line.contains("status: enabled") {
        Outcome::pass(line)
    } else if line.contains("status: disabled") || line.contains("status: unknown") {
        Outcome::fail(line)
    } else {
        Outcome::unknown("csrutil gave no answer")
    }
}

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

fn sharing(r: Runner, label: &str, what: &str) -> Outcome {
    let listing = r(&["launchctl", "print-disabled", "system"]);
    if listing.trim().is_empty() {
        return Outcome::unknown("launchctl print-disabled gave no answer");
    }
    match launchd_disabled(&listing, label) {
        Some(true) => Outcome::pass(format!("{what} is off")),
        Some(false) => Outcome::fail(format!("{what} is on")),
        // Not listed: never enabled on this system.
        None => Outcome::pass(format!("{what} is off (never enabled)")),
    }
}

fn remote_login(r: Runner) -> Outcome {
    sharing(r, "com.openssh.sshd", "Remote Login (ssh)")
}

fn screen_sharing(r: Runner) -> Outcome {
    sharing(r, "com.apple.screensharing", "Screen Sharing")
}

fn file_sharing(r: Runner) -> Outcome {
    sharing(r, "com.apple.smbd", "File Sharing (smb)")
}

fn remote_events(r: Runner) -> Outcome {
    sharing(r, "com.apple.AEServer", "Remote Apple Events")
}

fn remote_management(r: Runner) -> Outcome {
    let out = r(&["pgrep", "-x", "ARDAgent"]);
    Outcome::of(
        out.trim().is_empty(),
        if out.trim().is_empty() { "Remote Management is off" } else { "Remote Management (ARDAgent) is running" },
    )
}

fn internet_sharing(r: Runner) -> Outcome {
    let out = r(&["defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"]);
    if out.contains("does not exist") || out.trim().is_empty() {
        return Outcome::pass("Internet Sharing is off (never enabled)");
    }
    let on = out.lines().any(|l| l.replace(' ', "").starts_with("Enabled=1"));
    Outcome::of(!on, if on { "Internet Sharing is on" } else { "Internet Sharing is off" })
}

fn printer_sharing(r: Runner) -> Outcome {
    let out = r(&["cupsctl"]);
    if out.trim().is_empty() {
        return Outcome::unknown("cupsctl gave no answer");
    }
    let on = out.lines().any(|l| l.trim() == "_share_printers=1");
    Outcome::of(!on, if on { "Printer Sharing is on" } else { "Printer Sharing is off" })
}

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

fn terminal_secure_input(r: Runner) -> Outcome {
    match flag(&read(r, "com.apple.Terminal", "SecureKeyboardEntry")) {
        Some(true) => Outcome::pass("Terminal's Secure Keyboard Entry is on"),
        _ => Outcome::fail("Terminal's Secure Keyboard Entry is off"),
    }
}

fn safari_safe_files(r: Runner) -> Outcome {
    let home = crate::system::home();
    let container = home.join("Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari");
    let out = read(r, &container.to_string_lossy(), "AutoOpenSafeDownloads");
    match flag(&out) {
        Some(false) => Outcome::pass("Safari doesn't open \"safe\" downloads on its own"),
        Some(true) => Outcome::fail("Safari opens \"safe\" downloads on its own"),
        None if out.contains("does not exist") => Outcome::fail("Safari opens \"safe\" downloads on its own (default)"),
        None => Outcome::manual("Safari's preferences can't be read here (Full Disk Access)"),
    }
}

fn bluetooth_sharing(r: Runner) -> Outcome {
    match flag(&read_host(r, "com.apple.Bluetooth", "PrefKeyServicesEnabled")) {
        Some(true) => Outcome::fail("Bluetooth Sharing is on"),
        _ => Outcome::pass("Bluetooth Sharing is off"),
    }
}

fn xprotect(_: Runner) -> Outcome {
    let meta = std::path::Path::new(
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
    );
    let Ok(m) = std::fs::metadata(meta) else { return Outcome::unknown("XProtect's data isn't where macOS keeps it") };
    let age = m.modified().ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs()).unwrap_or(0);
    let days = age / 86400;
    Outcome::of(days <= 45, format!("XProtect's data was updated {days} days ago"))
}

fn lockdown(r: Runner) -> Outcome {
    match flag(&read(r, ".GlobalPreferences", "LDMGlobalEnabled")) {
        Some(true) => Outcome::pass("Lockdown Mode is on"),
        _ => Outcome::manual("Lockdown Mode is off (for people at risk of targeted attacks)"),
    }
}

const fn admin(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: true })
}
const fn user(cmd: &'static str) -> Option<Fix> {
    Some(Fix { cmd, admin: false })
}

pub static CHECKS: &[Check] = &[
    Check {
        id: "POSTURE-FILEVAULT",
        cis: "2.6.1.1",
        title: "FileVault disk encryption",
        severity: Severity::Critical,
        probe: filevault,
        fix: admin("System Settings → Privacy & Security → FileVault → Turn On (or: sudo fdesetup enable)"),
        explain: "A lost or stolen Mac gives up everything on it without encryption",
    },
    Check {
        id: "POSTURE-FIREWALL",
        cis: "2.2.1",
        title: "Application firewall",
        severity: Severity::Critical,
        probe: firewall,
        fix: admin("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
        explain: "Blocks incoming connections to programs that didn't ask for them",
    },
    Check {
        id: "POSTURE-STEALTH",
        cis: "2.2.2",
        title: "Firewall stealth mode",
        severity: Severity::Medium,
        probe: stealth,
        fix: admin("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"),
        explain: "The Mac stops answering probes (ping, port scans)",
    },
    Check {
        id: "POSTURE-GATEKEEPER",
        cis: "2.6.5",
        title: "Gatekeeper",
        severity: Severity::High,
        probe: gatekeeper,
        fix: admin("System Settings → Privacy & Security → Allow applications from: App Store & Known Developers"),
        explain: "Unsigned and unnotarized apps are blocked from running",
    },
    Check {
        id: "POSTURE-SIP",
        cis: "5.1.1",
        title: "System Integrity Protection",
        severity: Severity::Critical,
        probe: sip,
        fix: admin("Restart into Recovery (hold the power button), open Terminal, run: csrutil enable"),
        explain: "System files and processes are protected from root",
    },
    Check {
        id: "POSTURE-UPDATES-CHECK",
        cis: "1.2",
        title: "Software Update checks and downloads automatically",
        severity: Severity::High,
        probe: updates_check,
        fix: admin(
            "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
        ),
        explain: "Updates arrive without anyone remembering to look",
    },
    Check {
        id: "POSTURE-UPDATES-INSTALL",
        cis: "1.3",
        title: "Security responses and macOS updates install automatically",
        severity: Severity::High,
        probe: updates_install,
        fix: admin(
            "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true",
        ),
        explain: "Rapid Security Responses and macOS updates apply on their own",
    },
    Check {
        id: "POSTURE-APPSTORE-UPDATES",
        cis: "1.4",
        title: "App Store updates install automatically",
        severity: Severity::Medium,
        probe: app_store_updates,
        fix: admin("sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true"),
        explain: "App Store apps get their fixes without a visit",
    },
    Check {
        id: "POSTURE-REMOTE-LOGIN",
        cis: "2.3.3.4",
        title: "Remote Login (ssh) off",
        severity: Severity::Critical,
        probe: remote_login,
        fix: admin("sudo systemsetup -setremotelogin off  (System Settings → General → Sharing → Remote Login)"),
        explain: "No ssh server listening on a laptop",
    },
    Check {
        id: "POSTURE-SCREEN-SHARING",
        cis: "2.3.3.1",
        title: "Screen Sharing off",
        severity: Severity::High,
        probe: screen_sharing,
        fix: admin("System Settings → General → Sharing → Screen Sharing: off"),
        explain: "Nobody can take the screen over the network",
    },
    Check {
        id: "POSTURE-REMOTE-MANAGEMENT",
        cis: "2.3.3.5",
        title: "Remote Management off",
        severity: Severity::High,
        probe: remote_management,
        fix: admin("System Settings → General → Sharing → Remote Management: off"),
        explain: "No Apple Remote Desktop agent",
    },
    Check {
        id: "POSTURE-FILE-SHARING",
        cis: "2.3.3.2",
        title: "File Sharing off",
        severity: Severity::High,
        probe: file_sharing,
        fix: admin("System Settings → General → Sharing → File Sharing: off"),
        explain: "No smb shares offered to the network",
    },
    Check {
        id: "POSTURE-REMOTE-EVENTS",
        cis: "2.3.3.6",
        title: "Remote Apple Events off",
        severity: Severity::Medium,
        probe: remote_events,
        fix: admin("sudo systemsetup -setremoteappleevents off"),
        explain: "Other Macs can't script this one",
    },
    Check {
        id: "POSTURE-INTERNET-SHARING",
        cis: "2.3.3.7",
        title: "Internet Sharing off",
        severity: Severity::High,
        probe: internet_sharing,
        fix: admin("System Settings → General → Sharing → Internet Sharing: off"),
        explain: "The Mac isn't a router for whoever joins",
    },
    Check {
        id: "POSTURE-PRINTER-SHARING",
        cis: "2.3.3.3",
        title: "Printer Sharing off",
        severity: Severity::Low,
        probe: printer_sharing,
        fix: admin("sudo cupsctl --no-share-printers"),
        explain: "No printers offered to the network",
    },
    Check {
        id: "POSTURE-GUEST",
        cis: "2.13.1",
        title: "Guest account disabled",
        severity: Severity::High,
        probe: guest,
        fix: admin("sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"),
        explain: "No login without a password",
    },
    Check {
        id: "POSTURE-AUTO-LOGIN",
        cis: "2.13.3",
        title: "Automatic login off",
        severity: Severity::Critical,
        probe: auto_login,
        fix: admin(
            "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser  (System Settings → Users & Groups → Automatic login: off)",
        ),
        explain: "Whoever turns the Mac on is not logged in as you",
    },
    Check {
        id: "POSTURE-PASSWORD-HINTS",
        cis: "2.11.5",
        title: "Password hints off",
        severity: Severity::Medium,
        probe: password_hints,
        fix: admin("sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"),
        explain: "The login window never shows a hint",
    },
    Check {
        id: "POSTURE-SCREEN-LOCK",
        cis: "2.11.2",
        title: "Password required after sleep or screen saver",
        severity: Severity::High,
        probe: screen_lock,
        fix: user(
            "System Settings → Lock Screen → Require password after screen saver begins or display is turned off: immediately (or: sysadminctl -screenLock immediate -password -)",
        ),
        explain: "A sleeping Mac asks for the password",
    },
    Check {
        id: "POSTURE-SCREENSAVER",
        cis: "2.11.1",
        title: "Screen saver within 20 minutes",
        severity: Severity::Medium,
        probe: screensaver_idle,
        fix: user("defaults -currentHost write com.apple.screensaver idleTime -int 1200"),
        explain: "An unattended Mac locks itself",
    },
    Check {
        id: "POSTURE-TERMINAL-SECURE-INPUT",
        cis: "6.4.1",
        title: "Terminal Secure Keyboard Entry",
        severity: Severity::Medium,
        probe: terminal_secure_input,
        fix: user("defaults write com.apple.Terminal SecureKeyboardEntry -bool true"),
        explain: "Other apps can't read what you type into Terminal",
    },
    Check {
        id: "POSTURE-SAFARI-SAFE-FILES",
        cis: "6.3.1",
        title: "Safari doesn't open downloads on its own",
        severity: Severity::Medium,
        probe: safari_safe_files,
        fix: user("Safari → Settings → General → Open \"safe\" files after downloading: off"),
        explain: "A downloaded file runs only when you open it",
    },
    Check {
        id: "POSTURE-BLUETOOTH-SHARING",
        cis: "2.3.3.10",
        title: "Bluetooth Sharing off",
        severity: Severity::Low,
        probe: bluetooth_sharing,
        fix: user("defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"),
        explain: "No file exchange offered over Bluetooth",
    },
    Check {
        id: "POSTURE-XPROTECT",
        cis: "5.10",
        title: "XProtect data current",
        severity: Severity::Medium,
        probe: xprotect,
        fix: admin("softwareupdate --background-critical  (and check that Software Update installs system data files)"),
        explain: "The built-in malware definitions are fresh",
    },
    Check {
        id: "POSTURE-LOCKDOWN",
        cis: "2.6.7",
        title: "Lockdown Mode (advisory)",
        severity: Severity::Low,
        probe: lockdown,
        fix: None,
        explain: "For people who may be targeted: System Settings → Privacy & Security → Lockdown Mode",
    },
];

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    /// A machine's answers, keyed by the command's words.
    fn machine(answers: &'static [(&'static str, &'static str)]) -> impl Fn(&[&str]) -> String {
        move |argv: &[&str]| {
            let joined = argv.join(" ");
            answers.iter().find(|(k, _)| joined.contains(k)).map(|(_, v)| v.to_string()).unwrap_or_default()
        }
    }

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
        ] {
            assert!(fails.contains(&id), "{id} should fail: {fails:?}");
        }
        // Never enabled is off; Lockdown off is advice, not a failure.
        assert!(!fails.contains(&"POSTURE-FILE-SHARING"));
        assert!(!fails.contains(&"POSTURE-LOCKDOWN"));
        assert_eq!((lockdown)(&r).status, Status::Manual);
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
        ] {
            let c = CHECKS.iter().find(|c| c.id == id).unwrap();
            assert_eq!((c.probe)(&r).status, Status::Unknown, "{id}");
        }
    }
}
