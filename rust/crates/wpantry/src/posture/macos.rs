//! macOS: the CIS Apple macOS Benchmark items an unprivileged process can
//! read. `sudo` steps are printed, never run.

use super::{Check, Fix, Outcome, Runner, Severity, dns, flag, launchd_disabled};

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

/// "Set time and date automatically": certificates, Kerberos and logs need
/// a right clock. systemsetup needs admin; without it (or `sudo -n`) the
/// time server is all that can be read.
fn time_sync(r: Runner) -> Outcome {
    for argv in [&["systemsetup", "-getusingnetworktime"][..], &["sudo", "-n", "systemsetup", "-getusingnetworktime"]] {
        let out = r(argv);
        if let Some(line) = out.lines().find(|l| l.contains("Network Time:")) {
            let line = line.trim();
            return if line.ends_with("On") { Outcome::pass(line) } else { Outcome::fail(line) };
        }
    }
    let ntp = std::fs::read_to_string("/etc/ntp.conf").unwrap_or_default();
    match ntp.lines().find_map(|l| l.trim().strip_prefix("server ")) {
        Some(server) => Outcome::manual(format!(
            "the time server is {}; whether \"Set time and date automatically\" is on needs admin to read (sudo systemsetup -getusingnetworktime)",
            server.trim().trim_end_matches('.')
        )),
        None => Outcome::unknown("systemsetup needs admin, and /etc/ntp.conf names no server"),
    }
}

/// AirDrop off, or receiving from contacts only: "Everyone" lets anyone
/// nearby push files (and their names) at the Mac.
fn airdrop(r: Runner) -> Outcome {
    if flag(&read(r, "com.apple.NetworkBrowser", "DisableAirDrop")) == Some(true) {
        return Outcome::pass("AirDrop is disabled");
    }
    let out = read(r, "com.apple.sharingd", "DiscoverableMode");
    let mode = out.trim();
    match mode {
        "Everyone" => Outcome::fail("AirDrop receives from everyone"),
        "Off" => Outcome::pass("AirDrop receiving is off"),
        "Contacts Only" => Outcome::pass("AirDrop receives from contacts only"),
        m if m.is_empty() || m.contains("does not exist") => {
            Outcome::pass("AirDrop receives from contacts only (default)")
        }
        m => Outcome::unknown(format!("AirDrop's mode reads {m}")),
    }
}

/// The application firewall logs what it blocks. `--getloggingmode` went
/// away in macOS 15; since then only a configuration profile
/// (`com.apple.security.firewall` `EnableLogging`) sets it.
fn firewall_logging(r: Runner) -> Outcome {
    let out = r(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getloggingmode"]);
    if let Some(line) = out.lines().find(|l| l.contains("Log mode")) {
        return on_off(line.trim(), "socketfilterfw");
    }
    let managed = read(r, "/Library/Managed Preferences/com.apple.security.firewall", "EnableLogging");
    match flag(&managed) {
        Some(true) => Outcome::pass("firewall logging is on (configuration profile)"),
        Some(false) => Outcome::fail("firewall logging is off (configuration profile)"),
        None => Outcome::manual(
            "no configuration profile turns firewall logging on (com.apple.security.firewall EnableLogging); this macOS has no other switch for it",
        ),
    }
}

/// The boot security policy: Full Security boots only the current, signed
/// macOS. `bputil -d` reads it as root; `system_profiler` shows it to
/// anyone on Apple silicon and T2 Macs.
fn secure_boot(r: Runner) -> Outcome {
    let policy = r(&["bputil", "-d"]);
    let mode = policy
        .lines()
        .find(|l| l.trim_start().starts_with("Security Mode"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.split_whitespace().next().unwrap_or("").to_string())
        .or_else(|| {
            r(&["system_profiler", "SPiBridgeDataType"])
                .lines()
                .find_map(|l| l.trim().strip_prefix("Secure Boot:"))
                .map(|v| v.trim().trim_end_matches(" Security").to_string())
        });
    match mode.as_deref() {
        Some("Full") => Outcome::pass("Secure Boot: Full Security"),
        Some(m @ ("Reduced" | "Medium")) => Outcome::manual(format!(
            "Secure Boot: {m} Security, which allows third-party kernel extensions or older macOS; keep it only for a kext you need"
        )),
        Some(m @ ("Permissive" | "No")) => Outcome::fail(format!("Secure Boot: {m} Security")),
        Some(m) if !m.is_empty() => Outcome::unknown(format!("Secure Boot reads {m}")),
        _ => Outcome::unknown(
            "neither bputil -d (root) nor system_profiler shows a boot policy (an Intel Mac without a T2 has none)",
        ),
    }
}

fn lockdown(r: Runner) -> Outcome {
    match flag(&read(r, ".GlobalPreferences", "LDMGlobalEnabled")) {
        Some(true) => Outcome::pass("Lockdown Mode is on"),
        _ => Outcome::manual("Lockdown Mode is off (for people at risk of targeted attacks)"),
    }
}

/// Where macOS keeps the network-extension configurations: a DNS over
/// HTTPS or TLS profile and the DNS proxy extensions (NextDNS, AdGuard,
/// Cloudflare) are recorded here, and nowhere `scutil --dns` shows.
const NE_PLIST: &str = "/Library/Preferences/com.apple.networkextension.plist";

/// DNS proxy extensions known to forward over TLS or HTTPS, by bundle id prefix.
const ENCRYPTING_PROXIES: &[(&str, &str)] = &[
    ("com.nextdns", "NextDNS"),
    ("com.adguard", "AdGuard"),
    ("com.cloudflare", "Cloudflare"),
    ("controld", "Control D"),
];

/// The encrypted-DNS configuration the network-extension archive records,
/// read through `plutil -p`: the DoH or DoT settings class, with the DoH
/// server URL when it has one, or a DNS proxy extension and whose it is.
fn encrypted_configuration(archive: &str) -> Option<Outcome> {
    if archive.contains("NEDNSOverHTTPSSettings") {
        let url = archive.split("\"https://").nth(1).and_then(|r| r.split('"').next()).map(|u| format!("https://{u}"));
        return Some(Outcome::pass(match url {
            Some(u) => format!("a DNS over HTTPS configuration is installed ({u})"),
            None => "a DNS over HTTPS configuration is installed".into(),
        }));
    }
    if archive.contains("NEDNSOverTLSSettings") {
        return Some(Outcome::pass("a DNS over TLS configuration is installed"));
    }
    if archive.contains("NEDNSProxyProviderProtocol") {
        return Some(match ENCRYPTING_PROXIES.iter().find(|(id, _)| archive.contains(id)) {
            Some((_, app)) => Outcome::pass(format!(
                "{app}'s DNS proxy extension handles queries and forwards them over TLS or HTTPS"
            )),
            None => Outcome::manual(
                "a DNS proxy extension handles queries (network extension settings); check that it forwards over TLS or HTTPS",
            ),
        });
    }
    None
}

/// The resolver macOS uses for names no other resolver claims: the first
/// block of `scutil --dns` (before the scoped section) without a `domain`.
/// Its addresses and the interface it is bound to (`en0`, `utun4`).
fn default_resolver(out: &str) -> Option<(Vec<String>, String)> {
    let unscoped = out.split("(for scoped queries)").next().unwrap_or("");
    let mut blocks: Vec<(Vec<String>, String, bool)> = Vec::new();
    for raw in unscoped.lines() {
        let l = raw.trim();
        if l.starts_with("resolver #") {
            blocks.push((Vec::new(), String::new(), false));
            continue;
        }
        let Some((k, v)) = l.split_once(':') else { continue };
        let Some(b) = blocks.last_mut() else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.starts_with("nameserver[") {
            b.0.push(v.to_string());
        } else if k == "domain" {
            b.2 = true;
        } else if k == "if_index" {
            b.1 = v.split('(').nth(1).unwrap_or("").trim_end_matches(')').to_string();
        }
    }
    blocks.into_iter().find(|b| !b.2).map(|b| (b.0, b.1))
}

/// Whether DNS leaves the Mac encrypted: a DoH or DoT profile or a DNS
/// proxy extension in the network-extension settings, else a local stub
/// that forwards encrypted, else what `scutil --dns` sends the queries to.
/// Plain addresses on UDP 53 fail (Medium: a warning); a VPN tunnel or
/// Tailscale's resolver is manual, since what happens past it can't be
/// read here; no answer is unknown.
fn dns_encrypted(r: Runner) -> Outcome {
    if let Some(o) = encrypted_configuration(&r(&["plutil", "-p", NE_PLIST])) {
        return o;
    }
    let out = r(&["scutil", "--dns"]);
    if out.trim().is_empty() {
        return Outcome::unknown("scutil --dns gave no answer");
    }
    let Some((ns, iface)) = default_resolver(&out) else {
        return Outcome::unknown("scutil --dns names no default resolver");
    };
    if ns.is_empty() {
        return Outcome::unknown("the default resolver has no nameserver (scutil --dns)");
    }
    if ns.iter().all(|n| dns::is_loopback(n)) {
        return dns::local_stub(r, &ns);
    }
    if ns.iter().any(|n| n == "100.100.100.100") {
        return Outcome::manual(
            "Tailscale's resolver (100.100.100.100) answers inside the tunnel; whether its upstream is encrypted is the tailnet's DNS setting, which can't be read here",
        );
    }
    if iface.starts_with("utun") {
        return Outcome::manual(format!(
            "DNS goes through the VPN tunnel ({iface}) to {}: encrypted as far as the VPN's resolver, plaintext beyond it for all that can be read here",
            ns.join(", ")
        ));
    }
    Outcome::fail(dns::plaintext(&ns, "scutil --dns"))
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
        title: "XProtect data current and XProtect Remediator present",
        severity: Severity::Medium,
        probe: xprotect,
        fix: admin("softwareupdate --background-critical  (and check that Software Update installs system data files)"),
        explain: "The built-in malware definitions are fresh",
    },
    Check {
        id: "POSTURE-SECURE-BOOT",
        cis: "",
        title: "Secure Boot at Full Security",
        severity: Severity::High,
        probe: secure_boot,
        fix: admin("Restart into Recovery, open Startup Security Utility and choose Full Security"),
        explain: "Only the current, Apple-signed macOS boots, without third-party kernel extensions",
    },
    Check {
        id: "POSTURE-NOT-ADMIN",
        cis: "",
        title: "Everyday account is a standard user",
        severity: Severity::Medium,
        probe: not_admin,
        fix: admin(
            "Create a separate administrator account (System Settings → Users & Groups → Add User), log in to it, then turn off \"Allow this user to administer this computer\" for your everyday account",
        ),
        explain: "Malware run by the everyday account can't install system-wide or change security settings without another account's password",
    },
    Check {
        id: "POSTURE-TIME-SYNC",
        cis: "2.3.2.1",
        title: "Time and date set automatically",
        severity: Severity::Medium,
        probe: time_sync,
        fix: admin(
            "sudo systemsetup -setusingnetworktime on  (System Settings → General → Date & Time → Set time and date automatically)",
        ),
        explain: "Certificate checks, logins and logs rely on a right clock",
    },
    Check {
        id: "POSTURE-AIRDROP",
        cis: "2.3.1.1",
        title: "AirDrop off or contacts only",
        severity: Severity::Medium,
        probe: airdrop,
        fix: user(
            "defaults write com.apple.sharingd DiscoverableMode -string \"Contacts Only\"  (Control Center → AirDrop → Contacts Only)",
        ),
        explain: "Strangers nearby can't push files at the Mac",
    },
    Check {
        id: "POSTURE-FIREWALL-LOGGING",
        cis: "3.6",
        title: "Firewall logging",
        severity: Severity::Low,
        probe: firewall_logging,
        fix: admin(
            "Install a configuration profile with a com.apple.security.firewall payload setting EnableLogging true and LoggingOption detail (or, before macOS 15: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on)",
        ),
        explain: "What the firewall blocks is on record when something tries to get in",
    },
    Check {
        id: "POSTURE-DNS-ENCRYPTED",
        cis: "",
        title: "DNS leaves the Mac encrypted (DoH or DoT)",
        severity: Severity::Medium,
        probe: dns_encrypted,
        fix: admin(
            "Install a DNS over HTTPS or TLS configuration profile (a .mobileconfig with a DNSSettings payload; NextDNS, Cloudflare, Quad9, AdGuard and Control D publish them: open it, then System Settings → General → Device Management) or the provider's app (NextDNS, Cloudflare WARP, AdGuard), or run a local stub (dnscrypt-proxy, stubby) on 127.0.0.1 and set it as the DNS server in System Settings → Network",
        ),
        explain: "Whoever carries your packets (the ISP, the hotspot, the network's owner) can't read or rewrite what you look up",
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
        assert_eq!((lockdown)(&r).status, Status::Manual);
    }

    /// `scutil --dns` on a Mac on an ISP's resolvers, cut to what the probe reads.
    const SCUTIL_PLAIN: &str = "DNS configuration\n\nresolver #1\n  nameserver[0] : 2001:4e8:0:4001::16\n  nameserver[1] : 64.59.135.148\n  if_index : 14 (en0)\n  flags    : Request A records, Request AAAA records\n  reach    : 0x00000002 (Reachable)\n\nresolver #2\n  domain   : local\n  options  : mdns\n  timeout  : 5\n  order    : 300000\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 2001:4e8:0:4001::16\n  nameserver[1] : 64.59.135.148\n  if_index : 14 (en0)\n  flags    : Scoped, Request A records, Request AAAA records\n";
    /// The network-extension archive with a DoH profile, as `plutil -p` prints it.
    const NE_DOH: &str = "{\n  \"$objects\" => [\n    0 => \"$null\"\n    1 => {\n      \"DNSSettings\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 7}\n    }\n    7 => {\n      \"$class\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 9}\n      \"ServerURL\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 8}\n    }\n    8 => \"https://dns.nextdns.io/abc123\"\n    9 => {\n      \"$classes\" => [\n        0 => \"NEDNSOverHTTPSSettings\"\n        1 => \"NEDNSSettings\"\n        2 => \"NSObject\"\n      ]\n      \"$classname\" => \"NEDNSOverHTTPSSettings\"\n    }\n  ]\n}\n";

    #[test]
    fn dns_by_profile_proxy_stub_tunnel_or_plain_resolver() {
        let doh = dns_encrypted(&machine(&[("plutil -p", NE_DOH), ("scutil --dns", SCUTIL_PLAIN)]));
        assert_eq!(doh.status, Status::Pass);
        assert_eq!(doh.evidence, "a DNS over HTTPS configuration is installed (https://dns.nextdns.io/abc123)");
        let dot = dns_encrypted(&machine(&[("plutil -p", "\"$classname\" => \"NEDNSOverTLSSettings\"\n")]));
        assert_eq!(dot.status, Status::Pass);
        let proxy = dns_encrypted(&machine(&[(
            "plutil -p",
            "4 => \"com.nextdns.NextDNS.networkextension\"\n\"$classname\" => \"NEDNSProxyProviderProtocol\"\n",
        )]));
        assert_eq!(proxy.status, Status::Pass);
        assert!(proxy.evidence.starts_with("NextDNS's DNS proxy"), "{}", proxy.evidence);
        let other_proxy =
            dns_encrypted(&machine(&[("plutil -p", "\"$classname\" => \"NEDNSProxyProviderProtocol\"\n")]));
        assert_eq!(other_proxy.status, Status::Manual);
        // The archive without DNS settings (a VPN only) decides nothing: scutil does.
        const VPN_ONLY: &str =
            "\"DNSSettings\" => <CFKeyedArchiverUID 0x1 [0x2]>{value = 0}\n4 => \"com.nordvpn.NordVPN\"\n";
        let plain = dns_encrypted(&machine(&[("plutil -p", VPN_ONLY), ("scutil --dns", SCUTIL_PLAIN)]));
        assert_eq!(plain.status, Status::Fail);
        assert!(
            plain
                .evidence
                .starts_with("DNS goes to 2001:4e8:0:4001::16, 64.59.135.148 in plaintext on UDP 53 (scutil --dns)"),
            "{}",
            plain.evidence
        );
        assert!(plain.evidence.contains("only warns"));
        let stub = dns_encrypted(&machine(&[
            (
                "scutil --dns",
                "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n  flags    : Request A records\n",
            ),
            ("pgrep -x dnscrypt-proxy", "77\n"),
        ]));
        assert_eq!(stub.status, Status::Pass);
        assert!(stub.evidence.starts_with("dnscrypt-proxy is the local resolver (127.0.0.1)"), "{}", stub.evidence);
        let tunnel = dns_encrypted(&machine(&[(
            "scutil --dns",
            "DNS configuration\n\nresolver #1\n  nameserver[0] : 103.86.96.100\n  if_index : 29 (utun4)\n  flags    : Request A records\n",
        )]));
        assert_eq!(tunnel.status, Status::Manual);
        assert!(tunnel.evidence.contains("utun4"), "{}", tunnel.evidence);
        let tailscale = dns_encrypted(&machine(&[(
            "scutil --dns",
            "DNS configuration\n\nresolver #1\n  nameserver[0] : 100.100.100.100\n  if_index : 29 (utun5)\n",
        )]));
        assert_eq!(tailscale.status, Status::Manual);
        assert!(tailscale.evidence.contains("Tailscale"), "{}", tailscale.evidence);
        // The default resolver is the first unscoped block without a domain, whatever its number.
        assert_eq!(
            default_resolver(
                "resolver #1\n  domain   : corp.example\n  nameserver[0] : 10.1.1.1\n\nresolver #2\n  nameserver[0] : 1.1.1.1\n  if_index : 14 (en0)\n"
            ),
            Some((vec!["1.1.1.1".into()], "en0".into()))
        );
        assert_eq!(default_resolver("DNS configuration\n"), None);
        assert_eq!(dns_encrypted(&machine(&[("scutil --dns", "DNS configuration\n")])).status, Status::Unknown);
        assert_eq!(dns_encrypted(&machine(&[])).status, Status::Unknown);
    }

    #[test]
    fn xprotect_versions_and_the_newer_checks_middle_answers() {
        let v = xprotect_verdict(Some("5371".into()), Some("170".into()), Some(3));
        assert_eq!(v, Outcome::pass("XProtect 5371, updated 3 days ago; XProtect Remediator 170"));
        assert_eq!(xprotect_verdict(Some("5371".into()), Some("170".into()), Some(90)).status, Status::Fail);
        let missing = xprotect_verdict(Some("5371".into()), None, Some(3));
        assert_eq!(missing.status, Status::Fail);
        assert!(missing.evidence.contains("Remediator is missing"), "{}", missing.evidence);
        assert_eq!(xprotect_verdict(None, Some("170".into()), Some(3)).status, Status::Unknown);
        assert_eq!(
            bundle_version(&machine(&[("CFBundleShortVersionString", "170\n")]), XPROTECT_REMEDIATOR).as_deref(),
            Some("170")
        );
        assert_eq!(
            bundle_version(
                &machine(&[("CFBundleShortVersionString", "The domain/default pair of (x) does not exist")]),
                XPROTECT_REMEDIATOR
            ),
            None
        );
        // Reduced Security is a choice some kexts need: a warning, not a failure.
        let reduced = secure_boot(&machine(&[("SPiBridgeDataType", "        Secure Boot: Reduced Security\n")]));
        assert_eq!(reduced.status, Status::Manual);
        // AirDrop: disabled outright, off, or never set.
        assert_eq!(
            airdrop(&machine(&[("DisableAirDrop", "1\n"), ("DiscoverableMode", "Everyone\n")])).status,
            Status::Pass
        );
        assert_eq!(airdrop(&machine(&[("DiscoverableMode", "Off\n")])).status, Status::Pass);
        assert_eq!(airdrop(&machine(&[])).evidence, "AirDrop receives from contacts only (default)");
        // Firewall logging after macOS 15: a profile, or nothing to read.
        let profile = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n"), ("EnableLogging", "1\n")]);
        assert_eq!(firewall_logging(&profile).status, Status::Pass);
        let none = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n")]);
        assert_eq!(firewall_logging(&none).status, Status::Manual);
        // Time sync without admin: systemsetup refuses, sudo -n has no ticket.
        let refused =
            machine(&[("getusingnetworktime", "You need administrator access to run this tool... exiting!\n")]);
        assert!(matches!(time_sync(&refused).status, Status::Manual | Status::Unknown));
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
