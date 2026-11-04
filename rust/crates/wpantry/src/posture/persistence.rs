//! Persistence: every place a program can arrange to run again, listed and
//! diffed against the list from the last scan. An infostealer or a
//! backdoor has to come back after a reboot, and the places it can do that
//! from are few and known: launch agents and daemons, login items and the
//! Background Task Management database, cron, at, periodic, emond,
//! authorization plugins, kernel and system extensions, Quick Look and
//! Spotlight plugins, the shell's startup files and `DYLD_INSERT_LIBRARIES`
//! on macOS; systemd units, cron, at, XDG autostart, the startup files and
//! `LD_PRELOAD` on Linux.
//!
//! The first scan records what is there (the baseline, the cache's
//! `persistence` table) and says nothing about it; every later scan warns
//! about an item it hasn't seen before (`PERSISTENCE-NEW`), and records it.
//! Each source keeps its own baseline, so a source that couldn't be read
//! once (`systemextensionsctl` failing, say) doesn't make everything in it new the
//! next time. Three things warn on every scan, new or not: library
//! injection through the environment (`PERSISTENCE-INJECTION`), a program
//! whose code signature no longer verifies (`PERSISTENCE-SIGNATURE`), and
//! a program that runs from a temporary or hidden place
//! (`PERSISTENCE-HIDDEN`).
//!
//! On macOS each persisted program is put to `codesign` (who signed it,
//! and whether the signature still holds) and asked for its quarantine
//! attribute (still there: downloaded and not yet cleared by Gatekeeper;
//! missing on a downloaded program: someone stripped it). The startup
//! files are recorded by line, as hashes: a line's text can hold a token,
//! so it is never stored or shown, only its number.
//!
//! [`programs`] is the list of persisted programs, for the YARA scan to
//! read.

use super::Runner;
use crate::check::Finding;
use crate::clipper::{command_of, item_dirs_for, odd_place, program_file};
use crate::db::Cache;
use crate::error::Result;
use crate::system;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Where an item was found; each is baselined on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Launchd,
    LoginItem,
    Cron,
    At,
    Periodic,
    Emond,
    AuthPlugin,
    Kext,
    SystemExtension,
    QuickLook,
    Spotlight,
    Shell,
    LaunchdEnv,
    Systemd,
    Autostart,
    Preload,
}

impl Source {
    /// The name the baseline keeps it under.
    pub fn name(self) -> &'static str {
        match self {
            Source::Launchd => "launchd",
            Source::LoginItem => "app-login",
            Source::Cron => "cron",
            Source::At => "at",
            Source::Periodic => "periodic",
            Source::Emond => "emond",
            Source::AuthPlugin => "authorization",
            Source::Kext => "kext",
            Source::SystemExtension => "system-extension",
            Source::QuickLook => "quicklook",
            Source::Spotlight => "spotlight",
            Source::Shell => "shell",
            Source::LaunchdEnv => "launchd-env",
            Source::Systemd => "systemd",
            Source::Autostart => "autostart",
            Source::Preload => "preload",
        }
    }

    /// What an item of it is, for a person.
    pub fn what(self) -> &'static str {
        match self {
            Source::Launchd => "launch agent or daemon",
            Source::LoginItem => "login item or agent an app carries",
            Source::Cron => "cron job",
            Source::At => "at job",
            Source::Periodic => "periodic script",
            Source::Emond => "emond rule",
            Source::AuthPlugin => "authorization plugin",
            Source::Kext => "kernel extension",
            Source::SystemExtension => "system extension",
            Source::QuickLook => "Quick Look plugin",
            Source::Spotlight => "Spotlight importer",
            Source::Shell => "shell startup file",
            Source::LaunchdEnv => "launchd session environment",
            Source::Systemd => "systemd unit",
            Source::Autostart => "autostart entry",
            Source::Preload => "preloaded library",
        }
    }
}

/// One persistence item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub source: Source,
    /// Where it is, as shown: a path (`~/Library/LaunchAgents/x.plist`) or
    /// a name (a login item's or extension's identifier).
    pub location: String,
    /// What else tells it apart across scans (the command line, a startup
    /// file's line); hashed into the key, never shown or stored.
    pub ident: String,
    /// The program it runs, when that is a file here.
    pub program: Option<PathBuf>,
    /// The library-injection variables it sets (`DYLD_INSERT_LIBRARIES`,
    /// `LD_PRELOAD`).
    pub injects: Vec<String>,
    /// The line in a startup file or crontab, 0 otherwise.
    pub line: usize,
}

impl Item {
    /// The baseline's key: a hash, so a startup file's line is never kept.
    pub fn key(&self) -> String {
        crate::sha256::hex(format!("{}\u{1f}{}\u{1f}{}", self.source.name(), self.location, self.ident).as_bytes())
    }
}

/// What the inventory found, which sources it read and which it couldn't.
#[derive(Clone, Debug, Default)]
pub struct Inventory {
    pub items: Vec<Item>,
    pub read: Vec<Source>,
    pub unread: Vec<(Source, String)>,
}

/// The variables that load a library into every program started with them.
const INJECT: &[&str] = &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "LD_AUDIT"];

fn injects_in(text: &str) -> Vec<String> {
    INJECT
        .iter()
        .filter(|v| text.contains(&format!("{v}=")) || text.contains(&format!("setenv {v} ")))
        .map(|v| v.to_string())
        .collect()
}

/// The filesystem and commands the inventory reads: the real machine, or a
/// directory and recorded output in tests.
pub struct Roots<'a> {
    pub home: PathBuf,
    /// Prefixed to system paths (`/` on the real machine).
    pub root: PathBuf,
    pub macos: bool,
    pub runner: Runner<'a>,
}

impl Roots<'_> {
    fn sys(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }
    fn rebase(&self, p: &Path) -> PathBuf {
        if p.starts_with(&self.home) { p.to_path_buf() } else { self.sys(&p.to_string_lossy()) }
    }
    /// A path as the report shows it: `~/…`, or absolute on the machine.
    fn show(&self, p: &Path) -> String {
        if let Ok(rel) = p.strip_prefix(&self.home) {
            return format!("~/{}", rel.display());
        }
        match p.strip_prefix(&self.root) {
            Ok(rel) => format!("/{}", rel.display()),
            Err(_) => p.display().to_string(),
        }
    }
}

/// The entries of `dir`, sorted, keeping those `keep` accepts by name.
fn entries(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(OsStr::to_str).is_some_and(|n| !n.starts_with('.') && keep(n)))
        .collect();
    out.sort();
    out
}

impl Roots<'static> {
    /// This machine, for the user whose home is `home`.
    pub fn real(home: PathBuf) -> Roots<'static> {
        Roots { home, root: PathBuf::from("/"), macos: cfg!(target_os = "macos"), runner: &super::real_runner }
    }
}

/// This machine's persistence items.
pub fn inventory() -> Inventory {
    inventory_in(&Roots::real(system::home()))
}

/// The inventory and its programs' checks.
pub type Gathered = (Inventory, BTreeMap<PathBuf, Vetted>);

/// List the items and check their programs (a `codesign` per program),
/// run beside the scan's other probes.
pub fn gather(r: &Roots) -> Gathered {
    let inv = inventory_in(r);
    let vetted = vet_all(r, &inv);
    (inv, vetted)
}

pub fn inventory_in(r: &Roots) -> Inventory {
    let mut inv = Inventory::default();
    units(r, &mut inv);
    cron(r, &mut inv);
    at(r, &mut inv);
    shell(r, &mut inv);
    if r.macos {
        login_items(r, &mut inv);
        bundles(r, &mut inv);
        system_extensions(r, &mut inv);
        periodic_and_emond(r, &mut inv);
        launchd_env(r, &mut inv);
    } else {
        preload(r, &mut inv);
    }
    inv.read.sort();
    inv.read.dedup();
    inv
}

/// Launch agents and daemons (macOS), systemd units and autostart entries
/// (Linux): the clipper's directories, and on Linux the system units too.
fn units(r: &Roots, inv: &mut Inventory) {
    let mut dirs: Vec<PathBuf> = item_dirs_for(&r.home, r.macos).iter().map(|d| r.rebase(d)).collect();
    if !r.macos {
        dirs.extend(
            [
                "/etc/systemd/system",
                "/etc/systemd/user",
                "/usr/local/lib/systemd/system",
                "/usr/local/lib/systemd/user",
            ]
            .iter()
            .map(|d| r.sys(d)),
        );
    }
    const KINDS: &[&str] = &[".plist", ".desktop", ".service", ".timer", ".path", ".socket"];
    for dir in dirs {
        for path in entries(&dir, |n| KINDS.iter().any(|k| n.ends_with(k))) {
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
            let source = if name.ends_with(".plist") {
                Source::Launchd
            } else if name.ends_with(".desktop") {
                Source::Autostart
            } else {
                Source::Systemd
            };
            let argv = command_of(&path);
            let mut injects = injects_in(&argv.join(" "));
            if source == Source::Launchd {
                let plist = crate::plist::read(&path);
                if let Some(env) = plist.get("EnvironmentVariables").and_then(|e| e.as_object()) {
                    injects.extend(env.keys().filter(|k| INJECT.contains(&k.as_str())).cloned());
                }
            } else if let Ok(text) = system::read_capped(&path, 1 << 20) {
                injects.extend(injects_in(&text));
            }
            injects.sort();
            injects.dedup();
            inv.items.push(Item {
                source,
                location: r.show(&path),
                ident: argv.join("\u{1f}"),
                program: program_file(&argv),
                injects,
                line: 0,
            });
        }
    }
    if r.macos {
        inv.read.push(Source::Launchd);
    } else {
        inv.read.extend([Source::Systemd, Source::Autostart]);
    }
}

/// The command a crontab line runs: past the five time fields (or an
/// `@reboot`-style macro), and past the user field in a system crontab.
fn cron_command(line: &str, system_tab: bool) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let first = *words.first()?;
    // An environment line (`MAILTO=x`, `LD_PRELOAD=…`) runs nothing.
    if first.contains('=') && !first.starts_with('@') {
        return None;
    }
    let skip = if first.starts_with('@') { 1 } else { 5 } + usize::from(system_tab);
    (words.len() > skip).then(|| words[skip..].join(" "))
}

fn cron_items(text: &str, location: &str, system_tab: bool, inv: &mut Inventory) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let injects = injects_in(line);
        let cmd = cron_command(line, system_tab);
        if cmd.is_none() && injects.is_empty() {
            continue;
        }
        let n = seen.entry(line.to_string()).or_default();
        *n += 1;
        let argv: Vec<String> =
            cmd.as_deref().unwrap_or("").split_whitespace().map(|w| w.trim_matches('"').to_string()).collect();
        inv.items.push(Item {
            source: Source::Cron,
            location: location.to_string(),
            ident: format!("{line}#{n}"),
            program: program_file(&argv),
            injects,
            line: i + 1,
        });
    }
}

fn cron(r: &Roots, inv: &mut Inventory) {
    let user = (r.runner)(&["crontab", "-l"]);
    if !user.contains("no crontab for") {
        cron_items(&user, "crontab -l", false, inv);
    }
    let etc = r.sys("/etc/crontab");
    if let Ok(text) = system::read_capped(&etc, 1 << 20) {
        cron_items(&text, &r.show(&etc), true, inv);
    }
    if !r.macos {
        for path in entries(&r.sys("/etc/cron.d"), |_| true) {
            if let Ok(text) = system::read_capped(&path, 1 << 20) {
                cron_items(&text, &r.show(&path), true, inv);
            }
        }
        for dir in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
            for path in entries(&r.sys(dir), |_| true) {
                inv.items.push(file_item(r, Source::Cron, &path));
            }
        }
    }
    inv.read.push(Source::Cron);
}

/// A file that is itself the program (a periodic or cron.daily script, a
/// plugin bundle).
fn file_item(r: &Roots, source: Source, path: &Path) -> Item {
    Item {
        source,
        location: r.show(path),
        ident: String::new(),
        program: Some(path.to_path_buf()),
        injects: Vec::new(),
        line: 0,
    }
}

/// Pending `at` jobs: one-shot, but a way back all the same.
fn at(r: &Roots, inv: &mut Inventory) {
    let out = (r.runner)(&["atq"]);
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(job) = line.split_whitespace().next().filter(|j| j.chars().all(|c| c.is_ascii_digit())) else {
            continue;
        };
        inv.items.push(Item {
            source: Source::At,
            location: format!("at job {job}"),
            ident: line.to_string(),
            program: None,
            injects: Vec::new(),
            line: 0,
        });
    }
    inv.read.push(Source::At);
}

/// The startup files a shell reads, per user and system-wide.
const RC_HOME: &[&str] = &[
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".config/fish/config.fish",
];
const RC_SYSTEM: &[&str] =
    &["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/zlogin", "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"];

fn shell(r: &Roots, inv: &mut Inventory) {
    let mut files: Vec<PathBuf> = RC_HOME.iter().map(|f| r.home.join(f)).collect();
    files.extend(RC_SYSTEM.iter().map(|f| r.sys(f)));
    if !r.macos {
        files.push(r.sys("/etc/environment"));
        files.extend(entries(&r.sys("/etc/profile.d"), |n| n.ends_with(".sh")));
    }
    for path in files {
        let Ok(text) = system::read_capped(&path, 4 << 20) else { continue };
        let location = r.show(&path);
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let n = seen.entry(line).or_default();
            *n += 1;
            inv.items.push(Item {
                source: Source::Shell,
                location: location.clone(),
                ident: format!("{line}#{n}"),
                program: None,
                injects: injects_in(line),
                line: i + 1,
            });
        }
    }
    inv.read.push(Source::Shell);
}

/// The login items and launch agents and daemons apps carry inside
/// their bundles, which `SMAppService` and `SMLoginItemSetEnabled`
/// register: `Contents/Library/LaunchAgents`, `LaunchDaemons` and
/// `LoginItems` of every app in `/Applications` (and `Utilities`) and
/// `~/Applications`. Background Task Management records which of them are
/// enabled, but `sfltool dumpbtm`, the only reader, asks for an
/// administrator's password every time; so these are what apps can start,
/// enabled or not. A new one is still a new way back in.
fn login_items(r: &Roots, inv: &mut Inventory) {
    let dirs = [r.sys("/Applications"), r.sys("/Applications/Utilities"), r.home.join("Applications")];
    for dir in dirs {
        for app in entries(&dir, |n| n.ends_with(".app")) {
            let lib = app.join("Contents/Library");
            for sub in ["LaunchAgents", "LaunchDaemons"] {
                for plist in entries(&lib.join(sub), |n| n.ends_with(".plist")) {
                    let v = crate::plist::read(&plist);
                    let program = match v.get("BundleProgram").and_then(|p| p.as_str()) {
                        Some(rel) => Some(app.join(rel)),
                        None => program_file(&command_of(&plist)),
                    };
                    let mut injects: Vec<String> = v
                        .get("EnvironmentVariables")
                        .and_then(|e| e.as_object())
                        .map(|e| e.keys().filter(|k| INJECT.contains(&k.as_str())).cloned().collect())
                        .unwrap_or_default();
                    injects.sort();
                    inv.items.push(Item {
                        source: Source::LoginItem,
                        location: r.show(&plist),
                        ident: program.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                        program,
                        injects,
                        line: 0,
                    });
                }
            }
            for helper in entries(&lib.join("LoginItems"), |n| n.ends_with(".app")) {
                inv.items.push(file_item(r, Source::LoginItem, &helper));
            }
        }
    }
    inv.read.push(Source::LoginItem);
}

/// Plugin bundles the system loads into its own processes: authorization
/// plugins (into the login window and `authorizationhost`), third-party
/// kernel extensions, Quick Look generators and Spotlight importers.
fn bundles(r: &Roots, inv: &mut Inventory) {
    let groups: [(Source, Vec<PathBuf>, &str); 4] = [
        (Source::AuthPlugin, vec![r.sys("/Library/Security/SecurityAgentPlugins")], ".bundle"),
        (Source::Kext, vec![r.sys("/Library/Extensions")], ".kext"),
        (Source::QuickLook, vec![r.home.join("Library/QuickLook"), r.sys("/Library/QuickLook")], ".qlgenerator"),
        (Source::Spotlight, vec![r.home.join("Library/Spotlight"), r.sys("/Library/Spotlight")], ".mdimporter"),
    ];
    for (source, dirs, ext) in groups {
        for dir in dirs {
            for path in entries(&dir, |n| n.ends_with(ext)) {
                inv.items.push(file_item(r, source, &path));
            }
        }
        inv.read.push(source);
    }
}

/// `systemextensionsctl list`: network, endpoint-security, driver and
/// camera extensions, by bundle id and team.
fn system_extensions(r: &Roots, inv: &mut Inventory) {
    let out = (r.runner)(&["systemextensionsctl", "list"]);
    if !out.contains("extension(s)") {
        inv.unread.push((Source::SystemExtension, "systemextensionsctl list gave no answer".into()));
        return;
    }
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 || f[2] == "teamID" {
            continue;
        }
        let Some((id, _)) = f[3].split_once(" (") else { continue };
        inv.items.push(Item {
            source: Source::SystemExtension,
            location: id.trim().to_string(),
            ident: f[2].trim().to_string(),
            program: None,
            injects: Vec::new(),
            line: 0,
        });
    }
    inv.read.push(Source::SystemExtension);
}

/// periodic's scripts and local files, and emond's rules and clients (emond
/// is gone from macOS 13; a rule on a newer system is left over or planted).
fn periodic_and_emond(r: &Roots, inv: &mut Inventory) {
    for base in ["/etc/periodic", "/usr/local/etc/periodic"] {
        for when in ["daily", "weekly", "monthly"] {
            for path in entries(&r.sys(&format!("{base}/{when}")), |_| true) {
                inv.items.push(file_item(r, Source::Periodic, &path));
            }
        }
    }
    for f in [
        "/etc/periodic.conf",
        "/etc/periodic.conf.local",
        "/etc/daily.local",
        "/etc/weekly.local",
        "/etc/monthly.local",
    ] {
        let path = r.sys(f);
        if path.is_file() {
            inv.items.push(file_item(r, Source::Periodic, &path));
        }
    }
    inv.read.push(Source::Periodic);
    for dir in ["/etc/emond.d/rules", "/private/var/db/emondClients"] {
        for path in entries(&r.sys(dir), |_| true) {
            let mut item = file_item(r, Source::Emond, &path);
            item.program = None;
            inv.items.push(item);
        }
    }
    inv.read.push(Source::Emond);
}

/// `launchctl setenv DYLD_INSERT_LIBRARIES`: every app the session starts
/// loads the library.
fn launchd_env(r: &Roots, inv: &mut Inventory) {
    let value = (r.runner)(&["launchctl", "getenv", "DYLD_INSERT_LIBRARIES"]);
    let value = value.trim();
    if !value.is_empty() {
        inv.items.push(Item {
            source: Source::LaunchdEnv,
            location: "launchctl getenv DYLD_INSERT_LIBRARIES".into(),
            ident: value.to_string(),
            program: Some(r.rebase(Path::new(value.split(':').next().unwrap_or(value)))).filter(|p| p.exists()),
            injects: vec!["DYLD_INSERT_LIBRARIES".into()],
            line: 0,
        });
    }
    inv.read.push(Source::LaunchdEnv);
}

/// `/etc/ld.so.preload`: libraries the dynamic linker loads into every
/// program on the system.
fn preload(r: &Roots, inv: &mut Inventory) {
    let path = r.sys("/etc/ld.so.preload");
    if let Ok(text) = system::read_capped(&path, 1 << 20) {
        for (i, lib) in text.lines().map(str::trim).enumerate() {
            if lib.is_empty() || lib.starts_with('#') {
                continue;
            }
            inv.items.push(Item {
                source: Source::Preload,
                location: r.show(&path),
                ident: lib.to_string(),
                program: Some(r.rebase(Path::new(lib))).filter(|p| p.exists()),
                injects: vec!["ld.so.preload".into()],
                line: i + 1,
            });
        }
    }
    inv.read.push(Source::Preload);
}

/// The programs the persistence items run, each once: the hook the YARA
/// scan reads.
pub fn programs(inv: &Inventory) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = inv.items.iter().filter_map(|i| i.program.clone()).collect();
    out.sort();
    out.dedup();
    out
}

/// This machine's persisted programs.
pub fn persisted_programs() -> Vec<PathBuf> {
    programs(&inventory())
}

// Program checks -------------------------------------------------------------

/// Who signed a program, from `codesign -dv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Apple,
    /// The leaf authority (`Developer ID Application: …`, the App Store).
    Signed(String),
    AdHoc,
    Unsigned,
    /// Signed, but `codesign --verify` rejects it: changed after signing.
    Invalid(String),
    Unknown,
}

impl Signature {
    pub fn describe(&self) -> String {
        match self {
            Signature::Apple => "signed by Apple".into(),
            Signature::Signed(who) => format!("signed ({who})"),
            Signature::AdHoc => "ad-hoc signed (no developer identity)".into(),
            Signature::Unsigned => "not signed".into(),
            Signature::Invalid(why) => format!("its signature doesn't verify ({why})"),
            Signature::Unknown => "signature not read".into(),
        }
    }
}

/// What `codesign -dv --verbose=2` says about who signed it.
pub fn signature_of(display: &str) -> Signature {
    if display.contains("not signed at all") {
        return Signature::Unsigned;
    }
    if display.lines().any(|l| l.trim() == "Signature=adhoc") {
        return Signature::AdHoc;
    }
    let Some(leaf) = display.lines().find_map(|l| l.trim().strip_prefix("Authority=")) else {
        return Signature::Unknown;
    };
    if leaf == "Apple Mac OS Application Signing" {
        Signature::Signed("the App Store".into())
    } else if leaf == "Software Signing"
        || leaf == "macOS Software Signing"
        || (leaf.starts_with("Apple ") && display.contains("Platform identifier="))
    {
        Signature::Apple
    } else {
        Signature::Signed(leaf.to_string())
    }
}

/// What the checks found about one program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vetted {
    pub signature: Signature,
    /// Carries `com.apple.quarantine`; None off macOS or when unreadable.
    pub quarantined: Option<bool>,
    /// Runs from a temporary or hidden place.
    pub hidden: bool,
}

impl Vetted {
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.signature != Signature::Unknown {
            parts.push(self.signature.describe());
        }
        match self.quarantined {
            Some(true) => parts.push("still quarantined (downloaded)".into()),
            Some(false) => parts.push("no quarantine attribute".into()),
            None => {}
        }
        if self.hidden {
            parts.push("from a temporary or hidden place".into());
        }
        parts.join(", ")
    }
}

pub fn vet(r: &Roots, program: &Path) -> Vetted {
    let hidden = odd_place(&r.home, program);
    if !r.macos {
        return Vetted { signature: Signature::Unknown, quarantined: None, hidden };
    }
    let p = program.to_string_lossy();
    let mut signature = signature_of(&(r.runner)(&["codesign", "-dv", "--verbose=2", &p]));
    if matches!(signature, Signature::Apple | Signature::Signed(_) | Signature::AdHoc) {
        let verify = (r.runner)(&["codesign", "--verify", "--strict", &p]);
        if let Some(why) = verify.lines().map(str::trim).find(|l| !l.is_empty()) {
            let why = why.rsplit(": ").next().unwrap_or(why);
            signature = Signature::Invalid(why.to_string());
        }
    }
    let x = (r.runner)(&["xattr", "-p", "com.apple.quarantine", &p]);
    let quarantined = if x.contains("No such xattr") {
        Some(false)
    } else if x.trim().is_empty() || x.contains("No such file") {
        None
    } else {
        Some(true)
    };
    Vetted { signature, quarantined, hidden }
}

// Baseline and findings --------------------------------------------------------

/// Diff the inventory against the cache's baseline and record it: the
/// indexes of the items new since the last scan, and the sources baselined
/// for the first time.
pub fn diff(cache: &Cache, inv: &Inventory, at: f64) -> Result<(Vec<usize>, Vec<Source>)> {
    let mut new = Vec::new();
    let mut first = Vec::new();
    for &source in &inv.read {
        let mine: Vec<(usize, &Item)> = inv.items.iter().enumerate().filter(|(_, i)| i.source == source).collect();
        match cache.persistence_baseline(source.name())? {
            Some(known) => new.extend(mine.iter().filter(|(_, i)| !known.contains(&i.key())).map(|(n, _)| *n)),
            None => first.push(source),
        }
        let rows: Vec<(String, String, String)> = mine
            .iter()
            .map(|(_, i)| {
                (i.key(), i.location.clone(), i.program.as_ref().map(|p| p.display().to_string()).unwrap_or_default())
            })
            .collect();
        cache.persistence_record(source.name(), &rows, at)?;
    }
    Ok((new, first))
}

const NEW_FIX: &str = "If you didn't add it, find out what it is and who installed it before anything else: read the item and its program, unload it (launchctl bootout, systemctl disable --now, or remove the entry), move the program aside for a look, then change the passwords used on this machine. If you added it yourself, nothing to do: it is in the baseline now";

/// The findings for an inventory: what is new, and what warns every scan.
/// `vetted` holds the program checks by program path.
pub fn findings(
    inv: &Inventory,
    new: &[usize],
    vetted: &BTreeMap<PathBuf, Vetted>,
    show: &dyn Fn(&Path) -> String,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let warn = |component: String, location: String, id: &str, note: String, fix: &str| Finding {
        kind: "persistence".into(),
        component,
        location,
        vuln_id: id.into(),
        status: "warn".into(),
        severity: "MEDIUM".into(),
        note,
        fix_cmd: fix.into(),
        fix_auto: false,
        ..Default::default()
    };
    let runs = |i: &Item| -> (String, String) {
        match &i.program {
            Some(p) => {
                let shown = show(p);
                let v = vetted.get(p).map(Vetted::describe).filter(|d| !d.is_empty());
                let detail = v.map(|d| format!(" ({d})")).unwrap_or_default();
                (shown.clone(), format!(": runs {shown}{detail}"))
            }
            None => (String::new(), String::new()),
        }
    };
    // New items; a startup file's new lines are one finding per file.
    let mut lines: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &n in new {
        let i = &inv.items[n];
        if i.source == Source::Shell {
            lines.entry(i.location.as_str()).or_default().push(i.line);
            continue;
        }
        let (program, runs) = runs(i);
        let at = if i.line > 0 { format!(" (line {})", i.line) } else { String::new() };
        out.push(warn(
            i.location.clone(),
            program,
            "PERSISTENCE-NEW",
            format!("a {} that wasn't there at the last scan{at}{runs}", i.source.what()),
            NEW_FIX,
        ));
    }
    for (file, nums) in lines {
        let shown: Vec<String> = nums.iter().take(8).map(usize::to_string).collect();
        let more = if nums.len() > 8 { ", …" } else { "" };
        out.push(warn(
            file.to_string(),
            String::new(),
            "PERSISTENCE-NEW",
            format!(
                "{} new line{} since the last scan (line{} {}{more}); every new shell runs {}",
                nums.len(),
                if nums.len() == 1 { "" } else { "s" },
                if nums.len() == 1 { "" } else { "s" },
                shown.join(", "),
                if nums.len() == 1 { "it" } else { "them" }
            ),
            "Read those lines. An installer adding its PATH or completion is normal; a download, a background job or a variable you don't recognise is not: remove it and find what wrote it",
        ));
    }
    // Every scan: injection, broken signatures, hidden places.
    for i in &inv.items {
        if !i.injects.is_empty() {
            let at = if i.line > 0 { format!(" (line {})", i.line) } else { String::new() };
            out.push(warn(
                i.location.clone(),
                i.injects.join(", "),
                "PERSISTENCE-INJECTION",
                format!(
                    "the {} sets {}{at}: every program it starts loads that library first, which is how code is injected into other apps",
                    i.source.what(),
                    i.injects.join(" and ")
                ),
                "Unless you set it for a tool you know, remove the variable (and the library it names) and find what put it there",
            ));
        }
    }
    let mut flagged = HashSet::new();
    for i in &inv.items {
        let Some(p) = &i.program else { continue };
        let Some(v) = vetted.get(p) else { continue };
        if let Signature::Invalid(why) = &v.signature
            && flagged.insert((p.clone(), "sig"))
        {
            out.push(warn(
                i.location.clone(),
                show(p),
                "PERSISTENCE-SIGNATURE",
                format!("the {} runs {}, whose code signature doesn't verify ({why}): it was changed after it was signed", i.source.what(), show(p)),
                "Reinstall the app or tool from its publisher; if you don't know what it is, unload the item and move the program aside for a look",
            ));
        }
        if v.hidden && flagged.insert((p.clone(), "hidden")) {
            out.push(warn(
                i.location.clone(),
                show(p),
                "PERSISTENCE-HIDDEN",
                format!(
                    "the {} runs {} from a temporary or hidden place, where installers don't put programs and malware does",
                    i.source.what(),
                    show(p)
                ),
                NEW_FIX,
            ));
        }
    }
    out
}

/// Check every persisted program (four at a time).
pub fn vet_all(r: &Roots, inv: &Inventory) -> BTreeMap<PathBuf, Vetted> {
    let progs: Vec<PathBuf> = programs(inv).into_iter().filter(|p| p.exists()).collect();
    let results = system::par_map(&progs, 4, |p| vet(r, p));
    progs.into_iter().zip(results).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(p: &Path, text: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn roots<'a>(dir: &Path, macos: bool, runner: Runner<'a>) -> Roots<'a> {
        Roots { home: dir.join("home"), root: dir.join("root"), macos, runner }
    }

    const AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.helper</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>true</string></array>
<key>EnvironmentVariables</key><dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict>
</dict></plist>"#;

    const SM_AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.agent</string>
<key>BundleProgram</key><string>Contents/Resources/agent</string>
</dict></plist>"#;

    const SYSEXT: &str = "1 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tTEAM123\tcom.example.vpn.ext (1.0/1)\tExample VPN\t[activated enabled]\n";

    fn mac_runner(argv: &[&str]) -> String {
        match argv.join(" ").as_str() {
            "crontab -l" => {
                "# m h dom mon dow cmd\n*/5 * * * * /bin/sh /tmp/x.sh\nMAILTO=\"\"\n@reboot /usr/bin/true\n".into()
            }
            "atq" => "3\tWed Nov  4 10:00:00 2026\n".into(),
            "systemextensionsctl list" => SYSEXT.into(),
            "launchctl getenv DYLD_INSERT_LIBRARIES" => String::new(),
            _ => String::new(),
        }
    }

    #[test]
    fn a_mac_inventory_reads_every_source() {
        let d = system::TempDir::new("persist").unwrap();
        let r = roots(d.path(), true, &mac_runner);
        write(&r.home.join("Library/LaunchAgents/com.example.helper.plist"), AGENT);
        write(
            &r.home.join(".zshrc"),
            "# comment\nexport PATH=$HOME/bin:$PATH\n\nexport DYLD_INSERT_LIBRARIES=/x.dylib\n",
        );
        write(&r.sys("/Library/Security/SecurityAgentPlugins/Evil.bundle/Contents/Info.plist"), "<plist/>");
        write(&r.sys("/Library/Extensions/Foo.kext/Contents/Info.plist"), "<plist/>");
        write(&r.home.join("Library/QuickLook/Q.qlgenerator/x"), "");
        write(&r.sys("/Library/Spotlight/S.mdimporter/x"), "");
        write(&r.sys("/etc/periodic/daily/999.local"), "#!/bin/sh\n");
        write(&r.sys("/etc/emond.d/rules/r.plist"), "<plist/>");
        let app = r.sys("/Applications/Example App.app/Contents/Library");
        write(&app.join("LaunchAgents/com.example.agent.plist"), SM_AGENT);
        write(&app.join("LoginItems/Helper.app/Contents/Info.plist"), "<plist/>");
        write(&r.sys("/Applications/Plain.app/Contents/Info.plist"), "<plist/>");
        let inv = inventory_in(&r);
        let by = |s: Source| inv.items.iter().filter(|i| i.source == s).collect::<Vec<_>>();
        let launchd = by(Source::Launchd);
        assert_eq!(launchd.len(), 1);
        assert_eq!(launchd[0].location, "~/Library/LaunchAgents/com.example.helper.plist");
        assert_eq!(launchd[0].program.as_deref(), Some(Path::new("/bin/sh")));
        assert_eq!(launchd[0].injects, ["DYLD_INSERT_LIBRARIES"]);
        let logins = by(Source::LoginItem);
        let names: Vec<&str> = logins.iter().map(|i| i.location.as_str()).collect();
        assert_eq!(
            names,
            [
                "/Applications/Example App.app/Contents/Library/LaunchAgents/com.example.agent.plist",
                "/Applications/Example App.app/Contents/Library/LoginItems/Helper.app"
            ]
        );
        assert_eq!(
            logins[0].program.as_deref(),
            Some(r.sys("/Applications/Example App.app/Contents/Resources/agent").as_path()),
            "BundleProgram is inside the app"
        );
        assert_eq!(
            logins[1].program.as_deref(),
            Some(r.sys("/Applications/Example App.app/Contents/Library/LoginItems/Helper.app").as_path())
        );
        let cron = by(Source::Cron);
        assert_eq!(cron.len(), 2, "the environment line and the comment run nothing");
        assert_eq!((cron[0].location.as_str(), cron[0].line), ("crontab -l", 2));
        assert_eq!(by(Source::At).len(), 1);
        assert_eq!(by(Source::At)[0].location, "at job 3");
        let shell = by(Source::Shell);
        assert_eq!(shell.len(), 2);
        assert_eq!(shell[1].line, 4);
        assert_eq!(shell[1].injects, ["DYLD_INSERT_LIBRARIES"]);
        assert_eq!(by(Source::AuthPlugin)[0].location, "/Library/Security/SecurityAgentPlugins/Evil.bundle");
        assert_eq!(by(Source::Kext).len(), 1);
        assert_eq!(by(Source::QuickLook)[0].location, "~/Library/QuickLook/Q.qlgenerator");
        assert_eq!(by(Source::Spotlight).len(), 1);
        assert_eq!(by(Source::SystemExtension)[0].location, "com.example.vpn.ext");
        assert_eq!(by(Source::Periodic)[0].location, "/etc/periodic/daily/999.local");
        assert_eq!(by(Source::Emond).len(), 1);
        assert!(inv.unread.is_empty(), "{:?}", inv.unread);
        assert!(programs(&inv).contains(&PathBuf::from("/bin/sh")));
    }

    #[test]
    fn a_linux_inventory_reads_units_cron_autostart_and_preload() {
        let d = system::TempDir::new("persist").unwrap();
        let none = |_: &[&str]| String::new();
        let r = roots(d.path(), false, &none);
        write(&r.home.join(".config/systemd/user/sync.service"), "[Service]\nExecStart=/usr/bin/true --x\n");
        write(
            &r.sys("/etc/systemd/system/backdoor.service"),
            "[Service]\nEnvironment=LD_PRELOAD=/lib/x.so\nExecStart=/bin/true\n",
        );
        write(&r.sys("/etc/systemd/system/backup.timer"), "[Timer]\nOnCalendar=daily\n");
        write(&r.home.join(".config/autostart/app.desktop"), "[Desktop Entry]\nExec=/usr/bin/true\n");
        write(&r.sys("/etc/cron.d/job"), "SHELL=/bin/sh\n0 * * * * root /usr/bin/true\n");
        write(&r.sys("/etc/cron.daily/logrotate"), "#!/bin/sh\n");
        write(&r.sys("/etc/ld.so.preload"), "# none\n/lib/libevil.so\n");
        write(&r.sys("/etc/profile.d/x.sh"), "export X=1\n");
        let inv = inventory_in(&r);
        let by = |s: Source| inv.items.iter().filter(|i| i.source == s).collect::<Vec<_>>();
        let units: Vec<&str> = by(Source::Systemd).iter().map(|i| i.location.as_str()).collect();
        assert_eq!(
            units,
            [
                "~/.config/systemd/user/sync.service",
                "/etc/systemd/system/backdoor.service",
                "/etc/systemd/system/backup.timer"
            ]
        );
        assert_eq!(by(Source::Systemd)[1].injects, ["LD_PRELOAD"]);
        assert_eq!(by(Source::Autostart).len(), 1);
        let cron: Vec<&str> = by(Source::Cron).iter().map(|i| i.location.as_str()).collect();
        assert_eq!(cron, ["/etc/cron.d/job", "/etc/cron.daily/logrotate"]);
        assert_eq!(by(Source::Preload)[0].line, 2);
        assert_eq!(by(Source::Shell)[0].location, "/etc/profile.d/x.sh");
        assert!(by(Source::LoginItem).is_empty(), "macOS only");
        // The crontab line's command past the user field.
        assert_eq!(cron_command("0 * * * * root /usr/bin/true", true).as_deref(), Some("/usr/bin/true"));
        assert_eq!(cron_command("@daily /bin/x", false).as_deref(), Some("/bin/x"));
        assert_eq!(cron_command("PATH=/bin", false), None);
        assert_eq!(cron_command("* * *", false), None);
    }

    #[test]
    fn an_unreadable_source_is_unread_not_empty() {
        let d = system::TempDir::new("persist").unwrap();
        let none = |_: &[&str]| String::new();
        let inv = inventory_in(&roots(d.path(), true, &none));
        assert_eq!(inv.unread, [(Source::SystemExtension, "systemextensionsctl list gave no answer".into())]);
        assert!(!inv.read.contains(&Source::SystemExtension));
        assert!(inv.read.contains(&Source::LoginItem), "the app bundles are read from disk");
    }

    #[test]
    fn signatures_and_quarantine() {
        assert_eq!(signature_of("/etc/hosts: code object is not signed at all\n"), Signature::Unsigned);
        assert_eq!(
            signature_of("Executable=/x\nCodeDirectory v=1 flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\n"),
            Signature::AdHoc
        );
        assert_eq!(
            signature_of(
                "Identifier=com.apple.ls\nPlatform identifier=27\nAuthority=macOS Software Signing\nAuthority=Apple Root CA\n"
            ),
            Signature::Apple
        );
        assert_eq!(
            signature_of(
                "Authority=Developer ID Application: Example Inc (ABCDE12345)\nAuthority=Developer ID Certification Authority\n"
            ),
            Signature::Signed("Developer ID Application: Example Inc (ABCDE12345)".into())
        );
        assert_eq!(
            signature_of("Authority=Apple Mac OS Application Signing\n"),
            Signature::Signed("the App Store".into())
        );
        assert_eq!(signature_of(""), Signature::Unknown);

        let d = system::TempDir::new("persist").unwrap();
        let prog = d.path().join("home/.hidden/agent");
        write(&prog, "x");
        let broken = |argv: &[&str]| match argv[..2] {
            ["codesign", "-dv"] => "Authority=Developer ID Application: X (T)\n".to_string(),
            ["codesign", "--verify"] => {
                format!("{}: invalid signature (code or signature have been modified)\n", argv[3])
            }
            ["xattr", "-p"] => "0081;6720a1b2;Safari;\n".into(),
            _ => String::new(),
        };
        let r = roots(d.path(), true, &broken);
        let v = vet(&r, &prog);
        assert_eq!(v.signature, Signature::Invalid("invalid signature (code or signature have been modified)".into()));
        assert_eq!(v.quarantined, Some(true));
        assert!(v.hidden);
        assert!(v.describe().contains("doesn't verify"), "{}", v.describe());
        let clean = |argv: &[&str]| match argv[..2] {
            ["codesign", "-dv"] => "Signature=adhoc\n".to_string(),
            ["xattr", "-p"] => format!("xattr: {}: No such xattr: com.apple.quarantine\n", argv[3]),
            _ => String::new(),
        };
        let r = roots(d.path(), true, &clean);
        let bin = d.path().join("home/bin/x");
        write(&bin, "x");
        assert_eq!(vet(&r, &bin), Vetted { signature: Signature::AdHoc, quarantined: Some(false), hidden: false });
        let linux = roots(d.path(), false, &clean);
        assert_eq!(vet(&linux, &bin).signature, Signature::Unknown, "codesign is macOS only");
    }

    #[test]
    fn the_baseline_is_quiet_first_then_warns_on_new_items() {
        let d = system::TempDir::new("persist").unwrap();
        let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let item = |loc: &str, ident: &str| Item {
            source: Source::Launchd,
            location: loc.into(),
            ident: ident.into(),
            program: Some(PathBuf::from("/opt/x")),
            injects: Vec::new(),
            line: 0,
        };
        let mut inv =
            Inventory { items: vec![item("a.plist", "/opt/x")], read: vec![Source::Launchd], unread: Vec::new() };
        let (new, first) = diff(&cache, &inv, 1.0).unwrap();
        assert!(new.is_empty());
        assert_eq!(first, [Source::Launchd]);
        // A second scan with the same items: nothing new.
        assert_eq!(diff(&cache, &inv, 2.0).unwrap(), (vec![], vec![]));
        // A new plist, and the old one now runs something else.
        inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
        let (new, _) = diff(&cache, &inv, 3.0).unwrap();
        assert_eq!(new, [0, 1]);
        // Recorded: quiet again. A removed item that comes back is new again.
        assert!(diff(&cache, &inv, 4.0).unwrap().0.is_empty());
        inv.items.pop();
        diff(&cache, &inv, 5.0).unwrap();
        inv.items.push(item("b.plist", "/opt/x"));
        assert_eq!(diff(&cache, &inv, 6.0).unwrap().0, [1]);
        // An unread source keeps its baseline untouched.
        inv.read.clear();
        inv.items.clear();
        diff(&cache, &inv, 7.0).unwrap();
        inv.read.push(Source::Launchd);
        inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
        assert!(diff(&cache, &inv, 8.0).unwrap().0.is_empty());
    }

    #[test]
    fn findings_for_new_items_injection_signatures_and_hidden_programs() {
        let shell = |line: usize, ident: &str| Item {
            source: Source::Shell,
            location: "~/.zshrc".into(),
            ident: ident.into(),
            program: None,
            injects: Vec::new(),
            line,
        };
        let agent = Item {
            source: Source::Launchd,
            location: "~/Library/LaunchAgents/x.plist".into(),
            ident: "/Users/u/.x/agent".into(),
            program: Some(PathBuf::from("/Users/u/.x/agent")),
            injects: vec!["DYLD_INSERT_LIBRARIES".into()],
            line: 0,
        };
        let inv = Inventory { items: vec![shell(3, "a"), shell(9, "b"), agent], read: vec![], unread: vec![] };
        let mut vetted = BTreeMap::new();
        vetted.insert(
            PathBuf::from("/Users/u/.x/agent"),
            Vetted {
                signature: Signature::Invalid("invalid signature".into()),
                quarantined: Some(false),
                hidden: true,
            },
        );
        let show = |p: &Path| p.display().to_string();
        let got = findings(&inv, &[0, 1, 2], &vetted, &show);
        let ids: Vec<(&str, &str)> = got.iter().map(|f| (f.vuln_id.as_str(), f.component.as_str())).collect();
        assert_eq!(
            ids,
            [
                ("PERSISTENCE-NEW", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-NEW", "~/.zshrc"),
                ("PERSISTENCE-INJECTION", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-SIGNATURE", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-HIDDEN", "~/Library/LaunchAgents/x.plist"),
            ]
        );
        assert!(got.iter().all(|f| f.kind == "persistence" && f.status == "warn" && !f.fix_auto));
        assert!(got[0].note.contains("runs /Users/u/.x/agent (its signature doesn't verify"), "{}", got[0].note);
        assert_eq!(got[1].note, "2 new lines since the last scan (lines 3, 9); every new shell runs them");
        // Nothing new: only what warns every scan.
        assert_eq!(findings(&inv, &[], &vetted, &show).len(), 3);
    }
}
