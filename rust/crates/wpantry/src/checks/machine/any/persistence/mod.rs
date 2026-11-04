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
//!
//! Here: what every OS shares, the item and inventory types, the places
//! [`units`] (launch agents and daemons, systemd units, autostart),
//! [`cron`] and at, and the [`shell`]'s startup files; the program
//! checks ([`vet`]); and the baseline and its [`findings`]. Each OS adds
//! its own places: [`crate::checks::machine::macos::persistence`],
//! [`crate::checks::machine::linux::persistence`].
//!
//! [`programs`] is the list of persisted programs, for the YARA scan to
//! read.

use crate::checks::machine::settings::Runner;
use crate::utils::files;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

mod cron;
mod findings;
mod shell;
pub(crate) mod units;
mod vet;

pub use findings::{diff, findings};
pub use vet::{Signature, Vetted, signature_of, vet, vet_all};

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
        crate::utils::sha256::hex(
            format!("{}\u{1f}{}\u{1f}{}", self.source.name(), self.location, self.ident).as_bytes(),
        )
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
pub(crate) const INJECT: &[&str] = &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "LD_AUDIT"];

pub(crate) fn injects_in(text: &str) -> Vec<String> {
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
    pub(crate) fn sys(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }
    pub(crate) fn rebase(&self, p: &Path) -> PathBuf {
        if p.starts_with(&self.home) { p.to_path_buf() } else { self.sys(&p.to_string_lossy()) }
    }
    /// A path as the report shows it: `~/…`, or absolute on the machine.
    pub(crate) fn show(&self, p: &Path) -> String {
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
pub(crate) fn entries(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
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
        Roots {
            home,
            root: PathBuf::from("/"),
            macos: cfg!(target_os = "macos"),
            runner: &crate::checks::machine::settings::real_runner,
        }
    }
}

/// This machine's persistence items.
pub fn inventory() -> Inventory {
    inventory_in(&Roots::real(files::home()))
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
    units::units(r, &mut inv);
    cron::cron(r, &mut inv);
    cron::at(r, &mut inv);
    shell::shell(r, &mut inv);
    if r.macos {
        crate::checks::machine::macos::persistence::collect(r, &mut inv);
    } else {
        crate::checks::machine::linux::persistence::collect(r, &mut inv);
    }
    inv.read.sort();
    inv.read.dedup();
    inv
}

/// A file that is itself the program (a periodic or cron.daily script, a
/// plugin bundle).
pub(crate) fn file_item(r: &Roots, source: Source, path: &Path) -> Item {
    Item {
        source,
        location: r.show(path),
        ident: String::new(),
        program: Some(path.to_path_buf()),
        injects: Vec::new(),
        line: 0,
    }
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
