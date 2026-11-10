//! Clipboard clippers on this machine, found in its files. A clipper
//! watches the clipboard for a wallet address and replaces it with its
//! own, so the address a person pastes into a wallet isn't the one they
//! copied; it lives in a launch agent, an autostart entry or a browser
//! extension and rotates its addresses, so there is no list to match it
//! against. Every launch agent and daemon, autostart entry and user
//! service is read for the program it runs; a program that touches the
//! clipboard and carries wallet addresses, or the patterns that recognise
//! them, is a clipper; one that touches the clipboard from a temporary or
//! hidden place warns. wpantry never reads or writes the clipboard itself.
//!
//! The browser-extension side is the `SUSPECT-CLIPBOARD-SWAP` rule over
//! installed code.

use crate::checks::Scan;
use crate::checks::machine::any::persistence::units::{command_of, item_dirs_for};
use crate::finding::Finding;
use crate::utils::addresses::{self, Chain};
use crate::utils::{files, process};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

// Browser extensions ----------------------------------------------------------

/// What a browser extension's manifest lets it do with the clipboard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    /// Content scripts or host permissions on every site.
    pub all_sites: bool,
    pub name: String,
}

/// The manifest of an unpacked extension at `dir` (Chromium keeps it one
/// level down, in the version directory).
pub fn extension_permissions(dir: &Path) -> Option<Permissions> {
    let mut candidates = vec![dir.join("manifest.json")];
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut subs: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path().join("manifest.json")).collect();
        subs.sort();
        candidates.extend(subs);
    }
    let manifest = candidates.into_iter().find(|m| m.is_file()).and_then(|m| files::read_json(&m))?;
    let strings = |key: &str| -> Vec<String> {
        manifest
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let perms = strings("permissions");
    let everywhere = |m: &str| m == "<all_urls>" || m.starts_with("*://*/") || m == "http://*/*" || m == "https://*/*";
    let mut all_sites =
        strings("host_permissions").iter().any(|m| everywhere(m)) || perms.iter().any(|m| everywhere(m));
    if let Some(scripts) = manifest.get("content_scripts").and_then(|v| v.as_array()) {
        all_sites |= scripts
            .iter()
            .filter_map(|cs| cs.get("matches").and_then(|m| m.as_array()))
            .flatten()
            .filter_map(|m| m.as_str())
            .any(everywhere);
    }
    Some(Permissions {
        read: perms.iter().any(|p| p == "clipboardRead"),
        write: perms.iter().any(|p| p == "clipboardWrite"),
        all_sites,
        name: manifest.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
    })
}

// Persistence ---------------------------------------------------------------

/// A persisted program that touches the clipboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Persisted {
    /// The plist, .desktop or unit, as shown (`~/Library/LaunchAgents/x.plist`).
    pub item: String,
    /// The program it runs.
    pub program: String,
    pub chains: Vec<Chain>,
    /// Carries the regular expressions that recognise addresses.
    pub patterns: bool,
    /// Runs from a temporary, hidden or shared place.
    pub odd_place: bool,
    /// A clipper (addresses or patterns in hand) rather than a clipboard
    /// manager in an odd place.
    pub hard: bool,
}

/// How a program's text shows it touches the clipboard.
const CLIPBOARD: &[&str] = &[
    "NSPasteboard",
    "generalPasteboard",
    "pbpaste",
    "pbcopy",
    "pyperclip",
    "clipboard",
    "Clipboard",
    "CLIPBOARD",
    "xclip",
    "xsel",
    "wl-paste",
    "wl-copy",
    "GetClipboardData",
    "QClipboard",
    "the clipboard",
];
const INTERPRETERS: &[&str] =
    &["python", "python3", "node", "osascript", "bash", "sh", "zsh", "perl", "ruby", "bun", "deno", "swift", "env"];
/// How much of a program is read for its strings.
const MAX_PROGRAM: u64 = 16 << 20;

/// The directories of the persistence items on this OS.
pub(crate) fn item_dirs(home: &Path) -> Vec<PathBuf> {
    item_dirs_for(home, cfg!(target_os = "macos"))
}

/// Whether `program` is one of the interpreters, by file name (`python3.12` is `python`).
fn is_interpreter(program: &Path) -> bool {
    let name = program.file_name().and_then(OsStr::to_str).unwrap_or_default();
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().any(|i| base == i.trim_end_matches(|c: char| c.is_ascii_digit()))
}

/// The file whose contents say what the item does: the script an
/// interpreter is given, else the program itself.
pub(crate) fn program_file(argv: &[String]) -> Option<PathBuf> {
    let first = argv.first()?;
    if is_interpreter(Path::new(first))
        && let Some(script) = argv.iter().skip(1).find(|a| !a.starts_with('-') && Path::new(a).is_file())
    {
        return Some(PathBuf::from(script));
    }
    let p = if first.contains('/') { PathBuf::from(first) } else { process::which(first)? };
    Some(p)
}

pub(crate) fn odd_place(home: &Path, program: &Path) -> bool {
    // Under $HOME: a dot-directory straight under it other than the tool
    // managers' (whatever $HOME itself is under).
    if let Ok(rel) = program.strip_prefix(home) {
        if let Some(first) = rel.components().next().and_then(|c| c.as_os_str().to_str()) {
            let known = [
                ".local",
                ".cargo",
                ".npm",
                ".bun",
                ".deno",
                ".nvm",
                ".volta",
                ".rustup",
                ".config",
                ".cache",
                ".nix-profile",
                ".orbstack",
                ".docker",
                ".vscode",
                ".cursor",
                ".claude",
                ".codex",
            ];
            return first.starts_with('.') && !known.contains(&first);
        }
        return false;
    }
    let s = program.to_string_lossy();
    ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/Users/Shared/", "/dev/shm/"]
        .iter()
        .any(|p| s.starts_with(p))
}

/// Apple's and the distribution's own items: never clippers.
fn system_owned(path: &Path, argv: &[String]) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    if name.starts_with("com.apple.") || name.starts_with("org.gnome.") || name.starts_with("org.freedesktop.") {
        return true;
    }
    argv.first()
        .is_some_and(|p| p.starts_with("/System/") || p.starts_with("/usr/libexec/") || p.starts_with("/usr/lib/"))
}

/// The persisted programs that touch the clipboard under the given
/// directories, and how many items were read.
pub fn persistence_in(home: &Path, dirs: &[PathBuf]) -> (Vec<Persisted>, usize) {
    let mut out = Vec::new();
    let mut read = 0;
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        let mut items: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        items.sort();
        for item in items {
            let name = item.file_name().and_then(OsStr::to_str).unwrap_or("");
            if !(name.ends_with(".plist") || name.ends_with(".desktop") || name.ends_with(".service")) {
                continue;
            }
            let argv = command_of(&item);
            if argv.is_empty() || system_owned(&item, &argv) {
                continue;
            }
            read += 1;
            let program = program_file(&argv);
            let mut text = argv.join(" ");
            // An interpreter's own binary says nothing about the item, and a large one
            // (python3 with libpython linked in, as on arm64 Debian and Ubuntu) carries
            // clipboard and address-shaped strings of its own. With no script file to
            // read, the command line is all there is.
            if let Some(p) = &program
                && !is_interpreter(p)
                && let Ok(bytes) = files::read_capped_bytes(p, MAX_PROGRAM)
            {
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
            if !CLIPBOARD.iter().any(|m| text.contains(m)) {
                continue;
            }
            let chains = addresses::chains_in(&text);
            let patterns = crate::checks::suspects::ADDRESS_PATTERNS.iter().any(|p| text.contains(p));
            let shown_program =
                program.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| argv[0].clone());
            let odd = program.as_ref().is_some_and(|p| odd_place(home, p));
            let hard = !chains.is_empty() || patterns;
            if !hard && !odd {
                continue;
            }
            out.push(Persisted {
                item: files::short(&item.to_string_lossy()),
                program: files::short(&shown_program),
                chains,
                patterns,
                odd_place: odd,
                hard,
            });
        }
    }
    (out, read)
}

/// Every file a launch item names or runs, with the items themselves: what
/// the malware scan reads among the programs that start at login.
pub fn persisted_files() -> Vec<PathBuf> {
    let home = files::home();
    let mut out = Vec::new();
    for dir in item_dirs(&home) {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let item = e.path();
            if !item.is_file() {
                continue;
            }
            if let Some(program) = program_file(&command_of(&item)).filter(|p| p.is_file()) {
                out.push(program);
            }
            out.push(item);
        }
    }
    out
}

pub fn persistence() -> (Vec<Persisted>, usize) {
    let home = files::home();
    persistence_in(&home, &item_dirs(&home))
}

impl Persisted {
    pub fn note(&self) -> String {
        let where_ = if self.odd_place { " from a temporary or hidden place" } else { "" };
        if self.hard {
            let mut what = Vec::new();
            if !self.chains.is_empty() {
                what.push(format!(
                    "{} address{} hardcoded",
                    self.chains.iter().map(|c| c.name()).collect::<Vec<_>>().join(" and "),
                    if self.chains.len() == 1 { "" } else { "es" }
                ));
            }
            if self.patterns {
                what.push("the patterns that recognise wallet addresses".into());
            }
            format!(
                "{} runs{where_} at login, touches the clipboard and carries {}: a clipper",
                self.program,
                what.join(" and ")
            )
        } else {
            format!("{} runs{where_} at login and touches the clipboard", self.program)
        }
    }
}

/// Clipboard clippers: the persisted programs that touch the clipboard
/// with wallet addresses in hand. Critical: money sent from this machine
/// goes elsewhere.
pub fn clipper(scan: &mut Scan) {
    scan.status("Looking for clipboard clippers");
    let (found, read) = persistence();
    scan.count("launch agents and autostart items read", read as i64);
    for p in found {
        scan.add(Finding {
            kind: "clipper".into(),
            component: p.item.clone(),
            location: p.program.clone(),
            vuln_id: "CLIPPER-PERSISTENCE".into(),
            status: if p.hard { "fail" } else { "warn" }.into(),
            severity: if p.hard { "CRITICAL" } else { "" }.into(),
            note: p.note(),
            fix_cmd: if p.hard {
                format!(
                    "Don't send funds from this machine until it is gone. Unload it (launchctl bootout gui/$(id -u) {}; or remove the autostart entry), move the program aside for a look, check login items and browser extensions for the same, then change the passwords and move the wallets that were used here",
                    p.item
                )
            } else {
                format!("Read what {} is and who installed it; a clipboard manager you installed is fine, anything you don't recognise is not", p.program)
            },
            fix_auto: false,
            ..Default::default()
        });
    }
}

#[cfg(test)]
#[path = "clipper_tests.rs"]
mod tests;
