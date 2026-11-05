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

/// The file whose contents say what the item does: the script an
/// interpreter is given, else the program itself.
pub(crate) fn program_file(argv: &[String]) -> Option<PathBuf> {
    let first = argv.first()?;
    let base = Path::new(first).file_name().and_then(OsStr::to_str).unwrap_or(first);
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let interpreter = INTERPRETERS.iter().any(|i| base == i.trim_end_matches(|c: char| c.is_ascii_digit()));
    if interpreter && let Some(script) = argv.iter().skip(1).find(|a| !a.starts_with('-') && Path::new(a).is_file()) {
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
            if let Some(p) = &program
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
mod tests {
    use super::*;
    use crate::utils::temp;

    #[test]
    fn launch_agents_that_clip_are_found_and_managers_are_not() {
        let d = temp::TempDir::new("clipper").unwrap();
        let home = d.path();
        let agents = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::create_dir_all(home.join(".svc")).unwrap();
        std::fs::create_dir_all(home.join("bin")).unwrap();
        let plist = |label: &str, argv: &[&str]| {
            let args: String = argv.iter().map(|a| format!("<string>{a}</string>")).collect();
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/></dict></plist>\n"
            )
        };
        // A Python clipper under a hidden directory.
        let clip = home.join(".svc/sync.py");
        std::fs::write(&clip, "import pyperclip, re\nwhile 1:\n  c = pyperclip.paste()\n  if re.match(r'^0x[a-fA-F0-9]{40}$', c): pyperclip.copy('0xD62Eb957610d49f77cFce8bCc9827b5428D790E6')\n").unwrap();
        std::fs::write(
            agents.join("com.sync.helper.plist"),
            plist("com.sync.helper", &["/usr/bin/python3", &clip.to_string_lossy()]),
        )
        .unwrap();
        // A clipboard manager in the usual place.
        let manager = home.join("bin/paste-history");
        std::fs::write(&manager, "#!/bin/sh\nwhile true; do pbpaste >> ~/.paste-history; sleep 1; done\n").unwrap();
        std::fs::write(
            agents.join("me.paste.history.plist"),
            plist("me.paste.history", &["/bin/sh", &manager.to_string_lossy()]),
        )
        .unwrap();
        // A clipboard reader in a hidden place, no addresses.
        let odd = home.join(".svc/watch.sh");
        std::fs::write(&odd, "#!/bin/sh\npbpaste > /dev/null\n").unwrap();
        std::fs::write(
            agents.join("com.svc.watch.plist"),
            plist("com.svc.watch", &["/bin/sh", &odd.to_string_lossy()]),
        )
        .unwrap();
        // An inline AppleScript that sets the clipboard to an address.
        std::fs::write(
            agents.join("com.inline.plist"),
            plist(
                "com.inline",
                &["/usr/bin/osascript", "-e", "set the clipboard to \"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t\""],
            ),
        )
        .unwrap();
        // Apple's own, and something unrelated.
        std::fs::write(agents.join("com.apple.foo.plist"), plist("com.apple.foo", &["/System/Library/x", "pbpaste"]))
            .unwrap();
        std::fs::write(agents.join("com.other.plist"), plist("com.other", &["/usr/local/bin/backup"])).unwrap();

        let (found, read) = persistence_in(home, &[agents.clone(), home.join("missing")]);
        assert_eq!(read, 5, "every item but Apple's, missing directories skipped");
        let items: Vec<(&str, bool, bool)> =
            found.iter().map(|p| (p.item.rsplit('/').next().unwrap(), p.hard, p.odd_place)).collect();
        assert_eq!(
            items,
            [
                ("com.inline.plist", true, false),
                ("com.svc.watch.plist", false, true),
                ("com.sync.helper.plist", true, true)
            ],
            "{found:?}"
        );
        let clipper = found.iter().find(|p| p.item.ends_with("com.sync.helper.plist")).unwrap();
        assert_eq!(clipper.chains, [Chain::Evm]);
        assert!(clipper.patterns);
        assert!(clipper.note().contains("touches the clipboard and carries EVM (Ethereum, BSC, Tempo) address hardcoded and the patterns that recognise wallet addresses: a clipper"), "{}", clipper.note());
        assert!(clipper.note().contains("from a temporary or hidden place"), "{}", clipper.note());
        let inline = found.iter().find(|p| p.item.ends_with("com.inline.plist")).unwrap();
        assert_eq!(inline.chains, [Chain::Tron]);
        assert_eq!(inline.program, "/usr/bin/osascript");
        let watch = found.iter().find(|p| p.item.ends_with("com.svc.watch.plist")).unwrap();
        assert!(
            watch.note().ends_with("runs from a temporary or hidden place at login and touches the clipboard"),
            "{}",
            watch.note()
        );
    }

    #[test]
    fn autostart_entries_and_units_read_their_exec_lines() {
        let d = temp::TempDir::new("clipper-linux").unwrap();
        let home = d.path();
        let auto = home.join(".config/autostart");
        std::fs::create_dir_all(&auto).unwrap();
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        let bin = home.join(".cache/.x/clip");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\nwhile :; do c=$(xclip -o); case $c in bc1q*) echo bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq | xclip -i;; esac; done\n").unwrap();
        std::fs::write(
            auto.join("clip.desktop"),
            format!("[Desktop Entry]\nType=Application\nName=Clip\nExec={} --quiet\n", bin.display()),
        )
        .unwrap();
        let units = home.join(".config/systemd/user");
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(units.join("sync.service"), "[Service]\nExecStart=/usr/bin/python3 /opt/sync/main.py\n")
            .unwrap();
        let (found, read) = persistence_in(home, &[auto, units]);
        assert_eq!(read, 2);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            (found[0].chains.as_slice(), found[0].hard, found[0].odd_place),
            ([Chain::Bitcoin].as_slice(), true, false),
            "~/.cache is a known place; the addresses decide"
        );
    }

    #[test]
    fn extension_manifests_say_what_the_clipboard_is_to_them() {
        let d = temp::TempDir::new("clipper-ext").unwrap();
        let ext = d.path().join("abcdefgh");
        std::fs::create_dir_all(ext.join("1.2.3_0")).unwrap();
        std::fs::write(
            ext.join("1.2.3_0/manifest.json"),
            r#"{"name": "Wallet Helper", "manifest_version": 3, "permissions": ["clipboardRead", "clipboardWrite", "storage"], "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}]}"#,
        )
        .unwrap();
        let got = extension_permissions(&ext).unwrap();
        assert_eq!(got, Permissions { read: true, write: true, all_sites: true, name: "Wallet Helper".into() });
        let flat = d.path().join("flat");
        std::fs::create_dir_all(&flat).unwrap();
        std::fs::write(
            flat.join("manifest.json"),
            r#"{"name": "Notes", "permissions": ["clipboardWrite"], "host_permissions": ["https://notes.example/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            extension_permissions(&flat).unwrap(),
            Permissions { read: false, write: true, all_sites: false, name: "Notes".into() }
        );
        assert_eq!(extension_permissions(&d.path().join("missing")), None);
    }

    #[test]
    fn program_files_follow_interpreters_and_odd_places_are_named() {
        let d = temp::TempDir::new("clipper-prog").unwrap();
        let script = d.path().join("s.py");
        std::fs::write(&script, "x").unwrap();
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(program_file(&argv(&["/usr/bin/python3", "-u", &script.to_string_lossy()])), Some(script.clone()));
        assert_eq!(program_file(&argv(&["/usr/bin/env", "python3", &script.to_string_lossy()])), Some(script.clone()));
        assert_eq!(
            program_file(&argv(&["/usr/bin/osascript", "-e", "beep"])),
            Some(PathBuf::from("/usr/bin/osascript")),
            "inline: the interpreter itself"
        );
        assert_eq!(program_file(&argv(&["no-such-program-anywhere"])), None);
        let home = Path::new("/Users/me");
        assert!(odd_place(home, Path::new("/tmp/.x/a")));
        assert!(odd_place(home, Path::new("/Users/me/.svc/a")));
        assert!(odd_place(home, Path::new("/Users/Shared/.hidden/a")));
        assert!(!odd_place(home, Path::new("/Users/me/.local/bin/a")));
        assert!(!odd_place(home, Path::new("/Users/me/bin/a")));
        assert!(!odd_place(home, Path::new("/Applications/Maccy.app/Contents/MacOS/Maccy")));
    }
}
