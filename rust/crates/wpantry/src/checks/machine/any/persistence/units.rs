//! Launch agents and daemons (macOS), systemd units and autostart entries (Linux).

use super::{INJECT, Inventory, Item, Roots, Source, entries, injects_in};
use crate::checks::machine::clipper::program_file;
use crate::utils::files;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Launch agents and daemons (macOS), systemd units and autostart entries
/// (Linux): the clipper's directories, and on Linux the system units too.
pub(super) fn units(r: &Roots, inv: &mut Inventory) {
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
                let plist = crate::utils::plist::read(&path);
                if let Some(env) = plist.get("EnvironmentVariables").and_then(|e| e.as_object()) {
                    injects.extend(env.keys().filter(|k| INJECT.contains(&k.as_str())).cloned());
                }
            } else if let Ok(text) = files::read_capped(&path, 1 << 20) {
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

/// The directories of the persistence items on macOS, or on Linux.
pub(crate) fn item_dirs_for(home: &Path, macos: bool) -> Vec<PathBuf> {
    if macos {
        vec![
            home.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
        ]
    } else {
        vec![home.join(".config/autostart"), home.join(".config/systemd/user"), PathBuf::from("/etc/xdg/autostart")]
    }
}

/// The command line a persistence item runs.
pub(crate) fn command_of(path: &Path) -> Vec<String> {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    if name.ends_with(".plist") {
        let v = crate::utils::plist::read(path);
        if let Some(args) = v.get("ProgramArguments").and_then(|a| a.as_array()) {
            let mut argv: Vec<String> = args.iter().filter_map(|a| a.as_str().map(str::to_string)).collect();
            if let Some(p) = v.get("Program").and_then(|p| p.as_str()) {
                if argv.is_empty() {
                    argv.push(p.to_string());
                } else {
                    argv[0] = p.to_string();
                }
            }
            return argv;
        }
        return v.get("Program").and_then(|p| p.as_str()).map(|p| vec![p.to_string()]).unwrap_or_default();
    }
    let Ok(text) = files::read_capped(path, 1 << 20) else { return Vec::new() };
    let key = if name.ends_with(".desktop") { "Exec=" } else { "ExecStart=" };
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key))
        .map(|cmd| cmd.split_whitespace().map(|w| w.trim_matches('"').to_string()).collect())
        .unwrap_or_default()
}
