//! Launch agents and daemons (macOS), systemd units and autostart entries (Linux).

use super::{INJECT, Inventory, Item, Roots, Source, entries, injects_in};
use crate::clipper::{command_of, item_dirs_for, program_file};
use crate::system;
use std::ffi::OsStr;
use std::path::PathBuf;

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
