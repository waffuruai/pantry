//! The startup files a shell reads, recorded by line.

use super::{Inventory, Item, Roots, Source, entries, injects_in};
use crate::system;
use std::collections::BTreeMap;
use std::path::PathBuf;

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

pub(super) fn shell(r: &Roots, inv: &mut Inventory) {
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
