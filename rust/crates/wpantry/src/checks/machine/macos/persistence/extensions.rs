//! Plugin bundles and system extensions the system loads.

use crate::checks::machine::any::persistence::{Inventory, Item, Roots, Source, entries, file_item};
use std::path::PathBuf;

/// Plugin bundles the system loads into its own processes: authorization
/// plugins (into the login window and `authorizationhost`), third-party
/// kernel extensions, Quick Look generators and Spotlight importers.
pub(super) fn bundles(r: &Roots, inv: &mut Inventory) {
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
pub(super) fn system_extensions(r: &Roots, inv: &mut Inventory) {
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
