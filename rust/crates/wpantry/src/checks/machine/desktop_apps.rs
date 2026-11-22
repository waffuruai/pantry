//! Desktop apps against CVE records: the macOS apps in /Applications and
//! the Linux Flatpaks and snaps that Pantry's reviewed table ([`APPS`])
//! names, judged by their records' version ranges through the same check
//! as Windows programs ([`software_cves::check`]). NVD's copies of the
//! records count too, for the apps whose publishers often file records
//! naming no product or versions (Signal, 1Password, Notion).
//!
//! An app the table doesn't name is never asked about: nothing about it
//! leaves the machine. Apps a distro packages are the OS update check's.

use crate::checks::Scan;
use crate::checks::machine::settings::Runner;
use crate::checks::machine::software_cves::{self, Subject, vendors_for};
use crate::component::Component;
use crate::error::Result;

/// What the check's not-checked lines are called.
pub const WHAT: &str = "desktop apps against CVE records";

/// The apps checked against CVE records: an app's id (a macOS bundle id,
/// a Flatpak application id, or a snap name, as `snap:<name>`), then the
/// vendor and product its records name. The product is matched by
/// [`software_cves::product_key`], so NVD's CPE spelling of it
/// (`vlc_media_player`) is the same product; a vendor filed under other
/// names gets them in [`software_cves::VENDOR_ALIASES`]. An app with two
/// spellings of its product (Zoom's records name `Zoom Workplace` now and
/// `Zoom` before) has a row for each.
///
/// Rows are added from real records: the vendor and product checked
/// against `vulnerability.circl.lu/api/browse/<vendor>`, the id against
/// the app (Homebrew's cask, Flathub, the Snap Store).
pub const APPS: &[(&str, &str, &str)] = &[
    ("com.1password.1password", "1Password", "1Password"),
    ("snap:1password", "1Password", "1Password"),
    ("com.docker.docker", "Docker", "Docker Desktop"),
    ("org.blenderfoundation.blender", "Blender Foundation", "Blender"),
    ("org.blender.Blender", "Blender Foundation", "Blender"),
    ("snap:blender", "Blender Foundation", "Blender"),
    ("org.gimp.gimp", "GIMP", "GIMP"),
    ("org.gimp.GIMP", "GIMP", "GIMP"),
    ("snap:gimp", "GIMP", "GIMP"),
    ("org.keepassxc.keepassxc", "KeePassXC", "KeePassXC"),
    ("org.keepassxc.KeePassXC", "KeePassXC", "KeePassXC"),
    ("snap:keepassxc", "KeePassXC", "KeePassXC"),
    ("org.libreoffice.script", "The Document Foundation", "LibreOffice"),
    ("org.libreoffice.LibreOffice", "The Document Foundation", "LibreOffice"),
    ("snap:libreoffice", "The Document Foundation", "LibreOffice"),
    ("at.obdev.littlesnitch", "Objective Development", "Little Snitch"),
    ("notion.id", "Notion", "Notion"),
    ("md.obsidian", "Obsidian", "Obsidian"),
    ("md.obsidian.Obsidian", "Obsidian", "Obsidian"),
    ("snap:obsidian", "Obsidian", "Obsidian"),
    ("org.openshot.OpenShot", "OpenShot", "openshot-qt"),
    ("org.whispersystems.signal-desktop", "Signal", "Signal-Desktop"),
    ("org.signal.Signal", "Signal", "Signal-Desktop"),
    ("snap:signal-desktop", "Signal", "Signal-Desktop"),
    ("com.tdesktop.Telegram", "Telegram", "Telegram Desktop"),
    ("org.telegram.desktop", "Telegram", "Telegram Desktop"),
    ("snap:telegram-desktop", "Telegram", "Telegram Desktop"),
    ("com.teamviewer.TeamViewer", "TeamViewer", "TeamViewer"),
    ("org.m0k.transmission", "Transmission", "Transmission"),
    ("com.transmissionbt.Transmission", "Transmission", "Transmission"),
    ("org.videolan.vlc", "VideoLAN", "VLC media player"),
    ("org.videolan.VLC", "VideoLAN", "VLC media player"),
    ("snap:vlc", "VideoLAN", "VLC media player"),
    ("org.wireshark.Wireshark", "Wireshark", "Wireshark"),
    ("us.zoom.xos", "Zoom", "Zoom Workplace"),
    ("us.zoom.xos", "Zoom", "Zoom"),
    ("us.zoom.Zoom", "Zoom", "Zoom Workplace"),
    ("us.zoom.Zoom", "Zoom", "Zoom"),
    ("snap:zoom-client", "Zoom", "Zoom Workplace"),
    ("snap:zoom-client", "Zoom", "Zoom"),
];

/// One installed app: its id ([`APPS`]' first column), name, version and
/// where it is.
#[derive(Clone, Debug, PartialEq)]
pub struct App {
    pub id: String,
    pub name: String,
    pub version: String,
    pub location: String,
}

/// The [`APPS`] rows an id is: the same id, or a versioned one of it
/// (GIMP 3.2's bundle is `org.gimp.gimp-3.2`).
fn rows(id: &str) -> impl Iterator<Item = &'static (&'static str, &'static str, &'static str)> + '_ {
    APPS.iter().filter(move |(a, _, _)| {
        *a == id
            || id.strip_prefix(a).is_some_and(|rest| rest.starts_with('-') && rest[1..].starts_with(char::is_numeric))
    })
}

/// An app's version as its records number it: the first word, so Zoom's
/// `7.1.9 (88375)` is `7.1.9`.
fn version_of(v: &str) -> String {
    v.split_whitespace().next().unwrap_or_default().to_string()
}

/// The subjects [`APPS`] names among `apps`: one per row.
pub fn subjects(apps: &[App]) -> Vec<Subject> {
    apps.iter()
        .flat_map(|a| {
            rows(&a.id).map(|(_, vendor, product)| Subject {
                kind: "app".into(),
                name: a.name.clone(),
                version: version_of(&a.version),
                location: a.location.clone(),
                vendors: vendors_for(vendor),
                product: Some(product.to_string()),
                nvd: true,
                system: software_cves::this_system().into(),
                ..Default::default()
            })
        })
        .collect()
}

/// The macOS apps the inventory read ([`crate::checks::machine::apps::apps`]).
pub fn mac_apps(found: &[Component]) -> Vec<App> {
    found
        .iter()
        .filter_map(|c| {
            let id = c.extra.get("id")?;
            Some(App { id: id.clone(), name: c.name.clone(), version: c.version.clone(), location: c.path.clone() })
        })
        .collect()
}

/// The Flatpaks in `flatpak list --app --columns=application,version`
/// and the snaps in `snap list` that [`APPS`] names.
pub fn linux_apps(flatpaks: &str, snaps: &str) -> Vec<App> {
    let mut out = Vec::new();
    for l in flatpaks.lines() {
        let mut cols = l.split('\t').map(str::trim);
        let (Some(id), Some(v)) = (cols.next(), cols.next()) else { continue };
        if !v.is_empty() && rows(id).next().is_some() {
            out.push(App { id: id.into(), name: id.into(), version: v.into(), location: format!("flatpak:{id}") });
        }
    }
    for l in snaps.lines().skip(1) {
        let mut cols = l.split_whitespace();
        let (Some(name), Some(v)) = (cols.next(), cols.next()) else { continue };
        let id = format!("snap:{name}");
        if rows(&id).next().is_some() {
            out.push(App { id, name: name.into(), version: v.into(), location: format!("/snap/bin/{name}") });
        }
    }
    out
}

/// The apps installed here that [`APPS`] names, against CVE records.
pub fn check(scan: &mut Scan, run: Runner) -> Result<()> {
    let apps = if cfg!(target_os = "macos") {
        mac_apps(&crate::checks::machine::apps::apps())
    } else if cfg!(target_os = "linux") {
        let flatpaks = run(&["flatpak", "list", "--app", "--columns=application,version"]);
        linux_apps(&flatpaks, &run(&["snap", "list"]))
    } else {
        Vec::new()
    };
    check_found(scan, &apps)
}

/// [`check`] over the apps found.
pub fn check_found(scan: &mut Scan, apps: &[App]) -> Result<()> {
    software_cves::check(scan, &subjects(apps), WHAT)
}

#[cfg(test)]
#[path = "desktop_apps_tests.rs"]
mod tests;
