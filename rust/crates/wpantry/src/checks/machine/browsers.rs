//! Browsers installed on Linux, found read-only: the binaries on PATH and
//! what each prints for `--version`, then `snap list` and
//! `flatpak list --app`. No network and no root.
//!
//! Each is a component of kind `browser` with extra `browser` (the
//! `BROWSERS` id in `apps.rs`), as a macOS app bundle is, so
//! `app_updates` and the KEV escalation judge both alike. Extra `install`
//! says where it came from (`package`, `snap`, `flatpak` or `vendor`), and
//! its fix is how that source updates it. The fix is printed, never run.
//!
//! Ubuntu's `chromium-browser` and `firefox` debs are shims that start the
//! snap: those binaries are skipped and the snap is read from `snap list`.
//!
//! Example: `/usr/bin/google-chrome-stable --version` prints
//! "Google Chrome 131.0.6778.85": a `browser` component "Google Chrome"
//! 131.0.6778.85 with extra `browser` = `chrome` and `install` = `package`.

use crate::checks::machine::settings::Runner;
use crate::component::Component;
use crate::utils::os;
use crate::utils::process;
use crate::utils::re::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Whether this is Linux, where these browsers are looked for.
pub const LINUX: bool = cfg!(target_os = "linux");

/// (binary, browser id, the package that installs it).
const BINARIES: &[(&str, &str, &str)] = &[
    ("google-chrome-stable", "chrome", "google-chrome-stable"),
    ("google-chrome", "chrome", "google-chrome-stable"),
    ("chromium", "chromium", "chromium"),
    ("chromium-browser", "chromium", "chromium-browser"),
    ("microsoft-edge-stable", "edge", "microsoft-edge-stable"),
    ("microsoft-edge", "edge", "microsoft-edge-stable"),
    ("brave-browser-stable", "brave", "brave-browser"),
    ("brave-browser", "brave", "brave-browser"),
    ("firefox", "firefox", "firefox"),
    ("firefox-esr", "firefox", "firefox-esr"),
];

/// (browser id, component name, what `--version` prints before the version).
const NAMES: &[(&str, &str, &str)] = &[
    ("chrome", "Google Chrome", "Google Chrome"),
    ("chromium", "Chromium", "Chromium"),
    ("edge", "Microsoft Edge", "Microsoft Edge"),
    ("brave", "Brave Browser", "Brave Browser"),
    ("firefox", "Firefox", "Mozilla Firefox"),
];

/// (snap name, browser id).
const SNAPS: &[(&str, &str)] = &[("chromium", "chromium"), ("firefox", "firefox"), ("brave", "brave")];

/// (Flatpak application id, browser id).
const FLATPAKS: &[(&str, &str)] = &[
    ("com.google.Chrome", "chrome"),
    ("org.chromium.Chromium", "chromium"),
    ("com.microsoft.Edge", "edge"),
    ("com.brave.Browser", "brave"),
    ("org.mozilla.firefox", "firefox"),
];

fn name_of(id: &str) -> (&'static str, &'static str) {
    NAMES.iter().find(|(i, _, _)| *i == id).map(|(_, n, l)| (*n, *l)).unwrap_or(("", ""))
}

/// The browsers installed here; nothing off Linux.
pub fn browsers() -> Vec<Component> {
    if !LINUX {
        return Vec::new();
    }
    let dirs: Vec<PathBuf> = process::path_dirs().into_iter().filter(|d| !d.is_empty()).map(PathBuf::from).collect();
    found(&dirs, &crate::checks::machine::settings::real_runner, &os::os_release())
}

/// The browsers in `dirs` (PATH, in order) and the snaps and Flatpaks
/// `run` lists; `rel` is /etc/os-release, for the package fix.
pub fn found(dirs: &[PathBuf], run: Runner, rel: &BTreeMap<String, String>) -> Vec<Component> {
    let mut out = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for (bin, id, package) in BINARIES {
        let Some(exe) = dirs.iter().map(|d| d.join(bin)).find(|p| process::which(&p.display().to_string()).is_some())
        else {
            continue;
        };
        let real = std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone());
        if seen.contains(&real) || starts_snap(&real) {
            continue;
        }
        seen.push(real.clone());
        let (name, label) = name_of(id);
        let exe_s = exe.display().to_string();
        let Some(version) = version(&run(&[&exe_s, "--version"]), label) else { continue };
        let install = install_of(&real);
        out.push(component(id, &version, &exe_s, install, &fix(install, name, package, rel)));
    }
    for (snap, version) in snaps(&run(&["snap", "list"])) {
        let id = SNAPS.iter().find(|(s, _)| *s == snap).map(|(_, i)| *i).unwrap_or("");
        out.push(component(id, &version, &format!("/snap/bin/{snap}"), "snap", &format!("sudo snap refresh {snap}")));
    }
    for (app, version) in flatpaks(&run(&["flatpak", "list", "--app", "--columns=application,version"])) {
        let id = FLATPAKS.iter().find(|(a, _)| *a == app).map(|(_, i)| *i).unwrap_or("");
        out.push(component(id, &version, &format!("flatpak:{app}"), "flatpak", &format!("flatpak update {app}")));
    }
    out
}

/// How a browser installed from `install` is updated: the distro's
/// package command for `package`, else its vendor's updater.
pub fn fix(install: &str, name: &str, package: &str, rel: &BTreeMap<String, String>) -> String {
    match install {
        "package" => os::os_fix(rel, package),
        _ => format!("Update {name} from its vendor (or its own updater)"),
    }
}

/// A browser component as `app_updates` reads it.
pub(crate) fn component(id: &str, version: &str, path: &str, install: &str, fix: &str) -> Component {
    let mut c = Component::new("browser", name_of(id).0, version, path);
    c.extra.insert("browser".into(), id.into());
    c.extra.insert("install".into(), install.into());
    c.fix = fix.into();
    c
}

/// Whether `real` (a resolved binary) starts a snap: snapd's own binary,
/// a path under /snap, or a small script that runs one (Ubuntu's
/// transitional debs).
fn starts_snap(real: &Path) -> bool {
    if real.starts_with("/snap") || real.file_name().is_some_and(|f| f == "snap") {
        return true;
    }
    let head = crate::utils::files::read_capped_bytes(real, 1 << 16).unwrap_or_default();
    head.starts_with(b"#!") && String::from_utf8_lossy(&head).contains("/snap/")
}

/// Where a resolved binary came from: `package` under /usr (not
/// /usr/local) or the vendors' package directories in /opt, else `vendor`
/// (a tarball, or a copy in a home directory).
pub fn install_of(real: &Path) -> &'static str {
    let packaged = ["/opt/google/", "/opt/microsoft/", "/opt/brave.com/"];
    let s = real.display().to_string();
    if (s.starts_with("/usr/") && !s.starts_with("/usr/local/")) || packaged.iter().any(|p| s.starts_with(p)) {
        "package"
    } else {
        "vendor"
    }
}

/// The version in what `--version` printed: the dotted number after
/// `label` on its line ("Mozilla Firefox 128.5.0esr" → 128.5.0). Lines
/// before it (a toolkit's warnings) are skipped.
pub fn version(out: &str, label: &str) -> Option<String> {
    let num = Regex::new(r"^\s*(\d+(?:\.\d+)+)");
    out.lines().find_map(|l| {
        let (_, rest) = l.split_once(label)?;
        num.search(rest).map(|c| c.get(1).to_string())
    })
}

/// A package version without its packaging suffix ("133.0-2" → 133.0).
fn upstream(v: &str) -> String {
    v.split(['-', '+', '~']).next().unwrap_or("").to_string()
}

/// The browser snaps in `snap list`: (snap, version).
pub fn snaps(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let mut cols = l.split_whitespace();
            let (name, ver) = (cols.next()?, cols.next()?);
            SNAPS.iter().any(|(s, _)| *s == name).then(|| (name.to_string(), upstream(ver)))
        })
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

/// The browser Flatpaks in `flatpak list --app
/// --columns=application,version`: (application id, version).
pub fn flatpaks(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let mut cols = l.split('\t').map(str::trim);
            let (app, ver) = (cols.next()?, cols.next()?);
            FLATPAKS.iter().any(|(a, _)| *a == app).then(|| (app.to_string(), upstream(ver)))
        })
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

#[cfg(test)]
#[path = "browsers_tests.rs"]
mod tests;
