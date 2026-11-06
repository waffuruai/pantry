//! macOS apps and browsers, pending macOS updates, and Docker (the engine
//! and the images behind running containers).

use crate::component::Component;
use crate::utils::files;
use crate::utils::homebrew::brew_casks;
use crate::utils::net::github;
use crate::utils::os::MACOS;
use crate::utils::plist;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::re::Regex;
use serde_json::Value;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

/// Bundle id → browser.
pub const BROWSERS: &[(&str, &str)] = &[
    ("com.google.Chrome", "chrome"),
    ("org.mozilla.firefox", "firefox"),
    ("org.mozilla.firefoxdeveloperedition", "firefox-dev"),
    ("com.microsoft.edgemac", "edge"),
    ("com.brave.Browser", "brave"),
    ("company.thebrowser.Browser", "arc"),
    ("com.operasoftware.Opera", "opera"),
    ("com.vivaldi.Vivaldi", "vivaldi"),
    ("org.chromium.Chromium", "chromium"),
];

fn sh(argv: &[&str], timeout: u64) -> String {
    run(&argv.iter().map(OsStr::new).collect::<Vec<_>>(), Duration::from_secs(timeout))
}

fn plist_str(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// An app bundle as a component: kind app or browser; extra bundle, id,
/// browser, channel and electron (the bundled Electron's version).
pub fn app(bundle: &Path) -> Option<Component> {
    let info = plist::read(&bundle.join("Contents/Info.plist"));
    let id = plist_str(&info, "CFBundleIdentifier");
    if info.as_object().is_none_or(|o| o.is_empty()) || id.starts_with("com.apple.") {
        return None;
    }
    let ver = match plist_str(&info, "CFBundleShortVersionString") {
        v if v.is_empty() => plist_str(&info, "CFBundleVersion"),
        v => v,
    };
    let file = bundle.file_name()?.to_string_lossy().into_owned();
    let name = file.strip_suffix(".app").unwrap_or(&file).to_string();
    let browser = BROWSERS.iter().find(|(b, _)| *b == id).map(|(_, n)| *n);
    let mut c =
        Component::new(if browser.is_some() { "browser" } else { "app" }, &name, &ver, &bundle.display().to_string());
    c.extra.insert("bundle".into(), file);
    c.extra.insert("id".into(), id);
    if let Some(b) = browser {
        c.extra.insert("browser".into(), b.into());
        c.extra.insert("channel".into(), if b == "firefox" { firefox_channel(bundle) } else { String::new() });
    }
    let electron =
        plist::read(&bundle.join("Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"));
    let ev = plist_str(&electron, "CFBundleVersion");
    if !ev.is_empty() {
        c.extra.insert("electron".into(), ev);
    }
    Some(c)
}

/// Every app in /Applications and ~/Applications (one folder deep), except
/// Apple's own, which macOS updates cover.
pub fn apps() -> Vec<Component> {
    if !MACOS {
        return Vec::new();
    }
    let home = files::home().display().to_string();
    apps_in(&["/Applications".to_string(), format!("{home}/Applications")])
}

/// Every app in these folders (one folder deep), except Apple's own.
fn apps_in(roots: &[String]) -> Vec<Component> {
    let patterns: Vec<String> = roots.iter().flat_map(|r| [format!("{r}/*.app"), format!("{r}/*/*.app")]).collect();
    let mut bundles = files::expand(&patterns);
    bundles.sort();
    bundles.dedup();
    bundles.iter().filter_map(|b| app(Path::new(b))).collect()
}

fn firefox_channel(bundle: &Path) -> String {
    let Ok(prefs) =
        crate::utils::files::read_capped(&bundle.join("Contents/Resources/defaults/pref/channel-prefs.js"), 1 << 20)
    else {
        return String::new();
    };
    Regex::new(r#""app\.update\.channel",\s*"([^"]+)""#)
        .search(&prefs)
        .map(|c| c.get(1).to_string())
        .unwrap_or_default()
}

/// Recommended updates from the last automatic scan (no network):
/// [(title, version)], and that scan's date.
pub fn macos_updates() -> (Vec<(String, String)>, String) {
    if !MACOS {
        return (Vec::new(), String::new());
    }
    let out = sh(&["softwareupdate", "--list", "--no-scan"], 60);
    (
        parse_softwareupdate(&out),
        sh(&["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastSuccessfulDate"], 15)
            .trim()
            .to_string(),
    )
}

pub fn parse_softwareupdate(out: &str) -> Vec<(String, String)> {
    Regex::new(r"Title: ([^,]+), Version: ([^,]+),.*?Recommended: YES")
        .find_all(out)
        .iter()
        .map(|c| (c.get(1).to_string(), c.get(2).to_string()))
        .collect()
}

/// The Docker engine and the containerd and runc it runs, from the daemon
/// (nothing when it isn't running). Docker Desktop ships them inside its VM,
/// so its update is the fix there.
pub fn docker() -> Vec<Component> {
    let Some(exe) = which("docker") else { return Vec::new() };
    let exe = exe.display().to_string();
    let raw = sh(&[&exe, "version", "--format", "{{json .Server}}"], 20);
    docker_server(&exe, &raw, brew_casks)
}

/// The components in what `docker version` said of its server; `casks`
/// lists what Homebrew installed, read only for Docker Desktop.
fn docker_server(
    exe: &str,
    raw: &str,
    casks: impl FnOnce() -> std::collections::BTreeMap<String, String>,
) -> Vec<Component> {
    let Some(server) =
        raw.trim().lines().last().and_then(|l| serde_json::from_str::<Value>(l).ok()).filter(Value::is_object)
    else {
        return Vec::new();
    };
    let (fix, auto) = if MACOS || server.to_string().contains("Docker Desktop") {
        if casks().contains_key("docker-desktop") {
            ("brew upgrade --cask docker-desktop".to_string(), true)
        } else {
            ("Update Docker Desktop (Docker menu → Check for Updates)".to_string(), false)
        }
    } else {
        ("Upgrade the docker-ce, containerd.io and runc packages (sudo)".to_string(), false)
    };
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let mut found = vec![("docker engine".to_string(), s(&server, "Version"), "moby/moby")];
    for comp in server.get("Components").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let name = s(comp, "Name").to_lowercase();
        if name == "containerd" || name == "runc" {
            let repo = if name == "containerd" { "containerd/containerd" } else { "opencontainers/runc" };
            found.push((name, s(comp, "Version"), repo));
        }
    }
    let three = Regex::new(r"\d+\.\d+\.\d+");
    let mut out = Vec::new();
    for (name, ver, repo) in found {
        let ver = ver.trim_start_matches('v').split('-').next().unwrap_or("").to_string();
        if three.fullmatch(&ver).is_some() {
            let mut c = Component::new("tool", &name, &ver, exe);
            c.osv = Some(("GIT".into(), github(repo), format!("v{ver}")));
            c.fix = fix.clone();
            c.auto = auto;
            out.push(c);
        }
    }
    out
}

/// The images behind running containers.
pub fn running_images() -> Vec<String> {
    let Some(exe) = which("docker") else { return Vec::new() };
    let mut refs: Vec<String> = sh(&[&exe.display().to_string(), "ps", "--format", "{{.Image}}"], 20)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

/// The local image id for `r`, or "" when it isn't pulled or built here.
pub fn image_id(r: &str) -> String {
    let Some(exe) = which("docker") else { return String::new() };
    let out = sh(&[&exe.display().to_string(), "image", "inspect", "--format", "{{.Id}}", r], 20).trim().to_string();
    if out.starts_with("sha256:") { out } else { String::new() }
}

#[cfg(test)]
#[path = "apps_tests.rs"]
mod tests;
