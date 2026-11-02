//! macOS apps and browsers, pending macOS updates, and Docker (the engine
//! and the images behind running containers).

use crate::plist;
use crate::re::Regex;
use crate::system::{self, Component, MACOS, brew_casks, github, run, which};
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
    let home = system::home().display().to_string();
    apps_in(&["/Applications".to_string(), format!("{home}/Applications")])
}

/// Every app in these folders (one folder deep), except Apple's own.
fn apps_in(roots: &[String]) -> Vec<Component> {
    let patterns: Vec<String> = roots.iter().flat_map(|r| [format!("{r}/*.app"), format!("{r}/*/*.app")]).collect();
    let mut bundles = system::expand(&patterns);
    bundles.sort();
    bundles.dedup();
    bundles.iter().filter_map(|b| app(Path::new(b))).collect()
}

fn firefox_channel(bundle: &Path) -> String {
    let Ok(prefs) =
        crate::system::read_capped(&bundle.join("Contents/Resources/defaults/pref/channel-prefs.js"), 1 << 20)
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
mod tests {
    use super::*;

    #[test]
    fn softwareupdate_listing() {
        let out = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: macOS Sequoia 15.7.1-24G231\n\tTitle: macOS Sequoia 15.7.1, Version: 15.7.1, Size: 1514000KiB, Recommended: YES, Action: restart, \n* Label: Safari26.1\n\tTitle: Safari, Version: 26.1, Size: 200000K, Recommended: NO, \n";
        assert_eq!(parse_softwareupdate(out), [("macOS Sequoia 15.7.1".to_string(), "15.7.1".to_string())]);
    }

    #[test]
    fn app_bundles() {
        let d = system::TempDir::new("app").unwrap();
        let b = d.path().join("Slack.app");
        std::fs::create_dir_all(b.join("Contents/Frameworks/Electron Framework.framework/Versions/A/Resources"))
            .unwrap();
        let plist = |id: &str, k: &str, v: &str| {
            format!(
                "<plist><dict><key>CFBundleIdentifier</key><string>{id}</string><key>{k}</key><string>{v}</string></dict></plist>"
            )
        };
        std::fs::write(
            b.join("Contents/Info.plist"),
            plist("com.tinyspeck.slackmacgap", "CFBundleShortVersionString", "4.41.97"),
        )
        .unwrap();
        std::fs::write(
            b.join("Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"),
            plist("x", "CFBundleVersion", "33.4.11"),
        )
        .unwrap();
        let c = app(&b).unwrap();
        assert_eq!((c.kind.as_str(), c.name.as_str(), c.version.as_str()), ("app", "Slack", "4.41.97"));
        assert_eq!(c.extra["electron"], "33.4.11");
        let apple = d.path().join("Notes.app");
        std::fs::create_dir_all(apple.join("Contents")).unwrap();
        std::fs::write(
            apple.join("Contents/Info.plist"),
            plist("com.apple.Notes", "CFBundleShortVersionString", "4.0"),
        )
        .unwrap();
        assert!(app(&apple).is_none(), "Apple's apps are the OS update's");
    }

    fn bundle(root: &Path, rel: &str, id: &str, k: &str, v: &str) -> std::path::PathBuf {
        let b = root.join(rel);
        std::fs::create_dir_all(b.join("Contents")).unwrap();
        let plist =
            format!("<plist><dict><key>CFBundleIdentifier</key><string>{id}</string><key>{k}</key>{v}</dict></plist>");
        std::fs::write(b.join("Contents/Info.plist"), plist).unwrap();
        b
    }

    #[test]
    fn apps_in_folders_one_level_deep_except_apples() {
        let d = system::TempDir::new("apps").unwrap();
        let root = d.path().join("Applications");
        bundle(
            &root,
            "Slack.app",
            "com.tinyspeck.slackmacgap",
            "CFBundleShortVersionString",
            "<string>4.41.97</string>",
        );
        // An integer CFBundleVersion stands in for a missing short version.
        bundle(&root, "Utilities/Tool.app", "com.example.tool", "CFBundleVersion", "<integer>42</integer>");
        bundle(&root, "Notes.app", "com.apple.Notes", "CFBundleShortVersionString", "<string>4.0</string>");
        bundle(&root, "Deep/Too/Far.app", "com.example.far", "CFBundleShortVersionString", "<string>1</string>");
        std::fs::create_dir_all(root.join("Empty.app/Contents")).unwrap();
        std::fs::create_dir_all(root.join("Not an app")).unwrap();
        let found = apps_in(&[root.display().to_string(), d.path().join("missing").display().to_string()]);
        let names: Vec<(&str, &str)> = found.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
        assert_eq!(names, [("Slack", "4.41.97"), ("Tool", "42")]);
        assert_eq!(found[1].extra["bundle"], "Tool.app");
        assert_eq!(found[1].extra["id"], "com.example.tool");
        assert!(!found[1].extra.contains_key("electron"));
    }

    #[test]
    fn browsers_carry_their_channel() {
        let d = system::TempDir::new("browser").unwrap();
        let ff = bundle(
            d.path(),
            "Firefox.app",
            "org.mozilla.firefox",
            "CFBundleShortVersionString",
            "<string>128.3.0</string>",
        );
        std::fs::create_dir_all(ff.join("Contents/Resources/defaults/pref")).unwrap();
        std::fs::write(
            ff.join("Contents/Resources/defaults/pref/channel-prefs.js"),
            "//@line 6\npref(\"app.update.channel\", \"esr\");\n",
        )
        .unwrap();
        let c = app(&ff).unwrap();
        assert_eq!(
            (c.kind.as_str(), c.extra["browser"].as_str(), c.extra["channel"].as_str()),
            ("browser", "firefox", "esr")
        );
        let chrome = bundle(
            d.path(),
            "Google Chrome.app",
            "com.google.Chrome",
            "CFBundleShortVersionString",
            "<string>130.0</string>",
        );
        let c = app(&chrome).unwrap();
        assert_eq!(
            (c.name.as_str(), c.extra["browser"].as_str(), c.extra["channel"].as_str()),
            ("Google Chrome", "chrome", "")
        );
        // No channel-prefs.js: no channel.
        let plain =
            bundle(d.path(), "Firefox Plain.app", "org.mozilla.firefox", "CFBundleVersion", "<string>1</string>");
        assert_eq!(app(&plain).unwrap().extra["channel"], "");
        let dev = bundle(
            d.path(),
            "Firefox Developer Edition.app",
            "org.mozilla.firefoxdeveloperedition",
            "CFBundleShortVersionString",
            "<string>133.0b1</string>",
        );
        assert_eq!(app(&dev).unwrap().extra["channel"], "");
    }

    #[test]
    fn software_update_answers_from_its_last_scan() {
        // Offline (--no-scan): what the last automatic scan found, if anything.
        let (updates, last) = macos_updates();
        assert!(updates.iter().all(|(t, v)| !t.trim().is_empty() && !v.trim().is_empty()), "{updates:?}");
        assert_eq!(last.trim(), last, "{last:?}");
    }

    #[test]
    fn docker_server_components_from_the_daemon() {
        let raw = r#"WARNING: something
{"Platform":{"Name":"Docker Desktop 4.35.0 (172550)"},"Components":[{"Name":"Engine","Version":"27.3.1"},{"Name":"containerd","Version":"v1.7.22-rc.1"},{"Name":"runc","Version":"v1.1.14"},{"Name":"docker-init","Version":"0.19.0"}],"Version":"27.3.1"}"#;
        let casks = || [("docker-desktop".to_string(), "4.35.0".to_string())].into();
        let found = docker_server("/usr/local/bin/docker", raw, casks);
        let got: Vec<(&str, &str, &str)> =
            found.iter().map(|c| (c.name.as_str(), c.version.as_str(), c.osv.as_ref().unwrap().2.as_str())).collect();
        assert_eq!(
            got,
            [
                ("docker engine", "27.3.1", "v27.3.1"),
                ("containerd", "1.7.22", "v1.7.22"),
                ("runc", "1.1.14", "v1.1.14")
            ]
        );
        assert_eq!(found[1].osv.as_ref().unwrap().1, "https://github.com/containerd/containerd.git");
        assert_eq!(
            (found[0].fix.as_str(), found[0].auto, found[0].path.as_str()),
            ("brew upgrade --cask docker-desktop", true, "/usr/local/bin/docker")
        );
        // Docker Desktop without the cask: its own updater.
        let found = docker_server("/usr/local/bin/docker", raw, std::collections::BTreeMap::new);
        assert_eq!(
            (found[0].fix.as_str(), found[0].auto),
            ("Update Docker Desktop (Docker menu → Check for Updates)", false)
        );
        // An engine that isn't Docker Desktop: the distro's packages (on a
        // Mac every engine is Desktop's).
        let engine = r#"{"Version":"27.3.1","Components":[{"Name":"Engine","Version":"27.3.1"},{"Name":"containerd","Version":"dev"}]}"#;
        let found = docker_server("/usr/bin/docker", engine, std::collections::BTreeMap::new);
        assert_eq!(found.len(), 1, "a version without three numbers is left out");
        if !MACOS {
            assert_eq!(found[0].fix, "Upgrade the docker-ce, containerd.io and runc packages (sudo)");
        }
        // No daemon: nothing.
        assert!(docker_server("/usr/bin/docker", "", || panic!("no server")).is_empty());
        assert!(
            docker_server("/usr/bin/docker", "Cannot connect to the Docker daemon\nnull\n", || panic!()).is_empty()
        );
    }

    #[test]
    fn docker_images_without_a_daemon_or_the_image() {
        // The docker CLI may or may not be here, its daemon running or not.
        for c in docker() {
            assert_eq!((c.kind.as_str(), c.osv.as_ref().map(|o| o.0.as_str())), ("tool", Some("GIT")), "{c:?}");
            assert_eq!(c.version.split('.').count(), 3, "{c:?}");
        }
        let refs = running_images();
        let mut sorted = refs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(refs, sorted);
        assert_eq!(image_id("wpantry-no-such-image:0.0.0"), "");
    }
}
