use super::*;
use crate::checks::machine::testing;
use crate::utils::os::parse_os_release;

#[test]
fn versions_from_each_browsers_output() {
    let cases = [
        ("Google Chrome 131.0.6778.85 \n", "Google Chrome", "131.0.6778.85"),
        ("Chromium 131.0.6778.85 snap\n", "Chromium", "131.0.6778.85"),
        ("Chromium 131.0.6778.85 built on Debian GNU/Linux 12 (bookworm)\n", "Chromium", "131.0.6778.85"),
        ("Microsoft Edge 131.0.2903.70\n", "Microsoft Edge", "131.0.2903.70"),
        ("Brave Browser 131.1.73.97\n", "Brave Browser", "131.1.73.97"),
        ("Mozilla Firefox 133.0\n", "Mozilla Firefox", "133.0"),
        ("Mozilla Firefox 128.5.0esr\n", "Mozilla Firefox", "128.5.0"),
        // A toolkit's warning before the version line is skipped.
        (
            "(firefox:12): Gtk-WARNING 3.24: cannot open display\nMozilla Firefox 133.0.3\n",
            "Mozilla Firefox",
            "133.0.3",
        ),
    ];
    for (out, label, want) in cases {
        assert_eq!(version(out, label).as_deref(), Some(want), "{out:?}");
    }
    assert_eq!(version("", "Google Chrome"), None);
    assert_eq!(version("Google Chrome is not installed\n", "Google Chrome"), None);
    assert_eq!(version("Chromium 131.0.6778.85\n", "Google Chrome"), None, "another browser's line");
}

#[test]
fn snap_list_names_the_browser_snaps() {
    let out = "Name      Version          Rev    Tracking         Publisher   Notes\n\
               core22    20241001         1663   latest/stable    canonical** base\n\
               chromium  131.0.6778.85    2999   latest/stable    canonical** -\n\
               firefox   133.0-2          5273   latest/stable/…  mozilla**   -\n\
               brave     1.73.97          466    latest/stable    brave**     -\n";
    let esr = "Name     Version      Rev   Tracking    Publisher  Notes\n\
               firefox  153.8.0esr-1 7001  esr/stable  mozilla**  -\n";
    assert_eq!(snaps(esr), [("firefox".to_string(), "153.8.0".to_string())], "read as --version reads it");
    assert_eq!(
        snaps(out),
        [
            ("chromium".to_string(), "131.0.6778.85".to_string()),
            ("firefox".to_string(), "133.0".to_string()),
            ("brave".to_string(), "1.73.97".to_string())
        ]
    );
    assert!(snaps("").is_empty());
    assert!(snaps("error: no snaps found\n").is_empty());
}

#[test]
fn flatpak_list_names_the_browser_apps() {
    let out = "Application ID\tVersion\n\
               org.mozilla.firefox\t133.0\n\
               com.google.Chrome\t131.0.6778.85-1\n\
               org.chromium.Chromium\t\n\
               org.gnome.Calculator\t46.1\n";
    assert_eq!(
        flatpaks(out),
        [
            ("org.mozilla.firefox".to_string(), "133.0".to_string()),
            ("com.google.Chrome".to_string(), "131.0.6778.85".to_string())
        ]
    );
    assert!(flatpaks("").is_empty());
}

#[test]
fn where_a_binary_came_from_and_how_it_updates() {
    for p in [
        "/usr/lib/firefox/firefox",
        "/opt/google/chrome/chrome",
        "/opt/microsoft/msedge/msedge",
        "/opt/brave.com/brave/brave",
    ] {
        assert_eq!(install_of(Path::new(p)), "package", "{p}");
    }
    for p in ["/usr/local/bin/firefox", "/opt/firefox/firefox", "/home/user/.local/bin/chromium"] {
        assert_eq!(install_of(Path::new(p)), "vendor", "{p}");
    }
    let debian = parse_os_release("ID=debian\n");
    assert_eq!(
        fix("package", "Google Chrome", "google-chrome-stable", &debian),
        "sudo apt-get update && sudo apt-get install --only-upgrade google-chrome-stable"
    );
    assert_eq!(fix("package", "Firefox", "firefox", &parse_os_release("ID=arch\n")), "sudo pacman -Syu");
    assert_eq!(fix("vendor", "Firefox", "firefox", &debian), "Update Firefox from its vendor (or its own updater)");
}

#[test]
fn nothing_installed_is_nothing() {
    let d = crate::utils::temp::TempDir::new("nobrowsers").unwrap();
    assert!(found(&[d.path().to_path_buf()], &testing::machine(&[]), &BTreeMap::new()).is_empty());
    if !LINUX {
        assert!(browsers().is_empty());
    }
}

#[cfg(unix)]
fn exe(p: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    testing::write(p, body);
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn binaries_snaps_and_flatpaks_become_browser_components() {
    let d = crate::utils::temp::TempDir::new("browsers").unwrap();
    let bin = d.path().join("bin");
    let other = d.path().join("other");
    exe(&bin.join("google-chrome-stable"), "#!/bin/sh\nexec /opt/google/chrome/chrome \"$@\"\n");
    // The same Chrome under its other name is read once.
    std::os::unix::fs::symlink(bin.join("google-chrome-stable"), bin.join("google-chrome")).unwrap();
    // Ubuntu's shim starts the snap: the snap list says its version.
    exe(&bin.join("chromium-browser"), "#!/bin/sh\nexec /snap/bin/chromium \"$@\"\n");
    // A snap's command is snapd's own binary.
    exe(&other.join("snap"), "\x7fELF");
    std::os::unix::fs::symlink(other.join("snap"), bin.join("firefox")).unwrap();
    exe(&other.join("firefox-esr"), "\x7fELF");
    // Not executable: not a browser.
    testing::write(&bin.join("brave-browser"), "#!/bin/sh\n");
    // Prints nothing parseable: skipped.
    exe(&bin.join("microsoft-edge"), "#!/bin/sh\n");
    let run = testing::machine(&[
        ("google-chrome-stable --version", "Google Chrome 131.0.6778.85 \n"),
        ("google-chrome --version", "Google Chrome 131.0.6778.85 \n"),
        ("firefox-esr --version", "Mozilla Firefox 128.5.0esr\n"),
        ("microsoft-edge --version", "\n"),
        // The shims would answer; they are skipped before being asked.
        ("chromium-browser --version", "Chromium 131.0.6778.85 snap\n"),
        ("bin/firefox --version", "Mozilla Firefox 133.0\n"),
        (
            "snap list",
            "Name Version Rev Tracking Publisher Notes\nchromium 131.0.6778.85 2999 latest/stable canonical** -\n",
        ),
        ("flatpak list", "org.mozilla.firefox\t133.0\n"),
    ]);
    let got = found(&[bin.clone(), other.clone()], &run, &parse_os_release("ID=ubuntu\n"));
    let rows: Vec<(&str, &str, &str, &str, &str)> = got
        .iter()
        .map(|c| {
            (
                c.name.as_str(),
                c.version.as_str(),
                c.extra["browser"].as_str(),
                c.extra["install"].as_str(),
                c.fix.as_str(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "Google Chrome",
                "131.0.6778.85",
                "chrome",
                "vendor",
                "Update Google Chrome from its vendor (or its own updater)"
            ),
            ("Firefox", "128.5.0", "firefox", "vendor", "Update Firefox from its vendor (or its own updater)"),
            ("Chromium", "131.0.6778.85", "chromium", "snap", "sudo snap refresh chromium"),
            ("Firefox", "133.0", "firefox", "flatpak", "flatpak update org.mozilla.firefox"),
        ]
    );
    assert!(got.iter().all(|c| c.kind == "browser" && !c.auto), "{got:?}");
    assert_eq!(got[0].path, bin.join("google-chrome-stable").display().to_string());
    assert_eq!((got[2].path.as_str(), got[3].path.as_str()), ("/snap/bin/chromium", "flatpak:org.mozilla.firefox"));
}

/// A binary the OS package manager owns is the distro's build; a vendor's
/// package under /opt and a copy in /usr/local or a home directory are not.
/// Fedora's `chromium-browser` comes from the `chromium` package.
#[test]
fn distro_builds_are_told_from_vendor_packages() {
    let vouches = crate::utils::os::os_vouches();
    for p in [
        "/usr/lib/chromium/chromium",
        "/usr/lib64/chromium-browser/chromium-browser",
        "/usr/lib/firefox-esr/firefox-esr",
        "/usr/lib64/firefox/firefox",
    ] {
        assert_eq!(distro_built(Path::new(p)), vouches, "{p}");
    }
    for p in ["/opt/google/chrome/chrome", "/opt/microsoft/msedge/msedge", "/usr/local/bin/firefox", "/home/u/chrome"] {
        assert!(!distro_built(Path::new(p)), "{p}");
    }
    let package = |bin: &str| BINARIES.iter().find(|(b, _, _)| *b == bin).map(|(_, _, p)| *p);
    assert_eq!((package("chromium-browser"), package("chromium")), (Some("chromium"), Some("chromium")));
    assert!(fix("package", "Chromium", "chromium", &parse_os_release("ID=fedora\n")).ends_with(" upgrade chromium"));
}
