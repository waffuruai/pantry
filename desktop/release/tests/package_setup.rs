//! The desktop bundle, Setup's payload and Setup's downloads.

use wpantry_release::archive::{gunzip, read_zip};
use wpantry_release::{desktop_version, package, setup};

const DESKTOP_MANIFEST: &str = include_str!("../../Cargo.toml");

fn names(zip: &[u8]) -> Vec<(String, u32)> {
    read_zip(zip)
        .unwrap()
        .into_iter()
        .map(|m| (m.name, (m.external_attr >> 16) & 0o777))
        .collect()
}

#[test]
fn version_is_the_desktop_apps() {
    let version = desktop_version().unwrap();
    assert!(DESKTOP_MANIFEST.contains(&format!("version = \"{version}\"")));
}

#[test]
fn macos_bundle_is_pantry_app() {
    let zip = package::package("universal-apple-darwin", b"APP", b"SCAN", b"NOTICES").unwrap();
    let want: Vec<(String, u32)> = [
        ("FONT-LICENSE-GEIST.txt", 0o644),
        ("LICENSE.txt", 0o644),
        ("PANTRY-DESKTOP-NOTICES.txt", 0o644),
        ("PANTRY-SCANNER-NOTICES.txt", 0o644),
        ("Pantry.app/Contents/Info.plist", 0o644),
        ("Pantry.app/Contents/MacOS/Pantry", 0o755),
        ("Pantry.app/Contents/MacOS/wpantry", 0o755),
        ("Pantry.app/Contents/Resources/Pantry.icns", 0o644),
    ]
    .iter()
    .map(|(n, m)| (n.to_string(), *m))
    .collect();
    assert_eq!(names(&zip), want);
    let members = read_zip(&zip).unwrap();
    let body = |name: &str| {
        members
            .iter()
            .find(|m| m.name == name)
            .unwrap()
            .body
            .clone()
    };
    assert_eq!(body("Pantry.app/Contents/MacOS/Pantry"), b"APP");
    assert_eq!(body("Pantry.app/Contents/MacOS/wpantry"), b"SCAN");
    assert_eq!(body("PANTRY-DESKTOP-NOTICES.txt"), b"NOTICES");
    assert_eq!(body("LICENSE.txt"), package::LICENSE);
    assert_eq!(
        body("Pantry.app/Contents/Resources/Pantry.icns"),
        package::ICON
    );
}

#[test]
fn info_plist_is_what_plistlib_writes() {
    let zip = package::package("universal-apple-darwin", b"", b"", b"").unwrap();
    let members = read_zip(&zip).unwrap();
    let plist = &members
        .iter()
        .find(|m| m.name.ends_with("Info.plist"))
        .unwrap()
        .body;
    // Python 3's plistlib.dumps() of the same dict, keys sorted.
    let version = desktop_version().unwrap();
    let want = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>Pantry</string>
	<key>CFBundleExecutable</key>
	<string>Pantry</string>
	<key>CFBundleIconFile</key>
	<string>Pantry.icns</string>
	<key>CFBundleIdentifier</key>
	<string>ai.waffuru.pantry.desktop</string>
	<key>CFBundleName</key>
	<string>Pantry</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>{version}</string>
	<key>CFBundleVersion</key>
	<string>{version}</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
"#
    );
    assert_eq!(String::from_utf8_lossy(plist), want);
}

#[test]
fn plist_escapes_markup() {
    let out = package::plist(&[("k", package::Value::Str("a<b&c>"))]);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("<string>a&lt;b&amp;c&gt;</string>")
    );
}

#[test]
fn linux_and_windows_bundles_are_flat() {
    let linux = package::package("x86_64-unknown-linux-gnu", b"A", b"S", b"N").unwrap();
    let flat: Vec<String> = names(&linux).into_iter().map(|(n, _)| n).collect();
    assert_eq!(flat[4..], ["wpantry", "wpantry-desktop"]);
    let windows = package::package("x86_64-pc-windows-msvc", b"A", b"S", b"N").unwrap();
    let got = names(&windows);
    assert!(got.contains(&("wpantry-desktop.exe".to_string(), 0o755)));
    assert!(got.contains(&("wpantry.exe".to_string(), 0o755)));
}

#[test]
fn bundles_are_the_same_bytes_every_run() {
    for target in [
        "universal-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        let one = package::package(target, b"APP", b"SCAN", b"N").unwrap();
        let two = package::package(target, b"APP", b"SCAN", b"N").unwrap();
        assert_eq!(one, two, "{target}");
        let data = setup::payload(&one).unwrap();
        assert_eq!(data, setup::payload(&two).unwrap(), "{target} payload");
        assert_eq!(
            setup::bundle(target, b"SETUP", &data).unwrap(),
            setup::bundle(target, b"SETUP", &data).unwrap()
        );
    }
}

#[test]
fn payload_is_one_record_per_member_in_zip_order() {
    let zip = package::package("x86_64-unknown-linux-gnu", b"APP", b"SCAN", b"N").unwrap();
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&setup::payload(&zip).unwrap()).unwrap();
    let mut at = 0;
    let mut got = Vec::new();
    while at < raw.len() {
        let path_len = u16::from_le_bytes([raw[at], raw[at + 1]]) as usize;
        let body_len = u32::from_le_bytes(raw[at + 2..at + 6].try_into().unwrap()) as usize;
        let exec = raw[at + 6];
        let path = String::from_utf8(raw[at + 7..at + 7 + path_len].to_vec()).unwrap();
        let body = &raw[at + 7 + path_len..at + 7 + path_len + body_len];
        got.push((path, exec, body.to_vec()));
        at += 7 + path_len + body_len;
    }
    assert_eq!(got.len(), 6);
    assert_eq!(got[4], ("wpantry".to_string(), 1, b"SCAN".to_vec()));
    assert_eq!(got[5], ("wpantry-desktop".to_string(), 1, b"APP".to_vec()));
    assert_eq!(got[1].0, "LICENSE.txt");
    assert_eq!(got[1].1, 0);
}

#[test]
fn windows_setup_download_is_the_exe_itself() {
    assert_eq!(
        setup::bundle("x86_64-pc-windows-msvc", b"MZ setup", b"").unwrap(),
        b"MZ setup"
    );
    assert!(!setup::needs_payload("x86_64-pc-windows-msvc"));
    assert!(setup::needs_payload("universal-apple-darwin"));
}

#[test]
fn macos_setup_download_is_pantry_setup_app() {
    let zip = setup::bundle("universal-apple-darwin", b"SETUP", b"DATA").unwrap();
    let got = names(&zip);
    assert_eq!(
        got,
        [
            ("Pantry Setup.app/Contents/Info.plist".to_string(), 0o644),
            (
                "Pantry Setup.app/Contents/MacOS/Pantry Setup".to_string(),
                0o755
            ),
            (
                "Pantry Setup.app/Contents/Resources/Pantry.icns".to_string(),
                0o644
            ),
            (
                "Pantry Setup.app/Contents/Resources/pantry-setup.zlib".to_string(),
                0o644
            ),
        ]
    );
    let members = read_zip(&zip).unwrap();
    let plist = String::from_utf8(members[0].body.clone()).unwrap();
    assert!(plist.contains("<key>LSUIElement</key>\n\t<true/>"));
    assert!(plist.contains("<string>ai.waffuru.pantry.setup</string>"));
    assert_eq!(members[3].body, b"DATA");
}

#[test]
fn linux_setup_download_has_a_launcher() {
    let tar = gunzip(&setup::bundle("x86_64-unknown-linux-gnu", b"ELF", b"DATA").unwrap()).unwrap();
    // Sorted: "Pantry Setup", "README.txt", "pantry-setup.desktop".
    assert_eq!(&tar[..12], b"Pantry Setup");
    assert_eq!(&tar[512..515], b"ELF");
    assert_eq!(&tar[1024..1034], b"README.txt");
    let launcher_at = 1024 + 512 + setup::LINUX_README.len().div_ceil(512) * 512;
    assert_eq!(&tar[launcher_at..launcher_at + 20], b"pantry-setup.desktop");
    assert_eq!(&tar[launcher_at + 100..launcher_at + 108], b"0000755\0");
    assert!(
        setup::LINUX_LAUNCHER
            .contains(r#"Exec=sh -c "exec \\"\\$(dirname \\"\\$0\\")/Pantry Setup\\"" %k"#)
    );
}
