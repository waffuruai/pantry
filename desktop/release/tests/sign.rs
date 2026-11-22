//! Signing, driven through a recording stand-in for codesign, xcrun and
//! signtool: no real tool, keychain or certificate is ever touched. The
//! argv sequences are the ones the Python signer issued for the same input.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use wpantry_release::archive::read_zip;
use wpantry_release::temp::TempDir;
use wpantry_release::{json, package, setup, sign};

/// Records every call, with the temp directory shown as TMP. On a bundle
/// signature it writes `_CodeSignature/CodeResources` the way codesign
/// would; `output` answers with queued replies.
#[derive(Default)]
struct Recorder {
    calls: Vec<String>,
    replies: VecDeque<String>,
}

fn shown(argv: &[OsString]) -> String {
    argv.iter()
        .map(|a| {
            let a = a.to_string_lossy();
            match a.find("pantry-sign-") {
                Some(at) => {
                    let rest = &a[at..];
                    let tail = rest.find(['/', '\\']).map_or("", |i| &rest[i..]);
                    format!("TMP{}", tail.replace('\\', "/"))
                }
                None => a.into_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl sign::Runner for Recorder {
    fn run(&mut self, argv: &[OsString]) -> Result<(), String> {
        self.calls.push(shown(argv));
        let last = Path::new(argv.last().unwrap());
        if argv[1] == "--force" && last.extension().is_some_and(|e| e == "app") {
            let dir = last.join("Contents/_CodeSignature");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("CodeResources"), b"sig").unwrap();
        }
        if argv.len() > 2 && argv[1] == "stapler" && argv[2] == "staple" {
            std::fs::write(last.join("Contents/CodeResources"), b"ticket").unwrap();
        }
        Ok(())
    }

    fn output(&mut self, argv: &[OsString]) -> Result<String, String> {
        self.calls.push(shown(argv));
        Ok(self.replies.pop_front().unwrap_or_default())
    }
}

fn desktop_zip(dir: &Path) -> PathBuf {
    let path = dir.join("desktop.zip");
    std::fs::write(
        &path,
        package::package("universal-apple-darwin", b"APP", b"SCAN", b"N").unwrap(),
    )
    .unwrap();
    path
}

fn setup_zip(dir: &Path) -> PathBuf {
    let path = dir.join("setup.zip");
    std::fs::write(
        &path,
        setup::bundle("universal-apple-darwin", b"SETUP", b"DATA").unwrap(),
    )
    .unwrap();
    path
}

fn modes(zip: &Path) -> Vec<(String, u32)> {
    read_zip(&std::fs::read(zip).unwrap())
        .unwrap()
        .into_iter()
        .map(|m| (m.name, (m.external_attr >> 16) & 0o777))
        .collect()
}

#[test]
fn ad_hoc_signs_nested_executables_then_the_bundle() {
    let work = TempDir::new("release-test-").unwrap();
    let zip = desktop_zip(work.path());
    let mut r = Recorder::default();
    sign::macos(&mut r, &zip, "-", None, None).unwrap();
    assert_eq!(
        r.calls,
        [
            "codesign --force --sign - --identifier ai.waffuru.pantry.scanner --options runtime TMP/Pantry.app/Contents/MacOS/wpantry",
            "codesign --force --sign - --identifier ai.waffuru.pantry.desktop --options runtime TMP/Pantry.app",
            "codesign --verify --deep --strict TMP/Pantry.app",
        ]
    );
    let got = modes(&zip);
    // The signature is new, plain data; the executables keep 0755.
    assert!(got.contains(&(
        "Pantry.app/Contents/_CodeSignature/CodeResources".to_string(),
        0o644
    )));
    assert!(got.contains(&("Pantry.app/Contents/MacOS/Pantry".to_string(), 0o755)));
    assert!(got.contains(&("Pantry.app/Contents/MacOS/wpantry".to_string(), 0o755)));
    assert_eq!(got.len(), 9);
}

#[test]
fn ad_hoc_signing_is_deterministic() {
    let work = TempDir::new("release-test-").unwrap();
    let one = desktop_zip(work.path());
    let two = work.path().join("two.zip");
    std::fs::copy(&one, &two).unwrap();
    sign::macos(&mut Recorder::default(), &one, "-", None, None).unwrap();
    sign::macos(&mut Recorder::default(), &two, "-", None, None).unwrap();
    assert_eq!(std::fs::read(&one).unwrap(), std::fs::read(&two).unwrap());
}

#[test]
fn developer_id_signs_with_a_timestamp_then_notarizes_and_staples() {
    let work = TempDir::new("release-test-").unwrap();
    let zip = setup_zip(work.path());
    let mut r = Recorder::default();
    r.replies
        .push_back(r#"{"id": "req-1", "message": "ok", "status": "Accepted"}"#.to_string());
    sign::macos(
        &mut r,
        &zip,
        "DevID-Hash",
        Some("/fake/kc.keychain-db"),
        Some("pantry-notary"),
    )
    .unwrap();
    let submit = format!(
        "xcrun notarytool submit {} --keychain-profile pantry-notary --wait --output-format json --keychain /fake/kc.keychain-db",
        zip.display()
    );
    assert_eq!(
        r.calls,
        [
            "codesign --force --sign DevID-Hash --identifier ai.waffuru.pantry.setup --options runtime --timestamp --keychain /fake/kc.keychain-db TMP/Pantry Setup.app",
            "codesign --verify --deep --strict TMP/Pantry Setup.app",
            submit.as_str(),
            "xcrun stapler staple TMP/Pantry Setup.app",
            "xcrun stapler validate TMP/Pantry Setup.app",
        ]
    );
    // The stapled ticket is in the rewritten ZIP.
    assert!(modes(&zip).contains(&("Pantry Setup.app/Contents/CodeResources".to_string(), 0o644)));
}

#[test]
fn a_rejected_notarization_names_the_log_command() {
    let work = TempDir::new("release-test-").unwrap();
    let zip = desktop_zip(work.path());
    let mut r = Recorder::default();
    r.replies
        .push_back(r#"{"id":"req-9","status":"Invalid"}"#.to_string());
    let err = sign::macos(&mut r, &zip, "X", None, Some("n")).unwrap_err();
    assert_eq!(
        err,
        "notarization of desktop.zip ended as Invalid: run `xcrun notarytool log req-9` for the reasons"
    );
    assert_eq!(r.calls.len(), 4, "no stapling after a rejection");
}

#[test]
fn unknown_or_missing_bundles_are_refused() {
    let work = TempDir::new("release-test-").unwrap();
    let mut e = wpantry_release::archive::Entries::new();
    e.insert(
        "Other.app/Contents/MacOS/Other".into(),
        (0o755, b"x".to_vec()),
    );
    let other = work.path().join("other.zip");
    std::fs::write(&other, wpantry_release::archive::write_zip(&e).unwrap()).unwrap();
    let err = sign::macos(&mut Recorder::default(), &other, "-", None, None).unwrap_err();
    assert!(err.ends_with("no identifier for Other.app"), "{err}");

    let plain = work.path().join("plain.zip");
    std::fs::write(
        &plain,
        package::package("x86_64-unknown-linux-gnu", b"A", b"S", b"N").unwrap(),
    )
    .unwrap();
    let err = sign::macos(&mut Recorder::default(), &plain, "-", None, None).unwrap_err();
    assert!(err.ends_with("no .app bundle to sign"), "{err}");
}

#[test]
fn paths_that_leave_the_extraction_root_are_refused() {
    let work = TempDir::new("release-test-").unwrap();
    for bad in ["../escape.app/x", "/abs/x", "a/../../x", "a\\..\\x", "C:/x"] {
        let mut e = wpantry_release::archive::Entries::new();
        e.insert(bad.into(), (0o644, b"x".to_vec()));
        let zip = work.path().join("bad.zip");
        std::fs::write(&zip, wpantry_release::archive::write_zip(&e).unwrap()).unwrap();
        let err = sign::macos(&mut Recorder::default(), &zip, "-", None, None).unwrap_err();
        assert!(err.contains("unsafe path"), "{bad}: {err}");
    }
    assert!(!work.path().parent().unwrap().join("escape.app").exists());
}

#[test]
fn windows_signs_an_exe_in_place() {
    let work = TempDir::new("release-test-").unwrap();
    let exe = work.path().join("Setup.EXE");
    std::fs::write(&exe, b"MZ").unwrap();
    let mut r = Recorder::default();
    let tool = || Ok(PathBuf::from("signtool"));
    sign::windows(&mut r, &exe, "ABCDEF0123", sign::TIMESTAMP_URL, &tool).unwrap();
    let p = exe.display();
    assert_eq!(
        r.calls,
        [
            format!(
                "signtool sign /sha1 ABCDEF0123 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 {p}"
            ),
            format!("signtool verify /pa {p}"),
        ]
    );
}

#[test]
fn windows_signs_every_exe_in_a_zip_in_one_call() {
    let work = TempDir::new("release-test-").unwrap();
    let zip = work.path().join("desktop.zip");
    let before = package::package("x86_64-pc-windows-msvc", b"MZ app", b"MZ scan", b"N").unwrap();
    std::fs::write(&zip, &before).unwrap();
    let mut r = Recorder::default();
    let tool = || Ok(PathBuf::from("signtool"));
    sign::windows(&mut r, &zip, "ABCDEF0123", "http://ts.example", &tool).unwrap();
    assert_eq!(
        r.calls,
        [
            "signtool sign /sha1 ABCDEF0123 /fd SHA256 /tr http://ts.example /td SHA256 TMP/wpantry-desktop.exe TMP/wpantry.exe",
            "signtool verify /pa TMP/wpantry-desktop.exe TMP/wpantry.exe",
        ]
    );
    // The stand-in changed nothing, so the rewritten ZIP is the same bytes.
    assert_eq!(std::fs::read(&zip).unwrap(), before);
}

#[test]
fn windows_zip_without_an_exe_is_refused_before_looking_for_signtool() {
    let work = TempDir::new("release-test-").unwrap();
    let zip = work.path().join("linux.zip");
    std::fs::write(
        &zip,
        package::package("x86_64-unknown-linux-gnu", b"A", b"S", b"N").unwrap(),
    )
    .unwrap();
    let tool = || -> Result<PathBuf, String> { panic!("signtool looked up with nothing to sign") };
    let err = sign::windows(&mut Recorder::default(), &zip, "T", "u", &tool).unwrap_err();
    assert!(err.ends_with("no .exe to sign"), "{err}");
}

#[test]
fn signtool_is_the_newest_sdk_x64_build() {
    let kits = TempDir::new("release-test-").unwrap();
    for version in ["10.0.19041.0", "10.0.22621.0", "10.0.26100.0", "8.1"] {
        let dir = kits.path().join(version).join("x64");
        std::fs::create_dir_all(&dir).unwrap();
        if version != "10.0.26100.0" {
            std::fs::write(dir.join("signtool.exe"), b"").unwrap();
        }
    }
    let found = sign::find_signtool(kits.path()).unwrap();
    assert_eq!(
        found,
        kits.path()
            .join("10.0.22621.0")
            .join("x64")
            .join("signtool.exe")
    );
    let empty = TempDir::new("release-test-").unwrap();
    assert_eq!(
        sign::find_signtool(empty.path()).unwrap_err(),
        "signtool.exe not found in the Windows SDK"
    );
}

#[test]
fn notarytool_json_is_read_strictly() {
    let fields = json::top_level_strings(
        r#" {"id": "a\"b\u00e9", "status": "Accepted", "n": 3.5e2, "nested": {"status": "x", "l": [1, true, null]}} "#,
    )
    .unwrap();
    assert_eq!(fields["status"], "Accepted");
    assert_eq!(fields["id"], "a\"b\u{e9}");
    assert!(!fields.contains_key("nested"));
    assert!(json::top_level_strings("{}").unwrap().is_empty());
    for bad in [
        "",
        "[]",
        "{\"a\":}",
        "{\"a\":1,}",
        "{\"a\":\"b\"} x",
        "{\"a\": nope}",
        "{\"a\":\"\n\"}",
    ] {
        assert!(json::top_level_strings(bad).is_err(), "{bad:?}");
    }
}
