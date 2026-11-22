//! The portable desktop bundle: the scanner beside its desktop app, with the
//! licences, as one ZIP per platform.
//!
//! ```text
//! wpantry-release package universal-apple-darwin Pantry wpantry notices.txt out.zip
//! ```
//!
//! macOS gets `Pantry.app` with both executables under Contents/MacOS;
//! Linux and Windows get the two executables at the top of the ZIP.

use crate::archive::{Entries, write_zip};

pub const LICENSE: &[u8] = include_bytes!("../../LICENSE");
pub const SCANNER_NOTICES: &[u8] =
    include_bytes!("../../../rust/crates/wpantry-cli/THIRD-PARTY-NOTICES.txt");
pub const FONT_LICENSE: &[u8] = include_bytes!("../../fonts/LICENSE-Geist-OFL.txt");
pub const ICON: &[u8] = include_bytes!("../../assets/Pantry.icns");

/// A value in an Info.plist: the two kinds the bundles use.
pub enum Value<'a> {
    Str(&'a str),
    Bool(bool),
}

/// An XML property list of one dict, keys sorted, as Python's
/// `plistlib.dumps` writes it.
pub fn plist(items: &[(&str, Value)]) -> Vec<u8> {
    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
    let mut sorted: Vec<&(&str, Value)> = items.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    let mut out = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
        "<plist version=\"1.0\">\n<dict>\n",
    ));
    for (key, value) in sorted {
        out.push_str(&format!("\t<key>{}</key>\n", escape(key)));
        match value {
            Value::Str(s) => out.push_str(&format!("\t<string>{}</string>\n", escape(s))),
            Value::Bool(true) => out.push_str("\t<true/>\n"),
            Value::Bool(false) => out.push_str("\t<false/>\n"),
        }
    }
    out.push_str("</dict>\n</plist>\n");
    out.into_bytes()
}

pub fn is_windows(target: &str) -> bool {
    target.ends_with("-windows-msvc")
}

pub const MACOS: &str = "universal-apple-darwin";

/// The bundle's entries for `target` (a Rust triple, or
/// universal-apple-darwin).
pub fn entries(
    target: &str,
    app: &[u8],
    scanner: &[u8],
    notices: &[u8],
) -> Result<Entries, String> {
    let ext = if is_windows(target) { ".exe" } else { "" };
    let mut entries = Entries::new();
    let mut add = |name: &str, mode: u32, body: &[u8]| {
        entries.insert(name.to_string(), (mode, body.to_vec()));
    };
    add("LICENSE.txt", 0o644, LICENSE);
    add("PANTRY-SCANNER-NOTICES.txt", 0o644, SCANNER_NOTICES);
    add("PANTRY-DESKTOP-NOTICES.txt", 0o644, notices);
    add("FONT-LICENSE-GEIST.txt", 0o644, FONT_LICENSE);
    if target == MACOS {
        let version = crate::desktop_version()?;
        let info = plist(&[
            ("CFBundleDevelopmentRegion", Value::Str("en")),
            ("CFBundleDisplayName", Value::Str("Pantry")),
            ("CFBundleExecutable", Value::Str("Pantry")),
            (
                "CFBundleIdentifier",
                Value::Str("ai.waffuru.pantry.desktop"),
            ),
            ("CFBundleIconFile", Value::Str("Pantry.icns")),
            ("CFBundleName", Value::Str("Pantry")),
            ("CFBundlePackageType", Value::Str("APPL")),
            ("CFBundleShortVersionString", Value::Str(&version)),
            ("CFBundleVersion", Value::Str(&version)),
            ("NSHighResolutionCapable", Value::Bool(true)),
        ]);
        add("Pantry.app/Contents/Resources/Pantry.icns", 0o644, ICON);
        add("Pantry.app/Contents/Info.plist", 0o644, &info);
        add("Pantry.app/Contents/MacOS/Pantry", 0o755, app);
        add("Pantry.app/Contents/MacOS/wpantry", 0o755, scanner);
    } else {
        add(&format!("wpantry-desktop{ext}"), 0o755, app);
        add(&format!("wpantry{ext}"), 0o755, scanner);
    }
    Ok(entries)
}

/// The bundle ZIP's bytes.
pub fn package(
    target: &str,
    app: &[u8],
    scanner: &[u8],
    notices: &[u8],
) -> Result<Vec<u8>, String> {
    write_zip(&entries(target, app, scanner, notices)?)
}
