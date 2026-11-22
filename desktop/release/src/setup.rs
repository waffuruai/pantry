//! Pantry Setup's compressed payload and its platform download.
//!
//! ```text
//! wpantry-release setup payload wpantry-desktop-<target>.zip setup-payload.zlib
//! wpantry-release setup bundle <target> <setup binary> setup-payload.zlib <out>
//! ```
//!
//! The payload is zlib over one record per ZIP member, in the ZIP's order:
//! u16 path length, u32 body length, u8 executable (little endian), then
//! the path and the body. desktop/src/bin/wpantry-setup.rs reads it.

use crate::archive::{Entries, read_zip, write_tar_gz, write_zip};
use crate::package::{ICON, MACOS, Value, is_windows, plist};

/// The zlib payload Setup unpacks, from the desktop bundle ZIP.
pub fn payload(zip: &[u8]) -> Result<Vec<u8>, String> {
    let mut records = Vec::new();
    for member in read_zip(zip)? {
        let path = member.name.as_bytes();
        let path_len =
            u16::try_from(path.len()).map_err(|_| format!("{}: path too long", member.name))?;
        let body_len = u32::try_from(member.body.len())
            .map_err(|_| format!("{}: file too large", member.name))?;
        let executable = (member.external_attr >> 16) & 0o111 != 0;
        records.extend_from_slice(&path_len.to_le_bytes());
        records.extend_from_slice(&body_len.to_le_bytes());
        records.push(u8::from(executable));
        records.extend_from_slice(path);
        records.extend_from_slice(&member.body);
    }
    Ok(miniz_oxide::deflate::compress_to_vec_zlib(&records, 9))
}

/// Double-clicking a bare ELF does nothing in most Linux file managers, so
/// the download carries a desktop entry that runs Setup from the folder it
/// sits in. %k is the entry's own path; field codes may not appear inside
/// quotes, so it reaches sh as $0. After the string-value escapes (\\ to \)
/// the Exec rules give sh the script: exec "$(dirname "$0")/Pantry Setup"
pub const LINUX_LAUNCHER: &str = r#"[Desktop Entry]
Type=Application
Version=1.0
Name=Pantry Setup
Comment=Install or update Pantry for this account
Exec=sh -c "exec \\"\\$(dirname \\"\\$0\\")/Pantry Setup\\"" %k
Icon=system-software-install
Terminal=false
Categories=Utility;
"#;

pub const LINUX_README: &str = r#"Pantry Setup installs Pantry for this account and adds it to the app menu.

Open "pantry-setup.desktop" (GNOME Files: right-click, Allow Launching, then
open it), or run Setup from a terminal in this folder:

    ./"Pantry Setup"

If the files lost their permissions while extracting, run this first:

    chmod +x "Pantry Setup" pantry-setup.desktop

To remove Pantry later: ./"Pantry Setup" --uninstall
"#;

/// Whether `bundle` reads the payload for this target (Windows Setup has it
/// compiled in, so its download is the executable alone).
pub fn needs_payload(target: &str) -> bool {
    !is_windows(target)
}

/// The Setup download for `target`: the .exe itself on Windows, a
/// `Pantry Setup.app` ZIP on macOS, a .tar.gz with a launcher on Linux.
pub fn bundle(target: &str, setup: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if is_windows(target) {
        return Ok(setup.to_vec());
    }
    let mut entries = Entries::new();
    if target == MACOS {
        let version = crate::desktop_version()?;
        let info = plist(&[
            ("CFBundleDisplayName", Value::Str("Pantry Setup")),
            ("CFBundleExecutable", Value::Str("Pantry Setup")),
            ("CFBundleIdentifier", Value::Str("ai.waffuru.pantry.setup")),
            ("CFBundleIconFile", Value::Str("Pantry.icns")),
            ("CFBundleName", Value::Str("Pantry Setup")),
            ("CFBundlePackageType", Value::Str("APPL")),
            ("CFBundleShortVersionString", Value::Str(&version)),
            ("CFBundleVersion", Value::Str(&version)),
            // Agent app: Setup installs and hands off to Pantry.app, so it
            // never takes a Dock slot. osascript error alerts still show.
            ("LSUIElement", Value::Bool(true)),
        ]);
        entries.insert("Pantry Setup.app/Contents/Info.plist".into(), (0o644, info));
        entries.insert(
            "Pantry Setup.app/Contents/MacOS/Pantry Setup".into(),
            (0o755, setup.to_vec()),
        );
        entries.insert(
            "Pantry Setup.app/Contents/Resources/Pantry.icns".into(),
            (0o644, ICON.to_vec()),
        );
        entries.insert(
            "Pantry Setup.app/Contents/Resources/pantry-setup.zlib".into(),
            (0o644, data.to_vec()),
        );
        write_zip(&entries)
    } else {
        entries.insert("Pantry Setup".into(), (0o755, setup.to_vec()));
        entries.insert(
            "pantry-setup.desktop".into(),
            (0o755, LINUX_LAUNCHER.as_bytes().to_vec()),
        );
        entries.insert(
            "README.txt".into(),
            (0o644, LINUX_README.as_bytes().to_vec()),
        );
        write_tar_gz(&entries)
    }
}
