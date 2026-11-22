//! Sign the app bundles inside a Pantry release ZIP, or a Windows .exe.
//!
//! ```text
//! wpantry-release sign macos ZIP [--identity NAME --keychain PATH] [--notary-profile NAME]
//! wpantry-release sign windows FILE --thumbprint SHA1 [--timestamp-url URL]
//! ```
//!
//! macOS: every Mach-O under Contents/MacOS is signed first, then the bundle,
//! each with a fixed identifier and the hardened runtime, so Info.plist is
//! bound to the signature and the identity stays the same from version to
//! version. The default identity "-" is an ad-hoc signature: no certificate,
//! no timestamp, and the same bytes for the same input. With a Developer ID
//! identity the signature carries a secure timestamp, so two runs differ;
//! with --notary-profile the ZIP is notarized and the ticket stapled to each
//! app.
//!
//! Windows: Authenticode with a certificate already in the user's store,
//! selected by thumbprint. For a ZIP, every .exe inside is signed.
//!
//! The ZIP is rewritten in place with the same deterministic layout as
//! `package` (sorted names, fixed modes, no timestamps).
//!
//! The tools run through a [`Runner`], so tests drive every path with a
//! recording stand-in and never reach codesign, a keychain or a certificate.

use crate::archive::{Entries, read_zip, write_zip};
use crate::temp::TempDir;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

/// Runs the signing tools. `argv[0]` is the program.
pub trait Runner {
    /// Run to completion; a non-zero exit is an error.
    fn run(&mut self, argv: &[OsString]) -> Result<(), String>;
    /// Run to completion and return its stdout; a non-zero exit is an error.
    fn output(&mut self, argv: &[OsString]) -> Result<String, String>;
}

/// The real tools, found on PATH (or by absolute path).
pub struct System;

fn shown(argv: &[OsString]) -> String {
    argv.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

impl Runner for System {
    fn run(&mut self, argv: &[OsString]) -> Result<(), String> {
        let status = Command::new(&argv[0])
            .args(&argv[1..])
            .status()
            .map_err(|e| format!("{}: {e}", argv[0].to_string_lossy()))?;
        if !status.success() {
            return Err(format!("command failed ({status}): {}", shown(argv)));
        }
        Ok(())
    }

    fn output(&mut self, argv: &[OsString]) -> Result<String, String> {
        let out = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| format!("{}: {e}", argv[0].to_string_lossy()))?;
        if !out.status.success() {
            return Err(format!("command failed ({}): {}", out.status, shown(argv)));
        }
        String::from_utf8(out.stdout).map_err(|_| format!("{}: output is not UTF-8", shown(argv)))
    }
}

/// Bundle name to (bundle identifier, identifier for nested executables).
fn identifiers(app: &str) -> Option<(&'static str, Option<&'static str>)> {
    match app {
        "Pantry.app" => Some((
            "ai.waffuru.pantry.desktop",
            Some("ai.waffuru.pantry.scanner"),
        )),
        "Pantry Setup.app" => Some(("ai.waffuru.pantry.setup", None)),
        _ => None,
    }
}

/// A member name that stays inside the extraction root: relative, `/`
/// separated, no empty, `.` or `..` parts, no backslashes or drive letters.
/// zipfile would also accept some names this refuses (`a/../b`); Pantry's
/// own archives never carry them.
fn safe(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains(':')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(name)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Unpack a ZIP into `root`; returns name to Unix mode for every file.
pub fn extract(archive: &Path, root: &Path) -> Result<BTreeMap<String, u32>, String> {
    let mut modes = BTreeMap::new();
    for member in
        read_zip(&crate::read(archive)?).map_err(|e| format!("{}: {e}", archive.display()))?
    {
        if member.is_dir() {
            continue;
        }
        if !safe(&member.name) {
            return Err(format!(
                "{}: unsafe path {:?}",
                archive.display(),
                member.name
            ));
        }
        let target = root.join(&member.name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        crate::write(&target, &member.body)?;
        let mode = match (member.external_attr >> 16) & 0o777 {
            0 => 0o644,
            m => m,
        };
        set_mode(&target, mode)?;
        modes.insert(member.name, mode);
    }
    Ok(modes)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    // Windows keeps no Unix modes; the ZIP carries them from `modes`.
    Ok(())
}

/// Every file under `dir`, recursively.
fn files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// `path` relative to `root`, `/` separated.
fn member_name(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| format!("{} is outside {}", path.display(), root.display()))?;
    let parts: Option<Vec<&str>> = rel.components().map(|c| c.as_os_str().to_str()).collect();
    parts
        .map(|p| p.join("/"))
        .ok_or_else(|| format!("{}: name is not UTF-8", path.display()))
}

/// Zip `root` back into `archive`. New files (a signature, a stapled
/// ticket) are plain data, 0644.
pub fn rezip(root: &Path, modes: &BTreeMap<String, u32>, archive: &Path) -> Result<(), String> {
    let mut found = Vec::new();
    files(root, &mut found)?;
    let mut entries = Entries::new();
    for path in found {
        let name = member_name(root, &path)?;
        let mode = modes.get(&name).copied().unwrap_or(0o644);
        entries.insert(name, (mode, crate::read(&path)?));
    }
    crate::write(archive, &write_zip(&entries)?)
}

fn os(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

fn codesign(
    runner: &mut dyn Runner,
    path: &Path,
    identifier: &str,
    identity: &str,
    keychain: Option<&str>,
) -> Result<(), String> {
    let mut argv = os(&[
        "codesign",
        "--force",
        "--sign",
        identity,
        "--identifier",
        identifier,
        "--options",
        "runtime",
    ]);
    if identity != "-" {
        argv.push("--timestamp".into());
    }
    if let Some(k) = keychain {
        argv.extend(os(&["--keychain", k]));
    }
    argv.push(path.into());
    runner.run(&argv)
}

fn notarize(
    runner: &mut dyn Runner,
    archive: &Path,
    profile: &str,
    keychain: Option<&str>,
) -> Result<(), String> {
    let mut argv = os(&["xcrun", "notarytool", "submit"]);
    argv.push(archive.into());
    argv.extend(os(&[
        "--keychain-profile",
        profile,
        "--wait",
        "--output-format",
        "json",
    ]));
    if let Some(k) = keychain {
        argv.extend(os(&["--keychain", k]));
    }
    let result = crate::json::top_level_strings(&runner.output(&argv)?)?;
    let status = result.get("status").map(String::as_str);
    if status != Some("Accepted") {
        let name = archive
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let id = result.get("id").map(String::as_str).unwrap_or("None");
        return Err(format!(
            "notarization of {name} ended as {}: run `xcrun notarytool log {id}` for the reasons",
            status.unwrap_or("None")
        ));
    }
    Ok(())
}

/// The entries of `dir`, sorted by name.
fn children(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .map(|e| {
            e.map(|e| e.path())
                .map_err(|e| format!("{}: {e}", dir.display()))
        })
        .collect::<Result<_, _>>()?;
    out.sort();
    Ok(out)
}

/// Sign every .app in a macOS release ZIP and rewrite it in place.
pub fn macos(
    runner: &mut dyn Runner,
    archive: &Path,
    identity: &str,
    keychain: Option<&str>,
    notary_profile: Option<&str>,
) -> Result<(), String> {
    let temp = TempDir::new("pantry-sign-")?;
    let root = temp.path();
    let modes = extract(archive, root)?;
    let apps: Vec<PathBuf> = children(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .collect();
    if apps.is_empty() {
        return Err(format!("{}: no .app bundle to sign", archive.display()));
    }
    for app in &apps {
        let name = app.file_name().unwrap_or_default().to_string_lossy();
        let (bundle_id, nested_id) = identifiers(&name)
            .ok_or_else(|| format!("{}: no identifier for {name}", archive.display()))?;
        let macos_dir = app.join("Contents/MacOS");
        let main = macos_dir.join(app.file_stem().unwrap_or_default());
        // Inside out: nested executables, then the bundle (which signs the
        // main executable and seals Info.plist and Resources).
        for nested in children(&macos_dir)? {
            if nested != main {
                codesign(
                    runner,
                    &nested,
                    nested_id.unwrap_or(bundle_id),
                    identity,
                    keychain,
                )?;
            }
        }
        codesign(runner, app, bundle_id, identity, keychain)?;
        let mut verify = os(&["codesign", "--verify", "--deep", "--strict"]);
        verify.push(app.into());
        runner.run(&verify)?;
    }
    rezip(root, &modes, archive)?;
    if let Some(profile) = notary_profile {
        notarize(runner, archive, profile, keychain)?;
        for app in &apps {
            for step in ["staple", "validate"] {
                let mut argv = os(&["xcrun", "stapler", step]);
                argv.push(app.into());
                runner.run(&argv)?;
            }
        }
        rezip(root, &modes, archive)?;
    }
    Ok(())
}

/// The newest signtool.exe of the Windows 10/11 SDK under `kits_bin`
/// (normally `C:\Program Files (x86)\Windows Kits\10\bin`): the last of
/// `10.*\x64\signtool.exe` in name order.
pub fn find_signtool(kits_bin: &Path) -> Result<PathBuf, String> {
    let missing = || "signtool.exe not found in the Windows SDK".to_string();
    let mut found: Vec<PathBuf> = std::fs::read_dir(kits_bin)
        .map_err(|_| missing())?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("10."))
        .map(|e| e.path().join("x64").join("signtool.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort_by_key(|p| p.to_string_lossy().into_owned());
    found.pop().ok_or_else(missing)
}

pub const WINDOWS_KITS_BIN: &str = r"C:\Program Files (x86)\Windows Kits\10\bin";
pub const TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

fn authenticode(
    runner: &mut dyn Runner,
    tool: &Path,
    files: &[PathBuf],
    thumbprint: &str,
    timestamp_url: &str,
) -> Result<(), String> {
    let mut sign: Vec<OsString> = vec![tool.into()];
    sign.extend(os(&[
        "sign",
        "/sha1",
        thumbprint,
        "/fd",
        "SHA256",
        "/tr",
        timestamp_url,
        "/td",
        "SHA256",
    ]));
    sign.extend(files.iter().map(OsString::from));
    runner.run(&sign)?;
    let mut verify: Vec<OsString> = vec![tool.into()];
    verify.extend(os(&["verify", "/pa"]));
    verify.extend(files.iter().map(OsString::from));
    runner.run(&verify)
}

/// Whether a file name is an .exe (case-insensitively on Windows, as glob
/// matches there).
fn is_exe(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if cfg!(windows) {
        name.to_ascii_lowercase().ends_with(".exe")
    } else {
        name.ends_with(".exe")
    }
}

/// Authenticode-sign an .exe, or every .exe inside a ZIP (rewritten in
/// place). `signtool` locates the tool once something needs signing.
pub fn windows(
    runner: &mut dyn Runner,
    target: &Path,
    thumbprint: &str,
    timestamp_url: &str,
    signtool: &dyn Fn() -> Result<PathBuf, String>,
) -> Result<(), String> {
    if target
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
    {
        return authenticode(
            runner,
            &signtool()?,
            &[target.to_path_buf()],
            thumbprint,
            timestamp_url,
        );
    }
    let temp = TempDir::new("pantry-sign-")?;
    let root = temp.path();
    let modes = extract(target, root)?;
    let mut executables = Vec::new();
    files(root, &mut executables)?;
    executables.retain(|p| is_exe(p));
    if cfg!(windows) {
        executables.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    } else {
        executables.sort();
    }
    if executables.is_empty() {
        return Err(format!("{}: no .exe to sign", target.display()));
    }
    authenticode(
        runner,
        &signtool()?,
        &executables,
        thumbprint,
        timestamp_url,
    )?;
    rezip(root, &modes, target)
}
