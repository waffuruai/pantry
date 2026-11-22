//! Release packaging for Pantry Desktop: the portable ZIP (`package`), Pantry
//! Setup's payload and download (`setup`), and code signing (`sign`).
//!
//! Every archive depends only on its entries: names sorted, fixed modes, no
//! timestamps, deflate at level 9 from miniz_oxide. The release workflow
//! builds each one from two checkouts and compares the bytes, so nothing here
//! may read the clock, the checkout path or the environment into an output.
//!
//! ```text
//! cargo run --release -- package universal-apple-darwin app wpantry notices.txt out.zip
//! ```

pub mod archive;
pub mod json;
pub mod package;
pub mod setup;
pub mod sign;
pub mod temp;

/// desktop/Cargo.toml, compiled in: the bundles' version is the app's.
const DESKTOP_MANIFEST: &str = include_str!("../../Cargo.toml");

/// Pantry Desktop's version, from `[package] version` in desktop/Cargo.toml.
pub fn desktop_version() -> Result<String, String> {
    let mut in_package = false;
    for line in DESKTOP_MANIFEST.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("version") {
            let value = rest.trim_start().strip_prefix('=').map(str::trim);
            if let Some(v) = value
                .and_then(|v| v.strip_prefix('"'))
                .and_then(|v| v.strip_suffix('"'))
            {
                return Ok(v.to_string());
            }
        }
    }
    Err("desktop/Cargo.toml has no [package] version".to_string())
}

/// Read a file, naming it in the error.
pub fn read(path: &std::path::Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Write a file, naming it in the error.
pub fn write(path: &std::path::Path, body: &[u8]) -> Result<(), String> {
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}
