//! `Package.resolved` v1–v3 → `SwiftURL`. The package is the repository
//! URL without its scheme or `.git` (`github.com/apple/swift-nio`), as OSV
//! names SwiftURL packages; pins on a branch or revision have no version
//! and are skipped.

use super::Package;
use crate::error::Result;
use crate::json::{self, arr_at, str_at};

pub fn name(url: &str) -> &str {
    let u = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
    u.strip_suffix(".git").unwrap_or(u)
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let v1 = data.get("object").map(|o| arr_at(o, "pins")).unwrap_or(&[]);
    let mut out = Vec::new();
    for pin in v1.iter().chain(arr_at(&data, "pins")) {
        let url = match str_at(pin, "location") {
            "" => str_at(pin, "repositoryURL"),
            l => l,
        };
        let version = pin.get("state").map(|s| str_at(s, "version")).unwrap_or("");
        let pkg = match name(url) {
            "" => str_at(pin, "identity"),
            n => n,
        };
        out.push(Package::new("SwiftURL", pkg, version));
    }
    Ok(out)
}
