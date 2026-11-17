//! `deno.lock` v3–v5 → `npm`. v3 keeps npm packages under
//! `packages.npm`, v4 and v5 under `npm`; each key is `name@version`,
//! with peer dependencies after an underscore (`react-dom@18.2.0_react@18.2.0`).
//! `jsr:` packages have no OSV ecosystem yet, and remote modules no
//! version, so neither is reported. Other lockfile versions are refused
//! (reported unchecked) rather than misread.

use super::{Package, plausible};
use crate::error::{Error, Result};
use crate::utils::json::{self, str_at};
use serde_json::Value;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let npm = match str_at(&data, "version") {
        "3" => data.get("packages").and_then(|p| p.get("npm")),
        "4" | "5" => data.get("npm"),
        v => return Err(Error::Invalid(format!("deno.lock version {v:?} (read: 3 to 5)"))),
    };
    let mut out = Vec::new();
    for key in npm.and_then(Value::as_object).into_iter().flat_map(|m| m.keys()) {
        let Some(at) = key.get(1..).and_then(|r| r.find('@')).map(|i| i + 1) else { continue };
        let name = &key[..at];
        let version = key[at + 1..].split('_').next().unwrap_or("");
        if plausible(version) {
            out.push(Package::new("npm", name, version));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "deno_tests.rs"]
mod tests;
