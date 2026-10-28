//! `deno.lock` v3–v5 → `npm`. v3 keeps npm packages under
//! `packages.npm`, v4 and v5 under `npm`; each key is `name@version`,
//! with peer dependencies after an underscore (`react-dom@18.2.0_react@18.2.0`).
//! `jsr:` packages have no OSV ecosystem yet, and remote modules no
//! version, so neither is reported. Other lockfile versions are refused
//! (reported unchecked) rather than misread.

use super::{Package, plausible};
use crate::error::{Error, Result};
use crate::json::{self, str_at};
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
mod tests {
    use super::*;

    #[test]
    fn versions_and_keys() {
        let v4 = r#"{"version": "4", "specifiers": {"jsr:@std/path@1": "1.0.8"},
            "jsr": {"@std/path@1.0.8": {"integrity": "x"}},
            "npm": {"@types/node@20.11.0": {}, "react-dom@18.2.0_react@18.2.0": {}, "string_decoder@1.3.0": {}}}"#;
        let got: Vec<String> = parse(v4).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
        assert_eq!(got, ["@types/node 20.11.0", "react-dom 18.2.0", "string_decoder 1.3.0"]);
        let v3 = r#"{"version": "3", "packages": {"specifiers": {}, "npm": {"ms@2.1.3": {}}}, "remote": {}}"#;
        assert_eq!(parse(v3).unwrap(), [Package::new("npm", "ms", "2.1.3")]);
        assert!(parse(r#"{"version": "2", "npm": {}}"#).is_err());
    }
}
