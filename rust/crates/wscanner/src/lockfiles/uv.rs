//! `uv.lock` v1 → `PyPI`. Editable and virtual sources (the project and
//! its workspace members) are skipped.

use super::{Package, toml};
use crate::error::Result;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    for t in toml::parse(text)?.iter().filter(|t| t.array && t.name == "package") {
        let local = match t.get("source") {
            Some(toml::Val::Raw(raw)) => toml::inline(raw).iter().any(|(k, _)| k == "editable" || k == "virtual"),
            _ => false,
        };
        if !local {
            out.push(Package::new("PyPI", t.str("name"), t.str("version")));
        }
    }
    Ok(out)
}
