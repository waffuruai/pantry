//! `Cargo.lock` v1–v4 → `crates.io`. Only packages from the crates.io index
//! count: workspace members (no `source`), `path` and `git` packages and
//! other registries have no crates.io advisories to match.

use super::{Package, toml};
use crate::error::Result;

const CRATES_IO: &[&str] =
    &["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];

pub fn parse(text: &str) -> Result<Vec<Package>> {
    Ok(toml::parse(text)?
        .iter()
        .filter(|t| t.array && t.name == "package" && CRATES_IO.contains(&t.str("source")))
        .map(|t| Package::new("crates.io", t.str("name"), t.str("version")))
        .collect())
}
