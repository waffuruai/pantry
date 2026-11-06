//! `Cargo.lock` v1–v4 → `crates.io`. Only packages from the crates.io index
//! count: workspace members (no `source`), `path` and `git` packages and
//! other registries have no crates.io advisories to match.
//!
//! A workspace member's `dependencies` list names what the project itself
//! depends on (`name`, or `name version` when two versions are locked):
//! those crates are direct, the rest came with them. Cargo.lock doesn't
//! separate dev-dependencies from the rest, so the scope stays unknown.

use super::Package;
use crate::error::Result;
use crate::utils::toml;
use std::collections::BTreeSet;

const CRATES_IO: &[&str] =
    &["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];

/// The quoted entries of a raw TOML string array, as (name, version or "").
fn dependency_list(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(i) = rest.find('"') {
        match toml::string(&rest[i..]) {
            Some((entry, r)) => {
                let mut words = entry.split_whitespace();
                let name = words.next().unwrap_or("").to_string();
                let version = words.next().filter(|v| v.as_bytes().first().is_some_and(u8::is_ascii_digit));
                if !name.is_empty() {
                    out.push((name, version.unwrap_or("").to_string()));
                }
                rest = r;
            }
            None => rest = &rest[i + 1..],
        }
    }
    out
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let tables = toml::parse(text)?;
    let packages: Vec<&toml::Table> = tables.iter().filter(|t| t.array && t.name == "package").collect();
    // What the workspace's own crates depend on, by (name, version or "").
    let mut asked: BTreeSet<(String, String)> = BTreeSet::new();
    for t in packages.iter().filter(|t| t.get("source").is_none()) {
        if let Some(toml::Val::Raw(raw)) = t.get("dependencies") {
            asked.extend(dependency_list(raw));
        }
    }
    Ok(packages
        .iter()
        .filter(|t| CRATES_IO.contains(&t.str("source")))
        .map(|t| {
            let (name, version) = (t.str("name"), t.str("version"));
            let direct = asked.contains(&(name.to_string(), String::new()))
                || asked.contains(&(name.to_string(), version.to_string()));
            Package::new("crates.io", name, version).direct(direct)
        })
        .collect())
}

#[cfg(test)]
#[path = "cargo_tests.rs"]
mod tests;
