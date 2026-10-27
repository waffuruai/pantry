//! Lockfile extractors (F4): the (ecosystem, name, version) of every
//! dependency a lockfile pins. They never execute or resolve anything, read
//! line by line where the format allows (P5), and refuse files and lines
//! over a size cap (S7). Each is tested against golden files cut from real
//! lockfiles (`tests/lockfiles/`).

use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::Path;

pub mod cargo;
pub mod gomod;
pub mod npm;
pub mod pnpm;
pub mod swift;
pub mod toml;
pub mod uv;

/// The largest lockfile read.
pub const MAX_FILE: u64 = 64 << 20;
/// The longest line a line-based extractor accepts.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl Package {
    pub fn new(ecosystem: &str, name: &str, version: &str) -> Package {
        Package { ecosystem: ecosystem.into(), name: name.into(), version: version.into() }
    }
}

/// The packages a lockfile pins, sorted and without repeats; None for a
/// lockfile kind this implementation can't read yet.
pub fn extract(path: &Path) -> Result<Option<Vec<Package>>> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parse: fn(&str) -> Result<Vec<Package>> = match name {
        "Cargo.lock" => cargo::parse,
        "package-lock.json" => npm::parse,
        "pnpm-lock.yaml" => pnpm::parse,
        "Package.resolved" => swift::parse,
        "go.mod" => gomod::parse,
        "uv.lock" => uv::parse,
        _ => return Ok(None),
    };
    let text = crate::system::read_capped(path, MAX_FILE)?;
    let pkgs: BTreeSet<Package> =
        parse(&text)?.into_iter().filter(|p| !p.name.is_empty() && !p.version.is_empty()).collect();
    Ok(Some(pkgs.into_iter().collect()))
}

/// Whether [`extract`] reads this kind of lockfile.
pub fn supported(name: &str) -> bool {
    matches!(name, "Cargo.lock" | "package-lock.json" | "pnpm-lock.yaml" | "Package.resolved" | "go.mod" | "uv.lock")
}

/// The lines of a text, refusing any over [`MAX_LINE`].
pub(crate) fn lines(text: &str) -> Result<impl Iterator<Item = &str>> {
    if let Some(long) = text.lines().find(|l| l.len() > MAX_LINE) {
        return Err(Error::Invalid(format!("a line of {} bytes (cap {MAX_LINE})", long.len())));
    }
    Ok(text.lines())
}

/// Versions an advisory database can know: they start with a digit.
pub(crate) fn plausible(version: &str) -> bool {
    version.as_bytes().first().is_some_and(u8::is_ascii_digit)
}
