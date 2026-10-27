//! Lockfile extractors (F4): the (ecosystem, name, version) of every
//! dependency a lockfile pins. They never execute or resolve anything, read
//! line by line where the format allows (P5), and refuse files and lines
//! over a size cap (S7). Each is tested against golden files cut from real
//! lockfiles (`tests/lockfiles/`). Local, path, git and workspace entries
//! are skipped, as are versions that aren't registry versions.

use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::Path;

pub mod bun;
pub mod cargo;
pub mod composer;
pub mod conan;
pub mod deno;
pub mod gem;
pub mod gomod;
pub mod gradle;
pub mod maven;
pub mod mix;
pub mod npm;
pub mod nuget;
pub mod pipenv;
pub mod pnpm;
pub mod poetry;
pub mod pubspec;
pub mod requirements;
pub mod swift;
pub mod toml;
pub mod uv;
pub mod yarn;

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

type Parser = fn(&str) -> Result<Vec<Package>>;

/// The extractor for a lockfile name, except requirements files (which
/// read their includes themselves).
fn parser(name: &str) -> Option<Parser> {
    Some(match name {
        "Cargo.lock" => cargo::parse,
        "package-lock.json" => npm::parse,
        "pnpm-lock.yaml" => pnpm::parse,
        "yarn.lock" => yarn::parse,
        "bun.lock" => bun::parse,
        "deno.lock" => deno::parse,
        "Package.resolved" => swift::parse,
        "go.mod" => gomod::parse,
        "uv.lock" => uv::parse,
        "poetry.lock" => poetry::parse,
        "Pipfile.lock" => pipenv::parse,
        "Gemfile.lock" => gem::parse,
        "composer.lock" => composer::parse,
        "pubspec.lock" => pubspec::parse,
        "mix.lock" => mix::parse,
        "gradle.lockfile" => gradle::parse,
        "pom.xml" => maven::parse,
        "packages.lock.json" => nuget::parse,
        "conan.lock" => conan::parse,
        _ => return None,
    })
}

/// The packages a lockfile pins, sorted and without repeats; None for a
/// lockfile kind this implementation can't read yet. A requirements file's
/// `-r` includes are followed within its own directory; [`extract_within`]
/// widens that to the repository.
pub fn extract(path: &Path) -> Result<Option<Vec<Package>>> {
    extract_within(path, path.parent().unwrap_or(Path::new(".")))
}

/// As [`extract`], letting a requirements file include any file under
/// `root` (the repository it was found in), and nothing outside it.
pub fn extract_within(path: &Path, root: &Path) -> Result<Option<Vec<Package>>> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let found = if requirements::is_requirements(name) {
        requirements::parse_file(path, root)?
    } else {
        let Some(parse) = parser(name) else { return Ok(None) };
        parse(&crate::system::read_capped(path, MAX_FILE)?)?
    };
    let pkgs: BTreeSet<Package> = found.into_iter().filter(|p| !p.name.is_empty() && !p.version.is_empty()).collect();
    Ok(Some(pkgs.into_iter().collect()))
}

/// Whether [`extract`] reads this kind of lockfile.
pub fn supported(name: &str) -> bool {
    requirements::is_requirements(name) || parser(name).is_some()
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

/// A YAML scalar without its quotes.
pub(crate) fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scanned_name_is_supported() {
        for name in crate::repos::LOCKFILES {
            assert!(supported(name), "{name}");
        }
        assert!(supported("requirements-dev.txt") && supported("requirements.in.txt"));
        assert!(!supported("requirements.in") && !supported("yarn.lock.bak"));
    }
}
