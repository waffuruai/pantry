//! What pantry knows about each package ecosystem, in one table
//! ([`ECOSYSTEMS`]): OSV's name for it, how its versions order, and what
//! deps.dev and the OpenSSF malicious-packages index call it. Lockfiles
//! name ecosystems the OSV way; everything else asks here.
//!
//! The version comparators (F10) are one file per ecosystem. OSV decides
//! whether a version is affected; these only order fixed versions to pick
//! the safe one and to compare against "latest". Each is total and never
//! panics: a version its grammar rejects falls back to the generic order of
//! [`versions`]. Each is tested with its upstream's own vectors.

use std::cmp::Ordering;

pub mod apk;
pub mod dpkg;
pub mod go;
pub mod maven;
pub mod packagist;
pub mod pypi;
pub mod rpm;
pub mod rubygems;
pub mod semver;
pub mod versions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparator {
    Semver,
    Pep440,
    Go,
    Dpkg,
    Apk,
    Rpm,
    RubyGems,
    Maven,
    Packagist,
    Generic,
}

impl Comparator {
    pub fn cmp(self, a: &str, b: &str) -> Ordering {
        match self {
            Comparator::Semver => semver::cmp(a, b),
            Comparator::Pep440 => pypi::cmp(a, b),
            Comparator::Go => go::cmp(a, b),
            Comparator::Dpkg => dpkg::cmp(a, b),
            Comparator::Apk => apk::cmp(a, b),
            Comparator::Rpm => rpm::cmp(a, b),
            Comparator::RubyGems => rubygems::cmp(a, b),
            Comparator::Maven => maven::cmp(a, b),
            Comparator::Packagist => packagist::cmp(a, b),
            Comparator::Generic => versions::cmp(a, b),
        }
    }
}

/// One package ecosystem.
#[derive(Debug, PartialEq, Eq)]
pub struct Ecosystem {
    /// OSV's name ("PyPI"). A distro's OSV name carries its release after a
    /// colon ("Debian:12"); the row holds the part before it.
    pub osv: &'static str,
    /// How its versions order.
    pub order: Comparator,
    /// deps.dev's system, when deps.dev covers it.
    pub deps_dev: Option<&'static str>,
    /// Its directory in the OpenSSF malicious-packages index, when it has one.
    pub openssf: Option<&'static str>,
}

const fn eco(
    osv: &'static str,
    order: Comparator,
    deps_dev: Option<&'static str>,
    openssf: Option<&'static str>,
) -> Ecosystem {
    Ecosystem { osv, order, deps_dev, openssf }
}

use Comparator::*;

/// Every ecosystem pantry reads. One not here orders versions generically
/// and has no deps.dev system or OpenSSF directory.
pub static ECOSYSTEMS: &[Ecosystem] = &[
    eco("npm", Semver, Some("npm"), Some("npm")),
    eco("PyPI", Pep440, Some("pypi"), Some("pypi")),
    eco("crates.io", Semver, Some("cargo"), Some("crates.io")),
    eco("Go", Go, Some("go"), Some("go")),
    eco("Maven", Maven, Some("maven"), Some("maven")),
    eco("NuGet", Semver, Some("nuget"), Some("nuget")),
    eco("RubyGems", RubyGems, Some("rubygems"), Some("rubygems")),
    eco("Packagist", Packagist, None, Some("packagist")),
    eco("Pub", Semver, None, None),
    eco("Hex", Semver, None, None),
    eco("SwiftURL", Semver, None, None),
    eco("VSCode", Generic, None, Some("vscode")),
    eco("VSCode:https://open-vsx.org", Generic, None, Some("vscode:open-vsx.org")),
    eco("Debian", Dpkg, None, None),
    eco("Ubuntu", Dpkg, None, None),
    eco("Alpine", Apk, None, None),
    eco("Wolfi", Apk, None, None),
    eco("Chainguard", Apk, None, None),
    eco("openSUSE", Rpm, None, None),
    eco("SUSE", Rpm, None, None),
    eco("Red Hat", Rpm, None, None),
    eco("Rocky Linux", Rpm, None, None),
    eco("AlmaLinux", Rpm, None, None),
    eco("Mageia", Rpm, None, None),
];

impl Ecosystem {
    /// The ecosystem an OSV string names exactly.
    pub fn named(osv: &str) -> Option<&'static Ecosystem> {
        ECOSYSTEMS.iter().find(|e| e.osv == osv)
    }

    /// The ecosystem an OSV string names, or, failing that, the one before
    /// its first colon ("Debian:12" is Debian).
    pub fn of(osv: &str) -> Option<&'static Ecosystem> {
        Ecosystem::named(osv).or_else(|| Ecosystem::named(osv.split(':').next().unwrap_or("")))
    }
}

/// How versions in an OSV ecosystem order: the generic order when unknown.
pub fn order(osv: &str) -> Comparator {
    Ecosystem::of(osv).map_or(Comparator::Generic, |e| e.order)
}

/// deps.dev's system for an OSV ecosystem.
pub fn deps_dev(osv: &str) -> Option<&'static str> {
    Ecosystem::named(osv)?.deps_dev
}

/// The OpenSSF malicious-packages index's directory for an OSV ecosystem.
pub fn openssf(osv: &str) -> Option<&'static str> {
    Ecosystem::named(osv)?.openssf
}

/// A package name as its registry tells names apart: PyPI's per PEP 503,
/// every other lowercased.
pub fn normalize(osv: &str, name: &str) -> String {
    if osv == "PyPI" { pypi::normalize(name) } else { name.to_lowercase() }
}

#[cfg(test)]
pub(crate) fn assert_sorted(cmp: fn(&str, &str) -> Ordering, ascending: &[&str]) {
    for (i, a) in ascending.iter().enumerate() {
        for (j, b) in ascending.iter().enumerate() {
            assert_eq!(cmp(a, b), i.cmp(&j), "{a} vs {b}");
        }
    }
}

#[cfg(test)]
mod tests;
