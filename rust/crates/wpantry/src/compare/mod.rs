//! Per-ecosystem version comparators (F10). OSV decides whether a version is
//! affected; these only order fixed versions to pick the safe one and to
//! compare against "latest". Each is total and never panics: a version its
//! grammar rejects falls back to the generic order of [`crate::versions`].
//! Each is tested with its upstream's own vectors.

use std::cmp::Ordering;

pub mod apk;
pub mod dpkg;
pub mod gover;
pub mod maven;
pub mod packagist;
pub mod pep440;
pub mod rpm;
pub mod rubygems;
pub mod semver;

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
    /// The comparator for an OSV ecosystem string.
    pub fn for_ecosystem(eco: &str) -> Comparator {
        let base = eco.split(':').next().unwrap_or("");
        match base {
            "crates.io" | "npm" | "SwiftURL" | "Pub" | "Hex" | "NuGet" => Comparator::Semver,
            "PyPI" => Comparator::Pep440,
            "RubyGems" => Comparator::RubyGems,
            "Maven" => Comparator::Maven,
            "Packagist" => Comparator::Packagist,
            "Go" => Comparator::Go,
            "Debian" | "Ubuntu" => Comparator::Dpkg,
            "Alpine" | "Wolfi" | "Chainguard" => Comparator::Apk,
            "openSUSE" | "SUSE" | "Red Hat" | "Rocky Linux" | "AlmaLinux" | "Mageia" => Comparator::Rpm,
            _ => Comparator::Generic,
        }
    }

    pub fn cmp(self, a: &str, b: &str) -> Ordering {
        match self {
            Comparator::Semver => semver::cmp(a, b),
            Comparator::Pep440 => pep440::cmp(a, b),
            Comparator::Go => gover::cmp(a, b),
            Comparator::Dpkg => dpkg::cmp(a, b),
            Comparator::Apk => apk::cmp(a, b),
            Comparator::Rpm => rpm::cmp(a, b),
            Comparator::RubyGems => rubygems::cmp(a, b),
            Comparator::Maven => maven::cmp(a, b),
            Comparator::Packagist => packagist::cmp(a, b),
            Comparator::Generic => crate::versions::cmp(a, b),
        }
    }
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
mod tests {
    use super::*;

    #[test]
    fn ecosystems() {
        assert_eq!(Comparator::for_ecosystem("Debian:12"), Comparator::Dpkg);
        assert_eq!(Comparator::for_ecosystem("Ubuntu:24.04:LTS"), Comparator::Dpkg);
        assert_eq!(Comparator::for_ecosystem("Alpine:v3.20"), Comparator::Apk);
        assert_eq!(Comparator::for_ecosystem("openSUSE:Leap 15.6"), Comparator::Rpm);
        assert_eq!(Comparator::for_ecosystem("PyPI"), Comparator::Pep440);
        assert_eq!(Comparator::for_ecosystem("RubyGems"), Comparator::RubyGems);
        assert_eq!(Comparator::for_ecosystem("Maven"), Comparator::Maven);
        assert_eq!(Comparator::for_ecosystem("Packagist"), Comparator::Packagist);
        assert_eq!(Comparator::for_ecosystem("ConanCenter"), Comparator::Generic);
        assert_eq!(Comparator::for_ecosystem("GIT"), Comparator::Generic);
        assert_eq!(Comparator::Semver.cmp("1.0.0-rc.1", "1.0.0"), Ordering::Less);
    }
}
