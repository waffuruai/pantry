//! Lockfile extractors (F4): the (ecosystem, name, version) of every
//! dependency a lockfile pins. They never execute or resolve anything, read
//! line by line where the format allows (P5), and refuse files and lines
//! over a size cap (S7). Each is tested against golden files cut from real
//! lockfiles (`tests/lockfiles/`). Local, path, git and workspace entries
//! are skipped, as are versions that aren't registry versions.

use crate::error::{Error, Result};
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

/// How a dependency is depended on, where the lockfile says: a dev or test
/// dependency is usually not exposed where the code runs, which decides
/// most of an advisory's applicability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    #[default]
    Unknown,
    Runtime,
    Dev,
    Optional,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Unknown => "unknown",
            Scope::Runtime => "runtime",
            Scope::Dev => "dev",
            Scope::Optional => "optional",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Runtime, dev or optional, where the lockfile records it.
    pub scope: Scope,
    /// Depended on by the project itself (true) or pulled in by another
    /// dependency (false); None where the lockfile doesn't say.
    pub direct: Option<bool>,
}

impl Package {
    pub fn new(ecosystem: &str, name: &str, version: &str) -> Package {
        Package {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
            scope: Scope::Unknown,
            direct: None,
        }
    }

    pub fn scoped(mut self, scope: Scope) -> Package {
        self.scope = scope;
        self
    }

    pub fn direct(mut self, direct: bool) -> Package {
        self.direct = Some(direct);
        self
    }

    /// One package reached two ways: a runtime use outranks a dev one, a
    /// direct dependency a transitive one, anything known the unknown.
    fn merge(&mut self, other: &Package) {
        self.scope = match (self.scope, other.scope) {
            (Scope::Unknown, s) | (s, Scope::Unknown) => s,
            (Scope::Runtime, _) | (_, Scope::Runtime) => Scope::Runtime,
            (Scope::Optional, _) | (_, Scope::Optional) => Scope::Optional,
            (Scope::Dev, Scope::Dev) => Scope::Dev,
        };
        self.direct = match (self.direct, other.direct) {
            (None, d) | (d, None) => d,
            (Some(a), Some(b)) => Some(a || b),
        };
    }
}

/// `packages` sorted by (ecosystem, name, version), each once, with the
/// scope and directness merged where a lockfile listed one twice.
pub fn dedupe(packages: Vec<Package>) -> Vec<Package> {
    let mut out: Vec<Package> = Vec::new();
    for p in packages {
        match out.iter_mut().find(|q| q.ecosystem == p.ecosystem && q.name == p.name && q.version == p.version) {
            Some(q) => q.merge(&p),
            None => out.push(p),
        }
    }
    out.sort_by(|a, b| (&a.ecosystem, &a.name, &a.version).cmp(&(&b.ecosystem, &b.name, &b.version)));
    out
}

type Parser = fn(&str) -> Result<Vec<Package>>;

/// The extractor for a lockfile name, except requirements files (which
/// read their includes themselves).
fn parser(name: &str) -> Option<Parser> {
    Some(match name {
        "Cargo.lock" => cargo::parse,
        "package-lock.json" | "npm-shrinkwrap.json" => npm::parse,
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
    // A lockfile that links out of the repo isn't the repo's to report: its
    // packages would go to OSV as if they were.
    if parser(name).is_some() || requirements::is_requirements(name) {
        let (real, base) = (path.canonicalize()?, root.canonicalize()?);
        if !real.starts_with(&base) {
            return Err(Error::Invalid(format!("{} links outside {}; not read", path.display(), root.display())));
        }
    }
    let found = if requirements::is_requirements(name) {
        requirements::parse_file(path, root)?
    } else {
        let Some(parse) = parser(name) else { return Ok(None) };
        let text = crate::system::read_capped(path, MAX_FILE)?;
        if !looks_like(name, &text) {
            return Err(Error::Invalid(format!("{} isn't a {name} this can read", path.display())));
        }
        parse(&text)?
    };
    Ok(Some(dedupe(found.into_iter().filter(|p| !p.name.is_empty() && !p.version.is_empty()).collect())))
}

/// Whether `text` has the structure every `name` its tool writes has (a
/// format version, a section, a root element). The parsers read only what
/// they need and skip the rest, so without this a file that isn't a
/// lockfile at all would read as one with no packages: a clean check of
/// nothing.
fn looks_like(name: &str, text: &str) -> bool {
    let line = |f: &dyn Fn(&str) -> bool| text.lines().any(|l| f(l.trim_end()));
    let key = |k: &str| text.contains(&format!("\"{k}\""));
    match name {
        "Cargo.lock" => line(&|l| l.starts_with("version =") || l == "[[package]]"),
        "package-lock.json" | "npm-shrinkwrap.json" | "bun.lock" => key("lockfileVersion"),
        "pnpm-lock.yaml" => line(&|l| l.starts_with("lockfileVersion:")),
        "yarn.lock" => text.contains("# yarn lockfile v1") || line(&|l| l == "__metadata:"),
        "deno.lock" => key("version"),
        "uv.lock" => line(&|l| l.starts_with("version =")),
        "poetry.lock" => line(&|l| l == "[metadata]" || l == "[[package]]"),
        "Pipfile.lock" => key("_meta"),
        "go.mod" => line(&|l| l.trim_start().starts_with("module ")),
        "Package.resolved" => key("pins"),
        "Gemfile.lock" => {
            line(&|l| matches!(l, "GEM" | "PATH" | "GIT" | "PLATFORMS" | "DEPENDENCIES" | "BUNDLED WITH"))
        }
        "composer.lock" => key("packages"),
        "pubspec.lock" => line(&|l| l == "packages:" || l == "sdks:"),
        "mix.lock" => text.trim_start().starts_with("%{"),
        "gradle.lockfile" => line(&|l| l.starts_with("empty=") || (l.contains(':') && l.contains('='))),
        "pom.xml" => text.contains("<project"),
        "packages.lock.json" => key("dependencies"),
        "conan.lock" => key("graph_lock") || key("requires"),
        _ => true,
    }
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

    /// Text that isn't the lockfile it's named as is an error (so the scan
    /// reports it unchecked), never a lockfile with no packages; one the tool
    /// wrote with no packages still reads as empty.
    #[test]
    fn a_file_that_isnt_its_lockfile_is_an_error_not_empty() {
        let d = crate::system::TempDir::new("notlock").unwrap();
        for name in crate::repos::LOCKFILES.iter().filter(|n| !requirements::is_requirements(n)) {
            for (i, text) in ["this is not a valid lockfile\n", "", "{}\n"].iter().enumerate() {
                let dir = d.path().join(format!("{i}-{name}"));
                std::fs::create_dir_all(&dir).unwrap();
                let f = dir.join(name);
                std::fs::write(&f, text).unwrap();
                assert!(matches!(extract(&f), Err(Error::Invalid(_))), "{name} accepted {text:?}");
            }
        }
        let empty = [
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n"),
            ("package-lock.json", r#"{"name": "x", "lockfileVersion": 3, "packages": {"": {}}}"#),
            ("package-lock.json", r#"{"name": "x", "version": "1.0.0", "lockfileVersion": 1}"#),
            ("Cargo.lock", "version = 4\n"),
            ("go.mod", "module example.com/x\n\ngo 1.24\n"),
            ("yarn.lock", "# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n"),
        ];
        for (i, (name, text)) in empty.into_iter().enumerate() {
            let dir = d.path().join(format!("ok{i}-{name}"));
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join(name);
            std::fs::write(&f, text).unwrap();
            let got = extract(&f).unwrap().unwrap();
            assert!(got.iter().all(|p| p.name == "stdlib"), "{name}: {got:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_lockfile_linking_outside_the_repo_is_not_read() {
        let d = crate::system::TempDir::new("linkout").unwrap();
        let (repo, outside) = (d.path().join("repo"), d.path().join("outside"));
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("Cargo.lock"), "version = 4\n").unwrap();
        std::os::unix::fs::symlink(outside.join("Cargo.lock"), repo.join("Cargo.lock")).unwrap();
        assert!(matches!(extract_within(&repo.join("Cargo.lock"), &repo), Err(Error::Invalid(_))));
        // A link that stays inside the repo is fine.
        std::fs::write(repo.join("sub/Cargo.lock"), "version = 4\n").unwrap();
        std::os::unix::fs::symlink(repo.join("sub/Cargo.lock"), repo.join("sub/linked.lock")).unwrap();
        std::fs::rename(repo.join("sub/linked.lock"), repo.join("Cargo.lock")).unwrap();
        assert!(extract_within(&repo.join("Cargo.lock"), &repo).unwrap().is_some());
    }

    #[test]
    fn every_scanned_name_is_supported() {
        for name in crate::repos::LOCKFILES {
            assert!(supported(name), "{name}");
        }
        assert!(supported("requirements-dev.txt") && supported("requirements.in.txt"));
        assert!(!supported("requirements.in") && !supported("yarn.lock.bak"));
    }
}
