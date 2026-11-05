//! Homebrew formulae poured without `brew`: mise's `brew:` engine puts
//! bottles into the Homebrew prefix (`/opt/homebrew`, `/home/linuxbrew/
//! .linuxbrew`) without installing the `brew` command, so `brew vulns` never
//! runs there and `tools` skips Cellar-owned binaries as Homebrew's to
//! check. This reads `<prefix>/Cellar/<formula>/<version>` instead and maps
//! each formula to its catalog tool, so the formula is checked against OSV
//! and endoflife.date like any other inventoried tool.
//!
//! Only used when there is no `brew` on PATH: where there is one, `brew
//! vulns` covers the formulae (with Homebrew's own patch awareness), so a
//! formula is never reported twice. Formulae with no catalog mapping are
//! reported unchecked, never clean.

use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::{TOOLS, Tool};
use crate::checks::machine::tools::tag;
use crate::component::Component;
use crate::utils::files::home;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Formula names that aren't their catalog tool's name; `name@X` is looked
/// up by `name` first. Pythons are inventoried with their pip packages
/// elsewhere, and `mise` and `brew` are always checked from PATH.
const ALIASES: &[(&str, &str)] = &[
    ("openssh", "ssh"),
    ("postgresql", "postgres"),
    ("awscli", "aws"),
    ("nats-server", "nats"),
    ("mongodb-community", "mongodb"),
    ("mysql-client", "mysql"),
    ("mariadb-client", "mariadb"),
    ("openjdk", "java"),
    ("llvm", "clang"),
    ("rustup", "rustup"),
    ("rustup-init", "rustup"),
];
const SKIP: &[&str] = &["python", "mise", "brew"];

/// The catalog tool a formula directory stands for, if any.
pub fn catalog_tool(formula: &str) -> Option<&'static Tool> {
    let base = formula.split('@').next().unwrap_or(formula);
    if SKIP.contains(&base) {
        return None;
    }
    let name = ALIASES.iter().find(|(f, _)| *f == base).map(|(_, t)| *t).unwrap_or(base);
    TOOLS.iter().find(|t| t.name == name && t.name != "mise" && t.name != "brew")
}

/// A Cellar version directory as a version: Homebrew's revision suffix
/// (`1.8.2_1`) is dropped, as the formula's version has none.
pub fn version_of(dir: &str) -> &str {
    match dir.rsplit_once('_') {
        Some((v, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => v,
        _ => dir,
    }
}

/// The Cellar to read: HOMEBREW_CELLAR, else HOMEBREW_PREFIX's, else the
/// first of the standard prefixes that has one.
pub fn find_cellar() -> Option<PathBuf> {
    find_cellar_from(std::env::var_os("HOMEBREW_CELLAR"), std::env::var_os("HOMEBREW_PREFIX"), STANDARD_CELLARS)
}

const STANDARD_CELLARS: &[&str] = &["/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar"];

/// [`find_cellar`] from the two variables' values and the standard prefixes.
fn find_cellar_from(cellar: Option<OsString>, prefix: Option<OsString>, standard: &[&str]) -> Option<PathBuf> {
    if let Some(c) = cellar.filter(|c| !c.is_empty()) {
        return Some(PathBuf::from(c));
    }
    if let Some(p) = prefix.filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p).join("Cellar"));
    }
    standard.iter().map(PathBuf::from).find(|p| p.is_dir())
}

/// Where mise keeps its installs (`brew-<formula>` for the brew engine).
pub fn mise_installs() -> PathBuf {
    mise_installs_from(std::env::var_os("MISE_DATA_DIR"))
}

/// [`mise_installs`] from MISE_DATA_DIR's value.
fn mise_installs_from(data_dir: Option<OsString>) -> PathBuf {
    data_dir
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share/mise"))
        .join("installs")
}

/// What a Cellar holds: the components for the formulae the catalog knows,
/// and the names of the ones it doesn't.
#[derive(Debug, Default, PartialEq)]
pub struct Inventory {
    pub components: Vec<Component>,
    pub unmapped: Vec<String>,
}

/// Read `cellar`; `mise_installs` decides whether the fix is mise's.
pub fn read(cellar: &Path, mise_installs: &Path) -> Inventory {
    let mut out = Inventory::default();
    let Ok(entries) = std::fs::read_dir(cellar) else { return out };
    let mut formulae: Vec<(String, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.path().is_dir())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    formulae.sort();
    for (formula, dir) in formulae {
        let mut versions: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|v| !v.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        if versions.is_empty() {
            continue;
        }
        let Some(t) = catalog_tool(&formula) else {
            out.unmapped.push(formula);
            continue;
        };
        versions.sort_by(|a, b| versions::cmp(version_of(a), version_of(b)));
        let v = version_of(versions.last().expect("non-empty")).to_string();
        let path = dir.to_string_lossy().into_owned();
        let mut c = Component::new("brew", t.name, &v, &path);
        c.fix = if mise_installs.join(format!("brew-{formula}")).is_dir() {
            format!("mise upgrade brew:{formula}")
        } else {
            format!("Upgrade {formula} in the Cellar at {path} (poured without brew; mise's brew: engine or brew)")
        };
        c.auto = false;
        if let Some((eco, pkg, fmt)) = t.osv {
            c.osv = Some((eco.to_string(), pkg.to_string(), tag(fmt, &v)));
        }
        if let Some((product, cycle)) = t.eol {
            c.eol = Some((product.to_string(), cycle.of(&v)));
        }
        c.extra.insert("formula".into(), formula);
        out.components.push(c);
    }
    out
}

/// The Cellar inventory for this machine, when it has a Cellar.
pub fn inventory() -> Option<(PathBuf, Inventory)> {
    inventory_in(find_cellar()?, &mise_installs())
}

/// [`inventory`] for the Cellar at `cellar`.
fn inventory_in(cellar: PathBuf, mise_installs: &Path) -> Option<(PathBuf, Inventory)> {
    let inv = read(&cellar, mise_installs);
    (!inv.components.is_empty() || !inv.unmapped.is_empty()).then_some((cellar, inv))
}

#[cfg(test)]
#[path = "cellar_tests.rs"]
mod tests;
