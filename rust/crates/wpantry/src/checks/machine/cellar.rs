//! Homebrew formulae poured without `brew`: mise's `brew:` engine puts
//! bottles into the Homebrew prefix (`/opt/homebrew`, `/home/linuxbrew/
//! .linuxbrew`) without installing the `brew` command, so `brew vulns` never
//! runs there and `tools` skips Cellar-owned binaries as Homebrew's to
//! check. This reads `<prefix>/Cellar/<formula>/<version>` instead and maps
//! each formula to its catalog tool, so the formula is checked against OSV
//! and endoflife.date like any other inventoried tool.
//!
//! Only used when no `brew` is found (on PATH, or at its standard prefixes or
//! `$HOMEBREW_PREFIX`: an app or a service starts with a short PATH): where
//! there is one, `brew
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
        (c.fix, c.auto) = upgrade_step(&formula, cellar, mise_installs);
        if let Some((eco, pkg, fmt)) = t.osv {
            c.osv = Some((eco.to_string(), pkg.to_string(), tag(fmt, &v)));
            c.osv_also = c.osv.as_ref().map(crate::sources::osv::also).unwrap_or_default();
        }
        if let Some((product, cycle)) = t.eol {
            c.eol = Some((product.to_string(), cycle.of(&v)));
        }
        c.extra.insert("formula".into(), formula);
        out.components.push(c);
    }
    out
}

/// Whether a keg of `formula` in `cellar` has a Homebrew install receipt
/// naming the Homebrew that poured it (`homebrew_version` in
/// `INSTALL_RECEIPT.json`): then Homebrew owns it, whatever else is true of
/// this scan's PATH. mise's `brew:` engine writes no such version.
pub fn homebrew_receipt(cellar: &Path, formula: &str) -> bool {
    let Ok(kegs) = std::fs::read_dir(cellar.join(formula)) else { return false };
    kegs.filter_map(|e| e.ok()).any(|k| {
        crate::utils::files::read_json(&k.path().join("INSTALL_RECEIPT.json"))
            .and_then(|r| r.get("homebrew_version").and_then(|v| v.as_str()).map(|v| !v.is_empty()))
            .unwrap_or(false)
    })
}

/// What to do about an outdated formula whose keg is in `cellar`, and
/// whether `wpantry fix` may do it. Reached when `brew` is not on PATH or at
/// a standard prefix ([`crate::utils::process::find_tool`]); otherwise
/// `brew upgrade` is the fix and this isn't asked.
///
/// 1. A Homebrew receipt on the keg ([`homebrew_receipt`]): Homebrew's
///    `brew upgrade <formula>`, with the `brew` beside the Cellar when there
///    is one (automatic, like any other `brew upgrade`, except for formulae
///    whose catalog fix is manual); else a step naming the command.
/// 2. mise's `brew:` engine made it (mise has an `installs/brew-<formula>`
///    folder): `mise upgrade brew:<formula>`, a command for you.
/// 3. A `bin/brew` in the Cellar's own prefix: that `brew upgrade`.
/// 4. Nothing says: both commands, `brew` first, and when to use the second.
///
/// A name that isn't one plain word never reaches a command.
///
/// Example: `/opt/homebrew/bin/brew upgrade openssl@3` for a Cellar at
/// `/opt/homebrew/Cellar` with a `bin/brew` beside it.
pub fn upgrade_step(formula: &str, cellar: &Path, mise_installs: &Path) -> (String, bool) {
    if !formula.split('@').all(versions::is_safe_token) {
        return (
            format!(
                "Upgrade {formula} with Homebrew, or the tool that installed it: its name is not one wpantry will put in a command"
            ),
            false,
        );
    }
    let receipt = homebrew_receipt(cellar, formula);
    if !receipt && mise_installs.join(format!("brew-{formula}")).is_dir() {
        return (format!("mise upgrade brew:{formula}"), false);
    }
    let brew = cellar.parent().map(|p| p.join("bin/brew")).filter(|b| b.is_file());
    if let Some(brew) = brew {
        let brew = brew.to_string_lossy().into_owned();
        let plain = brew.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+@".contains(c));
        let base = formula.split('@').next().unwrap_or(formula);
        if plain && crate::checks::machine::manual(base).is_none() {
            return (format!("{brew} upgrade {formula}"), true);
        }
        return (format!("Run `{brew} upgrade {formula}`."), false);
    }
    if receipt {
        return (format!("Homebrew installed this copy: run `brew upgrade {formula}` where Homebrew is."), false);
    }
    (
        format!(
            "Run `brew upgrade {formula}`. If another tool installed this copy (mise's brew: engine), update it there instead: `mise upgrade brew:{formula}`."
        ),
        false,
    )
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
