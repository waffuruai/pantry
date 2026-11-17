//! `package-lock.json` (and `npm-shrinkwrap.json`) → `npm`. v2 and v3 list
//! `packages` by install path; the name is the last `node_modules/` segment
//! (or the entry's own `name`, for aliases); links and workspace sources
//! are skipped. v1 nests `dependencies`; `npm:` aliases resolve to the
//! real package. Versions that aren't registry versions (file:, git) are
//! skipped.
//!
//! Scope comes from npm's own flags (`dev`, `optional`, `devOptional`);
//! a direct dependency is one the root package (`packages[""]`) names in
//! its `dependencies`, `devDependencies` or `optionalDependencies` (v2+;
//! v1 hoists everything, so it says nothing about directness).

use super::{Package, Scope, plausible};
use crate::error::{Error, Result};
use crate::utils::json::{self, str_at};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

fn scope_of(entry: &Value) -> Scope {
    let flag = |k: &str| entry.get(k).and_then(Value::as_bool) == Some(true);
    if flag("optional") || flag("devOptional") {
        Scope::Optional
    } else if flag("dev") {
        Scope::Dev
    } else {
        Scope::Runtime
    }
}

/// The install names the root package depends on directly (an `npm:`
/// alias is installed under the alias, so that is the name that matches).
fn root_dependencies(root: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        for name in root.get(section).and_then(Value::as_object).into_iter().flatten().map(|(n, _)| n) {
            out.insert(name.clone());
        }
    }
    out
}

/// The object at `key`, if any; a `key` that is something else isn't a
/// lockfile npm wrote, and reading it as "no packages" would be a clean
/// check of nothing.
fn section<'a>(data: &'a Value, key: &str) -> Result<Option<&'a Map<String, Value>>> {
    match data.get(key) {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(Error::Invalid(format!("{key} isn't an object"))),
    }
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let version = data.get("lockfileVersion").and_then(Value::as_u64);
    if !matches!(version, Some(1..=3)) {
        let shown = data.get("lockfileVersion").unwrap_or(&Value::Null);
        return Err(Error::Invalid(format!("lockfileVersion {shown} isn't one this reads (1, 2 or 3)")));
    }
    let mut out = Vec::new();
    match (section(&data, "packages")?, section(&data, "dependencies")?) {
        (Some(pkgs), _) => {
            let direct = pkgs.get("").map(root_dependencies);
            for (path, p) in pkgs {
                let Some((parent, last)) = path.rsplit_once("node_modules/") else { continue };
                if p.get("link").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                let name = match str_at(p, "name") {
                    "" => last,
                    n => n,
                };
                let version = str_at(p, "version");
                if plausible(version) {
                    let mut pkg = Package::new("npm", name, version).scoped(scope_of(p));
                    // Only a top-level install can be the root's own dependency; a
                    // nested copy under another package is that package's.
                    if let Some(direct) = &direct {
                        pkg = pkg.direct(parent.is_empty() && (direct.contains(name) || direct.contains(last)));
                    }
                    out.push(pkg);
                }
            }
        }
        (None, Some(deps)) if version == Some(1) => v1(deps, &mut out),
        // v1 leaves `dependencies` out when there are none; v2 and v3 always
        // list the root package under `packages`.
        (None, None) if version == Some(1) => {}
        (None, _) => return Err(Error::Invalid("no packages section".into())),
    }
    Ok(out)
}

fn v1(deps: &Map<String, Value>, out: &mut Vec<Package>) {
    for (name, d) in deps {
        if let Some(nested) = d.get("dependencies").and_then(Value::as_object) {
            v1(nested, out);
        }
        let version = str_at(d, "version");
        let (name, version) = match version.strip_prefix("npm:").and_then(|a| a.rsplit_once('@')) {
            Some((real, v)) if !real.is_empty() => (real, v),
            _ => (name.as_str(), version),
        };
        if plausible(version) {
            out.push(Package::new("npm", name, version).scoped(scope_of(d)));
        }
    }
}

#[cfg(test)]
#[path = "npm_tests.rs"]
mod tests;
