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
use crate::error::Result;
use crate::json::{self, str_at};
use serde_json::Value;
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

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    if let Some(pkgs) = data.get("packages").and_then(Value::as_object) {
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
    } else if let Some(deps) = data.get("dependencies").and_then(Value::as_object) {
        v1(deps, &mut out);
    }
    Ok(out)
}

fn v1(deps: &serde_json::Map<String, Value>, out: &mut Vec<Package>) {
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
mod tests {
    use super::*;

    #[test]
    fn scope_and_directness_from_the_root_and_the_flags() {
        let text = r#"{"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"debug": "2.6.8", "my-ms": "npm:ms@2.1.3"}, "devDependencies": {"minimist": "1.2.5"},
                 "optionalDependencies": {"fsevents": "2.3.3"}},
            "node_modules/debug": {"version": "2.6.8"},
            "node_modules/ms": {"version": "2.0.0"},
            "node_modules/debug/node_modules/ms": {"version": "2.1.3"},
            "node_modules/my-ms": {"name": "ms", "version": "2.1.3"},
            "node_modules/minimist": {"version": "1.2.5", "dev": true},
            "node_modules/fsevents": {"version": "2.3.3", "optional": true},
            "node_modules/semver": {"version": "7.5.4", "devOptional": true}}}"#;
        let got = parse(text).unwrap();
        let find = |name: &str, version: &str| got.iter().find(|p| p.name == name && p.version == version).unwrap();
        assert_eq!((find("debug", "2.6.8").scope, find("debug", "2.6.8").direct), (Scope::Runtime, Some(true)));
        assert_eq!(find("ms", "2.0.0").direct, Some(false), "hoisted, not the root's");
        assert_eq!(find("ms", "2.1.3").direct, Some(false), "nested under debug");
        assert!(
            got.iter().any(|p| p.name == "ms" && p.version == "2.1.3" && p.direct == Some(true)),
            "the alias my-ms is the root's"
        );
        assert_eq!((find("minimist", "1.2.5").scope, find("minimist", "1.2.5").direct), (Scope::Dev, Some(true)));
        assert_eq!(find("fsevents", "2.3.3").scope, Scope::Optional);
        assert_eq!((find("semver", "7.5.4").scope, find("semver", "7.5.4").direct), (Scope::Optional, Some(false)));
        let v1 = r#"{"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dev": true}, "b": {"version": "2.0.0"}}}"#;
        let got = parse(v1).unwrap();
        assert_eq!((got[0].scope, got[0].direct), (Scope::Dev, None), "v1 says nothing about directness");
        assert_eq!(got[1].scope, Scope::Runtime);
    }
}
