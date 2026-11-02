//! `uv.lock` v1 → `PyPI`. Editable and virtual sources (the project and
//! its workspace members) are skipped, but their `[package.metadata]`
//! says what the project asks for: `requires-dist` names are direct runtime
//! dependencies, `requires-dev` (dependency groups) direct dev ones;
//! everything else came with them.

use super::{Package, Scope, requirements::normalize, toml};
use crate::error::Result;
use std::collections::BTreeMap;

/// The `name = "…"` values in a raw TOML array of inline tables.
fn names_in(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(i) = rest.find("name") {
        let after = rest[i + 4..].trim_start();
        match after.strip_prefix('=').map(str::trim_start).and_then(toml::string) {
            Some((name, r)) => {
                out.push(normalize(&name));
                rest = r;
            }
            None => rest = &rest[i + 4..],
        }
    }
    out
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let tables = toml::parse(text)?;
    // What the project itself asks for, by normalized name: runtime wins
    // over dev when a name is in both.
    let mut asked: BTreeMap<String, Scope> = BTreeMap::new();
    let mut root = false;
    for t in &tables {
        if t.array && t.name == "package" {
            root = match t.get("source") {
                Some(toml::Val::Raw(raw)) => toml::inline(raw).iter().any(|(k, _)| k == "editable" || k == "virtual"),
                _ => false,
            };
        } else if root && t.name == "package.metadata" {
            if let Some(toml::Val::Raw(raw)) = t.get("requires-dist") {
                for n in names_in(raw) {
                    asked.insert(n, Scope::Runtime);
                }
            }
        } else if root && t.name == "package.metadata.requires-dev" {
            for (_, v) in &t.entries {
                if let toml::Val::Raw(raw) = v {
                    for n in names_in(raw) {
                        asked.entry(n).or_insert(Scope::Dev);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for t in tables.iter().filter(|t| t.array && t.name == "package") {
        let local = match t.get("source") {
            Some(toml::Val::Raw(raw)) => toml::inline(raw).iter().any(|(k, _)| k == "editable" || k == "virtual"),
            _ => false,
        };
        if local {
            continue;
        }
        let mut p = Package::new("PyPI", t.str("name"), t.str("version"));
        match asked.get(&normalize(t.str("name"))) {
            Some(scope) => p = p.scoped(*scope).direct(true),
            None if !asked.is_empty() => p = p.direct(false),
            None => {}
        }
        out.push(p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_projects_metadata_says_what_is_direct() {
        let text = "version = 1\n\n[[package]]\nname = \"golden\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\ndependencies = [\n    { name = \"jinja2\" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = \"pytest\" },\n]\n\n[package.metadata]\nrequires-dist = [\n    { name = \"Jinja2\", specifier = \"==3.1.2\" },\n]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\", specifier = \"==7.4.0\" }]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"markupsafe\"\nversion = \"2.1.5\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"pytest\"\nversion = \"7.4.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        let got = parse(text).unwrap();
        let names: Vec<&str> = got.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["jinja2", "markupsafe", "pytest"]);
        assert_eq!((got[0].scope, got[0].direct), (Scope::Runtime, Some(true)));
        assert_eq!((got[1].scope, got[1].direct), (Scope::Unknown, Some(false)));
        assert_eq!((got[2].scope, got[2].direct), (Scope::Dev, Some(true)));
        assert_eq!(names_in("[{ name = \"a\", specifier = \">=1\" }, { name = 'B_c' }]"), ["a", "b-c"]);
    }
}
