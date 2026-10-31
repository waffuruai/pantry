//! `pnpm-lock.yaml` → `npm`, read line by line. The `packages:` keys name
//! every installed package: v9 as `name@version`, v6 as `/name@version`,
//! v5 as `/name/version`; peer suffixes (`(…)`, v5's `_…`) are dropped. An
//! entry's own `name:` and `version:` (tarball and git dependencies) win
//! over its key. Local and git versions are skipped.
//!
//! The `importers:` section (v6+) lists what each project in the workspace
//! asks for, under `dependencies:`, `devDependencies:` and
//! `optionalDependencies:`: those are direct, with that scope; everything
//! else came with them. v5 and v6 also flag each package `dev: true|false`.

use super::{Package, Scope, lines, plausible};
use crate::error::Result;
use std::collections::BTreeMap;

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(['\'', '"'])
}

/// (name, version) from a `packages:` key.
fn split_key(key: &str, v5: bool) -> (String, String) {
    let key = unquote(key);
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next().unwrap_or(key);
    if v5 {
        return match key.rsplit_once('/') {
            Some((name, ver)) => (name.to_string(), ver.split('_').next().unwrap_or(ver).to_string()),
            None => (String::new(), String::new()),
        };
    }
    match key.rfind('@') {
        Some(i) if i > 0 => (key[..i].to_string(), key[i + 1..].to_string()),
        _ => (key.to_string(), String::new()),
    }
}

/// The version an importer's `version:` resolves to, without a peer suffix:
/// `18.2.0(react@18.2.0)` → `18.2.0`; an alias `ms@2.1.3` → (`ms`, `2.1.3`).
fn resolved(alias_or_version: &str) -> (Option<String>, String) {
    let v = unquote(alias_or_version);
    let v = v.split('(').next().unwrap_or(v);
    match v.rfind('@') {
        Some(i) if i > 0 => (Some(v[..i].to_string()), v[i + 1..].to_string()),
        _ => (None, v.to_string()),
    }
}

struct Entry {
    name: String,
    version: String,
    dev: Option<bool>,
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut entries: Vec<Entry> = Vec::new();
    // (name, version) the importers ask for, with the scope they ask under.
    let mut asked: BTreeMap<(String, String), Scope> = BTreeMap::new();
    let mut v5 = false;
    let mut section = "";
    let mut current: Option<Entry> = None;
    let mut flush = |cur: &mut Option<Entry>| {
        if let Some(e) = cur.take()
            && plausible(&e.version)
        {
            entries.push(e);
        }
    };
    // Inside importers: the dependency section and the dependency's name.
    let (mut imp_scope, mut imp_name): (Option<Scope>, Option<String>) = (None, None);
    for line in lines(text)? {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let item = line.trim();
        if indent == 0 {
            flush(&mut current);
            if let Some(v) = line.strip_prefix("lockfileVersion:") {
                v5 = unquote(v).starts_with('5');
            }
            section = match item.trim_end_matches(':') {
                "packages" => "packages",
                "importers" => "importers",
                _ => "",
            };
            continue;
        }
        match section {
            "packages" => {
                if indent == 2 && item.ends_with(':') {
                    flush(&mut current);
                    let (name, version) = split_key(&item[..item.len() - 1], v5);
                    current = Some(Entry { name, version, dev: None });
                } else if indent == 4
                    && let Some(cur) = current.as_mut()
                {
                    if let Some(n) = item.strip_prefix("name:") {
                        cur.name = unquote(n).to_string();
                    } else if let Some(v) = item.strip_prefix("version:") {
                        cur.version = unquote(v).to_string();
                    } else if let Some(d) = item.strip_prefix("dev:") {
                        cur.dev = Some(unquote(d) == "true");
                    }
                }
            }
            "importers" => match indent {
                4 => {
                    imp_scope = match item.trim_end_matches(':') {
                        "dependencies" => Some(Scope::Runtime),
                        "devDependencies" => Some(Scope::Dev),
                        "optionalDependencies" => Some(Scope::Optional),
                        _ => None,
                    };
                    imp_name = None;
                }
                6 if imp_scope.is_some() => imp_name = Some(unquote(item.trim_end_matches(':')).to_string()),
                8 => {
                    if let (Some(scope), Some(name), Some(v)) = (imp_scope, &imp_name, item.strip_prefix("version:")) {
                        let (alias, version) = resolved(v);
                        let key = (alias.unwrap_or_else(|| name.clone()), version);
                        let merged = match asked.get(&key) {
                            Some(Scope::Runtime) => Scope::Runtime,
                            Some(Scope::Optional) if scope == Scope::Dev => Scope::Optional,
                            _ => scope,
                        };
                        asked.insert(key, merged);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    flush(&mut current);
    let mut out = Vec::new();
    for e in entries {
        let mut p = Package::new("npm", &e.name, &e.version);
        if let Some(scope) = asked.get(&(e.name.clone(), e.version.clone())) {
            p = p.scoped(*scope).direct(true);
        } else {
            if !asked.is_empty() {
                p = p.direct(false);
            }
            if let Some(dev) = e.dev {
                p = p.scoped(if dev { Scope::Dev } else { Scope::Runtime });
            }
        }
        out.push(p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_across_versions() {
        assert_eq!(split_key("'@babel/core@7.22.0'", false), ("@babel/core".into(), "7.22.0".into()));
        assert_eq!(split_key("/react-dom@18.2.0(react@18.2.0)", false), ("react-dom".into(), "18.2.0".into()));
        assert_eq!(split_key("/@types/node/20.1.0", true), ("@types/node".into(), "20.1.0".into()));
        assert_eq!(split_key("/foo/1.0.0_react@18.2.0", true), ("foo".into(), "1.0.0".into()));
        assert_eq!(
            split_key("foo@https://codeload.github.com/x/y/tar.gz/abc", false).1,
            "https://codeload.github.com/x/y/tar.gz/abc"
        );
    }

    #[test]
    fn importers_say_what_is_direct_and_in_which_scope() {
        let text = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      debug:\n        specifier: 2.6.8\n        version: 2.6.8\n      my-ms:\n        specifier: npm:ms@2.1.3\n        version: ms@2.1.3\n      react-dom:\n        specifier: ^18\n        version: 18.2.0(react@18.2.0)\n    devDependencies:\n      minimist:\n        specifier: 1.2.5\n        version: 1.2.5\n\npackages:\n\n  debug@2.6.8:\n    resolution: {integrity: sha512-x}\n\n  minimist@1.2.5:\n    resolution: {integrity: sha512-x}\n\n  ms@2.0.0:\n    resolution: {integrity: sha512-x}\n\n  ms@2.1.3:\n    resolution: {integrity: sha512-x}\n\n  react-dom@18.2.0:\n    resolution: {integrity: sha512-x}\n";
        let got = parse(text).unwrap();
        let find = |n: &str, v: &str| got.iter().find(|p| p.name == n && p.version == v).unwrap();
        assert_eq!((find("debug", "2.6.8").scope, find("debug", "2.6.8").direct), (Scope::Runtime, Some(true)));
        assert_eq!((find("minimist", "1.2.5").scope, find("minimist", "1.2.5").direct), (Scope::Dev, Some(true)));
        assert_eq!((find("ms", "2.0.0").scope, find("ms", "2.0.0").direct), (Scope::Unknown, Some(false)));
        assert_eq!(find("ms", "2.1.3").direct, Some(true), "the alias resolves to the real package");
        assert_eq!(find("react-dom", "18.2.0").direct, Some(true), "the peer suffix is dropped");
        let v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /a@1.0.0:\n    resolution: {integrity: sha512-x}\n    dev: true\n\n  /b@2.0.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n";
        let got = parse(v6).unwrap();
        assert_eq!((got[0].scope, got[0].direct), (Scope::Dev, None), "no importers: directness unknown");
        assert_eq!(got[1].scope, Scope::Runtime);
    }
}
