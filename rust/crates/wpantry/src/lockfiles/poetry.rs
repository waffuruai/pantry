//! `poetry.lock` (lock-version 1.x and 2.x) → `PyPI`. Every `[[package]]`
//! counts unless its `[package.source]` is `git`, `directory`, `file` or
//! `url`; `legacy` sources (other package indexes) are kept, as uv.lock's
//! other registries are. Lock-version 1 files carry each package's
//! `category` (`main` or `dev`); version 2 moved groups to pyproject.toml,
//! so there the scope stays unknown.

use super::{Package, Scope, toml};
use crate::error::Result;

const LOCAL: &[&str] = &["git", "directory", "file", "url"];

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out: Vec<(Package, bool)> = Vec::new();
    for t in toml::parse(text)? {
        if t.array && t.name == "package" {
            let scope = match t.str("category") {
                "main" => Scope::Runtime,
                "dev" => Scope::Dev,
                _ => Scope::Unknown,
            };
            out.push((Package::new("PyPI", t.str("name"), t.str("version")).scoped(scope), false));
        } else if !t.array
            && t.name == "package.source"
            && let Some((_, local)) = out.last_mut()
        {
            *local = LOCAL.contains(&t.str("type"));
        }
    }
    Ok(out.into_iter().filter(|(_, local)| !local).map(|(p, _)| p).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        let text = "[[package]]\nname = \"a\"\nversion = \"1.0\"\n\n[package.dependencies]\nb = {version = \"*\", markers = \"sys_platform == \\\"win32\\\"\"}\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"directory\"\nurl = \"local\"\n\n[[package]]\nname = \"private\"\nversion = \"2.0\"\n\n[package.source]\ntype = \"legacy\"\nurl = \"https://pypi.example.com/simple\"\nreference = \"private\"\n\n[[package]]\nname = \"g\"\nversion = \"3.0\"\n\n[package.source]\ntype = \"git\"\nurl = \"https://github.com/x/g.git\"\n\n[metadata]\nlock-version = \"2.1\"\n";
        assert_eq!(parse(text).unwrap(), [Package::new("PyPI", "a", "1.0"), Package::new("PyPI", "private", "2.0")]);
    }
}
