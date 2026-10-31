//! `composer.lock` → `Packagist`: `packages` and `packages-dev`. Packages
//! installed from a `path` repository are local and skipped, as are branch
//! versions (`dev-main`, `1.0.x-dev`). Versions are reported as Composer
//! writes them (`v6.4.0`); the Packagist comparator reads the "v".

use super::{Package, Scope, plausible};
use crate::error::Result;
use crate::json::{self, arr_at, str_at};

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    let sections = [("packages", Scope::Runtime), ("packages-dev", Scope::Dev)];
    for (section, scope) in sections {
        for p in arr_at(&data, section) {
            let path = |k: &str| p.get(k).map(|d| str_at(d, "type")) == Some("path");
            let version = str_at(p, "version");
            let bare = version.strip_prefix(['v', 'V']).unwrap_or(version);
            if path("dist") || path("source") || !plausible(bare) || version.ends_with("-dev") {
                continue;
            }
            out.push(Package::new("Packagist", str_at(p, "name"), version).scoped(scope));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_releases_only() {
        let text = r#"{"packages": [
            {"name": "symfony/yaml", "version": "v6.4.0", "dist": {"type": "zip"}},
            {"name": "example/local", "version": "1.0.0", "dist": {"type": "path", "url": "local"}},
            {"name": "example/branch", "version": "dev-main", "source": {"type": "git"}},
            {"name": "example/alias", "version": "2.1.x-dev"}],
          "packages-dev": [{"name": "psr/container", "version": "2.0.2"}]}"#;
        assert_eq!(
            parse(text).unwrap(),
            [
                Package::new("Packagist", "symfony/yaml", "v6.4.0").scoped(Scope::Runtime),
                Package::new("Packagist", "psr/container", "2.0.2").scoped(Scope::Dev)
            ]
        );
    }
}
