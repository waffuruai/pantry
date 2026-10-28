//! `Pipfile.lock` → `PyPI`: the `default` and `develop` sections. Entries
//! pinned `==version` count; git, path and editable entries have no
//! version and are skipped. Names are normalized (PEP 503).

use super::{Package, plausible, requirements::normalize};
use crate::error::Result;
use crate::json::{self, str_at};
use serde_json::Value;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        for (name, entry) in data.get(section).and_then(Value::as_object).into_iter().flatten() {
            let Some(version) = str_at(entry, "version").strip_prefix("==") else { continue };
            if plausible(version) && !version.contains('*') {
                out.push(Package::new("PyPI", &normalize(name), version));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_and_pins() {
        let text = r#"{"_meta": {"hash": {"sha256": "x"}},
            "default": {"Jinja2": {"version": "==3.1.2"}, "local": {"editable": true, "path": "."},
                        "g": {"git": "https://github.com/x/g.git", "ref": "abc"}, "star": {"version": "*"}},
            "develop": {"pytest": {"version": "==7.4.0", "markers": "python_version >= '3.7'"}}}"#;
        assert_eq!(
            parse(text).unwrap(),
            [Package::new("PyPI", "jinja2", "3.1.2"), Package::new("PyPI", "pytest", "7.4.0")]
        );
    }
}
