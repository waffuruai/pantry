//! `Pipfile.lock` → `PyPI`: the `default` and `develop` sections. Entries
//! pinned `==version` count; git, path and editable entries have no
//! version and are skipped. Names are normalized (PEP 503).

use super::{Package, Scope, plausible, requirements::normalize};
use crate::error::Result;
use crate::utils::json::{self, str_at};
use serde_json::Value;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    for (section, scope) in [("default", Scope::Runtime), ("develop", Scope::Dev)] {
        for (name, entry) in data.get(section).and_then(Value::as_object).into_iter().flatten() {
            let Some(version) = str_at(entry, "version").strip_prefix("==") else { continue };
            if plausible(version) && !version.contains('*') {
                out.push(Package::new("PyPI", &normalize(name), version).scoped(scope));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "pipenv_tests.rs"]
mod tests;
