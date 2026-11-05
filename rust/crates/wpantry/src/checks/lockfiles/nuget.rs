//! `packages.lock.json` (NuGet lock v1 and v2, the latter with central
//! package management) → `NuGet`: every package of every target framework
//! at its `resolved` version; `Project` references are local and skipped.

use super::{Package, plausible};
use crate::error::Result;
use crate::utils::json::{self, str_at};
use serde_json::Value;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    for framework in data.get("dependencies").and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
        for (name, p) in framework.as_object().into_iter().flatten() {
            let version = str_at(p, "resolved");
            if str_at(p, "type") != "Project" && plausible(version) {
                out.push(Package::new("NuGet", name, version));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "nuget_tests.rs"]
mod tests;
