//! `conan.lock` → `ConanCenter`. Conan 2 (lock version 0.5) lists
//! references under `requires`, `build_requires` and `python_requires`;
//! Conan 1 (0.4) under `graph_lock.nodes`, where the node with a `path` is
//! the consumer itself. A reference is `name/version[@user/channel][#rev]
//! [:package_id[#prev]][%timestamp]`; one with a user or channel is a
//! private recipe, not ConanCenter's, and is skipped.

use super::{Package, plausible};
use crate::error::Result;
use crate::utils::json::{self, str_at};
use serde_json::Value;

/// (name, version) of a reference from ConanCenter.
pub fn reference(r: &str) -> Option<(&str, &str)> {
    let r = r.split('%').next()?.split(':').next()?.split('#').next()?;
    if r.contains('@') {
        return None;
    }
    let (name, version) = r.split_once('/')?;
    (!name.is_empty() && plausible(version)).then_some((name, version))
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut refs: Vec<&str> = Vec::new();
    if let Some(nodes) = data.get("graph_lock").and_then(|g| g.get("nodes")).and_then(Value::as_object) {
        for node in nodes.values().filter(|n| n.get("path").is_none()) {
            refs.push(match str_at(node, "pref") {
                "" => str_at(node, "ref"),
                p => p,
            });
        }
    } else {
        for key in ["requires", "build_requires", "python_requires"] {
            refs.extend(data.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str));
        }
    }
    Ok(refs.into_iter().filter_map(reference).map(|(n, v)| Package::new("ConanCenter", n, v)).collect())
}

#[cfg(test)]
#[path = "conan_tests.rs"]
mod tests;
