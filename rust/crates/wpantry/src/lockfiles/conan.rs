//! `conan.lock` → `ConanCenter`. Conan 2 (lock version 0.5) lists
//! references under `requires`, `build_requires` and `python_requires`;
//! Conan 1 (0.4) under `graph_lock.nodes`, where the node with a `path` is
//! the consumer itself. A reference is `name/version[@user/channel][#rev]
//! [:package_id[#prev]][%timestamp]`; one with a user or channel is a
//! private recipe, not ConanCenter's, and is skipped.

use super::{Package, plausible};
use crate::error::Result;
use crate::json::{self, str_at};
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
mod tests {
    use super::*;

    #[test]
    fn references() {
        assert_eq!(
            reference("zlib/1.3.1#42bc0fa9eabcade24e42a0ddecfb8830%1793094518.3745675"),
            Some(("zlib", "1.3.1"))
        );
        assert_eq!(reference("zlib/1.2.11:5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9#prev"), Some(("zlib", "1.2.11")));
        assert_eq!(reference("mylib/1.0.0@acme/stable#810f"), None);
        assert_eq!(reference("conanfile"), None);
        let v04 = r#"{"version": "0.4", "graph_lock": {"nodes": {
            "0": {"path": "conanfile.txt", "requires": ["1"]},
            "1": {"ref": "openssl/3.2.0#rev", "requires": ["2"]},
            "2": {"pref": "zlib/1.3.1#rev:pkgid#prev", "ref": "ignored/0.0.1"}}}}"#;
        let got: Vec<String> = parse(v04).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
        assert_eq!(got, ["openssl 3.2.0", "zlib 1.3.1"]);
        let v05 = r#"{"version": "0.5", "requires": ["zlib/1.3.1#r%1"], "build_requires": ["cmake/3.28.1#r%1"], "python_requires": ["pyreq/1.0.0#r%1"], "config_requires": ["cfg/1.0#r"]}"#;
        let got: Vec<String> = parse(v05).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
        assert_eq!(got, ["zlib 1.3.1", "cmake 3.28.1", "pyreq 1.0.0"]);
    }
}
