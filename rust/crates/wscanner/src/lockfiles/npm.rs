//! `package-lock.json` (and `npm-shrinkwrap.json`) → `npm`. v2 and v3 list
//! `packages` by install path; the name is the last `node_modules/` segment
//! (or the entry's own `name`, for aliases); links and workspace sources
//! are skipped. v1 nests `dependencies`; `npm:` aliases resolve to the
//! real package. Versions that aren't registry versions (file:, git) are
//! skipped.

use super::{Package, plausible};
use crate::error::Result;
use crate::json::{self, str_at};
use serde_json::Value;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let data = json::parse(text.as_bytes(), json::MAX_DOCUMENT)?;
    let mut out = Vec::new();
    if let Some(pkgs) = data.get("packages").and_then(Value::as_object) {
        for (path, p) in pkgs {
            let Some((_, last)) = path.rsplit_once("node_modules/") else { continue };
            if p.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = match str_at(p, "name") {
                "" => last,
                n => n,
            };
            let version = str_at(p, "version");
            if plausible(version) {
                out.push(Package::new("npm", name, version));
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
            out.push(Package::new("npm", name, version));
        }
    }
}
