//! Editor extensions: the lists VS Code itself downloads (malicious and
//! deprecated ids), and the latest versions from Microsoft's marketplace or
//! Open VSX.

use crate::db::Cache;
use crate::error::Result;
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::json::{self, str_at};
use crate::utils::net::Net;
use serde_json::Value;

/// The lists VS Code itself downloads: malicious extension ids and
/// deprecated ones (id → replacement or ""), lowercased.
pub struct VscodeLists {
    pub malicious: std::collections::HashSet<String>,
    pub deprecated: std::collections::HashMap<String, String>,
}

pub fn vscode_lists(cache: &Cache, net: &dyn Net, offline: bool) -> Result<VscodeLists> {
    let fetch = || {
        let lists = fetch::get_json(net, "vscode-extension-lists", url("vscode-extension-lists"), &[])?;
        match lists {
            Some(v)
                if v.get("malicious").is_some_and(Value::is_array)
                    || v.get("deprecated").is_some_and(Value::is_object) =>
            {
                Ok(v)
            }
            _ => Err(fetch::invalid("vscode-extension-lists", "neither list in the answer")),
        }
    };
    let data = fetch::memo(cache, "vscode-extension-lists", "vscode-lists", fetch, "", false, offline)?;
    let mut deprecated = std::collections::HashMap::new();
    if let Some(m) = data.get("deprecated").and_then(Value::as_object) {
        for (ext, info) in m {
            let repl = match info {
                Value::Object(o) if !o.is_empty() => {
                    let id = info.get("extension").map(|e| str_at(e, "id")).unwrap_or("");
                    if id.is_empty() { str_at(info, "additionalInfo").to_string() } else { id.to_string() }
                }
                _ => String::new(),
            };
            deprecated.insert(ext.to_lowercase(), repl);
        }
    }
    let malicious = json::arr_at(&data, "malicious").iter().filter_map(Value::as_str).map(str::to_lowercase).collect();
    Ok(VscodeLists { malicious, deprecated })
}

/// {id: latest version} from Microsoft's marketplace, or Open VSX (which
/// Cursor, Windsurf and VSCodium install from). Unknown ids are left out.
pub fn latest_extensions(
    cache: &Cache,
    net: &dyn Net,
    ids: &[String],
    openvsx: bool,
    offline: bool,
) -> Result<std::collections::HashMap<String, String>> {
    let mut ids: Vec<String> = ids.to_vec();
    ids.sort();
    ids.dedup();
    let key = format!("{}:{}", if openvsx { "openvsx" } else { "marketplace" }, ids.join(","));
    let fetch = || -> Result<Value> {
        let mut out = serde_json::Map::new();
        if openvsx {
            for i in &ids {
                let (ns, name) = i.split_once('.').unwrap_or((i, ""));
                if let Some(d) = fetch::get_json(
                    net,
                    "open-vsx",
                    &url("open-vsx").replacen("{}", ns, 1).replacen("{}", name, 1),
                    &[],
                )? {
                    let v = str_at(&d, "version");
                    if !v.is_empty() {
                        out.insert(i.clone(), Value::String(v.into()));
                    }
                }
            }
            return Ok(Value::Object(out));
        }
        for chunk in ids.chunks(100) {
            let criteria: Vec<Value> = chunk.iter().map(|i| serde_json::json!({"filterType": 7, "value": i})).collect();
            let body = serde_json::json!({"filters": [{"criteria": criteria, "pageSize": 100}], "flags": 1 | 16});
            let resp = fetch::request(
                net,
                "vscode-marketplace",
                url("vscode-marketplace"),
                Some(&body),
                &[("Accept", "application/json;api-version=7.2-preview.1")],
                None,
            )?;
            let data = json::parse(&resp.body, json::MAX_DOCUMENT)?;
            let results = json::arr_at(&data, "results");
            for e in results.first().map(|r| json::arr_at(r, "extensions")).unwrap_or(&[]) {
                let ext = format!(
                    "{}.{}",
                    e.get("publisher").map(|p| str_at(p, "publisherName")).unwrap_or(""),
                    str_at(e, "extensionName")
                )
                .to_lowercase();
                let versions = json::arr_at(e, "versions");
                let pre = |v: &Value| {
                    json::arr_at(v, "properties")
                        .iter()
                        .any(|p| str_at(p, "key") == "Microsoft.VisualStudio.Code.PreRelease")
                };
                let stable: Vec<&str> = versions.iter().filter(|v| !pre(v)).map(|v| str_at(v, "version")).collect();
                let pick = stable.first().copied().or_else(|| versions.first().map(|v| str_at(v, "version")));
                if let Some(v) = pick {
                    out.insert(ext, Value::String(v.into()));
                }
            }
        }
        Ok(Value::Object(out))
    };
    let v =
        fetch::memo(cache, if openvsx { "open-vsx" } else { "vscode-marketplace" }, &key, fetch, "", false, offline)?;
    Ok(v.as_object()
        .map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default())
}

#[cfg(test)]
#[path = "extensions_tests.rs"]
mod tests;
