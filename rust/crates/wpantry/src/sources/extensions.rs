//! Editor extensions: the lists VS Code itself downloads (malicious and
//! deprecated ids), and the latest versions from Microsoft's marketplace or
//! Open VSX.

use crate::db::{Cache, DAY};
use crate::error::Result;
use crate::utils::json::{self, str_at};
use crate::utils::net::{self, Net};
use serde_json::Value;

pub const VSCODE_LISTS: &str = "https://main.vscode-cdn.net/extensions/marketplace.json";
pub const MARKETPLACE: &str = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";
pub const OPENVSX: &str = "https://open-vsx.org/api/{}/{}/latest";

/// The lists VS Code itself downloads: malicious extension ids and
/// deprecated ones (id → replacement or ""), lowercased.
pub struct VscodeLists {
    pub malicious: std::collections::HashSet<String>,
    pub deprecated: std::collections::HashMap<String, String>,
}

pub fn vscode_lists(cache: &Cache, net: &dyn Net, offline: bool) -> Result<VscodeLists> {
    let fetch = || Ok(net::get_json(net, VSCODE_LISTS, &[])?.unwrap_or(Value::Object(serde_json::Map::new())));
    let data = cache.memo("vscode-lists", fetch, DAY, "", false, offline)?;
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
                if let Some(d) = net::get_json(net, &OPENVSX.replacen("{}", ns, 1).replacen("{}", name, 1), &[])? {
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
            let resp = net::request(
                net,
                MARKETPLACE,
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
    let v = cache.memo(&key, fetch, DAY, "", false, offline)?;
    Ok(v.as_object()
        .map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::testing::cache;
    use crate::utils::net::{Fake, Response};
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn vscode_lists_are_lowercased_with_replacements() {
        let (_d, c) = cache();
        let net = Fake::new(|_| {
            Ok(Response::ok(
                json!({"malicious": ["Bad.Ext", 5], "deprecated": {
                    "Old.One": {"extension": {"id": "New.One"}}, "Old.Two": {"additionalInfo": "gone"},
                    "Old.Three": {}, "Old.Four": true}})
                .to_string(),
            ))
        });
        let l = vscode_lists(&c, &net, false).unwrap();
        assert_eq!(l.malicious, HashSet::from(["bad.ext".to_string()]));
        let mut dep: Vec<(String, String)> = l.deprecated.into_iter().collect();
        dep.sort();
        assert_eq!(
            dep,
            [("old.four", ""), ("old.one", "New.One"), ("old.three", ""), ("old.two", "gone")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        let (_d2, c2) = cache();
        let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
        let l = vscode_lists(&c2, &gone, false).unwrap();
        assert!(l.malicious.is_empty() && l.deprecated.is_empty());
    }

    #[test]
    fn marketplace_picks_the_latest_stable_version_in_chunks_of_100() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert_eq!((r.method, r.header("Accept")), ("POST", Some("application/json;api-version=7.2-preview.1")));
            let q: Value = serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
            let n = json::arr_at(&q["filters"][0], "criteria").len();
            assert!(n <= 100 && q["filters"][0]["criteria"][0]["filterType"] == 7);
            if n < 100 {
                return Ok(Response::ok(json!({"results": []}).to_string()));
            }
            Ok(Response::ok(json!({"results": [{"extensions": [
                {"publisher": {"publisherName": "MS-Python"}, "extensionName": "Python", "versions": [
                    {"version": "2026.2.0", "properties": [{"key": "Microsoft.VisualStudio.Code.PreRelease", "value": "true"}]},
                    {"version": "2026.1.0"}]},
                {"publisher": {"publisherName": "X"}, "extensionName": "Y", "versions": [
                    {"version": "0.1.0", "properties": [{"key": "Microsoft.VisualStudio.Code.PreRelease"}]}]},
                {"extensionName": "NoVersions", "versions": []}
            ]}]}).to_string()))
        });
        let mut ids: Vec<String> = (0..99).map(|i| format!("pub.ext{i}")).collect();
        ids.push("ms-python.python".into());
        ids.push("ms-python.python".into());
        ids.push("x.y".into());
        let got = latest_extensions(&c, &net, &ids, false, false).unwrap();
        let mut rows: Vec<(String, String)> = got.into_iter().collect();
        rows.sort();
        assert_eq!(rows, [("ms-python.python".to_string(), "2026.1.0".to_string()), ("x.y".into(), "0.1.0".into())]);
        assert_eq!(net.requests().len(), 2, "101 distinct ids, two queries");
        assert!(latest_extensions(&c, &Fake::offline(), &["a.b".into()], false, true).is_err());
    }

    #[test]
    fn open_vsx_is_asked_per_extension() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            Ok(match r.url.as_str() {
                "https://open-vsx.org/api/ms-python/python/latest" => {
                    Response::ok(json!({"version": "2026.1.0"}).to_string())
                }
                "https://open-vsx.org/api/nodot//latest" => Response { status: 404, body: Vec::new(), etag: None },
                "https://open-vsx.org/api/a/b/latest" => Response::ok("{}"),
                u => panic!("{u}"),
            })
        });
        let ids: Vec<String> = ["ms-python.python", "nodot", "a.b"].map(String::from).to_vec();
        let got = latest_extensions(&c, &net, &ids, true, false).unwrap();
        assert_eq!(got, std::collections::HashMap::from([("ms-python.python".to_string(), "2026.1.0".to_string())]));
        assert_eq!(net.requests().len(), 3);
    }
}
