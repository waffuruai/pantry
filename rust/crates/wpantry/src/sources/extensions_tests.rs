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
    assert!(vscode_lists(&c2, &gone, false).is_err(), "lists that are gone are unchecked, not empty");
    assert!(vscode_lists(&c, &gone, false).is_ok_and(|l| !l.malicious.is_empty()), "the last good lists stay");
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
