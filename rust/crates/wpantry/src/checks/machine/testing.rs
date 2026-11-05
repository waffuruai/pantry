//! What the machine tests share: a machine that answers commands from a
//! table, files written into a temporary directory, a scan over a temporary
//! cache, and canned OSV and release answers.

use crate::checks::Scan;
use crate::checks::machine::any::persistence::Roots;
use crate::checks::machine::settings::Runner;
use crate::component::Component;
use crate::db::Cache;
use crate::error::Result;
use crate::sources::releases;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// A machine's answers, keyed by the command's words: the first key the
/// command line contains wins.
pub fn machine(answers: &'static [(&'static str, &'static str)]) -> impl Fn(&[&str]) -> String {
    move |argv: &[&str]| {
        let joined = argv.join(" ");
        answers.iter().find(|(k, _)| joined.contains(k)).map(|(_, v)| v.to_string()).unwrap_or_default()
    }
}

/// Write `text` to `p`, making its directories.
pub fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A copy of /etc with the given files.
pub fn etc(files: &[(&str, &str)]) -> TempDir {
    let d = TempDir::new("etc").unwrap();
    for (rel, body) in files {
        write(&d.path().join(rel), body);
    }
    d
}

/// The persistence inventory's view of `dir`: `home` and `root` inside it.
pub fn roots<'a>(dir: &Path, macos: bool, runner: Runner<'a>) -> Roots<'a> {
    Roots { home: dir.join("home"), root: dir.join("root"), macos, runner }
}

pub(crate) fn scan<'a>(net: &'a Fake, d: &crate::utils::temp::TempDir) -> Scan<'a> {
    Scan::new(Default::default(), Cache::open(Some(&d.path().join("w.db"))).unwrap(), net, &|_| {}, &|_| {})
}

pub(crate) fn kinds(s: &Scan) -> Vec<(String, String, String)> {
    s.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone(), f.status.clone())).collect()
}

pub(crate) fn unchecked_note(s: &Scan, what: &str) -> String {
    s.findings
        .iter()
        .find(|f| f.kind == "unchecked" && f.component == what)
        .map(|f| f.note.clone())
        .unwrap_or_else(|| panic!("{what} isn't reported unchecked: {:?}", kinds(s)))
}

/// An OSV querybatch answer: the ids for each (package, version) asked.
pub(crate) fn querybatch(body: &[u8], answer: &dyn Fn(&str, &str) -> Vec<&'static str>) -> crate::utils::net::Response {
    let body: Value = serde_json::from_slice(body).unwrap();
    let results: Vec<Value> = crate::utils::json::arr_at(&body, "queries")
        .iter()
        .map(|q| {
            let ids =
                answer(crate::utils::json::str_at(&q["package"], "name"), crate::utils::json::str_at(q, "version"));
            let vulns: Vec<Value> = ids.iter().map(|id| serde_json::json!({"id": id, "modified": "m"})).collect();
            if vulns.is_empty() { serde_json::json!({}) } else { serde_json::json!({"vulns": vulns}) }
        })
        .collect();
    crate::utils::net::Response::ok(serde_json::json!({"results": results}).to_string())
}

pub(crate) fn npm_rec(id: &str, pkg: &str, fixed: Option<&str>, aliases: &[&str]) -> Value {
    let mut events = vec![serde_json::json!({"introduced": "0"})];
    if let Some(f) = fixed {
        events.push(serde_json::json!({"fixed": f}));
    }
    serde_json::json!({"id": id, "aliases": aliases, "modified": "m", "summary": format!("{id} summary"),
        "affected": [{"package": {"ecosystem": "npm", "name": pkg}, "ranges": [{"type": "SEMVER", "events": events}]}]})
}

pub(crate) fn app(name: &str, version: &str, extra: &[(&str, &str)]) -> Component {
    let mut c = Component::new("app", name, version, &format!("/Applications/{name}.app"));
    c.extra.insert("bundle".into(), format!("{name}.app"));
    for (k, v) in extra {
        if *k == "browser" {
            c.kind = "browser".into();
        }
        c.extra.insert(k.to_string(), v.to_string());
    }
    c
}

pub(crate) fn casks_body() -> String {
    serde_json::json!([
        {"token": "slack", "version": "4.41.100", "artifacts": [{"app": ["Slack.app"]}]},
        {"token": "zoom", "version": "6.2.0,1", "artifacts": [{"app": ["zoom.us.app"]}]},
        {"token": "notion", "version": "4.0.0", "artifacts": [{"app": ["Notion.app"]}]},
        {"token": "google-chrome", "version": "130.0.6723.117", "artifacts": [{"app": ["Google Chrome.app"]}]},
        {"token": "brave-browser", "version": "1.71.0", "artifacts": [{"app": ["Brave Browser.app"]}]},
        {"token": "arc", "version": "1.60.0", "artifacts": [{"app": ["Arc.app"]}]},
        {"token": "firefox", "version": "latest", "artifacts": [{"app": ["Firefox.app"]}]}
    ])
    .to_string()
}

/// The feeds the app check reads: casks, Chrome, Firefox and OSV.
pub(crate) fn app_net(r: &crate::utils::net::Request) -> Result<crate::utils::net::Response> {
    use crate::utils::net::Response;
    let url = r.url.as_str();
    if url == releases::CASKS_URL {
        return Ok(Response::ok(casks_body()));
    }
    if url.ends_with("/querybatch") {
        let body = r.body.clone().unwrap_or_default();
        return Ok(querybatch(&body, &|pkg, v| match (pkg, v) {
            ("electron", "33.4.11") => vec!["GHSA-e1"],
            ("electron", "34.0.0") => vec!["GHSA-e2"],
            ("electron", "35.0.0") => vec!["GHSA-e3"],
            _ => vec![],
        }));
    }
    if url.contains("/vulns/") {
        let id = url.rsplit('/').next().unwrap_or("");
        let rec = match id {
            "GHSA-e1" => npm_rec(id, "electron", Some("33.4.12"), &["CVE-2026-100"]),
            "GHSA-e2" => npm_rec(id, "electron", Some("34.0.1"), &[]),
            _ => npm_rec(id, "electron", None, &[]),
        };
        return Ok(Response::ok(rec.to_string()));
    }
    if url.starts_with("https://versionhistory.googleapis.com/") {
        // One release older than the grace period, one with no start.
        return Ok(Response::ok(
            serde_json::json!({"releases": [
                {"version": "130.0.6723.117", "serving": {"startTime": "2024-01-01T00:00:00Z"}},
                {"version": "129.0.0.0", "serving": {"startTime": ""}}
            ]})
            .to_string(),
        ));
    }
    if url.ends_with("firefox_versions.json") {
        return Ok(Response::ok(
            serde_json::json!({"LATEST_FIREFOX_VERSION": "132.0", "FIREFOX_ESR": "128.5.0esr", "FIREFOX_ESR_NEXT": ""})
                .to_string(),
        ));
    }
    if url.ends_with("firefox_history_major_releases.json") {
        return Ok(Response::ok(serde_json::json!({"132.0": "2024-10-29"}).to_string()));
    }
    if url.ends_with("firefox_history_stability_releases.json") {
        return Ok(Response::ok(serde_json::json!({"128.4.0": "2024-10-29"}).to_string()));
    }
    panic!("unexpected request {url}")
}

pub(crate) const FOO: &str = "https://github.com/jdx/foo.git";

pub(crate) fn rel(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}
