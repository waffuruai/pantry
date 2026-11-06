//! What the supply-chain tests share: a scan over a temporary cache, repos
//! and lockfiles written to disk, and a fake OSV.

use crate::checks::supply_chain::repos::Repo;
use crate::checks::{Options, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::utils::net::{Fake, Request, Response};
use crate::utils::process;
use crate::utils::temp::TempDir;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A scan over a temporary cache. The malware scan is off: it would
/// fetch its rules before reading the files, and its tests are its own.
pub(crate) fn scan<'a>(net: &'a Fake, d: &TempDir, opts: Options) -> Scan<'a> {
    let opts = Options { no_malware: true, ..opts };
    Scan::new(opts, Cache::open(Some(&d.path().join("w.db"))).unwrap(), net, &|_| {}, &|_| {})
}

/// A repo directory (with a `.git`) under `d`.
pub(crate) fn repo(d: &TempDir, name: &str) -> Repo {
    let root = d.path().join(name);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    (name.to_string(), root)
}

pub(crate) fn write(root: &Path, rel: &str, text: impl AsRef<[u8]>) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// An executable script.
#[cfg(unix)]
pub(crate) fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// OSV's answers for `vulnerable` (ecosystem, name) pairs: one advisory
/// each (`GHSA-<name>`, fixed in 9.9.9) and a malicious record for
/// `MAL-*` ids; None for any other request.
pub(crate) fn osv(r: &Request, vulnerable: &[(&str, &str)]) -> Option<Result<Response>> {
    if r.url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
        return Some(Ok(Response::not_found()));
    }
    if r.url.ends_with("/v1/querybatch") {
        let body: Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
        let results: Vec<Value> = body["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                let eco = q["package"]["ecosystem"].as_str().unwrap_or("");
                let name = q["package"]["name"].as_str().unwrap_or("");
                if vulnerable.contains(&(eco, name)) {
                    json!({"vulns": [{"id": format!("GHSA-{name}"), "modified": "2026-01-01T00:00:00Z"}]})
                } else {
                    json!({})
                }
            })
            .collect();
        return Some(Ok(Response::ok(json!({"results": results}).to_string())));
    }
    let id = r.url.strip_prefix("https://api.osv.dev/v1/vulns/")?;
    if let Some(name) = id.strip_prefix("GHSA-") {
        let (eco, _) = vulnerable.iter().find(|(_, n)| *n == name)?;
        let rec = json!({
            "id": id, "modified": "2026-01-01T00:00:00Z", "summary": format!("{name} is broken"),
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]
        });
        return Some(Ok(Response::ok(rec.to_string())));
    }
    if id.starts_with("MAL-") {
        let rec = json!({"id": id, "modified": "2026-01-01T00:00:00Z", "summary": format!("{id} is malicious")});
        return Some(Ok(Response::ok(rec.to_string())));
    }
    None
}

pub(crate) fn osv_net(vulnerable: &'static [(&'static str, &'static str)]) -> Fake {
    Fake::new(move |r| osv(r, vulnerable).unwrap_or_else(|| panic!("unexpected request to {}", r.url)))
}

/// A fresh malicious-package index, so the sweep doesn't clone it.
pub(crate) fn seed_index(d: &TempDir, rows: &[(&str, &str, &str)]) {
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    for (eco, name, id) in rows {
        c.conn.execute("INSERT INTO malicious VALUES (?, ?, ?)", [eco, name, id]).unwrap();
    }
    c.touch("malicious_at").unwrap();
    c.close().unwrap();
}

pub(crate) fn by_id<'a>(s: &'a Scan, id: &str) -> Vec<&'a Finding> {
    s.findings.iter().filter(|f| f.vuln_id == id).collect()
}

pub(crate) fn unchecked<'a>(s: &'a Scan) -> Vec<&'a str> {
    s.findings.iter().filter(|f| f.kind == "unchecked").map(|f| f.component.as_str()).collect()
}

pub(crate) const CARGO_LOCK: &str = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"sedre\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

/// A git repo made here with a private HOME; None when git can't.
pub(crate) fn git_repo(d: &TempDir, name: &str, args: &[&[&str]]) -> Option<Repo> {
    let home = d.path().join("git-home");
    let root = d.path().join(name);
    std::fs::create_dir_all(&home).ok()?;
    std::fs::create_dir_all(&root).ok()?;
    for a in args {
        let mut full: Vec<&OsStr> = vec![OsStr::new("git"), OsStr::new("-C"), root.as_os_str()];
        full.extend(["-c", "user.name=w", "-c", "user.email=w@example.invalid"].map(OsStr::new));
        full.extend(a.iter().map(OsStr::new));
        let env = [("HOME", home.to_str().unwrap()), ("GIT_CONFIG_NOSYSTEM", "1")];
        if !process::exec(&full, &env, Duration::from_secs(30)).is_ok_and(|o| o.code == Some(0)) {
            return None;
        }
    }
    Some((name.to_string(), root))
}

pub(crate) fn extension(id: &str, version: &str, market: &str, dir: &str) -> Component {
    let mut c = Component::new("extension", &id.to_lowercase(), version, dir);
    c.osv = Some((crate::checks::machine::editors::ecosystem(market).into(), id.into(), version.into()));
    for (k, v) in [("editor", "VS Code"), ("market", market), ("cli", "code"), ("id", id), ("dir", dir)] {
        c.extra.insert(k.into(), v.into());
    }
    c
}
