//! A whole repo scan against a recording fake network: lockfile → OSV
//! querybatch → records → findings, with KEV marks and alias grouping.

use serde_json::{Value, json};
use std::sync::Mutex;
use wpantry::check::{Options, Scan};
use wpantry::db::Cache;
use wpantry::net::{Fake, Response};

const LOCK: &str = r#"version = 4

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["itoa", "smallvec"]

[[package]]
name = "itoa"
version = "1.0.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "af150ab688ff2122fcef229be89cb50dd66af9e01a4ff320cc137eecc9bacc38"

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0"
"#;

fn record(id: &str, aliases: &[&str]) -> Value {
    json!({
        "id": id, "aliases": aliases, "modified": "2026-01-01T00:00:00Z",
        "summary": "Buffer overflow in SmallVec::insert_many",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"ecosystem": "crates.io", "name": "smallvec"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.6.3"}, {"fixed": "0.6.14"},
                                                                {"introduced": "1.0.0"}, {"fixed": "1.6.1"}]}]}]
    })
}

#[test]
fn repo_scan_end_to_end() {
    let tmp = wpantry::system::TempDir::new("scan").unwrap();
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("Cargo.lock"), LOCK).unwrap();
    let db = tmp.path().join("w.db");
    {
        // A fresh malicious-package index, so the sweep doesn't clone it.
        let c = Cache::open(Some(&db)).unwrap();
        c.conn.execute("INSERT INTO malicious VALUES ('crates.io', 'evil', 'MAL-0')", []).unwrap();
        c.touch("malicious_at").unwrap();
        c.close().unwrap();
    }
    let queried = std::sync::Arc::new(Mutex::new(Vec::new()));
    let q = queried.clone();
    let net = Fake::new(move |r| {
        if r.url.contains("cisa.gov") {
            return Ok(Response::ok(json!({"vulnerabilities": [{"cveID": "CVE-2021-25900"}]}).to_string()));
        }
        if r.url.ends_with("/v1/querybatch") {
            let body: Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
            let results: Vec<Value> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|query| {
                    q.lock().unwrap().push(format!(
                        "{} {}",
                        query["package"]["name"].as_str().unwrap(),
                        query["version"].as_str().unwrap()
                    ));
                    if query["package"]["name"] == "smallvec" {
                        json!({"vulns": [{"id": "GHSA-43w2-9j62-hq99", "modified": "2026-01-01T00:00:00Z"},
                                         {"id": "RUSTSEC-2021-0003", "modified": "2026-01-01T00:00:00Z"}]})
                    } else {
                        json!({})
                    }
                })
                .collect();
            return Ok(Response::ok(json!({"results": results}).to_string()));
        }
        if let Some(id) = r.url.strip_prefix("https://api.osv.dev/v1/vulns/") {
            let rec = match id {
                "RUSTSEC-2021-0003" => record(id, &["CVE-2021-25900", "GHSA-43w2-9j62-hq99"]),
                _ => record(id, &["CVE-2021-25900"]),
            };
            return Ok(Response::ok(rec.to_string()));
        }
        panic!("unexpected request to {}", r.url);
    });
    let opts = Options { paths: Some(vec![project.clone()]), machine: false, ..Default::default() };
    let cache = Cache::open(Some(&db)).unwrap();
    let out = Scan::new(opts, cache, &net, &|_| {}, &|_| {}).run().unwrap();

    let mut asked = queried.lock().unwrap().clone();
    asked.sort();
    assert_eq!(asked, ["itoa 1.0.9", "smallvec 1.6.0"], "only crates.io packages, not the workspace member");
    assert!(out.counts.contains(&("project dependencies".to_string(), 2)));
    let projects: Vec<_> = out.findings.iter().filter(|f| f.kind == "project").collect();
    assert_eq!(projects.len(), 1, "two databases' records of one CVE are one finding: {projects:?}");
    let f = projects[0];
    let dir = std::fs::canonicalize(&project).unwrap();
    assert_eq!(
        (
            f.component.as_str(),
            f.version.as_str(),
            f.vuln_id.as_str(),
            f.status.as_str(),
            f.fixed.as_str(),
            f.kev,
            f.severity.as_str()
        ),
        ("smallvec", "1.6.0", "CVE-2021-25900", "fail", "1.6.1", true, "CRITICAL")
    );
    assert_eq!(f.location, dir.join("Cargo.lock").to_string_lossy());
    assert_eq!(f.fix_cmd, format!("cd {} && cargo update -p smallvec --precise 1.6.1", dir.display()));
    assert!(
        !out.findings.iter().any(|f| f.component.contains("licenses")),
        "licenses are checked only with --licenses"
    );

    // The findings are the cache's latest, and a second run the same day asks nothing.
    let cache = Cache::open(Some(&db)).unwrap();
    let n: i64 =
        cache.conn.query_row("SELECT COUNT(*) FROM findings WHERE kind = 'project'", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
    let quiet = Fake::new(|r| panic!("cached answers are fresh, but asked {}", r.url));
    let opts = Options { paths: Some(vec![project]), machine: false, ..Default::default() };
    let again = Scan::new(opts, cache, &quiet, &|_| {}, &|_| {}).run().unwrap();
    assert_eq!(again.findings.iter().filter(|f| f.kind == "project").count(), 1);
}
