//! Offline regression fixtures for the advisory boundaries checked on
//! 2026-10-30 (tests/advisories/2026-10-30): the public OSV records as they
//! stood, replayed through the cache, against synthetic lockfiles that hold the
//! last affected and the first fixed version of each control. The binary must
//! report every affected control with the fix OSV names, and nothing for the
//! fixed ones.
//!
//!     cargo test -p wpantry-cli --test advisories [--release]

mod common;

use common::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/advisories/2026-10-30")
}

/// (ecosystem, package as the cache keys it, affected version, fixed version, OSV record id).
/// The package name is the PEP 503 normalized one for PyPI; the lockfiles spell
/// some of them differently (Authlib, Twisted, langgraph_sdk) on purpose.
const CONTROLS: &[(&str, &str, &str, &str, &str)] = &[
    ("crates.io", "zip", "9.0.4", "9.0.5", "GHSA-m665-v7pm-7grj"),
    ("crates.io", "zip", "8.6.0", "9.0.0", "GHSA-hjqx-j4rw-g7xv"),
    ("crates.io", "wasmtime", "48.0.6", "48.0.7", "GHSA-mghf-wjfp-p5xm"),
    ("PyPI", "mlflow", "3.16.0", "3.17.0", "GHSA-26p8-2jq9-3vq9"),
    ("npm", "better-auth", "1.7.6", "1.7.7", "GHSA-965c-763c-88jm"),
    ("PyPI", "authlib", "1.8.0", "1.9.0", "GHSA-6v38-4h7w-rj9h"),
    ("npm", "@sylphx/pdf-reader-mcp", "3.0.0", "3.0.1", "GHSA-q344-5v34-gm84"),
    ("PyPI", "twisted", "26.4.0", "26.10.0rc1", "GHSA-vpp8-g58w-m8mp"),
    ("npm", "vite", "6.4.4", "6.4.5", "GHSA-8g5g-mxqh-grgj"),
    ("npm", "decode-uri-component", "0.5.0", "0.5.1", "GHSA-qr28-fpjm-wq7f"),
    ("PyPI", "langgraph-sdk", "0.4.5", "0.4.6", "GHSA-3fx2-cqw9-xr3c"),
];
/// The KEV decoration control is synthetic (tests/advisories/2026-10-30/README.md):
/// the CVE is in CISA's catalog, the crates.io range is invented.
const KEV_CONTROL: (&str, &str, &str, &str, &str, &str) =
    ("crates.io", "brotli", "8.0.1", "8.0.2", "WPANTRY-TEST-KEV-1", "CVE-2026-111497");

fn records() -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let dir = fixtures().join("osv");
    for name in names(&dir).into_iter().filter(|n| n.ends_with(".json")) {
        let rec: Value = serde_json::from_str(&read(&dir.join(name))).unwrap();
        out.insert(str_(&rec["id"]).to_string(), rec);
    }
    out
}

/// One dotted part of a version: its leading number (-1 for none) and the rest.
fn key(v: &str) -> Vec<(i64, String)> {
    v.replace('-', ".")
        .split('.')
        .map(|p| {
            let digits = p.chars().take_while(|c| c.is_ascii_digit()).count();
            (if digits > 0 { p[..digits].parse().unwrap() } else { -1 }, p[digits..].to_string())
        })
        .collect()
}

fn lt(a: &str, b: &str) -> bool {
    let (ka, kb) = (key(a), key(b));
    let fill = (0, String::new());
    for i in 0..ka.len().max(kb.len()) {
        let (x, y) = (ka.get(i).unwrap_or(&fill), kb.get(i).unwrap_or(&fill));
        if x != y {
            if x.0 != y.0 {
                return x.0 < y.0;
            }
            // a tag ("rc1") sorts before the bare release
            return (!x.1.is_empty() && y.1.is_empty()) || (!x.1.is_empty() && !y.1.is_empty() && x.1 < y.1);
        }
    }
    false
}

/// Whether the record's own ranges put this version inside an affected
/// interval, by the same reading a person would do on the record. Only
/// used to seed what OSV would have answered; the binary does its own
/// comparison when it picks the fix.
fn applies(rec: &Value, eco: &str, name: &str, version: &str) -> bool {
    let empty = Vec::new();
    for a in rec["affected"].as_array().unwrap_or(&empty) {
        let p = &a["package"];
        if p["ecosystem"] != eco || p["name"] != name {
            continue;
        }
        for r in a["ranges"].as_array().unwrap_or(&empty) {
            let mut inside = false;
            for e in r["events"].as_array().unwrap_or(&empty) {
                if let Some(introduced) = e.get("introduced") {
                    let introduced = str_(introduced);
                    inside = introduced == "0" || !lt(version, introduced);
                } else if let Some(fixed) = e.get("fixed")
                    && inside
                    && !lt(version, str_(fixed))
                {
                    inside = false;
                }
            }
            if inside {
                return true;
            }
        }
    }
    false
}

/// A temp HOME and cache per test, the fixtures copied in as two checkouts.
struct Advisories {
    t: Ctx,
    root: PathBuf,
    records: BTreeMap<String, Value>,
}

impl Advisories {
    fn new() -> Advisories {
        let t = Ctx::with_unset(&["XDG_CACHE_HOME"]);
        let root = t.home.join("advisories");
        for repo in ["affected", "fixed"] {
            copy_tree(&fixtures().join(repo), &root.join(repo));
            mkdir(&root.join(repo).join(".git"));
        }
        Advisories { t, root, records: records() }
    }

    fn check(&self, paths: &[&Path]) -> (i32, Value) {
        let mut argv = vec!["scan", "--no-machine", "--offline", "--no-input", "--json"];
        for p in paths {
            argv.extend(["--path", s(p)]);
        }
        let r = self.t.run(&argv);
        assert!([0, 1].contains(&r.code), "{}", r.err);
        (r.code, r.json())
    }

    /// What OSV answered on 2026-10-31 for each control, replayed into the
    /// cache: the records, one `queries` row per (ecosystem, package, version)
    /// and CISA's KEV entry.
    fn seed(&self) {
        // creates the schema
        self.t.run(&["scan", "--no-machine", "--offline", "--no-input", "--json", "--path", s(&self.t.tmp)]);
        let conn = self.t.conn();
        for rec in self.records.values() {
            store(&conn, rec);
        }
        let now = now();
        let kev = (KEV_CONTROL.0, KEV_CONTROL.1, KEV_CONTROL.2, KEV_CONTROL.3, KEV_CONTROL.4);
        for &(eco, name, affected, fixed, _) in CONTROLS.iter().chain([&kev]) {
            for version in [affected, fixed] {
                let ids: Vec<&str> = self
                    .records
                    .iter()
                    .filter(|(_, r)| applies(r, eco, name, version))
                    .map(|(i, _)| i.as_str())
                    .collect(); // sorted: the map's order
                insert_query(&conn, "INSERT OR REPLACE", eco, name, version, now, &ids.join(" "));
            }
        }
        let kev: Value = serde_json::from_str(&read(&fixtures().join("kev.json"))).unwrap();
        for v in arr(&kev["vulnerabilities"]) {
            conn.execute(
                "INSERT OR REPLACE INTO kev VALUES (?, ?, ?)",
                rusqlite::params![str_(&v["cveID"]), str_(&v["dateAdded"]), str_(&v["vulnerabilityName"])],
            )
            .unwrap();
        }
    }

    fn ids_of(&self, rec_id: &str) -> BTreeSet<String> {
        ids_of(&self.records[rec_id])
    }

    fn findings_for<'a>(&self, env: &'a Value, name: &str, version: &str, rec_id: &str) -> Vec<&'a Value> {
        let ids = self.ids_of(rec_id);
        arr(&env["findings"])
            .iter()
            .filter(|f| {
                f["kind"] == "project"
                    && f["component"] == name
                    && f["version"] == version
                    && ids.contains(str_(&f["vuln_id"]))
            })
            .collect()
    }
}

fn ids_of(rec: &Value) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = [str_(&rec["id"]).to_string()].into();
    if let Some(aliases) = rec["aliases"].as_array() {
        ids.extend(aliases.iter().map(|a| str_(a).to_string()));
    }
    ids
}

/// `rec.get(k, "")`, a string.
fn field<'a>(rec: &'a Value, k: &str) -> &'a str {
    rec.get(k).map(str_).unwrap_or("")
}

/// A record into `vulns`, as OSV's answer was cached.
fn store(conn: &rusqlite::Connection, rec: &Value) {
    let aliases: Vec<&str> = rec["aliases"].as_array().map(|a| a.iter().map(str_).collect()).unwrap_or_default();
    let severity = rec["database_specific"]["severity"].as_str().unwrap_or("");
    let id = str_(&rec["id"]);
    let url = format!("https://osv.dev/vulnerability/{id}");
    insert_vuln(
        conn,
        "INSERT OR REPLACE",
        [
            id,
            &aliases.join(" "),
            field(rec, "summary"),
            field(rec, "details"),
            severity,
            field(rec, "published"),
            field(rec, "modified"),
            &url,
            &rec.to_string(),
        ],
    );
}

fn unchecked_repo_dependencies(env: &Value) -> Vec<&Value> {
    arr(&env["findings"])
        .iter()
        .filter(|f| f["kind"] == "unchecked" && str_(&f["component"]).starts_with("repo dependencies"))
        .collect()
}

// the controls -------------------------------------------------------------

/// The seeding reads the ranges the way the issue's table does.
#[test]
fn seeded_answers_match_the_records_own_ranges() {
    let a = Advisories::new();
    for &(eco, name, affected, fixed, rec_id) in CONTROLS {
        let rec = &a.records[rec_id];
        assert!(applies(rec, eco, name, affected), "{rec_id} {affected}");
        assert!(!applies(rec, eco, name, fixed), "{rec_id} {fixed}");
    }
    // zip 9.0.0 fixes one family and is still in the other's range
    assert!(applies(&a.records["GHSA-m665-v7pm-7grj"], "crates.io", "zip", "9.0.0"));
    assert!(!applies(&a.records["GHSA-hjqx-j4rw-g7xv"], "crates.io", "zip", "9.0.0"));
    // wasmtime's branches: 48.0.7 is out, 49.0.0 is back in
    assert!(!applies(&a.records["GHSA-mghf-wjfp-p5xm"], "crates.io", "wasmtime", "48.0.7"));
    assert!(applies(&a.records["GHSA-mghf-wjfp-p5xm"], "crates.io", "wasmtime", "49.0.0"));
}

#[test]
fn affected_controls_fail_with_the_fix_osv_names() {
    let a = Advisories::new();
    a.seed();
    let (code, env) = a.check(&[&a.root.join("affected")]);
    assert_eq!(env["checked"]["project dependencies"], 12, "{}", env["checked"]);
    assert_eq!(env["checked"]["git repos"], 1);
    for &(_, name, affected, fixed, rec_id) in CONTROLS {
        let got = a.findings_for(&env, name, affected, rec_id);
        let all: Vec<&str> = arr(&env["findings"]).iter().map(|f| str_(&f["vuln_id"])).collect();
        assert_eq!(got.len(), 1, "{rec_id} {name} {affected} {all:?}");
        let f = got[0];
        assert_eq!((str_(&f["status"]), str_(&f["fixed"])), ("fail", fixed), "{f}");
        assert!(str_(&f["fix_cmd"]).contains(fixed), "{}", f["fix_cmd"]); // the fix command names the safe version
        if a.records[rec_id]["aliases"].as_array().is_some_and(|v| !v.is_empty()) {
            assert!(str_(&f["vuln_id"]).starts_with("CVE-"), "{f}"); // the CVE alias is the id shown
        } else {
            assert_eq!(f["vuln_id"], rec_id, "{f}"); // Twisted's record has no alias
        }
    }
    // Branch-specific fixes: the fix for wasmtime 48.0.6 is on its own line.
    let wasmtime = a.findings_for(&env, "wasmtime", "48.0.6", "GHSA-mghf-wjfp-p5xm")[0];
    assert_eq!(wasmtime["fixed"], "48.0.7");
    // A prerelease is a released fix when it is the only one.
    let twisted = a.findings_for(&env, "twisted", "26.4.0", "GHSA-vpp8-g58w-m8mp")[0];
    assert_eq!(twisted["fixed"], "26.10.0rc1");
    // zip 8.6.0 is in both families, each with its own fix.
    let mut both: Vec<&str> = arr(&env["findings"])
        .iter()
        .filter(|f| f["component"] == "zip" && f["version"] == "8.6.0" && f["kind"] == "project")
        .map(|f| str_(&f["fixed"]))
        .collect();
    both.sort();
    assert_eq!(both, ["9.0.0", "9.0.5"]);
    // Every cached answer was used: nothing about these dependencies is unchecked.
    assert!(unchecked_repo_dependencies(&env).is_empty());
    // Exit 1 for the fails above (a missing gitleaks on the runner is a `tool` fail, not ours).
    assert!(arr(&env["findings"]).iter().any(|f| f["status"] == "fail"));
    assert_eq!(code, 1);
}

#[test]
fn fixed_controls_are_not_reported_and_zip_9_0_0_still_is() {
    let a = Advisories::new();
    a.seed();
    let (_, env) = a.check(&[&a.root.join("fixed")]);
    assert_eq!(env["checked"]["project dependencies"], 12, "{}", env["checked"]);
    for &(_, name, _, fixed, rec_id) in CONTROLS {
        if (name, fixed) == ("zip", "9.0.0") {
            continue;
        }
        assert!(a.findings_for(&env, name, fixed, rec_id).is_empty(), "{rec_id} {name} {fixed}");
    }
    // zip 9.0.0 fixes GHSA-hjqx-j4rw-g7xv and is still affected by GHSA-m665-v7pm-7grj:
    // a negative control for one family is not a clean verdict on the version.
    assert!(a.findings_for(&env, "zip", "9.0.0", "GHSA-hjqx-j4rw-g7xv").is_empty());
    let still: Vec<(&str, &str)> = a
        .findings_for(&env, "zip", "9.0.0", "GHSA-m665-v7pm-7grj")
        .iter()
        .map(|f| (str_(&f["status"]), str_(&f["fixed"])))
        .collect();
    assert_eq!(still, [("fail", "9.0.5")]);
    let project_fails: Vec<&Value> =
        arr(&env["findings"]).iter().filter(|f| f["status"] == "fail" && f["kind"] == "project").collect();
    assert_eq!(project_fails.len(), 1, "{project_fails:?}");
    assert!(unchecked_repo_dependencies(&env).is_empty());
}

/// A cached answer may name the CVE (another database's row) rather
/// than the GHSA: the finding must still appear, under the record stored.
#[test]
fn a_record_is_found_under_its_alias_too() {
    let a = Advisories::new();
    a.seed();
    {
        let conn = a.t.conn();
        // Re-store vite's record under its CVE id, with the GHSA as the alias,
        // and point the answer at that id: a CVE-form row can't evade a check.
        let mut rec = a.records["GHSA-8g5g-mxqh-grgj"].clone();
        rec["id"] = "CVE-2026-118662".into();
        rec["aliases"] = serde_json::json!(["GHSA-8g5g-mxqh-grgj"]);
        conn.execute("DELETE FROM vulns WHERE id = ?", ["GHSA-8g5g-mxqh-grgj"]).unwrap();
        store(&conn, &rec);
        conn.execute(
            "UPDATE queries SET vuln_ids = ? WHERE ecosystem = 'npm' AND package = 'vite' AND version = '6.4.4'",
            ["CVE-2026-118662"],
        )
        .unwrap();
    }
    let (_, env) = a.check(&[&a.root.join("affected")]);
    let vite: Vec<(&str, &str, &str)> = arr(&env["findings"])
        .iter()
        .filter(|f| f["component"] == "vite" && f["version"] == "6.4.4")
        .map(|f| (str_(&f["vuln_id"]), str_(&f["fixed"]), str_(&f["status"])))
        .collect();
    assert_eq!(vite, [("CVE-2026-118662", "6.4.5", "fail")]);
}

/// requirements.txt spells Authlib, Twisted and langgraph_sdk; the cache
/// holds PEP 503 keys. The findings carry the normalized names and the
/// export shows every alias.
#[test]
fn pypi_names_are_normalized_to_the_cache_keys() {
    let a = Advisories::new();
    a.seed();
    let (_, env) = a.check(&[&a.root.join("affected")]);
    let pypi: BTreeSet<&str> = arr(&env["findings"])
        .iter()
        .filter(|f| f["kind"] == "project" && str_(&f["location"]).ends_with("requirements.txt"))
        .map(|f| str_(&f["component"]))
        .collect();
    assert_eq!(pypi.into_iter().collect::<Vec<_>>(), ["authlib", "langgraph-sdk", "mlflow", "twisted"]);
    let keys: Vec<String> = {
        let conn = a.t.conn();
        let mut st = conn.prepare("SELECT package FROM queries WHERE ecosystem = 'PyPI'").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
    };
    assert!(!keys.is_empty());
    for k in &keys {
        assert_eq!(*k, k.to_lowercase().replace(['_', '.'], "-"), "{k}");
    }
    let out = a.t.tmp.join("f.csv");
    let r = a.t.run(&["report", "--csv", "-o", s(&out)]);
    assert_eq!(r.code, 1, "export exits as the scan did: these fail");
    let rows = csv_dicts(&read(&out));
    for &(_, name, affected, fixed, rec_id) in CONTROLS {
        // One row per (id, component, version); zip 8.6.0 has two.
        let exported: Vec<BTreeSet<String>> = rows
            .iter()
            .filter(|r| r["component"] == name && r["affected_version"] == affected && r["safe_version"] == fixed)
            .map(|r| {
                let mut ids: BTreeSet<String> = [r["id"].clone()].into();
                ids.extend(r["aliases"].split_whitespace().map(String::from));
                ids
            })
            .collect();
        assert_eq!(exported.len(), 1, "{name} {affected} {fixed} {exported:?}");
        assert!(!exported[0].is_disjoint(&a.ids_of(rec_id)), "{name} {exported:?}");
    }
}

/// A finding whose record carries a KEV CVE is marked `kev` from the
/// cached catalog; the range is synthetic (see the fixture README).
#[test]
fn kev_decoration_from_the_offline_catalog() {
    let a = Advisories::new();
    a.seed();
    let (_, name, affected, fixed, _, cve) = KEV_CONTROL;
    let (_, env) = a.check(&[&a.root.join("affected")]);
    let got: Vec<Value> = arr(&env["findings"])
        .iter()
        .filter(|f| f["component"] == name && f["version"] == affected)
        .map(|f| serde_json::json!([f["vuln_id"], f["kev"], f["fixed"], f["status"]]))
        .collect();
    assert_eq!(got, [serde_json::json!([cve, true, fixed, "fail"])]);
    // The real controls are not in KEV.
    for &(_, n, aff, _, r) in CONTROLS {
        for f in a.findings_for(&env, n, aff, r) {
            assert_eq!(f["kev"], false, "{f}");
        }
    }
    let (_, env) = a.check(&[&a.root.join("fixed")]);
    assert!(arr(&env["findings"]).iter().all(|f| f["component"] != name));
}
