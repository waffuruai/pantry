//! Advisories on this machine: a folder of OSV records as a source of the
//! person's own (`kind = "advisories"`, `format = "osv-dir"`;
//! specs/design/sources-file.md), from the outside. The built binary runs
//! with a temp HOME and cache, `--offline --no-input`, so nothing is
//! fetched and nothing can be asked. The oracle is the scan's JSON (a
//! finding on the locked package naming the record's id, its fix and its
//! source), `report --jsonl` and `report --csv` (the record's own link,
//! never an OSV.dev one) and `sources --json` (what the folder held).
//!
//!     cargo test -p wpantry-cli --test local_advisories

mod common;

use common::*;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const ID: &str = "TEAM-2026-0001";
const LINK: &str = "https://advisories.example.com/TEAM-2026-0001";

/// The team's record: `acme-internal-widget` below 1.2.4, a package link
/// first and its advisory page second.
fn record() -> Value {
    json!({
        "schema_version": "1.6.0",
        "id": ID,
        "modified": "2026-11-20T00:00:00Z",
        "summary": "acme-internal-widget leaks its signing key",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "acme-internal-widget"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]
        }],
        "references": [
            {"type": "PACKAGE", "url": "https://registry.example.com/acme-internal-widget"},
            {"type": "ADVISORY", "url": LINK}
        ]
    })
}

/// A temp HOME with a repo locking `acme-internal-widget@1.2.3` and a
/// folder holding the team's record (under `npm/`) and a file that isn't
/// one.
struct Setup {
    t: Ctx,
    repo: PathBuf,
    folder: PathBuf,
}

fn setup() -> Setup {
    let t = Ctx::new();
    let repo = git_repo(&t.home.join("work/app"), false);
    write(
        &repo.join("package-lock.json"),
        json!({
            "name": "app", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": {"name": "app", "version": "0.0.0", "dependencies": {"acme-internal-widget": "1.2.3"}},
                "node_modules/acme-internal-widget": {"version": "1.2.3"}
            }
        })
        .to_string(),
    );
    let folder = t.home.join("advisories");
    mkdir(&folder.join("npm"));
    write(&folder.join("npm").join(format!("{ID}.json")), record().to_string());
    write(&folder.join("notes.json"), "{\"these\": \"are notes\"}");
    Setup { t, repo, folder }
}

fn entry(id: &str, path: &Path, extra: &str) -> String {
    format!(
        "[[source]]\nid = \"{id}\"\nkind = \"advisories\"\nformat = \"osv-dir\"\npath = '{}'\n{extra}\n",
        path.display()
    )
}

fn scan(x: &Setup, extra: &[&str]) -> Out {
    let mut argv = vec!["scan", "--json", "--no-input", "--offline", "--no-machine", "--path", s(&x.repo)];
    argv.extend_from_slice(extra);
    x.t.run(&argv)
}

fn pick(f: &Value, ks: &[&str]) -> Value {
    Value::Array(ks.iter().map(|k| f[*k].clone()).collect())
}

/// The scan's findings on the widget.
fn widget(env: &Value) -> Vec<Value> {
    of_kind(env, "project").into_iter().filter(|f| f["component"] == "acme-internal-widget").cloned().collect()
}

/// The person's own sources file.
fn mine(x: &Setup, text: &str) -> PathBuf {
    let config = x.t.home.join(".config/wpantry");
    mkdir(&config);
    write(&config.join("sources.toml"), text);
    config.join("sources.toml")
}

/// Risk: a folder of the team's OSV records is never read where it
/// matters most (an offline machine, a program running wpantry with
/// `--no-input`), its record doesn't reach the lockfile check, or the
/// finding links OSV.dev for a record OSV.dev has never seen. Oracle: one
/// finding on the widget naming the record's id, the fix 1.2.4, the range
/// and the source; `report --jsonl` and `--csv` give the record's own
/// ADVISORY link; nothing in the finding or its row is an OSV.dev link;
/// `sources --json` counts one record and one skipped file. After the
/// record is deleted, the finding is gone.
#[test]
fn a_local_record_flags_a_locked_package_offline_with_its_own_link() {
    let x = setup();
    mine(&x, &entry("team-advisories", &x.folder, ""));
    let r = scan(&x, &[]);
    assert_eq!(r.code, 1, "{}", r.err);
    let env = r.json();
    let found = widget(&env);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(
        pick(f, &["vuln_id", "version", "fixed", "affected_range", "status"]),
        json!([ID, "1.2.3", "1.2.4", "<1.2.4", "fail"]),
        "{f}"
    );
    assert_eq!(
        str_(&f["note"]),
        format!("acme-internal-widget leaks its signing key (from your source team-advisories: {LINK})")
    );
    assert!(!f.to_string().contains("osv.dev"), "{f}");
    let missed: Vec<&Value> = of_kind(&env, "unchecked");
    assert!(!missed.iter().any(|m| str_(&m["component"]).contains("team-advisories")), "{missed:?}");
    // The exports.
    let r = x.t.run(&["report", "--jsonl", "-o", "-"]);
    assert_eq!(r.code, 1, "{}", r.err);
    let row: Value = r
        .out
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|v| v["vuln_id"] == ID)
        .unwrap_or_else(|| panic!("{}", r.out));
    assert_eq!(row["url"], LINK);
    assert_eq!(row["record"]["id"], ID);
    assert!(!row.to_string().contains("osv.dev"), "{row}");
    let r = x.t.run(&["report", "--csv", "-o", "-"]);
    let csv = csv_dicts(&r.out);
    let line = csv.iter().find(|d| d["id"] == ID).unwrap_or_else(|| panic!("{}", r.out));
    assert_eq!(line["url"], LINK);
    // What the folder held.
    let r = x.t.run(&["sources", "--json"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let listed = arr(&r.json()["sources"]).iter().find(|s| s["id"] == "team-advisories").cloned().unwrap();
    assert_eq!(
        pick(&listed, &["kind", "format", "transport", "host", "records", "skipped", "error"]),
        json!(["advisories", "osv-dir", "local", null, 1, 1, null]),
        "{listed}"
    );
    let r = x.t.run(&["sources"]);
    assert!(r.out.contains("1 record loaded, 1 file skipped"), "{}", r.out);
    // The record deleted: gone on the next run.
    std::fs::remove_file(x.folder.join("npm").join(format!("{ID}.json"))).unwrap();
    let r = scan(&x, &[]);
    assert!(widget(&r.json()).is_empty(), "{}", r.out);
}

/// Risk: `--add-sources` drops or ignores a folder of advisories a program
/// adds for one run, or the folder is used when the person turned it off.
/// Oracle: the finding appears through an added file beside another
/// sources file, and not with `tier = "off"`.
#[test]
fn added_with_add_sources_it_works_and_turned_off_it_doesnt() {
    let x = setup();
    let other = x.t.home.join("other.toml");
    write(&other, "[[source]]\nid = \"cisa-kev\"\ntier = \"off\"\n");
    let added = x.t.home.join("added.toml");
    write(&added, entry("team-advisories", &x.folder, ""));
    let r = scan(&x, &["--sources", s(&other), "--add-sources", s(&added)]);
    assert_eq!(r.code, 1, "{}", r.err);
    let found = widget(&r.json());
    assert_eq!(found.iter().map(|f| str_(&f["vuln_id"])).collect::<Vec<_>>(), [ID], "{found:?}");
    write(&added, entry("team-advisories", &x.folder, "tier = \"off\""));
    let r = scan(&x, &["--sources", s(&other), "--add-sources", s(&added)]);
    assert!(widget(&r.json()).is_empty(), "turned off: {}", r.out);
}

/// Risk: the same advisory from OSV and from the team's folder shows as two
/// findings. Oracle: with a cached OSV record for the widget that names the
/// local id as an alias, the scan has one finding on the widget, OSV's id,
/// with a note saying the person's source has it too.
#[test]
fn a_remote_record_aliasing_the_local_one_is_one_finding() {
    let x = setup();
    mine(&x, &entry("team-advisories", &x.folder, ""));
    // The schema first, then what OSV answered.
    let _ = scan(&x, &[]);
    let remote = json!({
        "id": "GHSA-acme-wdgt-0001", "aliases": [ID], "modified": "2026-11-21T00:00:00Z",
        "summary": "Signing key leak in acme-internal-widget",
        "affected": [{"package": {"ecosystem": "npm", "name": "acme-internal-widget"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]
    });
    let conn = x.t.conn();
    insert_vuln(
        &conn,
        "INSERT OR REPLACE",
        [
            "GHSA-acme-wdgt-0001",
            ID,
            "Signing key leak in acme-internal-widget",
            "",
            "",
            "",
            "2026-11-21T00:00:00Z",
            "https://osv.dev/vulnerability/GHSA-acme-wdgt-0001",
            &remote.to_string(),
        ],
    );
    insert_query(&conn, "INSERT OR REPLACE", "npm", "acme-internal-widget", "1.2.3", now(), "GHSA-acme-wdgt-0001");
    drop(conn);
    let r = scan(&x, &[]);
    assert_eq!(r.code, 1, "{}", r.err);
    let found = widget(&r.json());
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        pick(&found[0], &["vuln_id", "fixed", "note"]),
        json!([
            "GHSA-acme-wdgt-0001",
            "1.2.4",
            "Signing key leak in acme-internal-widget (also in your source team-advisories)"
        ])
    );
}
