//! `wpantry recheck` from the outside (specs/cli-contract.md, "recheck"):
//! the built binary with a scratch HOME, cache and PATH, stand-in tools and
//! a fake Cellar. Nothing here touches the real Homebrew, mise or cache.
//!
//! Oracles: a finding is `gone` only when the machine no longer has what the
//! scan found; `still_present` when it does; `unknown` when the cache cannot
//! say. After every re-check no scan row is added, no other finding changes,
//! `fix <other> --from-scan N` is still accepted, and no stand-in `mise` or
//! `brew` was started.
#![cfg(unix)]

mod common;

use common::*;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wpantry::checks::machine::catalog::TOOLS;
use wpantry::checks::machine::{components, tools};
use wpantry::checks::{Options, Scan};
use wpantry::db::Cache;
use wpantry::finding::Finding;
use wpantry::history;
use wpantry::utils::net::{Fake, Response};

struct Lab {
    t: Ctx,
    bin: PathBuf,
    cellar: PathBuf,
    ran: PathBuf,
    calls: PathBuf,
}

fn script(path: &Path, body: &str) {
    mkdir(path.parent().unwrap());
    write(path, format!("#!/bin/sh\n{body}\n"));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// OSV for Go: GO-2026-0001 (CVE-2026-0001) affects 1.26.9 and 1.26.10,
/// fixed in 1.26.11.
fn go_net() -> Fake {
    Fake::new(|r| {
        let u = r.url.as_str();
        if u.ends_with("/querybatch") {
            let body: Value = serde_json::from_slice(&r.body.clone().unwrap_or_default()).unwrap();
            let results: Vec<Value> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| match q["version"].as_str() {
                    Some("1.26.9") | Some("1.26.10") => {
                        serde_json::json!({"vulns": [{"id": "GO-2026-0001", "modified": "m"}]})
                    }
                    _ => serde_json::json!({}),
                })
                .collect();
            return Ok(Response::ok(serde_json::json!({"results": results}).to_string()));
        }
        if u == "https://api.osv.dev/v1/vulns/GO-2026-0001" {
            let range = serde_json::json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.26.11"}]}]);
            let affected: Vec<Value> = ["stdlib", "toolchain"]
                .iter()
                .map(|p| serde_json::json!({"package": {"ecosystem": "Go", "name": p}, "ranges": range}))
                .collect();
            return Ok(Response::ok(
                serde_json::json!({"id": "GO-2026-0001", "aliases": ["CVE-2026-0001"], "modified": "m",
                                   "summary": "a Go bug", "affected": affected})
                .to_string(),
            ));
        }
        if u.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        Err(wpantry::Error::Offline(format!("{u}: unreachable")))
    })
}

fn bystander() -> Finding {
    Finding {
        kind: "app".into(),
        component: "bystander".into(),
        version: "1.0".into(),
        location: "/opt/bystander".into(),
        vuln_id: "GHSA-bystander".into(),
        status: "fail".into(),
        fixed: "1.1".into(),
        fix_cmd: "true".into(),
        fix_auto: true,
        ..Default::default()
    }
}

/// What the cache says, for comparing before and after.
#[derive(Debug, PartialEq)]
struct Snap {
    scans: i64,
    latest: i64,
    findings: Vec<(String, String)>,
}

impl Lab {
    fn new() -> Lab {
        let t = Ctx::new();
        let (bin, cellar) = (t.tmp.join("bin"), t.tmp.join("Cellar"));
        let (ran, calls) = (t.tmp.join("ran.log"), t.tmp.join("calls.log"));
        mkdir(&cellar);
        for tool in ["mise", "brew"] {
            script(&bin.join(tool), &format!("echo \"$0 $@\" >> {}", s(&ran)));
        }
        Lab { t, bin, cellar, ran, calls }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", s(&self.bin))
    }

    fn run(&self, argv: &[&str]) -> Out {
        let (path, cellar) = (self.path(), s(&self.cellar).to_string());
        self.t.run_env(argv, &[("PATH", &path), ("HOMEBREW_CELLAR", &cellar)])
    }

    /// A Go whose version is the first word of `file`.
    fn go_shim(&self, at: &Path, file: &Path) {
        script(at, &format!("echo \"$@\" >> {}\ncat {}", s(&self.calls), s(file)));
    }

    fn go_at(&self, at: &Path, version: &str) {
        script(at, &format!("echo \"$@\" >> {}\necho go{version}", s(&self.calls)));
    }

    /// A scan of the stand-in Go at `shown`, made through the real checks
    /// against a fake OSV; `extra` findings are added; `no_personal` records
    /// `--no-personal-files`. Returns (scan id, the findings).
    fn scan_go(&self, shown: &Path, no_personal: bool) -> (i64, Vec<Finding>) {
        let tool = TOOLS.iter().find(|t| t.name == "go").unwrap();
        let real = wpantry::utils::files::realpath(s(shown));
        let c = tools::component_at(tool, s(shown), &real, false).expect("the stand-in's version is read");
        let (net, log) = (go_net(), |_: &str| {});
        let cache = Cache::open(Some(&self.t.db)).unwrap();
        let mut scan = Scan::new(Options { machine: true, ..Default::default() }, cache, &net, &log, &log);
        components::components(&mut scan, &[c]).unwrap();
        let mut findings: Vec<Finding> = scan.findings.iter().filter(|f| f.kind != "unchecked").cloned().collect();
        assert_eq!(findings.len(), 1, "{:?}", scan.findings);
        findings.push(bystander());
        (self.record(scan.cache, &findings, no_personal), findings)
    }

    fn record(&self, cache: Cache, findings: &[Finding], no_personal: bool) -> i64 {
        cache.replace_findings(findings).unwrap();
        let opts = Options { machine: true, no_personal_files: no_personal, ..Default::default() };
        let scan = history::record_scan(&cache, 1.0, findings, &[], &opts).unwrap();
        cache.close().unwrap();
        scan
    }

    /// A scan of hand-made findings.
    fn scan_of(&self, findings: &[Finding], no_personal: bool) -> i64 {
        self.record(Cache::open(Some(&self.t.db)).unwrap(), findings, no_personal)
    }

    /// `fix` ran for these keys, as `fix ID --from-scan N --yes` records it.
    fn fix_ran(&self, scan: i64, cmd: &str, keys: &[String]) {
        let cache = Cache::open(Some(&self.t.db)).unwrap();
        history::record_fix(&cache, Some(scan), cmd, "mitigate", true, keys).unwrap();
        cache.close().unwrap();
    }

    fn snap(&self) -> Snap {
        let conn = self.t.conn();
        let scans = conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0)).unwrap();
        let latest = conn.query_row("SELECT MAX(id) FROM scans", [], |r| r.get(0)).unwrap();
        let report = self.run(&["report", "all", "--json"]).json();
        let findings = arr(&report["findings"]).iter().map(|f| (str_(&f["id"]).to_string(), f.to_string())).collect();
        Snap { scans, latest, findings }
    }

    /// Every row of the tables a re-check could change.
    fn dump(&self) -> Vec<String> {
        let conn = self.t.conn();
        let mut out = Vec::new();
        for table in ["scans", "exposures", "fixes", "events", "findings", "run_findings"] {
            let mut st = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let n = st.column_count();
            let rows = st
                .query_map([], |r| {
                    Ok((0..n)
                        .map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap();
            out.extend(rows.map(|r| format!("{table}: {}", r.unwrap())));
        }
        out
    }

    /// The re-check as a program runs it; checks the object's shape and that
    /// the exit code follows the state.
    fn recheck(&self, id: &str, scan: i64) -> Value {
        let r = self.run(&["recheck", id, "--from-scan", &scan.to_string(), "--json", "--no-input"]);
        let v = r.json();
        assert_eq!(keys(&v), set(&["schema", "finding", "scan", "state", "reason", "detail", "keys"]), "{v}");
        assert_eq!((v["schema"].as_i64(), v["scan"].as_i64()), (Some(1), Some(scan)));
        let code = match str_(&v["state"]) {
            "gone" => 0,
            "still_present" => 1,
            "unknown" => 3,
            other => panic!("state {other}"),
        };
        assert_eq!(r.code, code, "{v} {}", r.err);
        assert!(!str_(&v["detail"]).is_empty() && !str_(&v["reason"]).contains(char::is_whitespace), "{v}");
        v
    }

    /// The invariants after a re-check of `id` that answered `gone` or not.
    fn invariants(&self, before: &Snap, id: &str, gone: bool) {
        let now = self.snap();
        assert_eq!((now.scans, now.latest), (before.scans, before.latest), "no scan row, same latest scan");
        let others = |s: &Snap| s.findings.iter().filter(|(i, _)| i != id).cloned().collect::<Vec<_>>();
        assert_eq!(others(&now), others(before), "every other finding is byte-identical");
        assert_eq!(now.findings.iter().any(|(i, _)| i == id), !gone, "gone leaves the report, nothing else does");
        let other = Finding::id(&bystander());
        let r = self.run(&["fix", &other, "--from-scan", &now.latest.to_string(), "--dry-run", "--json"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert!(!self.ran.exists(), "a stand-in mise or brew was started: {}", read(&self.ran));
    }

    fn id_of(f: &Finding) -> String {
        f.id()
    }
}

fn go_finding(findings: &[Finding]) -> &Finding {
    findings.iter().find(|f| f.component == "go").unwrap()
}

/// Oracle: a shim whose version did not change is still present, and a
/// still-present answer writes nothing at all.
#[test]
fn an_untouched_runtime_is_still_present_and_nothing_is_written() {
    let lab = Lab::new();
    let (version, shim) = (lab.t.tmp.join("go.version"), lab.t.home.join(".local/share/mise/shims/go"));
    write(&version, "go1.26.9\n");
    lab.go_shim(&shim, &version);
    let (scan, findings) = lab.scan_go(&shim, false);
    let id = Lab::id_of(go_finding(&findings));
    let (before, dump) = (lab.snap(), lab.dump());
    let v = lab.recheck(&id, scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("still_present", "affected"), "{v}");
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    lab.invariants(&before, &id, false);
    assert_eq!(lab.dump(), dump);
    // The text form is one line saying the same.
    let r = lab.run(&["recheck", &id, "--from-scan", &scan.to_string(), "--no-input"]);
    assert_eq!(r.code, 1);
    assert!(r.out.starts_with(&format!("{id}: still_present (affected).")) && r.out.lines().count() == 1, "{}", r.out);
    // The one binary it started is the shim, asked for its version only.
    assert!(read(&lab.calls).lines().all(|l| l == "env GOVERSION"), "{}", read(&lab.calls));
}

/// Oracle: after the fix the version at the same place is past the fix: gone,
/// recorded once, the fix verified by a re-check, the rest untouched.
#[test]
fn a_fixed_runtime_is_gone_and_recorded() {
    let lab = Lab::new();
    let (version, shim) = (lab.t.tmp.join("go.version"), lab.t.home.join(".local/share/mise/shims/go"));
    write(&version, "go1.26.9\n");
    lab.go_shim(&shim, &version);
    let (scan, findings) = lab.scan_go(&shim, false);
    let f = go_finding(&findings);
    let id = Lab::id_of(f);
    lab.fix_ran(scan, "mise install go@1.26.11", &[f.key()]);
    let before = lab.snap();
    write(&version, "go1.26.11\n"); // what `mise install go@1.26.11` leaves behind the shim
    let v = lab.recheck(&id, scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("gone", "fixed"), "{v}");
    assert_eq!(v["keys"][0], f.key().as_str());
    lab.invariants(&before, &id, true);
    let conn = lab.t.conn();
    let (verified, by): (Option<i64>, Option<String>) =
        conn.query_row("SELECT verified_scan, verified_by FROM fixes", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((verified, by.as_deref()), (Some(scan), Some("recheck")));
    let open: i64 =
        conn.query_row("SELECT COUNT(*) FROM exposures WHERE resolved_at IS NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(open, 1, "only the bystander's exposure is open");
    let list = lab.run(&["fix", "list", "--json"]).json();
    assert!(arr(&list["items"]).iter().all(|i| i["id"] != id.as_str()), "{list}");
    // Again: the same answer, and nothing more is written.
    let dump = lab.dump();
    assert_eq!(str_(&lab.recheck(&id, scan)["state"]), "gone");
    assert_eq!(lab.dump(), dump);
}

/// Oracle: an upgrade to another version that is still vulnerable is still
/// present, whether OSV's answer for it is cached or only the record is.
#[test]
fn an_upgrade_to_a_still_vulnerable_version_is_still_present() {
    let lab = Lab::new();
    let (version, shim) = (lab.t.tmp.join("go.version"), lab.t.home.join(".local/share/mise/shims/go"));
    write(&version, "go1.26.9\n");
    lab.go_shim(&shim, &version);
    let (scan, findings) = lab.scan_go(&shim, false);
    let id = Lab::id_of(go_finding(&findings));
    let before = lab.snap();
    write(&version, "go1.26.10\n"); // not asked about: the record's range decides
    let v = lab.recheck(&id, scan);
    assert_eq!(str_(&v["state"]), "still_present", "{v}");
    // Asked about, and OSV still names it.
    let cache = Cache::open(Some(&lab.t.db)).unwrap();
    for pkg in ["stdlib", "toolchain"] {
        cache.put_query("Go", pkg, "1.26.10", &["GO-2026-0001".to_string()]).unwrap();
    }
    cache.close().unwrap();
    assert_eq!(str_(&lab.recheck(&id, scan)["state"]), "still_present");
    lab.invariants(&before, &id, false);
    // Asked about, and OSV no longer names it for 1.26.12: gone by OSV's own answer.
    let cache = Cache::open(Some(&lab.t.db)).unwrap();
    for pkg in ["stdlib", "toolchain"] {
        cache.put_query("Go", pkg, "1.26.12", &[]).unwrap();
    }
    cache.close().unwrap();
    write(&version, "go1.26.12\n");
    assert_eq!(str_(&lab.recheck(&id, scan)["state"]), "gone");
}

/// Oracle: mise installs the fix beside the old copy; the old copy is still
/// there and still vulnerable (still present); once it is uninstalled the
/// finding's place is gone (gone, `removed`); a mise folder that is itself
/// missing says nothing (unknown), as an unmounted volume would.
#[test]
fn a_mise_install_beside_the_old_copy_does_not_fix_it_until_the_old_one_goes() {
    let lab = Lab::new();
    let installs = lab.t.home.join(".local/share/mise/installs/go");
    let old = installs.join("1.26.9/bin/go");
    lab.go_at(&old, "1.26.9");
    let (scan, findings) = lab.scan_go(&old, false);
    let id = Lab::id_of(go_finding(&findings));
    let before = lab.snap();
    lab.go_at(&installs.join("1.26.11/bin/go"), "1.26.11");
    assert_eq!(str_(&lab.recheck(&id, scan)["state"]), "still_present");
    std::fs::remove_dir_all(installs.join("1.26.9")).unwrap();
    let v = lab.recheck(&id, scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("gone", "removed"), "{v}");
    lab.invariants(&before, &id, true);
    // The same on a machine whose mise folder is not there at all.
    let lab = Lab::new();
    let old = lab.t.home.join(".local/share/mise/installs/go/1.26.9/bin/go");
    lab.go_at(&old, "1.26.9");
    let (scan, findings) = lab.scan_go(&old, false);
    std::fs::remove_dir_all(lab.t.home.join(".local")).unwrap();
    let v = lab.recheck(&Lab::id_of(go_finding(&findings)), scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("unknown", "unreachable"), "{v}");
}

/// Oracle: a version that cannot be read, or one OSV was never asked about
/// and whose record cannot be compared, is unknown, never gone.
#[test]
fn what_cannot_be_compared_is_unknown() {
    let lab = Lab::new();
    let (version, shim) = (lab.t.tmp.join("go.version"), lab.t.home.join(".local/share/mise/shims/go"));
    write(&version, "go1.26.9\n");
    lab.go_shim(&shim, &version);
    let (scan, findings) = lab.scan_go(&shim, false);
    let id = Lab::id_of(go_finding(&findings));
    write(&version, "something else\n");
    let v = lab.recheck(&id, scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("unknown", "unreadable"), "{v}");
    // A record of git commits only, for a version OSV was never asked about.
    let node = Finding {
        kind: "runtime".into(),
        component: "node".into(),
        version: "20.1.0".into(),
        location: s(&lab.t.home.join(".local/share/mise/installs/node/20.1.0/bin/node")).into(),
        vuln_id: "CVE-2026-7777".into(),
        status: "fail".into(),
        fixed: "20.18.1".into(),
        fix_cmd: "mise install node@20.18.1".into(),
        fix_auto: true,
        ..Default::default()
    };
    script(Path::new(&node.location), "echo v20.18.1");
    let cache = Cache::open(Some(&lab.t.db)).unwrap();
    cache
        .put_vuln(&serde_json::json!({"id": "CVE-2026-7777", "modified": "m", "affected": [{"ranges": [{"type": "GIT",
            "repo": "https://github.com/nodejs/node.git", "events": [{"introduced": "0"}, {"fixed": "abcdef0123456789abcdef"}]}]}]}))
        .unwrap();
    cache.close().unwrap();
    let scan = lab.scan_of(std::slice::from_ref(&node), false);
    let v = lab.recheck(&node.id(), scan);
    assert_eq!((str_(&v["state"]), str_(&v["reason"])), ("unknown", "uncached"), "{v}");
}

/// Oracle: a scan that left the personal folders out never has them opened
/// by a re-check: the binary there is not run. Positive control: when the
/// scan did read them, the same binary is run and judged.
#[test]
fn the_scans_no_personal_files_choice_is_kept() {
    for (no_personal, state) in [(true, "unknown"), (false, "still_present")] {
        let lab = Lab::new();
        let go = lab.t.home.join("Documents/mise/installs/go/1.26.9/bin/go");
        lab.go_at(&go, "1.26.9");
        let (scan, findings) = lab.scan_go(&go, no_personal);
        let id = Lab::id_of(go_finding(&findings));
        std::fs::remove_file(&lab.calls).unwrap();
        let v = lab.recheck(&id, scan);
        assert_eq!(str_(&v["state"]), state, "{v}");
        assert_eq!(lab.calls.exists(), !no_personal, "the binary in ~/Documents ran or not: {v}");
        if no_personal {
            assert_eq!(str_(&v["reason"]), "excluded");
        }
    }
}

fn brew_finding(location: &str) -> Finding {
    Finding {
        kind: "brew".into(),
        component: "foo".into(),
        version: "1.2.3".into(),
        location: location.into(),
        vuln_id: "CVE-2026-1111".into(),
        status: "fail".into(),
        fixed: "1.2.5".into(),
        fix_cmd: "brew upgrade foo".into(),
        fix_auto: true,
        ..Default::default()
    }
}

/// `brew vulns`' last answer, as the cache keeps it.
fn brew_answer(lab: &Lab, fixed: &[&str]) {
    let cache = Cache::open(Some(&lab.t.db)).unwrap();
    cache
        .put_run(
            "brew-vulns",
            "fp",
            &serde_json::json!({"checked": 1, "findings": [{"formula": "foo", "version": "1.2.3", "vulnerabilities": [
                {"id": "CVE-2026-1111", "summary": "s", "severity": "high", "fixed_versions": fixed}]}]}),
        )
        .unwrap();
    cache.close().unwrap();
}

/// Oracle for Homebrew formulae found by `brew vulns`: every installed
/// version must be past the fix. Two installs of one formula, an upgrade to
/// a version still behind the fix and a version between the fixes of two
/// release lines each get the answer that does not hide a vulnerable copy.
#[test]
fn a_homebrew_formula_is_gone_only_when_every_install_is_past_the_fix() {
    let lab = Lab::new();
    brew_answer(&lab, &["1.2.5"]);
    let f = brew_finding("Homebrew");
    let id = f.id();
    mkdir(&lab.cellar.join("foo/1.2.3"));
    let scan = lab.scan_of(&[f.clone(), bystander()], false);
    lab.fix_ran(scan, "brew upgrade foo", &[f.key()]);
    let before = lab.snap();
    let state = |lab: &Lab| {
        let v = lab.recheck(&id, scan);
        (str_(&v["state"]).to_string(), str_(&v["reason"]).to_string())
    };
    let is = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(state(&lab), is("still_present", "affected"));
    mkdir(&lab.cellar.join("foo/1.2.4")); // an upgrade that is not enough, beside the old keg
    std::fs::remove_dir_all(lab.cellar.join("foo/1.2.3")).unwrap();
    assert_eq!(state(&lab), is("still_present", "affected"));
    mkdir(&lab.cellar.join("foo/1.2.5_1")); // the fixed one beside the old: two installs
    assert_eq!(state(&lab), is("still_present", "affected"));
    std::fs::remove_dir_all(lab.cellar.join("foo/1.2.4")).unwrap();
    lab.invariants(&before, &id, false);
    assert_eq!(state(&lab), is("gone", "fixed"));
    lab.invariants(&before, &id, true);
    let by: Option<String> = lab.t.conn().query_row("SELECT verified_by FROM fixes", [], |r| r.get(0)).unwrap();
    assert_eq!(by.as_deref(), Some("recheck"));
}

#[test]
fn a_homebrew_formula_that_cannot_be_judged_is_unknown_and_a_removed_one_is_gone() {
    let lab = Lab::new();
    brew_answer(&lab, &["1.2.5", "2.0.1"]);
    let f = brew_finding("Homebrew");
    mkdir(&lab.cellar.join("foo/HEAD"));
    let scan = lab.scan_of(&[f.clone(), bystander()], false);
    let check = |lab: &Lab| {
        let v = lab.recheck(&f.id(), scan);
        (str_(&v["state"]).to_string(), str_(&v["reason"]).to_string())
    };
    let is = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(check(&lab), is("unknown", "uncomparable"));
    std::fs::remove_dir_all(lab.cellar.join("foo/HEAD")).unwrap();
    mkdir(&lab.cellar.join("foo/1.2.6")); // past 1.2.5, behind 2.0.1: only OSV can say
    assert_eq!(check(&lab), is("unknown", "ambiguous"));
    std::fs::remove_dir_all(lab.cellar.join("foo")).unwrap();
    assert_eq!(check(&lab), is("gone", "removed"));
}

/// Oracle: the odd inputs a program can send.
#[test]
fn odd_inputs_are_refused_without_changing_anything() {
    let lab = Lab::new();
    brew_answer(&lab, &["1.2.5"]);
    let f = brew_finding("Homebrew");
    mkdir(&lab.cellar.join("foo/1.2.3"));
    let manual = Finding { vuln_id: "CVE-2026-2".into(), fix_auto: false, ..brew_finding("Homebrew") };
    let scan = lab.scan_of(&[f.clone(), manual.clone(), bystander()], false);
    let (before, dump) = (lab.snap(), lab.dump());
    let reason = |v: &Value| (str_(&v["state"]).to_string(), str_(&v["reason"]).to_string());
    let is = |a: &str, b: &str| (a.to_string(), b.to_string());
    // an unknown id
    assert_eq!(reason(&lab.recheck("F-0123456789", scan)), is("unknown", "unlisted"));
    // a kind with no automatic fix
    assert_eq!(reason(&lab.recheck(&manual.id(), scan)), is("unknown", "unsupported"));
    // any case
    assert_eq!(str_(&lab.recheck(&f.id().to_lowercase(), scan)["finding"]), f.id());
    // an id that fix never ran for: nothing to verify, the exposure still resolves
    // (below); a scan that is not the latest
    assert_eq!(reason(&lab.recheck(&f.id(), scan + 1)), is("unknown", "stale"));
    // --from-scan missing, or not a number
    let r = lab.run(&["recheck", &f.id(), "--json"]);
    assert_eq!(r.code, 2, "{}{}", r.out, r.err);
    assert!(r.err.contains("--from-scan"), "{}", r.err);
    assert_eq!(lab.run(&["recheck", &f.id(), "--from-scan", "0"]).code, 2);
    assert_eq!(lab.run(&["recheck", "--from-scan", "1"]).code, 2);
    lab.invariants(&before, &f.id(), false);
    assert_eq!(lab.dump(), dump);
    // A newer scan makes the old id stale, as it does for fix.
    t_newer(&lab);
    let v = lab.recheck(&f.id(), scan);
    assert_eq!(reason(&v), is("unknown", "stale"));
    assert!(str_(&v["detail"]).contains("A newer scan is available"), "{v}");
    // Gone with no fix row to verify: the exposure resolves, no fix is stamped.
    let lab = Lab::new();
    brew_answer(&lab, &["1.2.5"]);
    mkdir(&lab.cellar.join("foo/1.2.5"));
    let scan = lab.scan_of(&[f.clone(), bystander()], false);
    assert_eq!(str_(&lab.recheck(&f.id(), scan)["state"]), "gone");
    let fixes: i64 = lab.t.conn().query_row("SELECT COUNT(*) FROM fixes", [], |r| r.get(0)).unwrap();
    assert_eq!(fixes, 0);
}

fn t_newer(lab: &Lab) {
    lab.t.conn().execute("INSERT INTO scans (started_at, finished_at, kept) VALUES (1, 1, 1)", []).unwrap();
}

/// Size: a cache of 30,000 findings, 400 of them with an automatic fix. Run
/// with `cargo test --release --test recheck -- --ignored --nocapture`.
#[test]
#[ignore = "measures a 30,000-finding cache"]
fn a_recheck_on_thirty_thousand_findings_takes_seconds() {
    let lab = Lab::new();
    brew_answer(&lab, &["1.2.5"]);
    mkdir(&lab.cellar.join("foo/1.2.3"));
    let mut findings: Vec<Finding> = (0..30_000)
        .map(|i| Finding {
            kind: "app".into(),
            component: format!("app{i}"),
            version: "1.0".into(),
            location: format!("/opt/app{i}"),
            vuln_id: format!("GHSA-{i}"),
            status: "fail".into(),
            fixed: "1.1".into(),
            fix_cmd: if i % 75 == 0 { "true".into() } else { String::new() },
            fix_auto: i % 75 == 0,
            ..Default::default()
        })
        .collect();
    let f = brew_finding("Homebrew");
    findings.push(f.clone());
    let scan = lab.scan_of(&findings, false);
    let start = std::time::Instant::now();
    let v = lab.recheck(&f.id(), scan);
    let took = start.elapsed();
    eprintln!("recheck on {} findings: {took:?}: {v}", findings.len());
    assert_eq!(str_(&v["state"]), "still_present");
    assert!(took.as_secs() < 10, "{took:?}");
}
