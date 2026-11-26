use super::*;
use crate::checks::machine::brew_cves::{self, Installed};
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use serde_json::json;

const EXPAT: &str = "https://github.com/libexpat/libexpat";

/// A CVE record as OSV generates it from the CVE list: a GIT range, and the
/// version range it extracted (`introduced` to `fixed`).
fn cve_rec(id: &str, fixed: &str) -> Value {
    json!({
        "id": id, "summary": format!("{id} summary"), "modified": "m",
        "database_specific": {"osv_generated_from": format!("https://github.com/CVEProject/cvelistV5/tree/main/cves/{id}.json")},
        "affected": [{
            "ranges": [{"type": "GIT", "repo": EXPAT,
                        "events": [{"introduced": "0"}, {"fixed": "18da38899ee04bd023171f0c4958a4cfafb2b38c"}],
                        "database_specific": {"extracted_events": [
                            {"source": "AFFECTED_FIELD", "range": [{"introduced": "0"}, {"fixed": fixed}]}]}}],
            "versions": ["v2.8.0"]
        }],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

/// formulae.brew.sh, OSV and Homebrew's advisory database for `expat`, which
/// has two CVEs: one fixed in 2.8.2, one in 2.9.0. Anything else is unreachable.
fn expat_net() -> Fake {
    Fake::new(|r| {
        use crate::utils::net::Response;
        let u = r.url.as_str();
        if u == "https://formulae.brew.sh/api/formula/expat.json" {
            return Ok(Response::ok(
                json!({"urls": {"stable": {"url": "https://github.com/libexpat/libexpat/archive/R_2_10_1.tar.gz"}},
                       "homepage": "https://example.org/", "versions": {"stable": "2.10.1"}})
                .to_string(),
            ));
        }
        if u.ends_with("/querybatch") {
            let body: Value = serde_json::from_slice(&r.body.clone().unwrap_or_default()).unwrap();
            let results: Vec<Value> = arr_at(&body, "queries")
                .iter()
                .map(|q| {
                    // Every record for the repo; nothing named for a version.
                    if str_at(q, "version").is_empty() && str_at(&q["package"], "name").starts_with(EXPAT) {
                        json!({"vulns": [{"id": "CVE-2026-1001", "modified": "m"}, {"id": "CVE-2026-1002", "modified": "m"}]})
                    } else {
                        json!({})
                    }
                })
                .collect();
            return Ok(Response::ok(json!({"results": results}).to_string()));
        }
        if let Some(id) = u.strip_prefix("https://api.osv.dev/v1/vulns/") {
            return Ok(Response::ok(cve_rec(id, if id == "CVE-2026-1001" { "2.8.2" } else { "2.9.0" }).to_string()));
        }
        if u.starts_with("https://vulnerability.circl.lu/") {
            return Ok(Response::ok("[]"));
        }
        Err(Error::Offline(format!("{u}: unreachable")))
    })
}

/// A Cellar with `kegs` (`formula/version`) in it.
fn cellar_with(dir: &TempDir, kegs: &[&str]) -> PathBuf {
    let cellar = dir.path().join("Cellar");
    for k in kegs {
        std::fs::create_dir_all(cellar.join(k)).unwrap();
    }
    cellar
}

/// A cache holding what a scan of `findings` leaves: the scan, its
/// exposures, the latest findings. Returns the cache's file and the scan.
fn scanned(dir: &TempDir, cache: Cache, findings: &[Finding]) -> (PathBuf, i64) {
    cache.replace_findings(findings).unwrap();
    let opts = Options { machine: true, ..Default::default() };
    let scan = crate::history::record_scan(&cache, 1.0, findings, &[], &opts).unwrap();
    let file = cache.file().to_path_buf();
    let _ = dir;
    cache.close().unwrap();
    (file, scan)
}

/// A scan of `expat` 2.8.1 in `cellar`, made online through the real check.
fn expat_scan(dir: &TempDir, cellar: &Path) -> (PathBuf, i64, Vec<Finding>) {
    let net = expat_net();
    let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
    let mut s = Scan::new(Options::default(), cache, &net, &|_| {}, &|_| {});
    let at = Installed {
        formula: "expat".into(),
        version: "2.8.1".into(),
        location: cellar.join("expat/2.8.1").to_string_lossy().into_owned(),
    };
    brew_cves::check(&mut s, &[at], &|f| (format!("brew upgrade {f}"), true)).unwrap();
    let findings: Vec<Finding> = s.findings.iter().filter(|f| f.kind == "brew").cloned().collect();
    assert_eq!(findings.len(), 2, "{:?}", s.findings);
    let (file, scan) = scanned(dir, s.cache, &findings);
    (file, scan, findings)
}

fn check_id(file: &Path, id: &str, scan: i64) -> Outcome {
    recheck(Cache::open(Some(file)).unwrap(), id, scan).unwrap()
}

fn by_id<'a>(findings: &'a [Finding], vuln: &str) -> &'a Finding {
    findings.iter().find(|f| f.vuln_id == vuln).unwrap()
}

#[test]
fn a_formula_still_at_the_version_the_scan_found_is_still_present() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    let f = by_id(&findings, "CVE-2026-1001");
    let out = check_id(&file, &f.id(), scan);
    assert_eq!(out.verdict.state, State::StillPresent, "{out:?}");
    assert_eq!(out.verdict.reason, "affected");
    assert_eq!(out.keys, [f.key()]);
}

#[test]
fn an_upgrade_that_fixes_one_cve_and_not_the_other_is_gone_for_one_and_present_for_the_other() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    // What `brew upgrade expat` leaves: the old keg removed, a newer one in.
    std::fs::remove_dir_all(cellar.join("expat/2.8.1")).unwrap();
    std::fs::create_dir_all(cellar.join("expat/2.8.2")).unwrap();
    let fixed = check_id(&file, &by_id(&findings, "CVE-2026-1001").id(), scan);
    assert_eq!((fixed.verdict.state, fixed.verdict.reason), (State::Gone, "fixed"), "{fixed:?}");
    // Still vulnerable, at the new keg: the same finding at another location.
    let still = check_id(&file, &by_id(&findings, "CVE-2026-1002").id(), scan);
    assert_eq!(still.verdict.state, State::StillPresent, "{still:?}");
    // The detail spells the path the platform's way (`expat\2.8.2` on Windows).
    let detail = still.verdict.detail.replace('\\', "/");
    assert!(detail.contains("expat/2.8.2"), "{}", still.verdict.detail);
    // Past both fixes.
    std::fs::remove_dir_all(cellar.join("expat/2.8.2")).unwrap();
    std::fs::create_dir_all(cellar.join("expat/2.10.1")).unwrap();
    assert_eq!(check_id(&file, &by_id(&findings, "CVE-2026-1002").id(), scan).verdict.state, State::Gone);
}

#[test]
fn a_formula_removed_from_a_cellar_that_is_still_there_is_gone() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    std::fs::remove_dir_all(cellar.join("expat")).unwrap();
    let out = check_id(&file, &by_id(&findings, "CVE-2026-1001").id(), scan);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Gone, "removed"), "{out:?}");
}

#[test]
fn a_cellar_that_is_gone_says_nothing() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    std::fs::remove_dir_all(&cellar).unwrap();
    let out = check_id(&file, &by_id(&findings, "CVE-2026-1001").id(), scan);
    // The Cellar is found by its name, under the location: it is not there.
    assert_eq!(out.verdict.state, State::Unknown, "{out:?}");
}

#[test]
fn a_version_that_cannot_be_compared_is_unknown_never_gone() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    std::fs::remove_dir_all(cellar.join("expat/2.8.1")).unwrap();
    std::fs::create_dir_all(cellar.join("expat/HEAD")).unwrap();
    let out = check_id(&file, &by_id(&findings, "CVE-2026-1001").id(), scan);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "uncomparable"), "{out:?}");
}

#[test]
fn a_gone_finding_is_recorded_and_the_others_are_not_touched() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    let (a, b) = (by_id(&findings, "CVE-2026-1001"), by_id(&findings, "CVE-2026-1002"));
    // A fix that ran for `a`, as `fix a --from-scan N` records it.
    {
        let cache = Cache::open(Some(&file)).unwrap();
        crate::history::record_fix(&cache, Some(scan), "brew upgrade expat", "mitigate", true, &[a.key()]).unwrap();
        cache.close().unwrap();
    }
    let scans_before = row_count(&file, "scans");
    std::fs::remove_dir_all(cellar.join("expat/2.8.1")).unwrap();
    std::fs::create_dir_all(cellar.join("expat/2.8.2")).unwrap();
    assert_eq!(check_id(&file, &a.id(), scan).verdict.state, State::Gone);
    let cache = Cache::open(Some(&file)).unwrap();
    // The scan, its other finding and the other exposure stand.
    assert_eq!(row_count(&file, "scans"), scans_before);
    let latest: Vec<String> = crate::reporters::jsonl::findings(&cache).unwrap().iter().map(Finding::key).collect();
    assert_eq!(latest, [b.key()]);
    assert_eq!(crate::history::latest_scan(&cache).unwrap(), Some(scan));
    let open: Vec<String> = crate::history::exposures(&cache, f64::MIN)
        .unwrap()
        .iter()
        .filter(|e| e.resolved_at.is_none())
        .map(|e| e.vuln_id.clone())
        .collect();
    assert_eq!(open, ["CVE-2026-1002"]);
    // The fix is verified, by a re-check and not by a scan.
    let fixes = crate::history::fixes(&cache, f64::MIN).unwrap();
    assert_eq!((fixes[0].verified_scan, fixes[0].verified_by.as_deref()), (Some(scan), Some("recheck")));
    // The scan's own copy of what it found is untouched.
    let kept: i64 =
        cache.conn.query_row("SELECT COUNT(*) FROM run_findings WHERE scan_id = ?", [scan], |r| r.get(0)).unwrap();
    assert_eq!(kept, 2);
    // Once more: the same answer, and nothing new is written.
    let events = row_count(&file, "events");
    cache.close().unwrap();
    assert_eq!(check_id(&file, &a.id(), scan).verdict.state, State::Gone);
    assert_eq!(row_count(&file, "events"), events);
}

#[test]
fn a_finding_that_is_still_there_writes_nothing() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    let before = dump(&file);
    assert_eq!(check_id(&file, &by_id(&findings, "CVE-2026-1001").id(), scan).verdict.state, State::StillPresent);
    assert_eq!(dump(&file), before);
}

#[test]
fn an_id_that_is_not_in_the_scan_and_a_scan_that_is_not_the_latest_are_unknown() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    let id = by_id(&findings, "CVE-2026-1001").id();
    let out = check_id(&file, "F-0000000000", scan);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "unlisted"));
    assert!(out.keys.is_empty());
    let out = check_id(&file, &id, scan + 1);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "stale"));
    // A newer scan: the old id is stale, and the answer is the same refusal `fix` gives.
    let cache = Cache::open(Some(&file)).unwrap();
    crate::history::record_scan(&cache, 2.0, &[], &[], &Options::default()).unwrap();
    cache.close().unwrap();
    let out = check_id(&file, &id, scan);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "stale"));
    assert!(out.verdict.detail.contains("A newer scan is available"), "{}", out.verdict.detail);
}

#[test]
fn only_findings_with_an_automatic_fix_are_checked() {
    let d = TempDir::new("recheck").unwrap();
    let cellar = cellar_with(&d, &["expat/2.8.1"]);
    let (file, scan, findings) = expat_scan(&d, &cellar);
    let mut manual = findings[0].clone();
    manual.vuln_id = "CVE-2026-2000".into();
    manual.fix_auto = false;
    let mut secret = findings[0].clone();
    secret.kind = "secret".into();
    secret.vuln_id = "SECRET-RULE".into();
    let mut other = findings[0].clone();
    other.kind = "app".into();
    other.component = "Demo".into();
    other.location = "/Applications/Demo.app".into();
    other.vuln_id = "CVE-2026-2001".into();
    {
        let cache = Cache::open(Some(&file)).unwrap();
        cache.replace_findings(&[manual.clone(), secret.clone(), other.clone()]).unwrap();
        cache.close().unwrap();
    }
    for f in [&manual, &secret, &other] {
        let out = check_id(&file, &f.id(), scan);
        assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "unsupported"), "{}: {out:?}", f.kind);
    }
}

fn row_count(file: &Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(file).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap()
}

/// Every row of the history tables and the findings, as text.
fn dump(file: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(file).unwrap();
    let mut out = Vec::new();
    for table in ["scans", "exposures", "fixes", "events", "findings", "run_findings"] {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let n = stmt.column_count();
        let rows = stmt
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

#[test]
fn a_finding_made_from_a_cellar_without_brew_is_read_again_as_a_catalog_tool() {
    let d = TempDir::new("recheck").unwrap();
    // Go, poured by mise's brew engine: no brew command, a Cellar to read.
    let cellar = cellar_with(&d, &["go/1.26.10"]);
    std::fs::create_dir_all(d.path().join("bin")).unwrap();
    let brew = d.path().join("bin/brew");
    std::fs::write(&brew, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&brew, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let net = go_net();
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let mut s = Scan::new(Options::default(), cache, &net, &|_| {}, &|_| {});
    let inv = cellar::read(&cellar, &d.path().join("mise"));
    assert_eq!(inv.components.len(), 1, "{inv:?}");
    components::components(&mut s, &inv.components).unwrap();
    let findings: Vec<Finding> = s.findings.iter().filter(|f| f.kind == "brew").cloned().collect();
    assert_eq!(findings.len(), 1, "{:?}", s.findings);
    // A fix by `brew upgrade` is offered where Homebrew runs, and never on Windows
    // (`cellar::upgrade_step`): the finding exists there, without an automatic fix.
    assert_eq!(findings[0].fix_auto, !cfg!(windows), "{findings:?}");
    let (file, scan) = scanned(&d, s.cache, &findings);
    let id = findings[0].id();
    let out = check_id(&file, &id, scan);
    if cfg!(windows) {
        // Without an automatic fix there is nothing to re-check: the answer is `unsupported`.
        assert_eq!((out.verdict.state, out.verdict.reason), (State::Unknown, "unsupported"), "{out:?}");
        return;
    }
    assert_eq!(out.verdict.state, State::StillPresent, "{out:?}");
    // Upgraded to a version OSV was never asked about: the record's ranges decide.
    std::fs::remove_dir_all(cellar.join("go/1.26.10")).unwrap();
    std::fs::create_dir_all(cellar.join("go/1.26.11")).unwrap();
    let out = check_id(&file, &id, scan);
    assert_eq!((out.verdict.state, out.verdict.reason), (State::Gone, "fixed"), "{out:?}");
    // Still inside the range.
    std::fs::remove_dir_all(cellar.join("go/1.26.11")).unwrap();
    std::fs::create_dir_all(cellar.join("go/1.26.9")).unwrap();
    let out = check_id(&file, &id, scan);
    assert_eq!(out.verdict.state, State::StillPresent, "{out:?}");
}

/// OSV for Go: one advisory for 1.26.10 under `stdlib` and `toolchain`,
/// fixed in 1.26.11. Anything else is unreachable.
fn go_net() -> Fake {
    Fake::new(|r| {
        use crate::utils::net::Response;
        let u = r.url.as_str();
        if u.ends_with("/querybatch") {
            let body: Value = serde_json::from_slice(&r.body.clone().unwrap_or_default()).unwrap();
            let results: Vec<Value> = arr_at(&body, "queries")
                .iter()
                .map(|q| {
                    if str_at(q, "version") == "1.26.10" {
                        json!({"vulns": [{"id": "GO-2026-0001", "modified": "m"}]})
                    } else {
                        json!({})
                    }
                })
                .collect();
            return Ok(Response::ok(json!({"results": results}).to_string()));
        }
        if u == "https://api.osv.dev/v1/vulns/GO-2026-0001" {
            let range = json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.26.11"}]}]);
            let affected: Vec<Value> = ["stdlib", "toolchain"]
                .iter()
                .map(|p| json!({"package": {"ecosystem": "Go", "name": p}, "ranges": range}))
                .collect();
            return Ok(Response::ok(
                json!({"id": "GO-2026-0001", "aliases": ["CVE-2026-0001"], "modified": "m", "summary": "s",
                       "affected": affected})
                .to_string(),
            ));
        }
        if u.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        Err(Error::Offline(format!("{u}: unreachable")))
    })
}

fn gap(component: &str, vuln_id: &str, note: &str) -> Finding {
    Finding {
        kind: "unchecked".into(),
        component: component.into(),
        vuln_id: vuln_id.into(),
        status: "warn".into(),
        note: note.into(),
        ..Default::default()
    }
}

fn verdict_with_gaps(row_vuln: &str, gaps: Vec<Finding>) -> Verdict {
    let d = TempDir::new("recheck").unwrap();
    let net = Fake::offline();
    let mut s = crate::checks::machine::testing::scan(&net, &d);
    s.findings = gaps;
    let row = Row {
        kind: "runtime".into(),
        component: "go".into(),
        location: "/x/go".into(),
        vuln_id: row_vuln.into(),
        fix_cmd: "mise install go@1".into(),
        fix_auto: true,
    };
    classify(&s, &row, &Component::new("runtime", "go", "1.26.11", "/x/go"), true)
}

#[test]
fn what_could_not_be_asked_decides_whether_a_missing_finding_means_gone() {
    // Nothing missing: gone.
    assert_eq!(verdict_with_gaps("CVE-1", vec![]).state, State::Gone);
    // OSV not asked about this version: unknown, and says it is the cache.
    let osv = gap("tools, runtimes and packages against OSV", "UNREACHABLE", "OSV unreachable and not cached");
    let v = verdict_with_gaps("CVE-1", vec![osv.clone()]);
    assert_eq!((v.state, v.reason), (State::Unknown, "uncached"));
    // A record OSV named and the cache lacks: unknown, not clean.
    let absent = gap(
        "tools, runtimes and packages against OSV",
        "UNCHECKED",
        "OSV lists advisories it couldn't serve here: GHSA-1",
    );
    assert_eq!(verdict_with_gaps("CVE-1", vec![absent]).reason, "unchecked");
    // Answers older than a day are not a reason to doubt the finding's own advisory.
    let old = gap(
        "tools, runtimes and packages against OSV",
        "UNCHECKED",
        "3 answers are more than a day out of date and couldn't be refreshed (--offline)",
    );
    assert_eq!(verdict_with_gaps("CVE-1", vec![old.clone()]).state, State::Gone);
    // ... but only that: another gap in the same line still counts.
    let both = gap(
        "tools, runtimes and packages against OSV",
        "UNCHECKED",
        "3 answers are more than a day out of date and couldn't be refreshed (--offline); OSV lists advisories it couldn't serve here: GHSA-1",
    );
    assert_eq!(verdict_with_gaps("CVE-1", vec![both]).state, State::Unknown);
    // An end-of-life source matters to an end-of-life finding, and only to it.
    let eol = gap("end of life for go", "UNREACHABLE", "end of life for go: offline and not cached");
    assert_eq!(verdict_with_gaps("CVE-1", vec![eol.clone()]).state, State::Gone);
    assert_eq!(verdict_with_gaps("OUTDATED", vec![eol]).state, State::Unknown);
    assert_eq!(verdict_with_gaps("OUTDATED", vec![osv]).state, State::Gone);
    // CVE records never cached: nothing could have come from them.
    let cve = gap(&software_cves::unreached(software_cves::TOOLS_WHAT), "UNREACHABLE", "go");
    assert_eq!(verdict_with_gaps("CVE-1", vec![cve]).state, State::Gone);
}

#[test]
fn rows_finds_an_id_in_the_latest_view_and_then_in_the_scans_kept_copy() {
    let d = TempDir::new("recheck").unwrap();
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let f = Finding {
        kind: "runtime".into(),
        component: "go".into(),
        location: "/x/go".into(),
        vuln_id: "CVE-1".into(),
        fix_auto: true,
        fix_cmd: "mise install go@2".into(),
        ..Default::default()
    };
    cache.replace_findings(std::slice::from_ref(&f)).unwrap();
    let scan = crate::history::record_scan(&cache, 1.0, std::slice::from_ref(&f), &[], &Options::default()).unwrap();
    assert_eq!(rows(&cache, &f.id().to_lowercase(), scan).unwrap().len(), 1, "any case");
    cache.conn.execute("DELETE FROM findings", []).unwrap();
    assert_eq!(rows(&cache, &f.id(), scan).unwrap().len(), 1, "the kept copy still has it");
    assert!(rows(&cache, "F-0000000000", scan).unwrap().is_empty());
}
