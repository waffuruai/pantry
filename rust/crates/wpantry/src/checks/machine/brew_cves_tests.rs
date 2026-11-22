use super::*;
use crate::checks::machine::testing;
use crate::sources::homebrew_advisories::tests::brew_record;
use crate::utils::net::{Fake, Net, Request, Response};
use crate::utils::temp::TempDir;

const OPENSHOT: &str = "https://github.com/openshot/openshot-qt";
const EXPAT: &str = "https://github.com/libexpat/libexpat";

/// An OSV record generated from the CVE list, as OSV serves it: a GIT
/// range of commits, a tag list, and the ranges it extracted.
fn cve_rec(id: &str, repo: &str, extracted: Value) -> Value {
    json!({
        "id": id,
        "summary": format!("{id} summary"),
        "modified": "m",
        "database_specific": {"osv_generated_from": format!("https://github.com/CVEProject/cvelistV5/tree/main/cves/{id}.json")},
        "affected": [{
            "ranges": [{"type": "GIT", "repo": repo,
                        "events": [{"introduced": "0"}, {"fixed": "18da38899ee04bd023171f0c4958a4cfafb2b38c"}],
                        "database_specific": {"extracted_events": extracted}}],
            "versions": ["v4.1.1", "v2.4.1", "v2.0.3"]
        }],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

fn field(range: Value) -> Value {
    json!({"source": "AFFECTED_FIELD", "strategy": "StandardRange", "range": range})
}

/// CVE-2026-134704 (openshot-qt), as OSV had it on 2026-11-22: tags
/// down to v2.0.3, none of 3.x; the CNA's `lessThanOrEqual 4.1.1`.
fn openshot_rec() -> Value {
    cve_rec(
        "CVE-2026-134704",
        OPENSHOT,
        json!([field(json!([{"introduced": "0"}, {"last_affected": "4.1.1"}])),
               {"source": "REFERENCES_COMMIT", "range": [{"fixed": "18da38899ee04bd023171f0c4958a4cfafb2b38c"}]}]),
    )
}

/// libexpat's records, each shaped as OSV had one on 2026-11-22.
fn expat_rec(id: &str) -> Value {
    match id {
        // `lessThan 2.8.2`.
        "CVE-2026-56131" => cve_rec(
            id,
            EXPAT,
            json!([field(json!([{"introduced": "0"}, {"fixed": "2.8.2"}])),
                   {"source": "CPE_RANGE", "cpe": "cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*",
                    "range": [{"introduced": "0"}, {"fixed": "2.8.2"}]}]),
        ),
        // `lessThanOrEqual 2.10.0`, no fix named.
        "CVE-2026-134703" => {
            cve_rec(id, EXPAT, json!([field(json!([{"introduced": "0"}, {"last_affected": "2.10.0"}]))]))
        }
        // NVD's CPE range only.
        "CVE-2026-117610" => cve_rec(
            id,
            EXPAT,
            json!([{"source": "CPE_RANGE", "cpe": "cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*",
                    "range": [{"introduced": "0"}, {"last_affected": "2.9.0"}]},
                   {"source": "REFERENCES_COMMIT", "range": [{"fixed": "7b0d50e4b1d16fafd55876260701e04279a7489d"}]}]),
        ),
        // From 2.7.2: older versions aren't affected.
        "CVE-2026-102633" => {
            cve_rec(id, EXPAT, json!([field(json!([{"introduced": "2.7.2"}, {"last_affected": "2.8.5"}]))]))
        }
        // Fixed long ago.
        "CVE-2024-45490" => cve_rec(id, EXPAT, json!([field(json!([{"introduced": "0"}, {"fixed": "2.6.3"}]))])),
        // Commits only: OSV's commit answer stands.
        "CVE-2016-0718" => cve_rec(id, EXPAT, json!([])),
        // An OSS-Fuzz record: no CVE, not judged.
        _ => {
            json!({"id": id, "modified": "m", "affected": [{"ranges": [{"type": "GIT", "repo": EXPAT, "events": [{"introduced": "0"}]}]}]})
        }
    }
}

const EXPAT_IDS: &[&str] = &[
    "CVE-2026-56131",
    "CVE-2026-134703",
    "CVE-2026-117610",
    "CVE-2026-102633",
    "CVE-2024-45490",
    "CVE-2016-0718",
    "OSV-2021-1",
];

fn formula_json(stable_url: &str, stable: &str) -> String {
    json!({"urls": {"stable": {"url": stable_url}}, "homepage": "https://example.org/", "versions": {"stable": stable}})
        .to_string()
}

/// formulae.brew.sh, OSV and Homebrew's advisory database for the tests'
/// formulae. `named` is OSV's answer for (repo, version) with a version.
fn net_with(named: fn(&str, &str) -> Vec<&'static str>, brew: fn(&str) -> Vec<Value>) -> Fake {
    Fake::new(move |r: &Request| {
        let u = r.url.as_str();
        if let Some(name) = u.strip_prefix("https://formulae.brew.sh/api/formula/") {
            return Ok(match name {
                "expat.json" => Response::ok(formula_json(
                    "https://github.com/libexpat/libexpat/releases/download/R_2_10_1/expat-2.10.1.tar.xz",
                    "2.10.1",
                )),
                "openshot-qt.json" => Response::ok(formula_json(
                    "https://github.com/OpenShot/openshot-qt/archive/refs/tags/v4.1.1.tar.gz",
                    "4.1.1",
                )),
                "unzip.json" => {
                    Response::ok(formula_json("https://downloads.sourceforge.net/infozip/unzip60.tar.gz", "6.0"))
                }
                "oddver.json" => {
                    Response::ok(formula_json("https://github.com/libexpat/libexpat/archive/x.tar.gz", "1.1.1x"))
                }
                _ => Response::not_found(),
            });
        }
        if u.ends_with("/querybatch") {
            let body = r.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|pkg, v| match (pkg, v) {
                // Every record for the repo, under the name OSV files it.
                (OPENSHOT, "") => vec!["CVE-2026-134704"],
                (EXPAT, "") => EXPAT_IDS.to_vec(),
                _ => named(pkg, v),
            }));
        }
        if let Some(id) = u.strip_prefix("https://api.osv.dev/v1/vulns/") {
            let rec = if id == "CVE-2026-134704" { openshot_rec() } else { expat_rec(id) };
            return Ok(Response::ok(rec.to_string()));
        }
        if u.starts_with("https://vulnerability.circl.lu/api/vulnerability/?source=osv_homebrew&product=") {
            let formula = u.split("product=").nth(1).unwrap().split('&').next().unwrap();
            return Ok(Response::ok(Value::Array(brew(formula)).to_string()));
        }
        Ok(Response::not_found())
    })
}

fn none(_: &str, _: &str) -> Vec<&'static str> {
    vec![]
}

fn no_patches(_: &str) -> Vec<Value> {
    vec![]
}

fn at(formula: &str, version: &str) -> Installed {
    Installed {
        formula: formula.into(),
        version: version.into(),
        location: format!("/opt/homebrew/Cellar/{formula}/{version}"),
    }
}

fn brew_fix(formula: &str) -> (String, bool) {
    (format!("brew upgrade {formula}"), true)
}

fn found(s: &Scan) -> Vec<(String, String, String, String, String)> {
    s.findings
        .iter()
        .filter(|f| f.kind == "brew")
        .map(|f| (f.component.clone(), f.vuln_id.clone(), f.status.clone(), f.fixed.clone(), f.affected_range.clone()))
        .collect()
}

fn row(c: &str, id: &str, status: &str, fixed: &str, range: &str) -> (String, String, String, String, String) {
    (c.into(), id.into(), status.into(), fixed.into(), range.into())
}

#[test]
fn a_version_outside_osvs_tag_list_is_judged_by_the_cve_record() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("openshot-qt", "3.3.0")], &brew_fix).unwrap();
    // Up to 4.1.1, and the formula's release is 4.1.1: no fix yet, a warning.
    assert_eq!(found(&s), [row("openshot-qt", "CVE-2026-134704", "warn", "", "<=4.1.1")]);
    let f = &s.findings[0];
    assert!(!f.fix_auto && f.fix_cmd.contains("No fixed release"), "{}", f.fix_cmd);
    assert_eq!(f.severity, "CRITICAL");
    assert_eq!(f.cvss, Some(9.8));
    assert!(
        f.note.contains("OSV's answer for https://github.com/OpenShot/openshot-qt 3.3.0 names no CVE"),
        "{}",
        f.note
    );
    // OSV was asked under the formula's spelling and the lowercased one.
    let asked: Vec<String> = net
        .requests()
        .iter()
        .filter(|r| r.url.ends_with("/querybatch"))
        .map(|r| String::from_utf8(r.body.clone().unwrap()).unwrap())
        .collect();
    assert!(asked[0].contains("https://github.com/OpenShot/openshot-qt") && asked[0].contains(OPENSHOT), "{asked:?}");
    assert!(s.findings.iter().all(|f| f.kind != "unchecked"), "{:?}", testing::kinds(&s));
}

#[test]
fn each_range_is_read_and_the_formulas_release_is_the_fix_the_record_doesnt_name() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    let mut s = testing::scan(&net, &d);
    s.kev.insert("CVE-2026-56131".into());
    check(&mut s, &[at("expat", "2.8.1")], &brew_fix).unwrap();
    let mut rows = found(&s);
    rows.sort();
    assert_eq!(
        rows,
        [
            row("expat", "CVE-2026-102633", "fail", "2.10.1", ">=2.7.2, <=2.8.5"),
            row("expat", "CVE-2026-117610", "fail", "2.10.1", "<=2.9.0"),
            row("expat", "CVE-2026-134703", "fail", "2.10.1", "<=2.10.0"),
            row("expat", "CVE-2026-56131", "fail", "2.8.2", "<2.8.2"),
        ]
    );
    let kev = s.findings.iter().find(|f| f.vuln_id == "CVE-2026-56131").unwrap();
    assert!(kev.kev && kev.fix_auto && kev.fix_cmd == "brew upgrade expat");
    // Before 2.7.2, CVE-2026-102633 doesn't apply.
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.7.1")], &brew_fix).unwrap();
    assert!(!found(&s).iter().any(|r| r.1 == "CVE-2026-102633"));
    // Past every range: clean, and nothing not checked.
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.10.1")], &brew_fix).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
}

#[test]
fn a_cve_osv_names_for_the_installed_version_is_left_to_osv_and_brew_vulns() {
    let d = TempDir::new("brew-cves").unwrap();
    let named = |pkg: &str, v: &str| if pkg == EXPAT && v == "2.8.1" { vec!["CVE-2026-56131"] } else { vec![] };
    let net = net_with(named, no_patches);
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.8.1")], &brew_fix).unwrap();
    assert!(found(&s).is_empty());
    let asked: Vec<String> =
        net.requests().iter().filter_map(|r| r.body.clone()).map(|b| String::from_utf8(b).unwrap()).collect();
    assert_eq!(asked.len(), 1, "the repo's records aren't asked for: {asked:?}");
    // A record with no CVE doesn't count as an answer.
    let fuzz = |pkg: &str, v: &str| if pkg == EXPAT && v == "2.8.1" { vec!["OSV-2021-1"] } else { vec![] };
    let (d, net) = (TempDir::new("brew-cves").unwrap(), net_with(fuzz, no_patches));
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.8.1")], &brew_fix).unwrap();
    assert_eq!(found(&s).len(), 4);
}

#[test]
fn a_cve_brew_vulns_or_osv_reported_for_the_formula_isnt_repeated() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    let mut s = testing::scan(&net, &d);
    s.add(Finding {
        kind: "brew".into(),
        component: "expat".into(),
        vuln_id: "CVE-2026-56131".into(),
        ..Default::default()
    });
    // OSV's finding for the catalog tool a formula maps to (openssh is `ssh`).
    s.add(Finding {
        kind: "tool".into(),
        component: "ssh".into(),
        vuln_id: "CVE-2026-134703".into(),
        ..Default::default()
    });
    check(&mut s, &[at("expat", "2.8.1")], &brew_fix).unwrap();
    let ids: Vec<String> = found(&s).into_iter().skip(1).map(|r| r.1).collect();
    assert!(!ids.contains(&"CVE-2026-56131".to_string()), "{ids:?}");
    assert!(ids.contains(&"CVE-2026-134703".to_string()), "another formula's finding is its own: {ids:?}");
}

#[test]
fn homebrews_patch_resolves_a_cve_in_its_revision() {
    let d = TempDir::new("brew-cves").unwrap();
    let patches = |formula: &str| {
        assert_eq!(formula, "expat");
        vec![brew_record("expat", "CVE-2026-56131", "2.8.1_1"), brew_record("expat", "CVE-2026-134703", "2.8.1_2")]
    };
    let net = net_with(none, patches);
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.8.1_1")], &brew_fix).unwrap();
    let rows = found(&s);
    assert!(!rows.iter().any(|r| r.1 == "CVE-2026-56131"), "patched in 2.8.1_1: {rows:?}");
    let later = s.findings.iter().find(|f| f.vuln_id == "CVE-2026-134703").unwrap();
    assert_eq!((later.status.as_str(), later.fixed.as_str()), ("fail", "2.8.1_2"));
    assert!(later.note.contains("Homebrew's patch ships in 2.8.1_2 (BREW-expat-CVE-2026-134703)"), "{}", later.note);
    // The others stand on the CVE records.
    assert!(rows.iter().any(|r| r.1 == "CVE-2026-117610" && r.3 == "2.10.1"));
    // The advisory database was asked once, for the formula with findings.
    let circl = net.requests().iter().filter(|r| r.url.contains("osv_homebrew")).count();
    assert_eq!(circl, 1);
}

#[test]
fn an_offline_run_judges_what_is_cached() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    check(&mut testing::scan(&net, &d), &[at("openshot-qt", "3.3.0")], &brew_fix).unwrap();
    let offline = Fake::offline();
    let mut s = testing::scan(&offline, &d);
    s.opts.offline = true;
    check(&mut s, &[at("expat", "2.8.1"), at("openshot-qt", "3.3.0")], &brew_fix).unwrap();
    assert_eq!(found(&s), [row("openshot-qt", "CVE-2026-134704", "warn", "", "<=4.1.1")]);
    // expat was never asked about: not checked, not clean.
    assert_eq!(testing::unchecked_note(&s, &software_cves::unreached(WHAT)), "expat");
}

#[test]
fn nothing_reachable_and_nothing_cached_is_not_checked_not_clean() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("expat", "2.8.1"), at("openshot-qt", "3.3.0")], &brew_fix).unwrap();
    assert_eq!(testing::unchecked_note(&s, &software_cves::unreached(WHAT)), "expat, openshot-qt");
    // formulae.brew.sh answered; OSV didn't.
    let half = Fake::new(|r| {
        if r.url.starts_with("https://formulae.brew.sh/") {
            return Ok(Response::ok(formula_json("https://github.com/libexpat/libexpat/archive/a.tar.gz", "2.10.1")));
        }
        Err(crate::error::Error::Offline("down".into()))
    });
    let d = TempDir::new("brew-cves").unwrap();
    let mut s = testing::scan(&half, &d);
    check(&mut s, &[at("expat", "2.8.1")], &brew_fix).unwrap();
    assert!(testing::unchecked_note(&s, WHAT).contains("OSV unreachable"));
    assert!(found(&s).is_empty());
    // Homebrew's patches unreachable: the finding stands, and says so.
    let d = TempDir::new("brew-cves").unwrap();
    let base = net_with(none, no_patches);
    let net = Fake::new(move |r| {
        if r.url.contains("osv_homebrew") {
            return Err(crate::error::Error::Offline("rate limited".into()));
        }
        base.send(r)
    });
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("openshot-qt", "3.3.0")], &brew_fix).unwrap();
    assert_eq!(found(&s).len(), 1);
    assert_eq!(testing::unchecked_note(&s, &software_cves::unreached(PATCHES)), "openshot-qt");
}

#[test]
fn a_version_the_ranges_cant_place_is_not_checked() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("oddver", "1.1.1x")], &brew_fix).unwrap();
    assert_eq!(testing::unchecked_note(&s, &software_cves::unjudged_label(WHAT)), "oddver");
    assert!(found(&s).is_empty());
    // A range in tags rather than versions.
    let rec = cve_rec("CVE-1", EXPAT, json!([field(json!([{"introduced": "0"}, {"fixed": "R_2_8_2"}]))]));
    let e = entry(&rec, EXPAT).unwrap();
    assert_eq!(judge(&dotted("2.8.1", false).unwrap(), &e), Verdict::Unknown);
}

#[test]
fn a_formula_from_no_git_host_or_unknown_to_the_api_isnt_asked_about() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, no_patches);
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[at("unzip", "6.0_8"), at("tapped", "1.0")], &brew_fix).unwrap();
    assert!(s.findings.is_empty(), "{:?}", testing::kinds(&s));
    assert!(net.requests().iter().all(|r| r.url.starts_with("https://formulae.brew.sh/")));
}

#[test]
fn only_formula_names_and_repo_urls_leave_the_machine() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = net_with(none, |f| vec![brew_record(f, "CVE-2026-56131", "2.8.1_1")]);
    let mut s = testing::scan(&net, &d);
    let local = Installed {
        formula: "expat".into(),
        version: "2.8.1".into(),
        location: d.path().join("keg").display().to_string(),
    };
    check(&mut s, &[local], &brew_fix).unwrap();
    for r in net.requests() {
        let body = r.body.as_deref().map(String::from_utf8_lossy).unwrap_or_default();
        for text in [r.url.as_str(), body.as_ref()] {
            assert!(!text.contains(&d.path().display().to_string()) && !text.contains("Cellar"), "{text}");
        }
        assert!(
            r.url.contains("expat") || body.contains(EXPAT) || r.url.starts_with("https://api.osv.dev/v1/vulns/"),
            "only the formula's name, its repo or the advisories OSV named are asked about: {} {body}",
            r.url
        );
    }
}

#[test]
fn a_cve_records_ranges_become_a_cve_json_5_entry() {
    assert_eq!(
        entry(&openshot_rec(), "https://github.com/OpenShot/openshot-qt/").unwrap(),
        json!({"versions": [{"status": "affected", "version": "0", "lessThanOrEqual": "4.1.1"}], "defaultStatus": "unaffected"})
    );
    // The CNA's range wins over NVD's and the description's.
    let rec = cve_rec(
        "CVE-2",
        EXPAT,
        json!([{"source": "DESCRIPTION", "range": [{"introduced": "0"}, {"fixed": "9.0"}]},
               {"source": "CPE_RANGE", "range": [{"introduced": "0"}, {"last_affected": "2.7.3"}]},
               field(json!([{"introduced": "0"}, {"last_affected": "2.7.5"}]))]),
    );
    assert_eq!(
        entry(&rec, EXPAT).unwrap()["versions"],
        json!([{"status": "affected", "version": "0", "lessThanOrEqual": "2.7.5"}])
    );
    // Intervals, an open one, and duplicates once.
    let rec = cve_rec(
        "CVE-3",
        EXPAT,
        json!([
            field(json!([{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"introduced": "3.0"}])),
            field(json!([{"introduced": "1.0"}, {"fixed": "1.5"}]))
        ]),
    );
    assert_eq!(
        entry(&rec, EXPAT).unwrap()["versions"],
        json!([{"status": "affected", "version": "1.0", "lessThan": "1.5"},
               {"status": "affected", "version": "2.0", "lessThan": "*"},
               {"status": "affected", "version": "3.0", "lessThan": "*"}])
    );
    // One string in words, as OSV extracts GitHub's records for Deno.
    let words = |v: &str| {
        let rec = cve_rec("CVE-4", EXPAT, json!([field(json!([{"introduced": v}, {"fixed": v}]))]));
        entry(&rec, EXPAT).unwrap()["versions"].clone()
    };
    assert_eq!(words("deno: < 1.42.0"), json!([{"status": "affected", "version": "< 1.42.0"}]));
    assert_eq!(words("= 1.32.0"), json!([{"status": "affected", "version": "1.32.0"}]));
    assert_eq!(words("deno = 1.34.0"), json!([{"status": "affected", "version": "1.34.0"}]));
    let judged = |v: &str, at: &str| {
        let rec = cve_rec("CVE-4", EXPAT, json!([field(json!([{"introduced": v}, {"fixed": v}]))]));
        judge(&dotted(at, false).unwrap(), &entry(&rec, EXPAT).unwrap())
    };
    assert_eq!(judged("deno: < 1.42.0", "2.9.8"), Verdict::Unaffected);
    assert!(matches!(judged("deno: < 1.42.0", "1.41.3"), Verdict::Affected { .. }));
    assert_eq!(judged("= 1.32.0", "1.32.1"), Verdict::Unaffected);
    // Anything else in words stays unread.
    assert_eq!(
        words("all versions before the fix"),
        json!([{"status": "affected", "version": "all versions before the fix", "lessThan": "all versions before the fix"}])
    );
    // Another repo's range, or none extracted: nothing to read.
    assert_eq!(entry(&openshot_rec(), EXPAT), None);
    assert_eq!(entry(&expat_rec("CVE-2016-0718"), EXPAT), None);
}

#[test]
fn the_cellar_gives_each_core_formulas_newest_keg() {
    let d = TempDir::new("cellar").unwrap();
    let c = d.path().join("Cellar");
    for v in ["jq/1.7.1", "jq/1.8.1", "jq/1.8.1_1", "jq/.DS_Store", "tapped/2.0", "core/1.0", "bare/3.0", ".hidden/1.0"]
    {
        std::fs::create_dir_all(c.join(v)).unwrap();
    }
    std::fs::create_dir_all(c.join("empty")).unwrap();
    testing::write(&c.join("tapped/2.0/INSTALL_RECEIPT.json"), r#"{"source": {"tap": "someone/tap"}}"#);
    testing::write(&c.join("core/1.0/INSTALL_RECEIPT.json"), r#"{"source": {"tap": "homebrew/core"}}"#);
    testing::write(&c.join("bare/3.0/INSTALL_RECEIPT.json"), "not json");
    let got: Vec<(String, String)> = installed(&c).into_iter().map(|i| (i.formula, i.version)).collect();
    assert_eq!(
        got,
        [("bare".to_string(), "3.0".to_string()), ("core".into(), "1.0".into()), ("jq".into(), "1.8.1_1".into())]
    );
    assert_eq!(installed(&c)[2].location, c.join("jq").join("1.8.1_1").display().to_string());
    assert!(installed(&d.path().join("nowhere")).is_empty());
}

#[test]
fn the_fix_is_brews_or_mises_or_words() {
    let d = TempDir::new("fix").unwrap();
    std::fs::create_dir_all(d.path().join("installs/brew-expat")).unwrap();
    let with = fixer(true, d.path().join("installs"), d.path().join("Cellar"));
    assert_eq!(with("openssl@3"), ("brew upgrade openssl@3".to_string(), true));
    let without = fixer(false, d.path().join("installs"), d.path().join("Cellar"));
    assert_eq!(without("expat"), ("mise upgrade brew:expat".to_string(), false));
    let (words, auto) = without("jq");
    assert!(words.starts_with("Upgrade jq in the Cellar at ") && !auto, "{words}");
    let (odd, auto) = with("a;b");
    assert!(odd.starts_with("Upgrade a;b") && !auto);
}

#[test]
fn nothing_installed_is_nothing_said() {
    let d = TempDir::new("brew-cves").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    check(&mut s, &[], &brew_fix).unwrap();
    assert!(s.findings.is_empty() && net.requests().is_empty());
}
