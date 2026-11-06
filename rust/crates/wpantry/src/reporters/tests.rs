use super::*;

#[test]
fn staging_preserves_previous_report_and_cleans_up() {
    let dir = std::env::temp_dir().join(format!("pantry-html-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("report.html");
    std::fs::write(&dest, "previous").unwrap();
    let output = Output::new(&dest).unwrap();
    let staged = output.staging.clone();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "previous");
    drop(output);
    assert!(!staged.exists());
    Output::new(&dest).unwrap().write("next").unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[cfg(unix)]
    {
        let link = dir.join("link.html");
        std::os::unix::fs::symlink(&dest, &link).unwrap();
        Output::new(&link).unwrap().write("separate").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "separate");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    }
    assert!(Output::new(&dir).is_err());
    assert!(Output::new(&dir.join("missing/report.html")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

/// A scan, read back from the cache, renders as it ran: the counts in the
/// order counted, the totals, the stored scope; the history only when asked.
#[test]
fn the_latest_scan_reads_back_as_it_was() {
    let d = crate::utils::temp::TempDir::new("report").unwrap();
    let cache = Cache::open(Some(&d.path().join("c.db"))).unwrap();
    assert!(latest(&cache, None).unwrap().is_none(), "no scan yet");
    let finding = crate::finding::Finding {
        kind: "brew".into(),
        component: "openssl".into(),
        vuln_id: "CVE-2026-1".into(),
        status: "fail".into(),
        fix_cmd: "brew upgrade openssl".into(),
        ..Default::default()
    };
    let opts = crate::checks::Options { machine: true, ..Default::default() };
    cache.replace_findings(std::slice::from_ref(&finding)).unwrap();
    let counts = vec![("zebras".to_string(), 2), ("apps".to_string(), 40)];
    let id = history::record_scan_totals(&cache, 1.0, std::slice::from_ref(&finding), &counts, (3, 1), &opts).unwrap();
    let r = latest(&cache, None).unwrap().unwrap();
    assert_eq!((r.outcome.scan_id, r.outcome.counts.clone()), (id, counts));
    assert_eq!((r.outcome.unfixed, r.outcome.unknown_licenses, r.status()), (3, 1, 1));
    assert_eq!(r.outcome.findings, [finding]);
    assert_eq!((r.phase(), r.scan.options["machine"].as_bool()), ("scan", Some(true)));
    assert!(r.history.is_none());
    let json = render(&cache, &r, Format::Json).unwrap();
    assert!(json.find("\"zebras\"").unwrap() < json.find("\"apps\"").unwrap(), "the counts keep their order");
    assert!(!json.contains("\"history\""));
    let mut with = latest(&cache, Some(30)).unwrap().unwrap();
    with.part = Part::All;
    assert!(render(&cache, &with, Format::Json).unwrap().contains("\"history\""));
    let md = render(&cache, &with, Format::Md).unwrap();
    assert!(md.contains("## Homebrew (1 fail, 0 warn)") && md.contains("`brew upgrade openssl`"), "{md}");
    assert!(md.contains("## Exposure log") && md.contains("## Update plan"), "{md}");
    assert!(render(&cache, &r, Format::Csv).unwrap().starts_with("id,aliases,url,"));
    let part = |p: Part| Report { part: p, ..with.clone() };
    assert!(render(&cache, &with, Format::Csv).unwrap().starts_with("id,aliases,url,"), "all: the findings table");
    let csv = |p: Part| render(&cache, &part(p), Format::Csv).unwrap();
    assert!(csv(Part::Exposure).starts_with("first_seen,resolved,severity,component,"), "the exposure log");
    assert!(csv(Part::History).starts_with("first_seen,resolved,"), "history's one table is the exposure log");
    assert!(csv(Part::Remediation).starts_with("when,user,host,command,"));
    assert!(csv(Part::Audit).starts_with("scan,finished,host,user,"));
    assert!(csv(Part::Summary).starts_with("metric,value"));
    let json = |p: Part| render(&cache, &part(p), Format::Json).unwrap();
    assert!(json(Part::Audit).contains("\"scans\"") && !json(Part::Audit).contains("\"findings\""), "a log alone");
    assert!(json(Part::Remediation).contains("\"fixes\"") && !json(Part::Remediation).contains("\"scans\""));
    assert!(json(Part::Summary).contains("\"summary\""));
    let md = |p: Part| render(&cache, &part(p), Format::Md).unwrap();
    assert!(md(Part::Exposure).contains("## Exposure log") && !md(Part::Exposure).contains("## Audit log"));
    assert!(!md(Part::History).contains("## Homebrew"), "history without the findings");
    assert!(md(Part::Summary).starts_with("# Security summary"));
    assert!(render(&cache, &r, Format::Html).unwrap().contains("pantry-bundle"));
    assert!(!render(&cache, &r, Format::Jsonl).unwrap().is_empty());
}
