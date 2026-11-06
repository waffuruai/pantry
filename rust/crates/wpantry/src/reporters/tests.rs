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
    let with = latest(&cache, Some(30)).unwrap().unwrap();
    assert!(render(&cache, &with, Format::Json).unwrap().contains("\"history\""));
    let md = render(&cache, &with, Format::Md).unwrap();
    assert!(md.contains("## Homebrew (1 fail, 0 warn)") && md.contains("`brew upgrade openssl`"), "{md}");
    assert!(md.contains("## Exposure log") && md.contains("## Update plan"), "{md}");
    assert!(render(&cache, &r, Format::Csv).unwrap().starts_with("id,aliases,url,"));
    assert!(render(&cache, &with, Format::Csv).unwrap().starts_with("kind,component,version,"), "the exposure log");
    assert!(render(&cache, &r, Format::Html).unwrap().contains("pantry-bundle"));
    assert!(!render(&cache, &r, Format::Jsonl).unwrap().is_empty());
}
