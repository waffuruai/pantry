use super::*;
use wpantry::finding::Finding;

#[test]
fn csv_fields_quote_only_what_needs_it() {
    use wpantry::reporters::csv::field as csv_field;
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field(""), "");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
    assert_eq!(csv_field("cr\r"), "\"cr\r\"");
}

#[test]
fn table_cells_keep_one_line_without_pipes() {
    use wpantry::reporters::md::cell as md;
    assert_eq!(md("a|b"), "a\\|b");
    assert_eq!(md("two\nlines\tand\x1b[0m"), "two lines and [0m");
    assert_eq!(md("plain"), "plain");
}

#[test]
fn numbers_round_and_sizes_read_in_mb() {
    assert_eq!(round3(1.23456), 1.235);
    assert_eq!(round3(-5.0004), -5.0);
    assert_eq!(mb(0), "0.0 MB");
    assert_eq!(mb(1_250_000), "1.2 MB");
    assert_eq!(mb(12_345_678), "12.3 MB");
}

#[test]
fn a_scans_duration_reads_in_its_largest_units() {
    for (seconds, want) in [(0.2, "0s"), (45.4, "45s"), (187.0, "3m 07s"), (3720.0, "1h 02m"), (-4.0, "0s")] {
        assert_eq!(took(seconds), want);
    }
    let _home = wpantry::utils::files::test_home();
    let home = wpantry::utils::files::home().to_string_lossy().into_owned();
    assert_eq!(scope_shown(&format!("project:{home}/code/app")), "project:~/code/app");
    assert_eq!(scope_shown("repos:/srv/app+licenses"), "repos:/srv/app+licenses");
}

#[test]
fn the_envelope_carries_the_counts_and_findings() {
    let scan = Outcome {
        scan_id: 3,
        findings: vec![Finding { vuln_id: "CVE-2026-1".into(), status: "fail".into(), ..Default::default() }],
        counts: vec![("git repos".into(), 2), ("packages".into(), 0)],
        unfixed: 1,
        unknown_licenses: 4,
    };
    let env = wpantry::utils::json::parse(
        wpantry::reporters::json::envelope(&scan).dumps().as_bytes(),
        wpantry::utils::json::MAX_DOCUMENT,
    )
    .unwrap();
    assert_eq!(env["schema"].as_i64(), Some(SCHEMA));
    assert_eq!(env["impl"].as_str(), Some(IMPL));
    assert_eq!(env["version"].as_str(), Some(VERSION));
    assert_eq!(env["checked"]["git repos"].as_i64(), Some(2));
    assert_eq!(env["checked"]["packages"].as_i64(), Some(0));
    assert_eq!(env["unfixed"].as_i64(), Some(1));
    assert_eq!(env["unknown_licenses"].as_i64(), Some(4));
    let findings = env["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["vuln_id"].as_str(), Some("CVE-2026-1"));
}

#[test]
fn a_format_on_a_terminal_goes_to_a_dated_file_and_a_pipe_gets_stdout() {
    let html = Show { format: Shown::Html, ..Show::default() };
    let t = 1_762_353_000.0; // 2025-11-05 14:30:00 UTC
    let to_file = resolve(html.clone(), true, t);
    assert_eq!(to_file.out, Some(std::path::PathBuf::from("pantry_report_20251105T143000Z.html")));
    assert_eq!(resolve(html.clone(), false, t).out, None, "a pipe or a file: stdout");
    assert_eq!(resolve(Show { stdout: true, ..html.clone() }, true, t).out, None, "-o - asked for stdout");
    let named = Show { out: Some("r.html".into()), ..html };
    assert_eq!(resolve(named, true, t).out, Some(std::path::PathBuf::from("r.html")));
    assert_eq!(resolve(Show::default(), true, t).out, None, "the terminal's tables stay on the terminal");
    let csv = resolve(Show { format: Shown::Csv, ..Show::default() }, true, t);
    assert_eq!(csv.out.unwrap().to_string_lossy(), "pantry_report_20251105T143000Z.csv");
}

/// A sources file of the person's own with one local YARA source on `tier`.
fn rules_source(tier: &str) -> (String, String) {
    let text = format!(
        "[[source]]\nid = \"t-deep-rules\"\nkind = \"yara\"\nformat = \"yara\"\npath = '/srv/t-deep-rules'\ntier = \"{tier}\"\n"
    );
    (wpantry::sources::file::USER_FILE_NAME.to_string(), text)
}

fn compiled_all(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("compiled-all-"))
        .collect();
    v.sort();
    v
}

/// Risk (a regression): `wpantry rules` configures the sources for a scan
/// that isn't `--deep`, so a `tier = "deep"` source is left out of the
/// count of all rules, and the compiled bundle it keeps is named for a
/// different set of files than `scan --deep`'s, so each evicts the other's.
/// Oracle: the source's rules are in "all" and not in this system's count;
/// running `rules`, then a deep scan's own load (the sources configured
/// for `--deep`), then `rules` again, leaves one compiled bundle of all
/// rules, the same file throughout (the cache key is the file's name, and
/// its being read back rather than rebuilt is that name being unchanged).
#[test]
fn rules_counts_a_deep_source_and_shares_its_bundle_with_a_deep_scan() {
    use wpantry::checks::malware::yara;
    use wpantry::sources::file;
    let d = wpantry::utils::temp::TempDir::new("rules-deep").unwrap();
    let dir = d.path().to_path_buf();
    std::fs::write(dir.join("hand.yar"), "rule Hand_Rule { strings: $a = \"hand\" condition: $a }").unwrap();
    std::fs::write(dir.join("user-t-deep-rules.yar"), "rule Deep_Rule { strings: $a = \"deep\" condition: $a }")
        .unwrap();
    let source = [rules_source("deep")];
    // As `rules` configures: a scan that isn't --deep.
    file::configure_files(&source, false).unwrap();
    let (this_system, all) = rules_loads(&dir);
    let named = |l: &yara::Loaded| l.sources.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    assert_eq!(named(&this_system), ["hand.yar"], "a deep source is not for this system's count");
    assert_eq!(named(&all), ["hand.yar", "user-t-deep-rules.yar"], "but it is in the count of all rules");
    assert!(all.rules.rules().iter().any(|r| r.name == "Deep_Rule"));
    let bundle = compiled_all(&dir);
    assert_eq!(bundle.len(), 1, "{bundle:?}");
    // As `scan --deep` configures and loads.
    file::configure_files(&source, true).unwrap();
    let scan = yara::load(&dir, true, &|id: &str| file::active(id));
    assert_eq!(scan.hash, all.hash, "the same files, the same rules");
    assert_eq!(compiled_all(&dir), bundle, "the deep scan reads the bundle `rules` kept: no rebuild, no eviction");
    // And back.
    file::configure_files(&source, false).unwrap();
    rules_loads(&dir);
    assert_eq!(compiled_all(&dir), bundle, "`rules` after a deep scan keeps it too");
    file::configure_files(&[], false).unwrap();
}
