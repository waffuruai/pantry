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
    assert_eq!(to_file.out, Some(std::path::PathBuf::from("20251105T143000Z_pantry_report.html")));
    assert_eq!(resolve(html.clone(), false, t).out, None, "a pipe or a file: stdout");
    assert_eq!(resolve(Show { stdout: true, ..html.clone() }, true, t).out, None, "-o - asked for stdout");
    let named = Show { out: Some("r.html".into()), ..html };
    assert_eq!(resolve(named, true, t).out, Some(std::path::PathBuf::from("r.html")));
    assert_eq!(resolve(Show::default(), true, t).out, None, "the terminal's tables stay on the terminal");
    let csv = resolve(Show { format: Shown::Csv, ..Show::default() }, true, t);
    assert_eq!(csv.out.unwrap().to_string_lossy(), "20251105T143000Z_pantry_report.csv");
}
