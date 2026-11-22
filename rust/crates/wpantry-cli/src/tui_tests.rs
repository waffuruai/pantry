use super::*;
use wpantry::checks::Outcome;
use wpantry::finding::Finding;
use wpantry::history::{ScanDetail, ScanRow};
use wpantry::reporters::Part;

fn report(findings: Vec<Finding>) -> Report {
    Report {
        outcome: Outcome {
            scan_id: 4,
            findings,
            counts: vec![("git repos".into(), 3), ("apps".into(), 40)],
            unfixed: 2,
            unknown_licenses: 0,
        },
        scan: ScanDetail { row: ScanRow { id: 4, finished_at: 1.0, ..Default::default() }, ..Default::default() },
        after_fixes: false,
        history: None,
        part: Part::Findings,
    }
}

fn text(r: &Report, width: usize) -> Vec<String> {
    lines(r, "/c/wpantry.db", width).iter().map(|l| paint(l, Style::new(false))).collect()
}

#[test]
fn wordfence_findings_carry_defiants_notice_in_full() {
    use wpantry::sources::wordfence::DEFIANT_LICENSE;
    let f = Finding {
        kind: "wordpress".into(),
        component: "akismet".into(),
        version: "5.3.1".into(),
        location: "/w/site/wp-content/plugins/akismet".into(),
        vuln_id: "CVE-2026-1001".into(),
        status: "fail".into(),
        fixed: "5.3.2".into(),
        note: "XSS (Wordfence: https://www.wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400)"
            .into(),
        fix_cmd: "wp plugin update akismet --path=/w/site".into(),
        ..Default::default()
    };
    let t = text(&report(vec![f]), 100);
    let words = t.join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("Defiant Inc.") && words.contains(DEFIANT_LICENSE), "{t:#?}");
    assert!(words.contains("The MITRE Corporation"));
    assert!(t.iter().all(|l| l.chars().count() <= 100), "wrapped to the width");
    assert!(!text(&report(vec![adv("CVE-1", false, "HIGH", "x", "1.6.1")]), 100).join(" ").contains("Defiant"));
}

/// The table rows and the notes under them: what must fit; summary
/// sentences wrap.
fn table(lines: &[String]) -> impl Iterator<Item = &String> {
    lines.iter().filter(|l| l.starts_with("  ✗") || l.starts_with("  ⚠ ") && l.contains("  ") || l.starts_with("    "))
}

fn adv(id: &str, kev: bool, sev: &str, note: &str, fixed: &str) -> Finding {
    Finding {
        kind: "project".into(),
        component: "smallvec".into(),
        version: "1.6.0".into(),
        location: "/w/app/Cargo.lock".into(),
        vuln_id: id.into(),
        status: "fail".into(),
        fixed: fixed.into(),
        kev,
        severity: sev.into(),
        note: note.into(),
        fix_cmd: format!("cd /w/app && cargo update -p smallvec --precise {fixed}"),
        ..Default::default()
    }
}

#[test]
fn areas_are_tables_with_the_reason_under_each_row() {
    let r = report(vec![
        Finding {
            kind: "unchecked".into(),
            component: "CISA KEV".into(),
            vuln_id: "UNCHECKED".into(),
            status: "warn".into(),
            note: "down".into(),
            ..Default::default()
        },
        adv("CVE-2021-25900", true, "CRITICAL", "Buffer overflow in SmallVec::insert_many", "1.6.1"),
        adv("CVE-2019-15551", false, "HIGH", "Double free", "1.0.0"),
        Finding {
            kind: "brew".into(),
            component: "openssl".into(),
            version: "3.0.1".into(),
            vuln_id: "CVE-2024-1".into(),
            status: "fail".into(),
            severity: "HIGH".into(),
            fix_cmd: "brew upgrade openssl".into(),
            fix_auto: true,
            ..Default::default()
        },
        Finding {
            kind: "brew".into(),
            component: "curl".into(),
            version: "8.0".into(),
            vuln_id: "CVE-2024-2".into(),
            status: "fail".into(),
            fix_cmd: "brew upgrade curl".into(),
            fix_auto: true,
            ..Default::default()
        },
    ]);
    let t = text(&r, 140);
    let all = t.join("\n");
    assert!(t[1].starts_with("==> Security scan #4") && t[2] == "  checked 3 git repos, 40 apps", "{all}");
    let project = t.iter().position(|l| l.starts_with("Project dependencies")).expect(&all);
    let brew = t.iter().position(|l| l.starts_with("Homebrew")).expect(&all);
    assert!(project < brew, "known exploited first:\n{all}");
    assert!(t[project].contains("2 fail") && t[project].ends_with("known exploited"), "{all}");
    assert!(t[project + 1].trim_start().starts_with("COMPONENT") && t[project + 1].contains("FIX"));
    let row = &t[project + 2];
    assert!(row.starts_with("  ✗ smallvec") && row.contains("CVE-2021-25900 +1") && row.contains("CRITICAL"), "{row}");
    assert!(row.contains("cargo update -p smallvec --precise 1.6.1"), "the fix covering both: {row}");
    assert_eq!(t[project + 3], "    /w/app/Cargo.lock · known exploited · Buffer overflow in SmallVec::insert_many");
    let narrow = text(&r, 100);
    assert!(table(&narrow).all(|l| l.chars().count() <= 100), "the tables fit the width:\n{}", narrow.join("\n"));
    assert!(all.contains("Not checked\n  ⚠ CISA KEV - down"), "{all}");
    assert!(all.contains("  automatic  brew upgrade openssl curl  clears 2 findings"), "{all}");
    assert!(all.contains("  · 2 applicable advisories have no released fix yet"), "{all}");
    assert!(t.last().unwrap().starts_with("✗ 3 thing(s) to update (4 advisories), 0 warning(s)"), "{all}");
}

#[test]
fn a_narrow_terminal_cuts_cells_and_nothing_found_says_so() {
    let mut long = adv("CVE-2021-25900", false, "LOW", "x", "1.6.1");
    long.component = "a-very-long-package-name-that-goes-on-and-on-and-on".into();
    let t = text(&report(vec![long]), 72);
    assert!(table(&t).all(|l| l.chars().count() <= 72), "{}", t.join("\n"));
    assert!(t.iter().any(|l| l.contains('…')));
    let clean = text(&report(Vec::new()), 80);
    assert_eq!(clean.last().unwrap(), "✓ nothing with a released fix applies to what was scanned");
    let mut warn = adv("OUTDATED", false, "", "behind", "");
    warn.status = "warn".into();
    warn.fix_cmd = String::new();
    assert_eq!(
        text(&report(vec![warn]), 80).last().unwrap(),
        "✓ nothing with a released fix applies; 1 warning(s) above"
    );
}

#[test]
fn colour_follows_the_roles_and_a_scanned_name_cant_escape() {
    let mut f = adv("CVE-1", true, "CRITICAL", "x", "2");
    f.component = "evil\x1b[2Jname".into();
    let r = report(vec![f]);
    let coloured: Vec<String> = lines(&r, "/c", 100).iter().map(|l| paint(l, Style::new(true))).collect();
    let row = coloured.iter().find(|l| l.contains("evil")).unwrap();
    assert!(row.contains("\x1b[1;31m✗\x1b[0m") && !row.contains("\x1b[2J"), "{row:?}");
}

#[test]
fn the_summary_says_how_many_gaps_and_which_couldnt_be_reached() {
    let gap = |what: &str, marker: &str| Finding {
        kind: "unchecked".into(),
        component: what.into(),
        vuln_id: marker.into(),
        status: "warn".into(),
        ..Default::default()
    };
    let (big, kev, osv) = (
        gap("secrets in 3 files of ~/x's history", "UNCHECKED"),
        gap("CISA KEV", "UNREACHABLE"),
        gap("OSV", "UNREACHABLE"),
    );
    assert_eq!(incomplete(&[]), "");
    assert_eq!(incomplete(&[&big]), " Incomplete: 1 thing couldn't be checked (Not checked, above).");
    let both = incomplete(&[&big, &kev, &osv]);
    assert!(both.contains("3 things couldn't be checked") && both.contains("2 sources couldn't be reached"), "{both}");
    assert!(!incomplete(&[&big]).contains("online"), "a big file isn't an offline source");
}

/// A gap's command is printed whole on its own line, however narrow the
/// terminal: cut, it wouldn't run.
#[test]
fn a_gaps_command_is_never_cut() {
    let cmd = "wpantry scan --path ~/Development/a/very/long/path/to/a/repo/with/big/files --no-machine --deep";
    let r = report(vec![Finding {
        kind: "unchecked".into(),
        component: "secrets in 4 files of ~/Development/a/very/long/path's history".into(),
        vuln_id: "UNCHECKED".into(),
        status: "warn".into(),
        note: "4 over 10 MB. Scan this repo on its own, with files up to 256 MB and no time limit".into(),
        fix_cmd: format!("git -C ~/r backfill\n{cmd}"),
        ..Default::default()
    }]);
    let out = text(&r, 60);
    assert!(out.iter().any(|l| l == &format!("    {cmd}")), "{out:#?}");
    assert!(out.iter().any(|l| l == "    git -C ~/r backfill"), "{out:#?}");
}
