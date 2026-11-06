use super::*;

fn f(kind: &str, component: &str, id: &str, status: &str) -> Finding {
    Finding {
        kind: kind.into(),
        component: component.into(),
        vuln_id: id.into(),
        status: status.into(),
        ..Default::default()
    }
}

#[test]
fn areas_and_rows_come_in_fix_order() {
    let mut low = f("package", "lodash", "GHSA-low", "warn");
    low.severity = "LOW".into();
    let mut crit = f("package", "lodash", "GHSA-crit", "fail");
    crit.severity = "CRITICAL".into();
    crit.fixed = "4.17.21".into();
    let mut kev = f("brew", "openssl", "CVE-2024-1", "fail");
    kev.kev = true;
    kev.fix_cmd = "brew upgrade openssl@3".into();
    let hook = f("repo-hook", "~/code/app", "RUNS-REPO-FILE", "fail");
    let gap = f("unchecked", "OSV.dev", "UNCHECKED", "warn");
    let image = f("image", "node:18 › openssl", "CVE-2024-2", "warn");
    let image2 = f("image", "node:18 › zlib", "CVE-2024-3", "warn");
    let all = vec![low, crit, kev, hook, gap, image, image2];
    let v = view(&all);
    let kinds: Vec<&str> = v.areas.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, ["repo-hook", "brew", "package", "image"], "code that acts first, then KEV, then by severity");
    let pkg = &v.areas[2];
    assert_eq!((pkg.label.as_str(), pkg.rows.len(), pkg.fails, pkg.warns), ("Global packages", 1, 1, 1));
    let row = &pkg.rows[0];
    assert_eq!(row.ids, ["GHSA-crit", "GHSA-low"], "worst first");
    assert_eq!((row.severity, row.fails, row.fix.as_str()), ("CRITICAL", true, "update to 4.17.21"));
    assert_eq!(v.areas[1].rows[0].fix, "brew upgrade openssl@3");
    assert!(v.areas[1].kev);
    let images = &v.areas[3];
    assert_eq!((images.rows.len(), images.rows[0].name.as_str()), (1, "node:18"), "an image's packages are one row");
    assert_eq!(v.gaps.len(), 1);
    assert_eq!((v.fails(), v.rows()), (3, 4));
    assert_eq!(label("something-new"), "Something-new");
}

#[test]
fn alike_commands_batch_and_sudo_stays_apart() {
    let fix = |component: &str, cmd: &str, auto: bool| Finding {
        kind: "brew".into(),
        component: component.into(),
        status: "fail".into(),
        fix_cmd: cmd.into(),
        fix_auto: auto,
        ..Default::default()
    };
    let all = vec![
        fix("a", "brew upgrade a", true),
        fix("b", "brew upgrade b", true),
        fix("c", "sudo apt-get install --only-upgrade c", false),
        fix("d", "sudo apt-get install --only-upgrade d", false),
        fix("e", "apt-get install --only-upgrade e", false),
        fix("f", "sudo apt-get update && sudo apt-get install --only-upgrade f", false),
        fix("g", "code --install-extension Pub.Ext --force", false),
        fix("h", "brew upgrade h", false),
    ];
    let b = batches(&all);
    let cmds: Vec<(&str, bool, &str, usize)> = b.iter().map(|b| (b.cmd.as_str(), b.sudo, b.mode, b.steps)).collect();
    assert_eq!(
        cmds,
        [
            ("brew upgrade a b", false, "auto", 2),
            ("sudo apt-get install --only-upgrade c d", true, "manual", 2),
            ("apt-get install --only-upgrade e", false, "manual", 1),
            ("sudo apt-get update && sudo apt-get install --only-upgrade f", true, "manual", 1),
            ("code --install-extension Pub.Ext --force", false, "manual", 1),
            ("brew upgrade h", false, "manual", 1),
        ]
    );
}

#[test]
fn a_row_carries_its_highest_scores_and_likelier_first() {
    let mut a = f("package", "lodash", "GHSA-a", "fail");
    a.severity = "HIGH".into();
    (a.cvss, a.cvss_version, a.epss, a.epss_percentile) = (Some(7.5), "3.1".into(), Some(0.02), Some(0.8));
    let mut b = f("package", "lodash", "GHSA-b", "fail");
    b.severity = "HIGH".into();
    (b.cvss, b.cvss_version, b.epss, b.epss_percentile) = (Some(8.7), "4.0".into(), Some(0.4), Some(0.99));
    let all = [a, b];
    let v = view(&all);
    let row = &v.areas[0].rows[0];
    assert_eq!(row.ids, ["GHSA-b", "GHSA-a"], "same severity: the likelier to be exploited first");
    assert_eq!(row.cvss, Some((8.7, "4.0".to_string())));
    assert_eq!(row.epss, Some((0.4, 0.99)));
    assert_eq!((cvss_text(row.cvss.as_ref()), epss_text(row.epss)), ("8.7".to_string(), "40.0%".to_string()));
    assert_eq!(
        (cvss_text(None), epss_text(None), epss_text(Some((0.0002, 0.1)))),
        (String::new(), String::new(), "<0.1%".to_string())
    );
}

#[test]
fn osv_malicious_records_rank_with_malware() {
    let mut mal = f("package", "evil", "MAL-2026-1", "fail");
    mal.severity = "CRITICAL".into();
    let mut crit = f("package", "lodash", "GHSA-c", "fail");
    crit.severity = "CRITICAL".into();
    crit.kev = true;
    assert!(rank(&mal) < rank(&crit));
}
