use super::*;

fn f(cmd: &str, auto: bool, status: &str) -> Finding {
    Finding {
        kind: "tool".into(),
        component: cmd.rsplit(' ').next().unwrap_or("").into(),
        version: "1".into(),
        vuln_id: "CVE-1".into(),
        status: status.into(),
        fix_cmd: cmd.into(),
        fix_auto: auto,
        ..Default::default()
    }
}

// The test vectors the Python implementation had (`Plan` and `Mise`).
#[test]
fn plan_dedupes_and_splits() {
    let (auto, manual, optional) = plan(&[
        f("brew upgrade a", true, "fail"),
        f("brew upgrade a", true, "fail"),
        f("sudo apt-get install b", false, "fail"),
        f("Update App", false, "warn"),
    ]);
    assert_eq!(
        (auto, manual, optional),
        (
            vec!["brew upgrade a".to_string()],
            vec!["sudo apt-get install b".to_string()],
            vec!["Update App".to_string()]
        )
    );
}

/// Seventeen generic hits in one test-vector file are one decision in
/// the plan, not seventeen steps.
#[test]
fn secret_hits_in_one_file_are_one_step() {
    let hit = |n: i64| Finding {
        kind: "secret".into(),
        component: "repo/TestVectors/xts.txt".into(),
        location: format!("line {n}, commit abc"),
        vuln_id: "generic-api-key".into(),
        status: "warn".into(),
        fix_cmd: format!(
            "If it's real: rotate it, then purge it from history. If not: add abc:TestVectors/xts.txt:generic-api-key:{n} to ~/repo/.gitleaksignore"
        ),
        ..Default::default()
    };
    let fs: Vec<Finding> = (1..=5).map(hit).collect();
    let (auto, manual, optional) = plan(&fs);
    assert!(auto.is_empty() && manual.is_empty());
    assert_eq!(optional.len(), 1, "{optional:?}");
    assert!(optional[0].starts_with("5 hits in repo/TestVectors/xts.txt (generic rules: review): "), "{}", optional[0]);
    assert!(optional[0].ends_with("to ~/repo/.gitleaksignore"), "{}", optional[0]);
    assert!(optional[0].contains("the 5 fingerprints"), "{}", optional[0]);
    let two: Vec<Finding> = (1..=2).map(hit).collect();
    let (_, _, optional) = plan(&two);
    assert!(
        optional[0].contains("abc:TestVectors/xts.txt:generic-api-key:1, abc:TestVectors/xts.txt:generic-api-key:2"),
        "{}",
        optional[0]
    );
}

#[test]
fn steps_keep_the_findings_each_command_covers() {
    let fs = [
        f("brew upgrade a", true, "fail"),
        f("brew upgrade a", true, "fail"),
        Finding { component: "b".into(), ..f("sudo apt-get install b", false, "warn") },
        Finding { component: "c".into(), ..f("sudo apt-get install b", false, "fail") },
        Finding { fix_cmd: String::new(), ..f("", false, "fail") },
    ];
    let steps = steps(&fs);
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(
        (steps[0].cmd.as_str(), steps[0].mode(), steps[0].findings.as_slice()),
        ("brew upgrade a", "auto", &[0, 1][..])
    );
    // Two components sharing a command are one step; a failing one anywhere makes it manual, not optional.
    assert_eq!(
        (steps[1].cmd.as_str(), steps[1].mode(), steps[1].findings.as_slice()),
        ("sudo apt-get install b", "manual", &[3, 2][..])
    );
}

#[test]
fn one_fix_per_component_covers_every_advisory() {
    let fs: Vec<Finding> = [("CVE-1", "0.23.45"), ("CVE-2", "0.23.46")]
        .iter()
        .map(|(id, safe)| Finding {
            component: "rustls".into(),
            vuln_id: id.to_string(),
            fixed: safe.to_string(),
            ..f(&format!("cargo update -p rustls --precise {safe}"), false, "fail")
        })
        .collect();
    assert_eq!(plan(&fs).1, ["cargo update -p rustls --precise 0.23.46"]);
}

#[test]
fn dryrun_runs_nothing() {
    let mut lines = Vec::new();
    assert_eq!(apply(&[f("false", true, "fail")], true, &|_| true, &mut |l| lines.push(l.to_string())).status, 0);
    assert!(lines.contains(&"  would run: false".to_string()));
    let mut lines = Vec::new();
    assert_eq!(apply(&[f("false", true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string())).status, 1);
    assert!(lines.contains(&"  ✗ failed: false".to_string()));
    // Declined: the command is offered, and nothing runs.
    let mut lines = Vec::new();
    let offered = std::cell::RefCell::new(Vec::new());
    let decline = |cmds: &[String]| {
        offered.borrow_mut().extend_from_slice(cmds);
        false
    };
    assert_eq!(apply(&[f("false", true, "fail")], false, &decline, &mut |l| lines.push(l.to_string())).status, 0);
    assert_eq!(*offered.borrow(), ["false"]);
    assert!(lines.contains(&"  Nothing was changed.".to_string()));
    assert!(!lines.iter().any(|l| l.contains("failed")));
}

#[test]
fn update_never_upgrades_mise() {
    let fs = [
        Finding { component: "mise".into(), ..f("brew upgrade mise", true, "fail") },
        Finding { component: "node".into(), ..f("mise install node@24.11.1", true, "fail") },
        Finding { component: "all".into(), ..f("brew upgrade", true, "warn") },
    ];
    let (auto, manual, optional) = plan(&fs);
    assert_eq!(
        (auto, manual, optional),
        (vec!["mise install node@24.11.1".to_string()], vec![MISE_FIX.to_string()], vec![])
    );
}

#[test]
fn shlex() {
    assert_eq!(
        shlex_split(r#"cd '/w/my app' && echo "a \"b\" \x" c\ d"#).unwrap(),
        ["cd", "/w/my app", "&&", "echo", r#"a "b" \x"#, "c d"]
    );
    assert_eq!(shlex_split("x 'unclosed"), None);
}
