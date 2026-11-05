use super::*;

fn p(args: &[&str]) -> Parsed {
    parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

#[test]
fn malware_options_and_the_rules_command() {
    let Parsed::Run(Command::Scan(c)) = p(&["scan", "--no-malware"]) else { panic!() };
    assert!(c.no_malware && !c.deep);
    let Parsed::Run(Command::Scan(c)) = p(&["check", "--deep"]) else { panic!() };
    assert!(c.deep && !c.no_malware);
    let Parsed::Run(Command::Scan(c)) = p(&["fix", "--deep", "--no-malware", "--no-online-hash"]) else { panic!() };
    assert!(c.fix && c.deep && c.no_malware && c.no_online_hash);
    assert!(matches!(p(&["scan", "--no-m"]), Parsed::Usage(_)), "--no-m is now ambiguous");
    let rules = |action: &str, samples: Vec<PathBuf>, update: bool, json: bool| Command::Rules {
        action: action.into(),
        samples,
        update,
        json,
        category: "malware".into(),
        family: None,
        name: None,
        out: None,
    };
    assert_eq!(p(&["rules"]), Parsed::Run(rules("", vec![], false, false)));
    assert_eq!(p(&["rules", "--update", "--json"]), Parsed::Run(rules("", vec![], true, true)));
    assert_eq!(p(&["rules", "goodware"]), Parsed::Run(rules("goodware", vec![], false, false)));
    assert_eq!(
        p(&["rules", "gen", "/a", "/b"]),
        Parsed::Run(rules("gen", vec!["/a".into(), "/b".into()], false, false))
    );
    let Parsed::Run(Command::Rules { category, family, name, out, .. }) =
        p(&["rules", "gen", "--category", "miner", "--family", "Kit", "--name", "R", "--out", "/o.yar", "/a"])
    else {
        panic!()
    };
    assert_eq!(
        (category.as_str(), family.as_deref(), name.as_deref(), out),
        ("miner", Some("Kit"), Some("R"), Some("/o.yar".into()))
    );
    assert!(matches!(p(&["rules", "gen"]), Parsed::Usage(_)));
    assert!(matches!(p(&["rules", "extra"]), Parsed::Usage(_)));
    assert!(matches!(p(&["rules", "goodware", "x"]), Parsed::Usage(_)));
    assert!(usage("scan").contains("[--no-malware] [--deep]"));
    assert!(help("rules").contains("--update"));
    assert_eq!(p(&["sources"]), Parsed::Run(Command::Sources { json: false, file: None }));
    assert_eq!(p(&["sources", "--json"]), Parsed::Run(Command::Sources { json: true, file: None }));
    assert_eq!(
        p(&["sources", "--sources", "/s.toml"]),
        Parsed::Run(Command::Sources { json: false, file: Some("/s.toml".into()) })
    );
    let Parsed::Run(Command::Scan(c)) = p(&["scan", "--sources", "/s.toml"]) else { panic!() };
    assert_eq!(c.sources, Some("/s.toml".into()));
    assert!(matches!(p(&["sources", "extra"]), Parsed::Usage(_)));
    assert!(help("sources").contains("--json"));
}

#[test]
fn no_arguments_print_the_help_and_options_alone_scan() {
    assert_eq!(p(&[]), Parsed::Help(help("")));
    assert_eq!(p(&["--json"]), Parsed::Run(Command::Scan(Check { json: true, ..Default::default() })));
    let Parsed::Run(Command::Scan(c)) = p(&["--path", "/a", "--path=/b", "--no-mac", "--json"]) else { panic!() };
    assert_eq!(c.path, Some(vec![PathBuf::from("/a"), PathBuf::from("/b")]));
    assert!(c.no_machine && c.json && !c.offline && !c.check_licenses);
    let Parsed::Run(Command::Scan(c)) = p(&["--licenses", "--json"]) else { panic!() };
    assert!(c.check_licenses && c.licenses.is_none() && c.json, "--licenses alone uses the bundled allowlist");
    let Parsed::Run(Command::Scan(c)) = p(&["--license", "--json"]) else { panic!() };
    assert!(c.check_licenses && c.licenses.is_none() && c.json, "--license is --licenses");
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let Parsed::Run(Command::Scan(c)) = p(&[&format!("--license={file}")]) else { panic!() };
    assert!(c.check_licenses && c.licenses == Some(PathBuf::from(file)));
}

#[test]
fn html_is_optional_and_composes_with_json() {
    let Parsed::Run(Command::Scan(c)) = p(&["--ht=report with spaces.html", "--json"]) else { panic!() };
    assert!(c.json);
    assert_eq!(c.html, Some(PathBuf::from("report with spaces.html")));
    for bad in [&["--html"][..], &["--html="], &["--html=-"]] {
        assert!(matches!(p(bad), Parsed::Usage(_)));
    }
}

#[test]
fn usage_errors() {
    for bad in [
        &["--bogus"][..],
        &["search"],
        &["search", "--limit", "x", "q"],
        &["export"],
        &["breach", "--enable", "--disable"],
        &["check", "--licenses", "/nonexistent/x.txt"],
        &["version", "extra"],
        &["--path"],
        &["--no-machine=1"],
        &["--n"],
    ] {
        assert!(matches!(p(bad), Parsed::Usage(_)), "{bad:?}");
    }
    let Parsed::Usage(msg) = p(&["--bogus"]) else { panic!() };
    assert!(msg.starts_with("usage: wpantry scan") && msg.contains("error: unrecognized arguments: --bogus"));
    let Parsed::Usage(msg) = p(&["scna", "--json"]) else { panic!() };
    assert!(msg.starts_with(TOP_USAGE) && msg.contains("wpantry: error: argument command: invalid choice: 'scna'"));
}

#[test]
fn scan_check_and_fix() {
    let all = ["--path", "/a", "--no-machine", "--offline", "--json", "--no-input", "--jobs", "2", "--no-posture"];
    let Parsed::Run(Command::Scan(scan)) = p(&[&["scan"][..], &all].concat()) else { panic!() };
    assert!(!scan.fix && scan.no_machine && scan.offline && scan.json && scan.no_input && scan.no_posture);
    assert_eq!(p(&[&["check"][..], &all].concat()), Parsed::Run(Command::Scan(scan)), "check is scan");
    let fix =
        |dryrun: bool, yes: bool| Parsed::Run(Command::Scan(Check { fix: true, dryrun, yes, ..Default::default() }));
    assert_eq!(p(&["fix"]), fix(false, false));
    assert_eq!(p(&["fix", "--dryrun", "--yes"]), fix(true, true));
    // the spellings from before `fix`, kept for scripts
    for old in [&["--fix"][..], &["--update"], &["scan", "--fix"], &["check", "--fix"], &["check", "--update"]] {
        assert_eq!(p(old), fix(false, false), "{old:?}");
    }
    assert_eq!(p(&["check", "--fix", "--dryrun"]), fix(true, false));
    assert_eq!(p(&["--fix", "--yes"]), fix(false, true));
    for (cmd, head) in [
        ("scan", "usage: wpantry scan [-h] [--path DIR]"),
        ("check", "usage: wpantry check [-h] [--path DIR]"),
        ("fix", "usage: wpantry fix [-h] [--dryrun] [--yes] [--path DIR]"),
    ] {
        let Parsed::Help(text) = p(&[cmd, "--help"]) else { panic!("{cmd}") };
        assert!(
            text.starts_with(head) && text.contains("--no-malware") && text.contains("Exit codes:"),
            "{cmd}: {text}"
        );
        assert_eq!(text.contains("--dryrun"), cmd == "fix", "{cmd}: only fix documents --dryrun");
        assert!(!text.contains("--fix") && !text.contains("--update"), "{cmd}: the old flags stay undocumented");
    }
    let Parsed::Usage(text) = p(&["fix", "--fix"]) else { panic!() };
    assert!(text.starts_with("usage: wpantry fix") && text.contains("unrecognized arguments: --fix"), "{text}");
}

#[test]
fn help_and_subcommands() {
    assert!(matches!(p(&["--help"]), Parsed::Help(_)));
    assert!(matches!(p(&["search", "-h"]), Parsed::Help(_)));
    assert_eq!(
        p(&["search", "tls AND cert", "--limit", "5"]),
        Parsed::Run(Command::Search { query: "tls AND cert".into(), applicable: false, limit: 5, json: false })
    );
    assert_eq!(p(&["version", "--json"]), Parsed::Run(Command::Version { json: true }));
    assert_eq!(p(&["skill"]), Parsed::Run(Command::Skill));
    assert_eq!(p(&["watch", "--offline", "--json"]), Parsed::Run(Command::Watch { json: true, offline: true }));
    assert!(matches!(p(&["watch", "x"]), Parsed::Usage(_)));
}

#[test]
fn every_subcommand_has_help_and_a_usage_line() {
    for cmd in SUBCOMMANDS.iter().filter(|c| **c != "help") {
        let Parsed::Help(text) = p(&[cmd, "-h"]) else { panic!("{cmd}") };
        assert_eq!(p(&["help", cmd]), Parsed::Help(text.clone()), "help {cmd} is {cmd} -h");
        assert!(text.starts_with(&format!("usage: wpantry {cmd} [-h]")), "{cmd}: {text}");
        assert!(text.contains("-h, --help"), "{cmd}");
        let Parsed::Help(long) = p(&[cmd, "--help"]) else { panic!("{cmd}") };
        assert_eq!(long, text);
    }
    let Parsed::Help(top) = p(&["-h"]) else { panic!() };
    assert!(top.starts_with(TOP_USAGE) && top.contains("Exit codes:"));
    for same in [&["help"][..], &["help", "-h"], &["help", "help"], &["--help"]] {
        assert_eq!(p(same), Parsed::Help(top.clone()), "{same:?}");
    }
    for (bad, msg) in [
        (&["help", "scna"][..], "invalid choice: 'scna'"),
        (&["help", "scan", "fix"], "wpantry help: error: unrecognized arguments: fix"),
    ] {
        let Parsed::Usage(text) = p(bad) else { panic!("{bad:?}") };
        assert!(text.starts_with(TOP_USAGE) && text.contains(msg), "{bad:?}: {text}");
    }
}

#[test]
fn check_options_and_their_errors() {
    let _home = wpantry::utils::files::test_home();
    let file = wpantry::utils::files::home().join("g.toml");
    std::fs::write(&file, "").unwrap();
    let Parsed::Run(Command::Scan(c)) = p(&["--gitleaks-config", "~/g.toml", "--jobs=3", "--no-posture"]) else {
        panic!()
    };
    assert_eq!((c.gitleaks_config, c.jobs, c.no_posture), (Some(file.clone()), Some(3), true));
    let Parsed::Usage(text) = p(&["--install-scripts", "~", "--update"]) else { panic!() };
    assert!(text.contains("argument --install-scripts: no such file: ~"), "a directory is no policy file: {text}");
    assert_eq!(expand("~"), wpantry::utils::files::home());
    assert_eq!(expand("/x"), PathBuf::from("/x"));
    for (bad, msg) in [
        (&["check", "extra"][..], "unrecognized arguments: extra"),
        (&["--jobs", "0"], "argument --jobs: expected a number of 1 or more, got 0"),
        (&["--jobs", "many"], "argument --jobs: expected a number of 1 or more, got many"),
        (&["--repo-hooks", "~/missing.txt"], "argument --repo-hooks: no such file: ~/missing.txt"),
        (&["-x"], "unrecognized arguments: -x"),
        (&["--off", "--", "--json"], "unrecognized arguments: --json"),
    ] {
        let Parsed::Usage(text) = p(bad) else { panic!("{bad:?}") };
        assert!(text.contains(msg), "{bad:?}: {text}");
    }
}

#[test]
fn search_export_breach_and_sync_errors() {
    for (bad, msg) in [
        (&["search", "a", "b"][..], "unrecognized arguments: b"),
        (&["export", "x", "--csv", "f"], "unrecognized arguments: x"),
        (&["breach", "x"], "unrecognized arguments: x"),
        (&["sync", "x"], "unrecognized arguments: x"),
        (&["skill", "--json"], "unrecognized arguments: --json"),
        (&["tools", "--js=1"], "argument --json: ignored explicit argument '1'"),
    ] {
        let Parsed::Usage(text) = p(bad) else { panic!("{bad:?}") };
        assert!(text.contains(msg), "{bad:?}: {text}");
    }
    assert_eq!(
        p(&["search", "--applicable", "--limit=-2", "--json", "--", "-q"]),
        Parsed::Run(Command::Search { query: "-q".into(), applicable: true, limit: -2, json: true })
    );
    assert_eq!(
        p(&["export", "--jsonl", "f.jsonl", "--all"]),
        Parsed::Run(Command::Export { csv: None, jsonl: Some("f.jsonl".into()), all: true })
    );
    assert_eq!(p(&["breach", "--enable"]), Parsed::Run(Command::Breach { enable: true, disable: false }));
    assert_eq!(p(&["sync", "--refresh", "--json"]), Parsed::Run(Command::Sync { refresh: true, json: true }));
    assert_eq!(p(&["tools"]), Parsed::Run(Command::Tools { json: false }));
}

#[test]
fn report_options() {
    assert_eq!(
        p(&["report"]),
        Parsed::Run(Command::Report { sections: vec!["all".into()], since_days: 90, format: "md".into(), out: None })
    );
    assert_eq!(
        p(&["report", "--exposure", "--audit", "--since", "30d", "--format=csv", "-o", "r.csv"]),
        Parsed::Run(Command::Report {
            sections: vec!["exposure".into(), "audit".into()],
            since_days: 30,
            format: "csv".into(),
            out: Some("r.csv".into())
        })
    );
    let Parsed::Run(Command::Report { sections, .. }) = p(&["report", "--remediation", "--all"]) else { panic!() };
    assert_eq!(sections, ["all"]);
    for (bad, msg) in [
        (&["report", "x"][..], "unrecognized arguments: x"),
        (&["report", "--since", "0"], "argument --since: expected a number of days, got '0'"),
        (&["report", "--format", "pdf"], "invalid choice: 'pdf' (choose from md, json, csv)"),
    ] {
        let Parsed::Usage(text) = p(bad) else { panic!("{bad:?}") };
        assert!(text.contains(msg), "{bad:?}: {text}");
    }
}

#[test]
fn schedule_cache_update_and_harden_options() {
    assert_eq!(
        p(&["schedule", "install"]),
        Parsed::Run(Command::Schedule {
            action: "install".into(),
            every: "daily".into(),
            at: "09:30".into(),
            dry_run: false
        })
    );
    assert_eq!(
        p(&["schedule", "install", "--every", "weekly", "--at", "7:05", "--dry-run"]),
        Parsed::Run(Command::Schedule {
            action: "install".into(),
            every: "weekly".into(),
            at: "7:05".into(),
            dry_run: true
        })
    );
    assert_eq!(p(&["cache", "prune"]), Parsed::Run(Command::Cache { action: "prune".into(), older_than: 90 }));
    assert_eq!(
        p(&["cache", "prune", "--older-than", "7"]),
        Parsed::Run(Command::Cache { action: "prune".into(), older_than: 7 })
    );
    assert_eq!(
        p(&["update", "--check", "--yes", "--no-input", "--offline", "--version", "v1.2.3"]),
        Parsed::Run(Command::Update {
            check: true,
            yes: true,
            no_input: true,
            offline: true,
            version: Some("v1.2.3".into())
        })
    );
    assert_eq!(
        p(&["harden", "extension-cooldown"]),
        Parsed::Run(Command::Harden { what: "extension-cooldown".into(), hours: 72, bundle: None })
    );
    assert_eq!(
        p(&["harden", "extension-cooldown", "--hours", "48"]),
        Parsed::Run(Command::Harden { what: "extension-cooldown".into(), hours: 48, bundle: None })
    );
    let mitigate = |target: Target, dry_run: bool, yes: bool, no_input: bool, undo: bool| Command::Mitigate {
        target,
        dry_run,
        yes,
        no_input,
        undo,
        offline: false,
        no_machine: false,
        path: None,
    };
    assert_eq!(
        p(&["mitigate", "cve-2026-98432"]),
        Parsed::Run(mitigate(Target::Id("CVE-2026-98432".into()), false, false, false, false))
    );
    assert_eq!(p(&["mitigate", "list"]), Parsed::Run(mitigate(Target::List, false, false, false, false)));
    assert_eq!(
        p(&["mitigate", "--dry-run", "--yes", "--no-input", "GHSA-xxxx-yyyy-zzzz"]),
        Parsed::Run(mitigate(Target::Id("GHSA-XXXX-YYYY-ZZZZ".into()), true, true, true, false))
    );
    for undo in ["--undo", "--remove"] {
        assert_eq!(
            p(&["mitigate", "CVE-2026-98432", undo]),
            Parsed::Run(mitigate(Target::Id("CVE-2026-98432".into()), false, false, false, true))
        );
    }
    assert_eq!(
        p(&["mitigate", "all", "--offline", "--no-machine", "--path", "/w", "--yes"]),
        Parsed::Run(Command::Mitigate {
            target: Target::All,
            dry_run: false,
            yes: true,
            no_input: false,
            undo: false,
            offline: true,
            no_machine: true,
            path: Some(vec![PathBuf::from("/w")]),
        })
    );
    for (bad, msg) in [
        (&["mitigate"][..], "the following arguments are required: target"),
        (
            &["mitigate", "kernel"],
            "argument target: expected list, all or an advisory id such as CVE-2026-98432, got 'kernel'",
        ),
        (&["mitigate", "CVE-2026-98432", "now"], "unrecognized arguments: now"),
        (&["mitigate", "CVE-2026-98432", "--dry-run", "--undo"], "--dry-run and --undo can't be combined"),
        (&["mitigate", "all", "--remove"], "--undo takes one advisory id"),
        (&["schedule"], "the following arguments are required: action"),
        (
            &["schedule", "dance"],
            "argument action: invalid choice: 'dance' (choose from install, status, uninstall, run)",
        ),
        (&["schedule", "install", "run"], "unrecognized arguments: run"),
        (
            &["schedule", "install", "--every", "sometimes"],
            "argument --every: invalid choice: 'sometimes' (choose from hourly, daily, weekly)",
        ),
        (&["schedule", "install", "--at", "25:00"], "argument --at: expected HH:MM, got '25:00'"),
        (&["schedule", "install", "--at", "9:5"], "argument --at: expected HH:MM, got '9:5'"),
        (&["cache"], "the following arguments are required: action"),
        (&["cache", "vacuum"], "argument action: invalid choice: 'vacuum' (choose from prune)"),
        (&["cache", "prune", "all"], "unrecognized arguments: all"),
        (&["cache", "prune", "--older-than", "0"], "argument --older-than: expected a number of days, got '0'"),
        (&["update", "now"], "unrecognized arguments: now"),
        (&["harden"], "the following arguments are required: what"),
        (
            &["harden", "firewall"],
            "argument what: invalid choice: 'firewall' (choose from extension-cooldown, ca-trust)",
        ),
        (&["harden", "extension-cooldown", "now"], "unrecognized arguments: now"),
        (
            &["harden", "extension-cooldown", "--hours", "lots"],
            "argument --hours: expected a number of hours, got 'lots'",
        ),
        (&["schedule", "--every"], "argument --every: expected one argument"),
        (&["report", "--a"], "ambiguous option: --a could match --audit, --all"),
    ] {
        let Parsed::Usage(text) = p(bad) else { panic!("{bad:?}") };
        assert!(text.contains(msg), "{bad:?}: {text}");
    }
}
