use super::*;
use wpantry::reporters::Part;

fn p(args: &[&str]) -> Parsed {
    parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

fn help(path: &[&str]) -> String {
    program().help_for(path).expect("a command wpantry has")
}

/// The usage error for `args`, which must be one.
fn usage(args: &[&str]) -> String {
    match p(args) {
        Parsed::Usage(text) => text,
        other => panic!("{args:?}: {other:?}"),
    }
}

fn scan(args: &[&str]) -> Check {
    match p(args) {
        Parsed::Run(Command::Scan(c)) => c,
        other => panic!("{args:?}: {other:?}"),
    }
}

#[test]
fn malware_options_and_the_rules_command() {
    let c = scan(&["scan", "--no-malware"]);
    assert!(c.no_malware && !c.deep);
    let c = scan(&["fix", "--deep", "--no-malware", "--no-online-hash"]);
    assert!(c.fix && c.deep && c.no_malware && c.no_online_hash);
    assert!(scan(&["scan", "--allow-sleep"]).allow_sleep);
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
        p(&["rules", "gen", "--category", "miner", "--family", "Kit", "--name", "R", "-o", "/o.yar", "/a"])
    else {
        panic!()
    };
    assert_eq!(
        (category.as_str(), family.as_deref(), name.as_deref(), out),
        ("miner", Some("Kit"), Some("R"), Some("/o.yar".into()))
    );
    assert!(usage(&["rules", "gen"]).contains("missing required argument 'sample'"));
    assert!(usage(&["rules", "extra"]).contains("unknown command 'extra'"));
    assert!(usage(&["rules", "goodware", "x"]).contains("too many arguments for 'goodware'"));
    assert!(help(&["scan"]).contains("--no-malware") && help(&["scan"]).contains("--deep"));
    assert!(help(&["rules"]).contains("--update") && help(&["rules"]).contains("gen [options] <sample...>"));
    assert_eq!(p(&["sources"]), Parsed::Run(Command::Sources { json: false, file: None, added: vec![] }));
    assert_eq!(p(&["sources", "--json"]), Parsed::Run(Command::Sources { json: true, file: None, added: vec![] }));
    assert_eq!(
        p(&["sources", "--sources", "/s.toml"]),
        Parsed::Run(Command::Sources { json: false, file: Some("/s.toml".into()), added: vec![] })
    );
    assert_eq!(scan(&["scan", "--sources", "/s.toml"]).sources, Some("/s.toml".into()));
    // --add-sources repeats, in order, on scan, fix and sources; sync and rules don't take it.
    let added: Vec<std::path::PathBuf> = vec!["/a.toml".into(), "/b.toml".into()];
    assert_eq!(scan(&["scan", "--add-sources", "/a.toml", "--add-sources", "/b.toml"]).add_sources, added);
    assert_eq!(scan(&["fix", "--add-sources", "/a.toml", "--add-sources", "/b.toml"]).add_sources, added);
    assert_eq!(scan(&["scan"]).add_sources, Vec::<std::path::PathBuf>::new());
    assert_eq!(
        p(&["sources", "--add-sources", "/a.toml", "--add-sources", "/b.toml"]),
        Parsed::Run(Command::Sources { json: false, file: None, added })
    );
    assert!(usage(&["sync", "--add-sources", "/a.toml"]).contains("add-sources"));
    assert!(usage(&["rules", "--add-sources", "/a.toml"]).contains("add-sources"));
    assert!(usage(&["sources", "extra"]).contains("too many arguments for 'sources'"));
}

/// `--no-personal-files` is off unless given, on `scan` and `fix`, and
/// refused with `--deep`, which walks all of `~`.
#[test]
fn personal_files_are_left_out_only_when_asked() {
    for cmd in ["scan", "fix"] {
        assert!(!scan(&[cmd]).no_personal_files, "{cmd}");
        assert!(scan(&[cmd, "--no-personal-files"]).no_personal_files, "{cmd}");
        assert!(
            usage(&[cmd, "--deep", "--no-personal-files"]).contains("cannot be used with option '--deep'"),
            "{cmd}: {}",
            usage(&[cmd, "--deep", "--no-personal-files"])
        );
        assert!(usage(&[cmd, "--no-personal-files", "--deep"]).contains("cannot be used with"), "{cmd}");
    }
    assert!(help(&["scan"]).contains("--no-personal-files") && help(&["fix"]).contains("--no-personal-files"));
}

#[test]
fn no_arguments_print_the_help_and_the_version_is_one_flag() {
    assert_eq!(p(&[]), Parsed::Help(help(&[])));
    assert_eq!(p(&["--version"]), Parsed::Help(format!("wpantry {}\n", wpantry::VERSION)));
    assert!(usage(&["--json"]).contains("unknown option '--json'"), "options belong to a command");
    let c = scan(&["scan", "--path", "/a", "--path=/b", "--no-machine", "--json"]);
    assert_eq!(c.path, Some(vec![PathBuf::from("/a"), PathBuf::from("/b")]));
    assert!(c.no_machine && c.show.format == Shown::Json && !c.offline && !c.check_licenses);
    // A bare directory isn't a scope: the error says how to scan one.
    let bare = usage(&["scan", "--path", "/a", "/b"]);
    assert!(bare.contains("unknown command '/b'"), "one directory a --path: {bare}");
    assert!(
        bare.ends_with(
            "To scan one directory: wpantry scan project DIR (or scan --path DIR, which keeps the machine inventory)\n"
        ),
        "{bare}"
    );
    assert!(!usage(&["report", "nothing"]).contains("To scan one directory"));
    let c = scan(&["scan", "--licenses", "--json"]);
    assert!(c.check_licenses && c.licenses.is_none(), "--licenses alone uses the bundled allowlist");
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let c = scan(&["scan", "--licenses", file]);
    assert!(c.check_licenses && c.licenses == Some(PathBuf::from(file)));
}

#[test]
fn one_format_a_file_and_the_history_are_the_report_options() {
    let c = scan(&["scan", "--html", "-o", "report with spaces.html"]);
    assert_eq!(
        c.show,
        Show { format: Shown::Html, out: Some(PathBuf::from("report with spaces.html")), ..Default::default() }
    );
    assert_eq!(scan(&["scan", "--out=r.txt"]).show.format, Shown::Txt, "a file gets plain text");
    let c = scan(&["fix", "--md", "--since", "30"]);
    assert_eq!((c.fix, c.show.format, c.show.since), (true, Shown::Md, 30));
    for (bad, msg) in [
        (&["scan", "--html", "--json"][..], "option '--json' cannot be used with option '--html'"),
        (&["scan", "-o"], "option '-o, --out <file>' argument missing"),
        (&["scan", "--out="], "expects a file path, or - for stdout"),
        (&["scan", "--since", "x"], "option '--since' expects a number of days, got 'x'"),
        (&["scan", "--history"], "unknown option '--history'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
}

#[test]
fn usage_errors_name_the_closest_spelling() {
    let msg = usage(&["scan", "--no-machin"]);
    assert!(
        msg.starts_with(
            "Usage: wpantry scan [options] [command]\nerror: unknown option '--no-machin'\n(Did you mean --no-machine?)"
        ),
        "{msg}"
    );
    let msg = usage(&["scna", "--json"]);
    assert!(
        msg.starts_with("Usage: wpantry [options] [command]\nerror: unknown command 'scna'\n(Did you mean scan?)"),
        "{msg}"
    );
    for bad in [
        &["search"][..],
        &["search", "--limit", "x", "q"],
        &["breach", "--enable", "--disable"],
        &["scan", "--licenses", "/nonexistent/x.txt"],
        &["version", "extra"],
        &["scan", "--path"],
        &["scan", "--no-machine=1"],
        &["scan", "--no-m"],
        &["report", "--h"],
    ] {
        assert!(matches!(p(bad), Parsed::Usage(_)), "{bad:?}");
    }
}

#[test]
fn the_aliases_are_gone() {
    for (old, msg) in [
        (&["check"][..], "unknown command 'check'"),
        (&["export", "--csv"], "unknown command 'export'"),
        (&["mitigate", "list"], "unknown command 'mitigate'"),
        (&["harden", "ca-trust"], "unknown command 'harden'"),
        (&["scan", "--fix"], "unknown option '--fix'"),
        (&["scan", "--update"], "unknown option '--update'"),
        (&["scan", "--license"], "unknown option '--license'\n(Did you mean --licenses?)"),
        (&["fix", "--dryrun"], "unknown option '--dryrun'\n(Did you mean --dry-run?)"),
        (&["fix", "x-y-zzzz", "--remove"], "unknown option '--remove'"),
    ] {
        assert!(usage(old).contains(msg), "{old:?}: {}", usage(old));
    }
}

#[test]
fn scan_and_fix() {
    let all = ["--path", "/a", "--no-machine", "--offline", "--json", "--no-input", "--jobs", "2", "--no-posture"];
    let c = scan(&[&["scan"][..], &all].concat());
    assert!(!c.fix && c.no_machine && c.offline && c.show.format == Shown::Json && c.no_input && c.no_posture);
    assert_eq!(c.jobs, Some(2));
    let fix =
        |dry_run: bool, yes: bool| Parsed::Run(Command::Scan(Check { fix: true, dry_run, yes, ..Default::default() }));
    assert_eq!(p(&["fix"]), fix(false, false));
    assert_eq!(p(&["fix", "all"]), fix(false, false));
    assert_eq!(p(&["fix", "--dry-run", "--yes"]), fix(true, true));
    assert!(usage(&["scan", "--dry-run"]).contains("unknown option '--dry-run'"), "scan changes nothing");
    let text = help(&["scan"]);
    assert!(text.starts_with("Usage: wpantry scan [options] [command]\n") && text.contains("Exit codes:"), "{text}");
    let text = help(&["fix"]);
    assert!(text.starts_with("Usage: wpantry fix [options] [target] [id]\n") && text.contains("--dry-run"), "{text}");
}

#[test]
fn every_command_has_help() {
    let root = program();
    let Parsed::Help(top) = p(&["-h"]) else { panic!() };
    assert!(top.starts_with("Usage: wpantry [options] [command]") && top.contains("Exit codes:"));
    for same in [&["help"][..], &["--help"]] {
        assert_eq!(p(same), Parsed::Help(top.clone()), "{same:?}");
    }
    for cmd in [
        "scan", "fix", "report", "runs", "prune", "search", "watch", "sync", "schedule", "rules", "sources", "ignore",
        "breach", "cache", "update", "version", "tools", "skill", "licenses",
    ] {
        let text = help(&[cmd]);
        assert!(top.contains(&format!("\n  {cmd}")), "{cmd} is listed");
        assert_eq!(p(&[cmd, "-h"]), Parsed::Help(text.clone()), "{cmd}");
        assert_eq!(p(&["help", cmd]), Parsed::Help(text.clone()), "help {cmd} is {cmd} -h");
        assert!(text.starts_with(&format!("Usage: wpantry {cmd} ")) && text.contains("-h, --help"), "{cmd}");
        for line in text.lines() {
            assert!(line.chars().count() <= wcli::WIDTH, "{cmd}: {line}");
        }
    }
    assert_eq!(p(&["help", "schedule", "install"]), Parsed::Help(help(&["schedule", "install"])));
    assert_eq!(p(&["help", "scan", "project"]), Parsed::Help(help(&["scan", "project"])));
    assert!(root.help_for(&["check"]).is_none());
    assert!(usage(&["help", "scna"]).contains("unknown command 'scna'"));
}

#[test]
fn check_options_and_their_errors() {
    let _home = wpantry::utils::files::test_home();
    let file = wpantry::utils::files::home().join("g.toml");
    std::fs::write(&file, "").unwrap();
    let c = scan(&["scan", "--secret-rules", "~/g.toml", "--jobs=3", "--no-posture"]);
    assert_eq!((c.secret_rules, c.jobs, c.no_posture), (Some(file.clone()), Some(3), true));
    assert!(usage(&["scan", "--install-scripts", "~"]).contains("option '--install-scripts': no such file: ~"));
    // Secret rules are YARA, and must compile beside the bundled ones.
    let bad = wpantry::utils::files::home().join("bad.yar");
    std::fs::write(&bad, "rule Any_Secret_Bad { strings: $secret = /(/ condition: $secret }").unwrap();
    assert!(
        usage(&["scan", "--secret-rules", "~/bad.yar"]).contains("option '--secret-rules'"),
        "{}",
        usage(&["scan", "--secret-rules", "~/bad.yar"])
    );
    // A rule whose $secret is text, not a regex, is refused, not a crash.
    std::fs::write(&bad, "rule Any_Secret_Text { meta: category = \"secret\" id = \"text\" strings: $secret = \"abc\" condition: $secret }").unwrap();
    assert!(
        usage(&["scan", "--secret-rules", "~/bad.yar"]).contains("must be a regex"),
        "{}",
        usage(&["scan", "--secret-rules", "~/bad.yar"])
    );
    // 0.4's --gitleaks-config is still accepted, and ignored.
    assert_eq!(scan(&["scan", "--gitleaks-config", "~/g.toml"]).secret_rules, None);
    assert_eq!(expand("~"), wpantry::utils::files::home());
    assert_eq!(expand("/x"), PathBuf::from("/x"));
    for (bad, msg) in [
        (&["scan", "extra"][..], "unknown command 'extra'"),
        (&["scan", "--jobs", "0"], "option '--jobs' expects a number of 1 or more, got '0'"),
        (&["scan", "--jobs", "many"], "option '--jobs' expects a number of 1 or more, got 'many'"),
        (&["scan", "--repo-hooks", "~/missing.txt"], "option '--repo-hooks': no such file: ~/missing.txt"),
        (&["scan", "-x"], "unknown option '-x'"),
        (&["scan", "--offline", "--", "--json"], "too many arguments for 'scan'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
}

#[test]
fn search_breach_and_sync() {
    for (bad, msg) in [
        (&["search", "a", "b"][..], "too many arguments for 'search'"),
        (&["breach", "x"], "too many arguments for 'breach'"),
        (&["sync", "x"], "too many arguments for 'sync'"),
        (&["skill", "--json"], "unknown option '--json'"),
        (&["tools", "--json=1"], "option '--json' takes no value, got '1'"),
        (&["search", "--limit", "x", "q"], "option '--limit <n>' argument 'x' is invalid"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
    assert_eq!(
        p(&["search", "--applicable", "--limit=-2", "--json", "--", "-q"]),
        Parsed::Run(Command::Search { query: "-q".into(), applicable: true, limit: -2, json: true })
    );
    assert_eq!(
        p(&["search", "tls AND cert", "--limit", "5"]),
        Parsed::Run(Command::Search { query: "tls AND cert".into(), applicable: false, limit: 5, json: false })
    );
    assert_eq!(p(&["breach", "--enable"]), Parsed::Run(Command::Breach { enable: true, disable: false }));
    assert!(usage(&["breach", "--disable", "--enable"]).contains("cannot be used with"));
    assert_eq!(p(&["sync", "--refresh", "--json"]), Parsed::Run(Command::Sync { refresh: true, json: true }));
    assert_eq!(p(&["tools"]), Parsed::Run(Command::Tools { json: false }));
    assert_eq!(p(&["version", "--json"]), Parsed::Run(Command::Version { json: true }));
    assert_eq!(p(&["skill"]), Parsed::Run(Command::Skill));
    assert_eq!(p(&["watch", "--offline", "--json"]), Parsed::Run(Command::Watch { json: true, offline: true }));
}

#[test]
fn licenses_takes_no_options_or_arguments() {
    assert_eq!(p(&["licenses"]), Parsed::Run(Command::Licenses));
    for (bad, msg) in [
        (&["licenses", "--json"][..], "unknown option '--json'"),
        (&["licenses", "ring"], "too many arguments for 'licenses'"),
        (&["license"], "unknown command 'license'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
    let text = help(&["licenses"]);
    assert!(text.contains("THIRD-PARTY-NOTICES.txt"), "{text}");
}

#[test]
fn report_options() {
    assert_eq!(p(&["report"]), Parsed::Run(Command::Report(Show::default())));
    assert_eq!(
        p(&["report", "remediation", "--csv", "--since", "30d", "-o", "r.csv"]),
        Parsed::Run(Command::Report(Show {
            part: Part::Remediation,
            format: Shown::Csv,
            out: Some("r.csv".into()),
            stdout: false,
            since: 30,
            run: None,
        }))
    );
    assert_eq!(
        p(&["report", "--json", "-o", "-"]),
        Parsed::Run(Command::Report(Show { format: Shown::Json, stdout: true, ..Default::default() }))
    );
    assert_eq!(
        p(&["report", "exposure", "--jsonl"]),
        Parsed::Run(Command::Report(Show { part: Part::Exposure, format: Shown::Jsonl, ..Default::default() }))
    );
    for (bad, msg) in [
        (&["report", "x"][..], "argument 'x' is invalid for 'part'. Allowed choices are findings, history"),
        (&["report", "--since", "0"], "option '--since' expects a number of days, got '0'"),
        (&["report", "--md", "--csv"], "option '--csv' cannot be used with option '--md'"),
        (&["report", "--exposure"], "unknown option '--exposure'"),
        (&["report", "audit", "x"], "too many arguments for 'report'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
}

#[test]
fn schedule_cache_and_update() {
    let sched = |every: &str, at: &str, dry_run: bool| {
        Parsed::Run(Command::Schedule {
            action: "install".into(),
            every: every.into(),
            at: at.into(),
            dry_run,
            json: false,
        })
    };
    assert_eq!(p(&["schedule", "install"]), sched("day", "09:30", false));
    assert_eq!(
        p(&["schedule", "install", "--every", "quarter", "--at", "7:05", "--dry-run"]),
        sched("quarter", "7:05", true)
    );
    for action in ["status", "uninstall", "run"] {
        let Parsed::Run(Command::Schedule { action: a, .. }) = p(&["schedule", action]) else { panic!("{action}") };
        assert_eq!(a, action);
    }
    assert_eq!(p(&["cache", "prune"]), Parsed::Run(Command::Cache { action: "prune".into(), older_than: 90 }));
    assert_eq!(
        p(&["cache", "prune", "--older-than", "7"]),
        Parsed::Run(Command::Cache { action: "prune".into(), older_than: 7 })
    );
    assert_eq!(
        p(&["update", "--check", "--yes", "--no-input", "--offline", "--version", "v1.2.3"]),
        Parsed::Run(Command::Update {
            json: false,
            check: true,
            yes: true,
            no_input: true,
            offline: true,
            version: Some("v1.2.3".into())
        })
    );
    for (bad, msg) in [
        (&["schedule"][..], "missing command: one of install, status, uninstall, run"),
        (&["schedule", "dance"], "unknown command 'dance'"),
        (&["schedule", "install", "run"], "too many arguments for 'install'"),
        (
            &["schedule", "install", "--every", "sometimes"],
            "argument 'sometimes' is invalid. Allowed choices are hour, day, week, month, quarter, year.",
        ),
        (&["schedule", "install", "--every", "weekly"], "is invalid"),
        (&["schedule", "install", "--at", "25:00"], "option '--at <time>' expects HH:MM, got '25:00'"),
        (&["schedule", "install", "--at", "9:5"], "expects HH:MM, got '9:5'"),
        (&["schedule", "install", "--every"], "option '--every <period>' argument missing"),
        (&["cache"], "missing command: one of prune"),
        (&["cache", "vacuum"], "unknown command 'vacuum'"),
        (&["cache", "prune", "all"], "too many arguments for 'prune'"),
        (&["cache", "prune", "--older-than", "0"], "option '--older-than' expects a number of days, got '0'"),
        (&["update", "now"], "too many arguments for 'update'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
}

#[test]
fn fix_one_thing() {
    let one = |target: Target, dry_run: bool, yes: bool, no_input: bool, undo: bool| {
        Parsed::Run(Command::Mitigate {
            target,
            dry_run,
            yes,
            no_input,
            undo,
            bundle: None,
            hours: 72,
            json: false,
            from_scan: None,
        })
    };
    assert_eq!(p(&["fix", "cve-2026-98432"]), one(Target::Id("CVE-2026-98432".into()), false, false, false, false));
    assert_eq!(p(&["fix", "list"]), one(Target::List, false, false, false, false));
    assert_eq!(p(&["fix", "next"]), one(Target::Next, false, false, false, false));
    assert_eq!(p(&["fix", "f-3fa9c01b2e"]), one(Target::Id("F-3FA9C01B2E".into()), false, false, false, false));
    assert_eq!(
        p(&["fix", "secret", "f-3fa9c01b2e", "--dry-run"]),
        one(Target::Secret("F-3FA9C01B2E".into()), true, false, false, false)
    );
    let Parsed::Run(Command::Mitigate { json, .. }) = p(&["fix", "next", "--json"]) else { panic!() };
    assert!(json);
    assert_eq!(
        p(&["fix", "--dry-run", "--yes", "--no-input", "GHSA-xxxx-yyyy-zzzz"]),
        one(Target::Id("GHSA-XXXX-YYYY-ZZZZ".into()), true, true, true, false)
    );
    assert_eq!(
        p(&["fix", "CVE-2026-98432", "--undo"]),
        one(Target::Id("CVE-2026-98432".into()), false, false, false, true)
    );
    let Parsed::Run(Command::Mitigate { target, hours, .. }) = p(&["fix", "extension-cooldown", "--hours", "48"])
    else {
        panic!()
    };
    assert_eq!((target, hours), (Target::Id("EXTENSION-COOLDOWN".into()), 48));
    let Parsed::Run(Command::Mitigate { bundle, .. }) = p(&["fix", "ca-trust", "--bundle", "/b.pem"]) else { panic!() };
    assert_eq!(bundle, Some(PathBuf::from("/b.pem")));
    let c = scan(&["fix", "all", "--offline", "--no-machine", "--path", "/w", "--yes"]);
    assert!(c.fix && c.offline && c.no_machine && c.yes && c.path == Some(vec![PathBuf::from("/w")]));
    for (bad, msg) in [
        (
            &["fix", "kernel"][..],
            "argument 'target' expects all, list, next, secret ID, a finding id such as F-3fa9c01b2e, an advisory id such as CVE-2026-98432, or ca-trust or extension-cooldown, got 'kernel'",
        ),
        (&["fix", "CVE-2026-98432", "now"], "too many arguments for 'fix'"),
        (&["fix", "secret"], "secret takes a finding id"),
        (&["fix", "secret", "CVE-2026-1"], "argument 'id' expects a finding id"),
        (&["fix", "secret", "F-3fa9c01b2e", "--undo"], "--undo takes one id"),
        (&["fix", "CVE-2026-98432", "--dry-run", "--undo"], "--dry-run and --undo can't be combined"),
        (&["fix", "list", "--undo"], "--undo takes one id"),
        (&["fix", "--undo"], "--undo takes one id"),
        (&["fix", "extension-cooldown", "--hours", "lots"], "option '--hours' expects a number of hours, got 'lots'"),
    ] {
        assert!(usage(bad).contains(msg), "{bad:?}: {}", usage(bad));
    }
}

#[test]
fn policy_files_come_from_the_config_folder_unless_an_option_names_one() {
    if std::env::var_os("XDG_CONFIG_HOME").is_some_and(|v| !v.is_empty()) {
        return; // the config folder is elsewhere on this machine
    }
    let _home = wpantry::utils::files::test_home();
    let dir = wpantry::utils::files::home().join(".config/wpantry");
    std::fs::create_dir_all(&dir).unwrap();
    for (file, body) in [
        ("suspect.toml", "ids = [\"PRIV-ESCALATION\"]\n"),
        ("hooks.toml", "repos = [\"~/code\"]\n"),
        ("posture.toml", "skip = [\"FIREWALL\"]\n"),
        ("licenses.toml", "allow = [\"MIT\"]\n"),
    ] {
        std::fs::write(dir.join(file), body).unwrap();
    }
    let c = scan(&["scan"]);
    assert_eq!(
        (c.suspect_policy, c.hooks_policy, c.posture_policy),
        (Some(dir.join("suspect.toml")), Some(dir.join("hooks.toml")), Some(dir.join("posture.toml")))
    );
    assert_eq!(c.install_scripts, None, "no file of yours: the bundled default");
    assert!(
        !c.check_licenses && c.licenses == Some(dir.join("licenses.toml")),
        "used when --licenses is given, never turns it on"
    );
    // An option names another file: that one.
    let mine = dir.join("other.toml");
    std::fs::write(&mine, "ids = []\n").unwrap();
    assert_eq!(scan(&["fix", "--suspect-policy", &mine.to_string_lossy()]).suspect_policy, Some(mine));
    // A file of yours that isn't TOML is as much an error as a named one.
    std::fs::write(dir.join("posture.toml"), "FIREWALL\n").unwrap();
    let text = usage(&["scan"]);
    assert!(
        text.contains("option '--posture-policy'") && text.contains("posture.toml: not a TOML policy file"),
        "{text}"
    );
}

#[test]
fn scan_project_is_one_directory_and_never_the_machine() {
    let _home = wpantry::utils::files::test_home();
    let dir = wpantry::utils::files::home().join("app");
    std::fs::create_dir_all(&dir).unwrap();
    let whole = std::fs::canonicalize(&dir).unwrap();
    let c = scan(&["scan", "project", "~/app", "--offline", "--json"]);
    assert_eq!(c.path, Some(vec![whole.clone()]));
    assert!(c.project && c.no_machine && c.offline && !c.fix);
    assert_eq!(c.show.format, Shown::Json);
    // No directory: here, by its whole path.
    let here = scan(&["scan", "project"]);
    assert_eq!(here.path, Some(vec![std::fs::canonicalize(".").unwrap()]));
    // A plain scan isn't one.
    assert!(!scan(&["scan", "--path", "~/app", "--no-machine"]).project);
    assert!(usage(&["scan", "project", "~/nowhere"]).contains("argument 'dir': no such directory: ~/nowhere"));
    assert!(usage(&["scan", "project", "--path", "~/app"]).contains("takes its directory as an argument, not --path"));
    assert!(usage(&["scan", "project", "~/app", "~/app"]).contains("too many arguments"));
    // The machine's options reach this command from `scan`, hidden from its
    // help: each is refused, so none changes what a project scan covers.
    for (flag, value) in [
        ("--no-machine", None),
        ("--no-posture", None),
        ("--no-personal-files", None),
        ("--posture-policy", Some("~/p.toml")),
    ] {
        let argv: Vec<&str> = ["scan", "project", "~/app", flag].into_iter().chain(value).collect();
        let text = usage(&argv);
        assert!(text.contains(&format!("option '{flag}' is for a scan of this computer")), "{flag}: {text}");
    }
    // A posture policy that doesn't parse fails a machine scan, and never a
    // project scan, which runs no posture check and so never reads it.
    if std::env::var_os("XDG_CONFIG_HOME").is_none_or(|v| v.is_empty()) {
        let config = wpantry::utils::files::home().join(".config/wpantry");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("posture.toml"), "FIREWALL\n").unwrap();
        assert!(usage(&["scan"]).contains("posture.toml: not a TOML policy file"), "{}", usage(&["scan"]));
        let c = scan(&["scan", "project", "~/app"]);
        assert!(c.project && c.posture_policy.is_none());
    }
    // Its help offers the scan's options, without the machine's.
    let text = help(&["scan", "project"]);
    assert!(text.starts_with("Usage: wpantry scan project [options] [dir]\n"), "{text}");
    for gone in ["--path", "--no-machine", "--no-posture", "--posture-policy", "--no-personal-files"] {
        assert!(!text.contains(&format!("\n  {gone}")), "{gone}");
    }
    for kept in ["--deep", "--licenses [file]", "--json", "--offline", "--no-malware"] {
        assert!(text.contains(&format!("\n  {kept}")), "{kept}");
    }
    assert!(help(&["scan"]).contains("\n  project [options] [dir]"));
}

#[test]
fn runs_prune_and_one_run_reported() {
    assert_eq!(p(&["runs"]), Parsed::Run(Command::Runs { json: false }));
    assert_eq!(p(&["runs", "--json"]), Parsed::Run(Command::Runs { json: true }));
    assert_eq!(p(&["prune", "61", "#62"]), Parsed::Run(Command::Prune { ids: vec![61, 62] }));
    assert!(usage(&["prune"]).contains("missing required argument 'id'"), "{}", usage(&["prune"]));
    for bad in ["latest", "0", "-3", "1.5"] {
        let text = usage(&["prune", "--", bad]);
        assert!(text.contains(&format!("expects a scan's number (wpantry runs lists them), got '{bad}'")), "{text}");
    }
    assert_eq!(
        p(&["report", "--run", "61", "--md"]),
        Parsed::Run(Command::Report(Show { run: Some(61), format: Shown::Md, ..Show::default() }))
    );
    assert!(usage(&["report", "--run", "last"]).contains("option '--run' expects a scan's number"));
    // A scan reports itself: it takes no --run.
    assert!(usage(&["scan", "--run", "3"]).contains("unknown option '--run'"));
    assert!(help(&["report"]).contains("\n  --run <id>"));
    assert!(help(&[]).contains("\n  runs [options]") && help(&[]).contains("\n  prune <id...>"));
}

#[test]
fn ignore_takes_a_finding_or_rule_id_and_never_a_prompt() {
    use wpantry::checks::ignore_edit::Scope;
    let run = |action: IgnoreAction, json: bool| Parsed::Run(Command::Ignore { action, json });
    assert_eq!(
        p(&["ignore", "add", "F-3FA9C01B2E"]),
        run(
            IgnoreAction::Add { id: "F-3fa9c01b2e".into(), scope: Scope::User, reason: None, all_places: false },
            false
        ),
        "the id is kept lower case, the scope is your file"
    );
    assert_eq!(
        p(&[
            "ignore",
            "add",
            "F-3fa9c01b2e",
            "--scope",
            "repo",
            "--reason",
            "  revoked  ",
            "--all-places",
            "--json",
            "--no-input"
        ]),
        run(
            IgnoreAction::Add {
                id: "F-3fa9c01b2e".into(),
                scope: Scope::Repo,
                reason: Some("revoked".into()),
                all_places: true
            },
            true
        )
    );
    assert_eq!(p(&["ignore", "list"]), run(IgnoreAction::List { path: None }, false));
    assert_eq!(
        p(&["ignore", "list", "--path", "/r", "--json"]),
        run(IgnoreAction::List { path: Some("/r".into()) }, true)
    );
    assert_eq!(
        p(&["ignore", "remove", "R-3FA9C01B2E", "--path", "/r"]),
        run(IgnoreAction::Remove { id: "R-3fa9c01b2e".into(), path: Some("/r".into()) }, false)
    );
    assert_eq!(
        p(&["ignore", "remove", "f-3fa9c01b2e", "--no-input", "--json"]),
        run(IgnoreAction::Remove { id: "F-3fa9c01b2e".into(), path: None }, true)
    );
    assert!(usage(&["ignore", "add", "CVE-2026-1"]).contains("expects a finding id such as F-3fa9c01b2e"));
    assert!(usage(&["ignore", "add", "F-3fa9c01b2e", "--scope", "both"]).contains("--scope"));
    assert!(usage(&["ignore", "add", "F-3fa9c01b2e", "--reason", "a\nb"]).contains("one line"));
    assert!(usage(&["ignore", "remove", "F-xyz"]).contains("expects a rule id such as R-3fa9c01b2e"));
    assert!(usage(&["ignore", "list", "x"]).contains("too many arguments"));
    assert!(usage(&["ignore"]).contains("Usage: wpantry ignore"));
}

/// Oracle: the parser refuses `fix F-… --from-scan N --no-input`
/// without `--yes` or `--dry-run`, and accepts either. Known bad: before the
/// fix it parsed, and the fix ran unasked.
#[test]
fn from_scan_with_no_input_needs_yes_or_dry_run() {
    let id = "F-0123456789";
    assert!(usage(&["fix", id, "--from-scan", "3", "--no-input"]).contains(FROM_SCAN_NEEDS_YES));
    for ok in [["--no-input", "--yes"], ["--no-input", "--dry-run"]] {
        let argv: Vec<&str> = ["fix", id, "--from-scan", "3"].into_iter().chain(ok).collect();
        assert!(matches!(p(&argv), Parsed::Run(_)), "{argv:?}");
    }
}
