//! Argument parsing, behaving as the Python implementation's argparse
//! parser does where the contract can see it: `check` is the default
//! subcommand, options may be abbreviated to a unique prefix and take their
//! value as the next argument or after `=`, and a usage error prints the
//! usage line and the error to stderr and exits 2.

use std::path::PathBuf;

pub const SUBCOMMANDS: &[&str] = &[
    "check", "search", "export", "breach", "version", "tools", "skill", "sync", "schedule", "cache", "update", "report",
];

#[derive(Debug, Default, PartialEq)]
pub struct Check {
    pub path: Option<Vec<PathBuf>>,
    pub no_machine: bool,
    pub update: bool,
    pub dryrun: bool,
    pub refresh: bool,
    pub offline: bool,
    pub json: bool,
    pub no_input: bool,
    /// `--jobs N`: CPU-bound scans at once.
    pub jobs: Option<usize>,
    pub gitleaks_config: Option<PathBuf>,
    /// `--licenses [FILE]`: check dependency licenses (off by default).
    pub check_licenses: bool,
    pub licenses: Option<PathBuf>,
    pub install_scripts: Option<PathBuf>,
    pub no_posture: bool,
    pub posture_policy: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Check(Check),
    Search { query: String, applicable: bool, limit: i64, json: bool },
    Export { csv: Option<String>, jsonl: Option<String>, all: bool },
    Breach { enable: bool, disable: bool },
    Version { json: bool },
    Tools { json: bool },
    Report { sections: Vec<String>, since_days: i64, format: String, out: Option<String> },
    Sync { refresh: bool, json: bool },
    Schedule { action: String, every: String, at: String, dry_run: bool },
    Cache { action: String, older_than: i64 },
    Update { check: bool, yes: bool, no_input: bool, offline: bool, version: Option<String> },
    Skill,
}

/// What parsing decided: run a command, or exit now (help printed, or a
/// usage error).
#[derive(Debug, PartialEq)]
pub enum Parsed {
    Run(Command),
    Help(String),
    Usage(String),
}

const TOP_USAGE: &str =
    "usage: wpantry [-h] {check,search,export,breach,version,tools,skill,sync,schedule,cache,update,report} ...";

pub fn usage(cmd: &str) -> &'static str {
    match cmd {
        "check" => {
            "usage: wpantry check [-h] [--path DIR] [--no-machine] [--update] [--dryrun] [--refresh] [--offline] [--json]\n                      [--no-input] [--jobs N] [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE]\n                      [--no-posture] [--posture-policy FILE]"
        }
        "search" => "usage: wpantry search [-h] [--applicable] [--limit LIMIT] [--json] query",
        "export" => "usage: wpantry export [-h] [--csv CSV] [--jsonl JSONL] [--all]",
        "breach" => "usage: wpantry breach [-h] [--enable | --disable]",
        "version" => "usage: wpantry version [-h] [--json]",
        "tools" => "usage: wpantry tools [-h] [--json]",
        "skill" => "usage: wpantry skill [-h]",
        _ => TOP_USAGE,
    }
}

fn help(cmd: &str) -> String {
    let body = match cmd {
        "check" => {
            "scan this computer (default)\n\noptions:\n  -h, --help            show this help message and exit\n  --path DIR            check only the repos at or under DIR (repeatable; default: every git repo under ~)\n  --no-machine          skip the machine inventory: repo checks only\n  --update              apply the fixes that can run unattended, then re-check\n  --dryrun              print the update plan without changing anything\n  --refresh             ignore cached answers and ask every source again\n  --offline             use only the local cache\n  --json                print the findings as JSON (schema 1)\n  --no-input            never prompt\n  --jobs N              gitleaks scans at once (default: half the cores, at most 4)\n  --gitleaks-config FILE\n                        policy file (default: bundled gitleaks.toml)\n  --licenses [FILE], --license [FILE]\n                        also check dependency licenses (off by default), against FILE or the bundled licenses.txt\n  --install-scripts FILE\n                        policy file (default: bundled install-scripts.txt)\n  --no-posture          skip the machine's security settings (FileVault, firewall, sharing, …)\n  --posture-policy FILE\n                        posture checks to skip, one id per line (default: none)"
        }
        "search" => {
            "search cached advisories (for agents)\n\npositional arguments:\n  query\n\noptions:\n  -h, --help       show this help message and exit\n  --applicable     only advisories that apply here\n  --limit LIMIT\n  --json"
        }
        "export" => {
            "write the latest findings as CSV, or as JSON Lines joined with their OSV records, lifecycle and fix outcome\n\noptions:\n  -h, --help     show this help message and exit\n  --csv CSV      the summary columns, one finding per row\n  --jsonl JSONL  one JSON object per finding: the finding, aliases, url, record, first_seen, last_seen, resolved_at, days_exposed, fix\n  --all          with --jsonl: also the resolved exposures the latest scan no longer lists"
        }
        "breach" => {
            "show or set consent for the email breach check\n\noptions:\n  -h, --help  show this help message and exit\n  --enable\n  --disable"
        }
        "version" => {
            "print the version, implementation and JSON schema\n\noptions:\n  -h, --help  show this help message and exit\n  --json"
        }
        "tools" => {
            "list the external tools this implementation uses\n\noptions:\n  -h, --help  show this help message and exit\n  --json"
        }
        "skill" => "print the agent skill (SKILL.md)\n\noptions:\n  -h, --help  show this help message and exit",
        "sync" => {
            "refresh the cache: the feeds, end-of-life dates and OSV answers for what was scanned before, so check --offline has fresh answers\n\noptions:\n  -h, --help  show this help message and exit\n  --refresh   ask every source again, even when its answer is fresh\n  --json      print what was refreshed as JSON"
        }
        "schedule" => {
            "run sync and check on a schedule (launchd, a systemd user timer, or cron); never --update\n\npositional arguments:\n  {install,status,uninstall,run}\n\noptions:\n  -h, --help       show this help message and exit\n  --every WHEN     hourly, daily (default) or weekly\n  --at HH:MM       the time of day (default 09:30; weekly: Mondays)\n  --dry-run        print the job definition without installing it"
        }
        "cache" => {
            "maintain the cache\n\npositional arguments:\n  {prune}               drop what no scan has used in a while, then compact the file\n\noptions:\n  -h, --help            show this help message and exit\n  --older-than DAYS     what counts as unused (default 90)"
        }
        "update" => {
            "check for a newer wpantry release and, after a yes, install it verified\n\noptions:\n  -h, --help       show this help message and exit\n  --check          only say whether a newer release exists (exit 10 when one does)\n  --yes            install without asking\n  --no-input       never ask: report only\n  --offline        use only the cached answer\n  --version VER    this release instead of the latest"
        }
        "report" => {
            "the exposure, remediation and audit logs kept across scans\n\noptions:\n  -h, --help        show this help message and exit\n  --exposure        what applied, from first seen to resolved (default: all three)\n  --remediation     the fixes --update ran, and the scans that verified them\n  --audit           every scan and event\n  --since DAYS      how far back (default 90)\n  --format FORMAT   md (default), json or csv (csv: the exposure log)\n  -o, --out FILE    write there instead of stdout"
        }
        _ => {
            "wpantry: the vulnerabilities that apply to this computer. See README.md;\n\npositional arguments:\n  {check,search,export,breach,version,tools,skill,sync,schedule,cache,update,report}\n    check               scan this computer (default)\n    search              search cached advisories (for agents)\n    export              write the findings as CSV or JSON Lines\n    breach              show or set consent for the email breach check\n    version             print the version, implementation and JSON schema\n    tools               list the external tools this implementation uses\n    skill               print the agent skill (SKILL.md)\n    sync                refresh the cache for offline checks\n    schedule            run sync and check on a schedule\n    cache               maintain the cache (prune)\n    update              check for a newer release and install it verified\n    report              the exposure, remediation and audit logs\n\noptions:\n  -h, --help            show this help message and exit\n\nExit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error."
        }
    };
    format!("{}\n\n{body}\n", usage(cmd))
}

/// Other spellings an option answers to, matched before prefixes are:
/// `--license` for `--licenses`.
const ALIASES: &[(&str, &str)] = &[("--license", "--licenses"), ("-o", "--out")];

/// (option, takes a value) for each subcommand.
fn options(cmd: &str) -> &'static [(&'static str, bool)] {
    match cmd {
        "check" => &[
            ("--help", false),
            ("--path", true),
            ("--no-machine", false),
            ("--update", false),
            ("--dryrun", false),
            ("--refresh", false),
            ("--offline", false),
            ("--json", false),
            ("--no-input", false),
            ("--jobs", true),
            ("--gitleaks-config", true),
            ("--licenses", true),
            ("--install-scripts", true),
            ("--no-posture", false),
            ("--posture-policy", true),
        ],
        "search" => &[("--help", false), ("--applicable", false), ("--limit", true), ("--json", false)],
        "export" => &[("--help", false), ("--csv", true), ("--jsonl", true), ("--all", false)],
        "breach" => &[("--help", false), ("--enable", false), ("--disable", false)],
        "version" | "tools" => &[("--help", false), ("--json", false)],
        "report" => &[
            ("--help", false),
            ("--exposure", false),
            ("--remediation", false),
            ("--audit", false),
            ("--all", false),
            ("--since", true),
            ("--format", true),
            ("--out", true),
        ],
        "sync" => &[("--help", false), ("--refresh", false), ("--json", false), ("--no-input", false)],
        "schedule" => &[("--help", false), ("--every", true), ("--at", true), ("--dry-run", false)],
        "cache" => &[("--help", false), ("--older-than", true)],
        "update" => &[
            ("--help", false),
            ("--check", false),
            ("--yes", false),
            ("--no-input", false),
            ("--offline", false),
            ("--version", true),
        ],
        _ => &[("--help", false)],
    }
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/").or(if p == "~" { Some("") } else { None }) {
        Some(rest) => wpantry::system::home().join(rest),
        None => PathBuf::from(p),
    }
}

pub fn parse(argv: &[String]) -> Parsed {
    let mut argv: Vec<String> = argv.to_vec();
    if argv.first().is_none_or(|a| !SUBCOMMANDS.contains(&a.as_str()) && a != "-h" && a != "--help") {
        argv.insert(0, "check".into()); // `check` is the default subcommand
    }
    if matches!(argv[0].as_str(), "-h" | "--help") {
        return Parsed::Help(help(""));
    }
    let cmd = argv[0].clone();
    let fail = |msg: String| Parsed::Usage(format!("{}\nwpantry {cmd}: error: {msg}\n", usage(&cmd)));
    let mut given: Vec<(&'static str, Option<String>)> = Vec::new();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1;
    let mut only_positional = false;
    while i < argv.len() {
        let a = &argv[i];
        i += 1;
        if only_positional || !a.starts_with('-') || a == "-" {
            positional.push(a.clone());
            continue;
        }
        if a == "--" {
            only_positional = true;
            continue;
        }
        if a == "-h" {
            return Parsed::Help(help(&cmd));
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        let name = ALIASES.iter().find(|(alias, _)| *alias == name).map_or(name, |(_, opt)| *opt);
        let opts = options(&cmd);
        let matched: Vec<&(&str, bool)> = match opts.iter().find(|(o, _)| *o == name) {
            Some(exact) => vec![exact],
            None if name.starts_with("--") && name.len() > 2 => {
                opts.iter().filter(|(o, _)| o.starts_with(name)).collect()
            }
            None => vec![],
        };
        let (opt, takes) = match matched.as_slice() {
            [one] => **one,
            [] => {
                let rest: Vec<&str> = argv[i - 1..].iter().map(String::as_str).collect();
                return fail(format!("unrecognized arguments: {}", rest.join(" ")));
            }
            many => {
                let names: Vec<&str> = many.iter().map(|(o, _)| *o).collect();
                return fail(format!("ambiguous option: {name} could match {}", names.join(", ")));
            }
        };
        if opt == "--help" {
            return Parsed::Help(help(&cmd));
        }
        let value = if takes {
            match inline {
                Some(v) => Some(v),
                None if i < argv.len() && !argv[i].starts_with('-') => {
                    i += 1;
                    Some(argv[i - 1].clone())
                }
                // The one option whose value is optional (argparse's nargs="?").
                None if opt == "--licenses" => None,
                None => return fail(format!("argument {opt}: expected one argument")),
            }
        } else {
            if inline.is_some() {
                return fail(format!("argument {opt}: ignored explicit argument '{}'", inline.unwrap_or_default()));
            }
            None
        };
        given.push((opt, value));
    }
    let flag = |name: &str| given.iter().any(|(o, _)| *o == name);
    let value = |name: &str| given.iter().rev().find(|(o, _)| *o == name).and_then(|(_, v)| v.clone());
    let command = match cmd.as_str() {
        "check" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let mut c = Check {
                no_machine: flag("--no-machine"),
                update: flag("--update"),
                dryrun: flag("--dryrun"),
                refresh: flag("--refresh"),
                offline: flag("--offline"),
                json: flag("--json"),
                no_input: flag("--no-input"),
                check_licenses: flag("--licenses"),
                no_posture: flag("--no-posture"),
                ..Default::default()
            };
            let paths: Vec<PathBuf> = given
                .iter()
                .filter(|(o, _)| *o == "--path")
                .filter_map(|(_, v)| v.as_deref().map(PathBuf::from))
                .collect();
            c.path = (!paths.is_empty()).then_some(paths);
            if let Some(v) = value("--jobs") {
                match v.parse::<usize>() {
                    Ok(n) if n >= 1 => c.jobs = Some(n),
                    _ => return fail(format!("argument --jobs: expected a number of 1 or more, got {v}")),
                }
            }
            for (opt, slot) in [
                ("--gitleaks-config", &mut c.gitleaks_config),
                ("--licenses", &mut c.licenses),
                ("--install-scripts", &mut c.install_scripts),
                ("--posture-policy", &mut c.posture_policy),
            ] {
                if let Some(v) = value(opt) {
                    let p = expand(&v);
                    if !p.is_file() {
                        return fail(format!("argument {opt}: no such file: {v}"));
                    }
                    *slot = Some(p);
                }
            }
            Command::Check(c)
        }
        "search" => {
            let query = match positional.as_slice() {
                [q] => q.clone(),
                [] => return fail("the following arguments are required: query".into()),
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            let limit = match value("--limit") {
                None => 20,
                Some(v) => match v.trim().parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => return fail(format!("argument --limit: invalid int value: '{v}'")),
                },
            };
            Command::Search { query, applicable: flag("--applicable"), limit, json: flag("--json") }
        }
        "export" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let (csv, jsonl) = (value("--csv"), value("--jsonl"));
            if csv.is_none() && jsonl.is_none() {
                return fail("one of the following arguments is required: --csv, --jsonl".into());
            }
            Command::Export { csv, jsonl, all: flag("--all") }
        }
        "breach" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let (enable, disable) = (flag("--enable"), flag("--disable"));
            if enable && disable {
                return fail("argument --disable: not allowed with argument --enable".into());
            }
            Command::Breach { enable, disable }
        }
        "report" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let mut sections: Vec<String> = ["exposure", "remediation", "audit"]
                .iter()
                .filter(|s| flag(&format!("--{s}")))
                .map(|s| s.to_string())
                .collect();
            if sections.is_empty() || flag("--all") {
                sections = vec!["all".into()];
            }
            let since_days = match value("--since") {
                None => 90,
                Some(v) => match v.trim().trim_end_matches('d').parse::<i64>() {
                    Ok(n) if n >= 1 => n,
                    _ => return fail(format!("argument --since: expected a number of days, got '{v}'")),
                },
            };
            let format = value("--format").unwrap_or_else(|| "md".into());
            if !["md", "json", "csv"].contains(&format.as_str()) {
                return fail(format!("argument --format: invalid choice: '{format}' (choose from md, json, csv)"));
            }
            Command::Report { sections, since_days, format, out: value("--out") }
        }
        "sync" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            Command::Sync { refresh: flag("--refresh"), json: flag("--json") }
        }
        "schedule" => {
            let action = match positional.as_slice() {
                [a] if ["install", "status", "uninstall", "run"].contains(&a.as_str()) => a.clone(),
                [a] => {
                    return fail(format!(
                        "argument action: invalid choice: '{a}' (choose from install, status, uninstall, run)"
                    ));
                }
                [] => return fail("the following arguments are required: action".into()),
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            let every = value("--every").unwrap_or_else(|| "daily".into());
            if !["hourly", "daily", "weekly"].contains(&every.as_str()) {
                return fail(format!(
                    "argument --every: invalid choice: '{every}' (choose from hourly, daily, weekly)"
                ));
            }
            let at = value("--at").unwrap_or_else(|| "09:30".into());
            let ok_time = at.split_once(':').is_some_and(|(h, m)| {
                h.parse::<u32>().is_ok_and(|h| h < 24) && m.len() == 2 && m.parse::<u32>().is_ok_and(|m| m < 60)
            });
            if !ok_time {
                return fail(format!("argument --at: expected HH:MM, got '{at}'"));
            }
            Command::Schedule { action, every, at, dry_run: flag("--dry-run") }
        }
        "cache" => {
            let action = match positional.as_slice() {
                [a] if a == "prune" => a.clone(),
                [a] => return fail(format!("argument action: invalid choice: '{a}' (choose from prune)")),
                [] => return fail("the following arguments are required: action".into()),
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            let older_than = match value("--older-than") {
                None => 90,
                Some(v) => match v.trim().parse::<i64>() {
                    Ok(n) if n >= 1 => n,
                    _ => return fail(format!("argument --older-than: expected a number of days, got '{v}'")),
                },
            };
            Command::Cache { action, older_than }
        }
        "update" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            Command::Update {
                check: flag("--check"),
                yes: flag("--yes"),
                no_input: flag("--no-input"),
                offline: flag("--offline"),
                version: value("--version"),
            }
        }
        "version" | "tools" | "skill" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            match cmd.as_str() {
                "version" => Command::Version { json: flag("--json") },
                "tools" => Command::Tools { json: flag("--json") },
                _ => Command::Skill,
            }
        }
        _ => unreachable!("subcommands are fixed"),
    };
    Parsed::Run(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Parsed {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn check_is_the_default() {
        assert_eq!(p(&[]), Parsed::Run(Command::Check(Check::default())));
        let Parsed::Run(Command::Check(c)) = p(&["--path", "/a", "--path=/b", "--no-m", "--json"]) else { panic!() };
        assert_eq!(c.path, Some(vec![PathBuf::from("/a"), PathBuf::from("/b")]));
        assert!(c.no_machine && c.json && !c.offline && !c.check_licenses);
        let Parsed::Run(Command::Check(c)) = p(&["--licenses", "--json"]) else { panic!() };
        assert!(c.check_licenses && c.licenses.is_none() && c.json, "--licenses alone uses the bundled allowlist");
        let Parsed::Run(Command::Check(c)) = p(&["--license", "--json"]) else { panic!() };
        assert!(c.check_licenses && c.licenses.is_none() && c.json, "--license is --licenses");
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let Parsed::Run(Command::Check(c)) = p(&[&format!("--license={file}")]) else { panic!() };
        assert!(c.check_licenses && c.licenses == Some(PathBuf::from(file)));
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
        assert!(msg.starts_with("usage: wpantry check") && msg.contains("error: unrecognized arguments: --bogus"));
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
    }
}
