//! Argument parsing, behaving as the Python implementation's argparse
//! parser does where the contract can see it: `check` is the default
//! subcommand, options may be abbreviated to a unique prefix and take their
//! value as the next argument or after `=`, and a usage error prints the
//! usage line and the error to stderr and exits 2.

use std::path::PathBuf;

pub const SUBCOMMANDS: &[&str] = &["check", "search", "export", "breach", "version", "tools", "skill", "harden"];

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
    Export { csv: String },
    Breach { enable: bool, disable: bool },
    Version { json: bool },
    Tools { json: bool },
    Harden { what: String, hours: u32 },
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

const TOP_USAGE: &str = "usage: wpantry [-h] {check,search,export,breach,version,tools,skill,harden} ...";

pub fn usage(cmd: &str) -> &'static str {
    match cmd {
        "check" => {
            "usage: wpantry check [-h] [--path DIR] [--no-machine] [--update] [--dryrun] [--refresh] [--offline] [--json]\n                      [--no-input] [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE]\n                      [--no-posture] [--posture-policy FILE]"
        }
        "search" => "usage: wpantry search [-h] [--applicable] [--limit LIMIT] [--json] query",
        "export" => "usage: wpantry export [-h] --csv CSV",
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
            "scan this computer (default)\n\noptions:\n  -h, --help            show this help message and exit\n  --path DIR            check only the repos at or under DIR (repeatable; default: every git repo under ~)\n  --no-machine          skip the machine inventory: repo checks only\n  --update              apply the fixes that can run unattended, then re-check\n  --dryrun              print the update plan without changing anything\n  --refresh             ignore cached answers and ask every source again\n  --offline             use only the local cache\n  --json                print the findings as JSON (schema 1)\n  --no-input            never prompt\n  --gitleaks-config FILE\n                        policy file (default: bundled gitleaks.toml)\n  --licenses [FILE], --license [FILE]\n                        also check dependency licenses (off by default), against FILE or the bundled licenses.txt\n  --install-scripts FILE\n                        policy file (default: bundled install-scripts.txt)\n  --no-posture          skip the machine's security settings (FileVault, firewall, sharing, …)\n  --posture-policy FILE\n                        posture checks to skip, one id per line (default: none)"
        }
        "search" => {
            "search cached advisories (for agents)\n\npositional arguments:\n  query\n\noptions:\n  -h, --help       show this help message and exit\n  --applicable     only advisories that apply here\n  --limit LIMIT\n  --json"
        }
        "export" => "write the findings as CSV\n\noptions:\n  -h, --help  show this help message and exit\n  --csv CSV",
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
        "harden" => {
            "apply one of the user-level posture fixes\n\npositional arguments:\n  {extension-cooldown}  set extensions.installCooldownHours in every VS Code-family editor's settings.json\n\noptions:\n  -h, --help     show this help message and exit\n  --hours N      the cooldown (default 72)"
        }
        _ => {
            "wpantry: the vulnerabilities that apply to this computer. See README.md;\n\npositional arguments:\n  {check,search,export,breach,version,tools,skill,harden}\n    check               scan this computer (default)\n    search              search cached advisories (for agents)\n    export              write the findings as CSV\n    breach              show or set consent for the email breach check\n    version             print the version, implementation and JSON schema\n    tools               list the external tools this implementation uses\n    skill               print the agent skill (SKILL.md)\n    harden              apply a user-level posture fix (extension-cooldown)\n\noptions:\n  -h, --help            show this help message and exit\n\nExit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error."
        }
    };
    format!("{}\n\n{body}\n", usage(cmd))
}

/// Other spellings an option answers to, matched before prefixes are:
/// `--license` for `--licenses`.
const ALIASES: &[(&str, &str)] = &[("--license", "--licenses")];

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
            ("--gitleaks-config", true),
            ("--licenses", true),
            ("--install-scripts", true),
            ("--no-posture", false),
            ("--posture-policy", true),
        ],
        "search" => &[("--help", false), ("--applicable", false), ("--limit", true), ("--json", false)],
        "export" => &[("--help", false), ("--csv", true)],
        "breach" => &[("--help", false), ("--enable", false), ("--disable", false)],
        "version" | "tools" => &[("--help", false), ("--json", false)],
        "harden" => &[("--help", false), ("--hours", true)],
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
            match value("--csv") {
                Some(csv) => Command::Export { csv },
                None => return fail("the following arguments are required: --csv".into()),
            }
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
        "harden" => {
            let what = match positional.as_slice() {
                [w] if w == "extension-cooldown" => w.clone(),
                [w] => return fail(format!("argument what: invalid choice: '{w}' (choose from extension-cooldown)")),
                [] => return fail("the following arguments are required: what".into()),
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            let hours = match value("--hours") {
                None => 72,
                Some(v) => match v.trim().parse::<u32>() {
                    Ok(n) if n >= 1 => n,
                    _ => return fail(format!("argument --hours: expected a number of hours, got '{v}'")),
                },
            };
            Command::Harden { what, hours }
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
