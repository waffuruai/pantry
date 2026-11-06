//! Argument parsing, behaving as the Python implementation's argparse
//! parser does where the contract can see it: no arguments print the help,
//! options may be abbreviated to a unique prefix and take their value as the
//! next argument or after `=`, and a usage error prints the usage line and
//! the error to stderr and exits 2.

use std::path::PathBuf;

pub const SUBCOMMANDS: &[&str] = &[
    "scan", "check", "fix", "search", "export", "breach", "watch", "version", "tools", "skill", "sync", "schedule",
    "cache", "update", "report", "mitigate", "rules", "sources", "help",
];

/// How a report is shown: the terminal's tables (the default), or a format
/// a file or another program reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Shown {
    #[default]
    Tui,
    Txt,
    Json,
    Jsonl,
    Csv,
    Md,
    Html,
}

impl Shown {
    /// The flag that picks it.
    pub fn flag(self) -> &'static str {
        match self {
            Shown::Tui => "",
            Shown::Txt => "--txt",
            Shown::Json => "--json",
            Shown::Jsonl => "--jsonl",
            Shown::Csv => "--csv",
            Shown::Md => "--md",
            Shown::Html => "--html",
        }
    }
}

const FORMATS: [Shown; 6] = [Shown::Txt, Shown::Json, Shown::Jsonl, Shown::Csv, Shown::Md, Shown::Html];

/// The report's options, shared by `report` (and `export`), `scan`, `check`
/// and `fix`: what it covers (`report`'s word; the findings for a scan),
/// which format, written where, and how far back the logs go.
#[derive(Clone, Debug, PartialEq)]
pub struct Show {
    pub part: wpantry::reporters::Part,
    pub format: Shown,
    pub out: Option<PathBuf>,
    /// `-o -`: to stdout even on a terminal. Otherwise a format other than
    /// the terminal's goes to a file (`<when>_pantry_report.<ext>`) on a
    /// terminal, and to stdout when stdout is a pipe or a file.
    pub stdout: bool,
    /// `--since DAYS`: the logs' reach.
    pub since: i64,
}

impl Default for Show {
    fn default() -> Show {
        Show {
            part: wpantry::reporters::Part::Findings,
            format: Shown::Tui,
            out: None,
            stdout: false,
            since: wpantry::reporters::HISTORY_DAYS,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
/// The scan's options: `scan`, its alias `check`, and `fix`.
pub struct Check {
    pub path: Option<Vec<PathBuf>>,
    pub no_machine: bool,
    /// `fix` (`scan --fix` and `--update` still work): the unattended fixes and the stopgaps, then a re-check.
    pub fix: bool,
    /// `fix --yes`: run and write without asking.
    pub yes: bool,
    /// `fix --dryrun`: print the plan, change nothing.
    pub dryrun: bool,
    pub refresh: bool,
    pub offline: bool,
    /// How the report is shown when the scan is done.
    pub show: Show,
    pub no_input: bool,
    /// `--jobs N`: CPU-bound scans at once.
    pub jobs: Option<usize>,
    pub gitleaks_config: Option<PathBuf>,
    /// `--licenses [FILE]`: check dependency licenses (off by default).
    pub check_licenses: bool,
    pub licenses: Option<PathBuf>,
    pub install_scripts: Option<PathBuf>,
    pub repo_hooks: Option<PathBuf>,
    pub no_posture: bool,
    pub posture_policy: Option<PathBuf>,
    pub suspect_policy: Option<PathBuf>,
    pub hooks_policy: Option<PathBuf>,
    /// `--no-malware`: skip the YARA malware scan.
    pub no_malware: bool,
    /// `--deep`: the malware scan reads all of `~` with every system's rules.
    pub deep: bool,
    /// `--no-online-hash`: never look up a flagged file's hash online.
    pub no_online_hash: bool,
    /// `--sources FILE`: the user's sources file for this run.
    pub sources: Option<PathBuf>,
}

/// What `fix list` and `fix ID` act on.
#[derive(Debug, PartialEq)]
pub enum Target {
    /// What can be fixed, from the latest scan.
    List,
    /// One advisory, or one of wpantry's own fixes by name, upper-cased.
    Id(String),
}

#[derive(Debug, PartialEq)]
pub enum Command {
    /// `scan`, `check` or `fix` (`fix` is set).
    Scan(Check),
    Search {
        query: String,
        applicable: bool,
        limit: i64,
        json: bool,
    },
    Breach {
        enable: bool,
        disable: bool,
    },
    Watch {
        json: bool,
        offline: bool,
    },
    Version {
        json: bool,
    },
    Tools {
        json: bool,
    },
    /// `sources`: every source wpantry reads and what its fetches came to.
    Sources {
        json: bool,
        /// `--sources FILE`: the user's sources file to list with.
        file: Option<PathBuf>,
    },
    /// `report` (or `export`): the latest scan, shown.
    Report(Show),
    Sync {
        refresh: bool,
        json: bool,
    },
    Schedule {
        action: String,
        every: String,
        at: String,
        dry_run: bool,
    },
    Cache {
        action: String,
        older_than: i64,
    },
    Update {
        check: bool,
        yes: bool,
        no_input: bool,
        offline: bool,
        version: Option<String>,
    },
    /// `fix list` and `fix ID` (`mitigate` is the same command).
    Mitigate {
        target: Target,
        dry_run: bool,
        yes: bool,
        no_input: bool,
        /// `--undo` (`--remove` is the same): take the stopgap away.
        undo: bool,
        /// `--bundle FILE` (`ca-trust`) and `--hours N` (`extension-cooldown`).
        bundle: Option<PathBuf>,
        hours: u32,
    },
    Skill,
    /// `rules`: the YARA rule sources and what compiled (`--update` fetches);
    /// `rules gen SAMPLE...` writes a rule; `rules goodware` rebuilds the goodware database.
    Rules {
        /// "" (list), "gen" or "goodware".
        action: String,
        samples: Vec<PathBuf>,
        update: bool,
        json: bool,
        category: String,
        family: Option<String>,
        name: Option<String>,
        out: Option<PathBuf>,
    },
}

/// What parsing decided: run a command, or exit now (help printed, or a
/// usage error).
#[derive(Debug, PartialEq)]
// `Run` carries the whole parsed command; the other two are one string each.
// One value is built per process, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum Parsed {
    Run(Command),
    Help(String),
    Usage(String),
}

const TOP_USAGE: &str = "usage: wpantry [-h] {scan,check,fix,search,export,breach,watch,version,tools,skill,sync,schedule,cache,update,report,mitigate,rules,sources,help} ...";

/// The scan's options in its usage line, shared by `scan`, `check` and
/// `fix` (`fix` adds `--dryrun` and `--yes` in front).
const SCAN_USAGE: [&str; 4] = [
    "[--path DIR] [--no-machine] [--refresh] [--offline] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--since DAYS] [--no-input] [--jobs N]",
    "[--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]",
    "[--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-malware] [--deep]",
    "[--no-online-hash]",
];

/// The scan's options in its help, shared by `scan`, `check` and `fix`.
/// The report options in a help text, shared by `report`, `export`, `scan`,
/// `check` and `fix`.
macro_rules! report_options {
    () => {
        "  --txt                 the report as plain text, without colour\n  --json                the findings as JSON (schema 1)\n  --jsonl               one JSON object per finding, joined with its OSV record, lifecycle and fix\n  --csv                 one table: the findings, or the log asked for\n  --md                  Markdown\n  --html                one offline HTML page\n  -o, --out FILE        write the report there (- for stdout). Without it, a format is written to <when>_pantry_report.<ext> here when stdout is a terminal, and to stdout when it is a pipe or a file\n  --since DAYS          how far back the logs go (default 14)"
    };
}

const SCAN_OPTIONS: &str = concat!(
    "  --path DIR            check only the repos at or under DIR (repeatable; default: every git repo under ~)\n  --no-machine          skip the machine inventory: repo checks only\n  --refresh             ignore cached answers and ask every source again\n  --offline             use only the local cache\n",
    report_options!(),
    "\n  --no-input            never prompt\n  --jobs N              gitleaks scans at once (default: half the cores, at most 4)\n  --gitleaks-config FILE\n                        policy file (default: bundled gitleaks.toml)\n  --licenses [FILE], --license [FILE]\n                        also check dependency licenses (off by default), against FILE or the bundled licenses.txt\n  --install-scripts FILE\n                        policy file (default: bundled install-scripts.txt)\n  --repo-hooks FILE     indicators of hijacked repos (default: bundled repo-hooks.txt)\n  --hooks-policy FILE   repo hooks you've read and accept, one per line (default: none)\n  --suspect-policy FILE\n                        suspicious-code ids and paths that warn instead of fail (default: none)\n  --no-posture          skip the machine's security settings (FileVault, firewall, sharing, …)\n  --posture-policy FILE\n                        posture checks to skip, one id per line (default: none)\n  --no-malware          skip the malware scan (YARA rules over Downloads, Desktop, temp, login items and repo programs)\n  --deep                the malware scan reads everything under ~ with every system's rules (slower)\n  --no-online-hash      never look up a flagged file's SHA-256 at YARAify, CIRCL or MalwareBazaar (asked once otherwise)\n  --sources FILE        your sources file for this run (default: ~/.config/wpantry/sources.toml when it exists)"
);

pub fn usage(cmd: &str) -> String {
    let cmd = if cmd == "mitigate" { "fix" } else { cmd };
    let line: &str = match cmd {
        "scan" | "check" | "fix" => {
            let pad = " ".repeat(format!("usage: wpantry {cmd} ").len());
            let fix = if cmd == "fix" {
                " [--dryrun] [--yes] [--undo] [--bundle FILE] [--hours N] [list|all|ID]"
            } else {
                ""
            };
            return format!(
                "usage: wpantry {cmd} [-h]{fix} {}\n{pad}{}\n{pad}{}\n{pad}{}",
                SCAN_USAGE[0], SCAN_USAGE[1], SCAN_USAGE[2], SCAN_USAGE[3]
            );
        }
        "search" => "usage: wpantry search [-h] [--applicable] [--limit LIMIT] [--json] query",
        "breach" => "usage: wpantry breach [-h] [--enable | --disable]",
        "watch" => "usage: wpantry watch [-h] [--offline] [--json]",
        "version" => "usage: wpantry version [-h] [--json]",
        "tools" => "usage: wpantry tools [-h] [--json]",
        "sources" => "usage: wpantry sources [-h] [--json] [--sources FILE]",
        "skill" => "usage: wpantry skill [-h]",
        "rules" => {
            "usage: wpantry rules [-h] [--update] [--json]\n       wpantry rules gen [--category CAT] [--family NAME] [--name RULE] [--out FILE] SAMPLE [SAMPLE ...]\n       wpantry rules goodware"
        }
        "schedule" => {
            "usage: wpantry schedule [-h] [--every PERIOD] [--at HH:MM] [--dry-run] {install,status,uninstall,run}"
        }
        "sync" => "usage: wpantry sync [-h] [--refresh] [--json]",
        "cache" => "usage: wpantry cache [-h] [--older-than DAYS] {prune}",
        "update" => "usage: wpantry update [-h] [--check] [--yes] [--no-input] [--offline] [--version VER]",
        "report" | "export" => {
            return format!(
                "usage: wpantry {cmd} [-h] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--since DAYS]\n{}{{findings,history,exposure,remediation,audit,summary,all}}",
                " ".repeat(format!("usage: wpantry {cmd} ").len())
            );
        }
        _ => TOP_USAGE,
    };
    line.to_string()
}

fn help(cmd: &str) -> String {
    let cmd = if cmd == "mitigate" { "fix" } else { cmd };
    let body = match cmd {
        "scan" => {
            return format!(
                "{}\n\nscan this computer and report what applies to it; change nothing\n\noptions:\n  -h, --help            show this help message and exit\n{SCAN_OPTIONS}\n\nExit codes: 0 nothing fails, 1 something fails, 2 usage error, 3 internal error.\n",
                usage(cmd)
            );
        }
        "check" => {
            return format!(
                "{}\n\nthe same as scan\n\noptions:\n  -h, --help            show this help message and exit\n{SCAN_OPTIONS}\n\nExit codes: 0 nothing fails, 1 something fails, 2 usage error, 3 internal error.\n",
                usage(cmd)
            );
        }
        "fix" => {
            return format!(
                "{}\n\nscan, then run the fixes that can run unattended and the stopgaps wpantry has for what it found, then re-check. mitigate is the same command\n\npositional arguments:\n  all                   everything (the default): a scan, the unattended fixes, every stopgap that applies, a re-check\n  list                  what can be fixed, from the latest scan: the update plan in batches, the stopgaps and whether each applies here; nothing runs\n  ID                    one advisory (CVE-…, GHSA-…; an alias works): its unattended fixes from the last scan, wpantry's stopgap for it, the steps that need you. Or one of wpantry's own fixes by name: ca-trust (distrust the leaked eMudhra roots in the system trust store), extension-cooldown (editors wait before installing a new extension version), cve-2026-98432\n\noptions:\n  -h, --help            show this help message and exit\n  --dryrun, --dry-run   print what would run or be written; change nothing\n  --yes                 run the fixes and write the stopgaps without asking\n  --undo                ID only: take wpantry's stopgap away again once the real fix is installed (--remove is the same)\n  --bundle FILE         ca-trust: rewrite this PEM bundle instead of the system trust store\n  --hours N             extension-cooldown: the cooldown (default 72)\n{SCAN_OPTIONS}\n\nExit codes: 0 nothing fails after the re-check, 1 something still fails or a fix failed, 2 usage error, 3 internal error.\n",
                usage(cmd)
            );
        }
        "search" => {
            "search cached advisories (for agents)\n\npositional arguments:\n  query\n\noptions:\n  -h, --help       show this help message and exit\n  --applicable     only advisories that apply here\n  --limit LIMIT\n  --json"
        }
        "breach" => {
            "show or set consent for the email breach check\n\noptions:\n  -h, --help  show this help message and exit\n  --enable\n  --disable"
        }
        "watch" => {
            "ask OSV again about the advisories the last scan found with no released fix (Critical, High, exploited in the wild): exit 10 when a fix has landed\n\noptions:\n  -h, --help  show this help message and exit\n  --offline   use only the local cache\n  --json"
        }
        "version" => {
            "print the version, implementation and JSON schema\n\noptions:\n  -h, --help  show this help message and exit\n  --json"
        }
        "tools" => {
            "list the external tools this implementation uses\n\noptions:\n  -h, --help  show this help message and exit\n  --json"
        }
        "skill" => "print the agent skill (SKILL.md)\n\noptions:\n  -h, --help  show this help message and exit",
        "sources" => {
            "every outside source wpantry reads (assets/defaults/sources.toml): its kind, tier, host and licence, when it was last fetched, whether that is fresh, and what last went wrong\n\noptions:\n  -h, --help      show this help message and exit\n  --json          the sources as JSON\n  --sources FILE  your sources file (default: ~/.config/wpantry/sources.toml when it exists)"
        }
        "rules" => {
            "the YARA rules the malware scan uses: ours, built in, and YARA Forge's, fetched into the cache directory; gen writes a rule from samples\n\npositional arguments:\n  gen SAMPLE ...   write a YARA rule matching what the samples share and this machine's programs don't (unreviewed: category suspicious, score 60)\n  goodware         rebuild the goodware database from this machine's system programs (gen builds it the first time)\n\noptions:\n  -h, --help       show this help message and exit\n  --update         fetch YARA Forge's latest package now\n  --json           the sources and counts as JSON\n  --category CAT   gen: the category you propose (default malware)\n  --family NAME    gen: the family's name (default: the first sample's file name)\n  --name RULE      gen: the rule's name (default Gen_<category>_<family>)\n  --out FILE       gen: write the rule there, and its test file beside it (default: stdout)"
        }
        "sync" => {
            "refresh the cache: the feeds, end-of-life dates and OSV answers for what was scanned before, so scan --offline has fresh answers\n\noptions:\n  -h, --help  show this help message and exit\n  --refresh   ask every source again, even when its answer is fresh\n  --json      print what was refreshed as JSON"
        }
        "schedule" => {
            "run sync and scan on a schedule (launchd, a systemd user timer, or cron); never fixes (that is wpantry fix)\n\npositional arguments:\n  {install,status,uninstall,run}\n\noptions:\n  -h, --help         show this help message and exit\n  --every PERIOD     hour, day (default), week, month, quarter or year, each from its start (a week on Monday, a month on the 1st, a quarter on 1 January, April, July and October, a year on 1 January)\n  --at HH:MM         the time of day (default 09:30)\n  --dry-run          print the job definition without installing it"
        }
        "cache" => {
            "maintain the cache\n\npositional arguments:\n  {prune}               drop what no scan has used in a while, then compact the file\n\noptions:\n  -h, --help            show this help message and exit\n  --older-than DAYS     what counts as unused (default 90)"
        }
        "update" => {
            "check for a newer wpantry release and, after a yes, install it verified\n\noptions:\n  -h, --help       show this help message and exit\n  --check          only say whether a newer release exists (exit 10 when one does)\n  --yes            install without asking\n  --no-input       never ask: report only\n  --offline        use only the cached answer\n  --version VER    this release instead of the latest"
        }
        "report" | "export" => {
            return format!(
                "{}\n\nthe latest scan's report, from the cache; it never scans (scan and fix show the same when they finish). export is the same command\n\npositional arguments:\n  findings              the latest scan's findings (the default)\n  history               the exposure, remediation and audit logs, without the findings\n  exposure              what applied, from first seen to resolved\n  remediation           the fixes run: when, who, the result, the scan that verified them\n  audit                 every scan and event\n  summary               one page for a CSO, an auditor or an insurer: where things stand, times to fix against the targets, who fixed what\n  all                   the findings, then every log\n\noptions:\n  -h, --help            show this help message and exit\n{}\n\nExit codes: 0 nothing fails, 1 something fails in the latest scan or there is none, 2 usage error, 3 internal error.\n",
                usage(cmd),
                report_options!()
            );
        }
        _ => {
            "wpantry: the vulnerabilities that apply to this computer. See README.md;\n\npositional arguments:\n  {scan,check,fix,search,export,breach,watch,version,tools,skill,sync,schedule,cache,update,report,mitigate,rules,sources,help}\n    scan                scan this computer and report what applies; change nothing\n    check               the same as scan\n    fix                 scan, run the unattended fixes and the stopgaps, then re-check (--dryrun prints the plan; list, or one ID)\n    search              search cached advisories (for agents)\n    export              the same as report\n    breach              show or set consent for the email breach check\n    watch               re-check the unfixed Critical/High advisories; exit 10 when a fix has landed\n    version             print the version, implementation and JSON schema\n    tools               list the external tools this implementation uses\n    skill               print the agent skill (SKILL.md)\n    sync                refresh the cache for offline scans\n    schedule            run sync and scan on a schedule\n    cache               maintain the cache (prune)\n    update              check for a newer release and install it verified\n    report              the latest scan's report, or its history, a log or the summary (--json, --md, --html, …)\n    mitigate            the same as fix\n    rules               the YARA rules the malware scan uses (--update fetches)\n    sources             every outside source, when it was last fetched and what went wrong\n    help                this help, or with a command that command's (wpantry help fix)\n\noptions:\n  -h, --help            show this help message and exit\n\nExit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error."
        }
    };
    format!("{}\n\n{body}\n", usage(cmd))
}

/// Other spellings an option answers to, matched before prefixes are:
/// `--license` for `--licenses`, `--update` for the scan's old `--fix`.
const ALIASES: &[(&str, &str)] = &[
    ("--license", "--licenses"),
    ("-o", "--out"),
    ("--update", "--fix"),
    ("--remove", "--undo"),
    ("--dry-run", "--dryrun"),
];

/// The report options given: at most one format, a file to write, and the
/// logs' reach.
fn show(flag: &dyn Fn(&str) -> bool, value: &dyn Fn(&str) -> Option<String>) -> Result<Show, String> {
    let picked: Vec<Shown> = FORMATS.iter().copied().filter(|f| flag(f.flag())).collect();
    let format = match picked.as_slice() {
        [] => Shown::Tui,
        [one] => *one,
        [a, b, ..] => return Err(format!("argument {}: not allowed with argument {}", b.flag(), a.flag())),
    };
    let stdout = value("--out").as_deref() == Some("-");
    let out = match value("--out") {
        Some(v) if v.is_empty() => return Err("argument -o/--out: expected a file path, or - for stdout".into()),
        Some(v) if v == "-" => None,
        Some(v) => Some(expand(&v)),
        None => None,
    };
    // A file gets plain text, never the terminal's colours.
    let format = if format == Shown::Tui && out.is_some() { Shown::Txt } else { format };
    let since = match value("--since") {
        None => wpantry::reporters::HISTORY_DAYS,
        Some(v) => match v.trim().trim_end_matches('d').parse::<i64>() {
            Ok(n) if n >= 1 => n,
            _ => return Err(format!("argument --since: expected a number of days, got '{v}'")),
        },
    };
    Ok(Show { part: wpantry::reporters::Part::Findings, format, out, stdout, since })
}

/// (option, takes a value) for each subcommand.
fn options(cmd: &str) -> &'static [(&'static str, bool)] {
    match cmd {
        // The scan's, with `fix`'s hidden in front: `scan --fix` (and
        // `--update`) still parse, undocumented, for scripts older than `fix`.
        "scan" | "check" => &[
            ("--help", false),
            ("--fix", false),
            ("--dryrun", false),
            ("--yes", false),
            ("--path", true),
            ("--no-machine", false),
            ("--refresh", false),
            ("--offline", false),
            ("--txt", false),
            ("--json", false),
            ("--jsonl", false),
            ("--csv", false),
            ("--md", false),
            ("--html", false),
            ("--out", true),
            ("--since", true),
            ("--no-input", false),
            ("--jobs", true),
            ("--gitleaks-config", true),
            ("--licenses", true),
            ("--install-scripts", true),
            ("--repo-hooks", true),
            ("--no-posture", false),
            ("--posture-policy", true),
            ("--suspect-policy", true),
            ("--hooks-policy", true),
            ("--no-malware", false),
            ("--deep", false),
            ("--no-online-hash", false),
            ("--sources", true),
        ],
        "fix" => &[
            ("--help", false),
            ("--dryrun", false),
            ("--yes", false),
            ("--undo", false),
            ("--bundle", true),
            ("--hours", true),
            ("--path", true),
            ("--no-machine", false),
            ("--refresh", false),
            ("--offline", false),
            ("--txt", false),
            ("--json", false),
            ("--jsonl", false),
            ("--csv", false),
            ("--md", false),
            ("--html", false),
            ("--out", true),
            ("--since", true),
            ("--no-input", false),
            ("--jobs", true),
            ("--gitleaks-config", true),
            ("--licenses", true),
            ("--install-scripts", true),
            ("--repo-hooks", true),
            ("--no-posture", false),
            ("--posture-policy", true),
            ("--suspect-policy", true),
            ("--hooks-policy", true),
            ("--no-malware", false),
            ("--deep", false),
            ("--no-online-hash", false),
            ("--sources", true),
        ],
        "rules" => &[
            ("--help", false),
            ("--update", false),
            ("--json", false),
            ("--category", true),
            ("--family", true),
            ("--name", true),
            ("--out", true),
        ],
        "search" => &[("--help", false), ("--applicable", false), ("--limit", true), ("--json", false)],
        "breach" => &[("--help", false), ("--enable", false), ("--disable", false)],
        "watch" => &[("--help", false), ("--offline", false), ("--json", false)],
        "version" | "tools" => &[("--help", false), ("--json", false)],
        "sources" => &[("--help", false), ("--json", false), ("--sources", true)],
        "report" | "export" => &[
            ("--help", false),
            ("--txt", false),
            ("--json", false),
            ("--jsonl", false),
            ("--csv", false),
            ("--md", false),
            ("--html", false),
            ("--out", true),
            ("--since", true),
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

/// A first word that is no subcommand.
fn invalid_command(word: &str) -> Parsed {
    Parsed::Usage(format!(
        "{TOP_USAGE}\nwpantry: error: argument command: invalid choice: '{word}' (choose from {})\n",
        SUBCOMMANDS.join(", ")
    ))
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/").or(if p == "~" { Some("") } else { None }) {
        Some(rest) => wpantry::utils::files::home().join(rest),
        None => PathBuf::from(p),
    }
}

pub fn parse(argv: &[String]) -> Parsed {
    let mut argv: Vec<String> = argv.to_vec();
    match argv.first().map(String::as_str) {
        None | Some("-h" | "--help") => return Parsed::Help(help("")),
        // Options with no subcommand are the scan's, as before `scan` had a
        // name: `wpantry --fix` and `wpantry --json` keep working.
        Some(a) if a.starts_with('-') => argv.insert(0, "scan".into()),
        Some(a) if !SUBCOMMANDS.contains(&a) => return invalid_command(a),
        // `help` alone is `-h`; `help CMD` is `CMD -h`.
        Some("help") => {
            return match argv[1..].iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [] | ["-h" | "--help"] => Parsed::Help(help("")),
                [c] if SUBCOMMANDS.contains(c) => Parsed::Help(help(if *c == "help" { "" } else { c })),
                [c] => invalid_command(c),
                [_, rest @ ..] => Parsed::Usage(format!(
                    "{TOP_USAGE}\nwpantry help: error: unrecognized arguments: {}\n",
                    rest.join(" ")
                )),
            };
        }
        Some(_) => {}
    }
    // `mitigate` is `fix` under its older name.
    let cmd = if argv[0] == "mitigate" { "fix".to_string() } else { argv[0].clone() };
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
        let opts = options(&cmd);
        // An alias applies only where the command has no option of that name
        // (`rules --update` is its own; `scan --update` is the old `--fix`).
        let name = if opts.iter().any(|(o, _)| *o == name) {
            name
        } else {
            ALIASES.iter().find(|(alias, _)| *alias == name).map_or(name, |(_, opt)| *opt)
        };
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
                None if i < argv.len() && (!argv[i].starts_with('-') || argv[i] == "-") => {
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
        "fix" if !positional.is_empty() && positional[0] != "all" => {
            let target = match positional.as_slice() {
                [w] if w == "list" => Target::List,
                [id] if id.contains('-') && id.len() >= 6 => Target::Id(id.trim().to_ascii_uppercase()),
                [id] => {
                    return fail(format!(
                        "argument what: expected list, all, an advisory id such as CVE-2026-98432, or ca-trust or extension-cooldown, got '{id}'"
                    ));
                }
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
                [] => unreachable!("matched above"),
            };
            if flag("--dryrun") && flag("--undo") {
                return fail(
                    "--dry-run and --undo can't be combined: --dry-run prints what applying would write".into(),
                );
            }
            if target == Target::List && flag("--undo") {
                return fail("--undo takes one id: wpantry fix CVE-2026-98432 --undo".into());
            }
            let hours = match value("--hours") {
                None => wpantry::remediation::editors::COOLDOWN_HOURS,
                Some(v) => match v.trim().parse::<u32>() {
                    Ok(n) if n >= 1 => n,
                    _ => return fail(format!("argument --hours: expected a number of hours, got '{v}'")),
                },
            };
            Command::Mitigate {
                target,
                dry_run: flag("--dryrun"),
                yes: flag("--yes"),
                no_input: flag("--no-input"),
                undo: flag("--undo"),
                bundle: value("--bundle").map(|v| expand(&v)),
                hours,
            }
        }
        "scan" | "check" | "fix" => {
            if !positional.is_empty() && !(cmd == "fix" && positional == ["all"]) {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let mut c = Check {
                no_machine: flag("--no-machine"),
                fix: cmd == "fix" || flag("--fix"),
                yes: flag("--yes"),
                dryrun: flag("--dryrun"),
                refresh: flag("--refresh"),
                offline: flag("--offline"),
                no_input: flag("--no-input"),
                check_licenses: flag("--licenses"),
                no_posture: flag("--no-posture"),
                no_malware: flag("--no-malware"),
                deep: flag("--deep"),
                no_online_hash: flag("--no-online-hash"),
                sources: value("--sources").map(|s| expand(&s)),
                ..Default::default()
            };
            c.show = match show(&flag, &value) {
                Ok(s) => s,
                Err(e) => return fail(e),
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
                ("--repo-hooks", &mut c.repo_hooks),
                ("--posture-policy", &mut c.posture_policy),
                ("--suspect-policy", &mut c.suspect_policy),
                ("--hooks-policy", &mut c.hooks_policy),
            ] {
                if let Some(v) = value(opt) {
                    let p = expand(&v);
                    if !p.is_file() {
                        return fail(format!("argument {opt}: no such file: {v}"));
                    }
                    *slot = Some(p);
                }
            }
            Command::Scan(c)
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
        "report" | "export" => {
            let part = match positional.as_slice() {
                [] => wpantry::reporters::Part::Findings,
                [word] => match wpantry::reporters::Part::parse(word) {
                    Some(p) => p,
                    None => {
                        return fail(format!(
                            "argument what: invalid choice: '{word}' (choose from {})",
                            wpantry::reporters::Part::NAMES.join(", ")
                        ));
                    }
                },
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            match show(&flag, &value) {
                Ok(s) => Command::Report(Show { part, ..s }),
                Err(e) => return fail(e),
            }
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
            let every = value("--every").unwrap_or_else(|| "day".into());
            if crate::schedule::Every::parse(&every).is_none() {
                return fail(format!(
                    "argument --every: invalid choice: '{every}' (choose from {})",
                    crate::schedule::Every::NAMES.join(", ")
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
        "rules" => {
            let action = positional.first().cloned().unwrap_or_default();
            let samples: Vec<PathBuf> = positional.iter().skip(1).map(|p| expand(p)).collect();
            match action.as_str() {
                "" => {}
                "gen" if samples.is_empty() => return fail("rules gen: at least one SAMPLE".into()),
                "gen" => {}
                "goodware" if samples.is_empty() => {}
                _ => return fail(format!("unrecognized arguments: {}", positional.join(" "))),
            }
            Command::Rules {
                action,
                samples,
                update: flag("--update"),
                json: flag("--json"),
                category: value("--category").unwrap_or_else(|| "malware".into()),
                family: value("--family"),
                name: value("--name"),
                out: value("--out").map(|o| expand(&o)),
            }
        }
        "version" | "tools" | "skill" | "watch" | "sources" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            match cmd.as_str() {
                "watch" => Command::Watch { json: flag("--json"), offline: flag("--offline") },
                "version" => Command::Version { json: flag("--json") },
                "tools" => Command::Tools { json: flag("--json") },
                "sources" => Command::Sources { json: flag("--json"), file: value("--sources").map(|s| expand(&s)) },
                _ => Command::Skill,
            }
        }
        _ => unreachable!("subcommands are fixed"),
    };
    Parsed::Run(command)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
