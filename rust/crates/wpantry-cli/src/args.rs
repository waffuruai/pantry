//! Argument parsing, behaving as the Python implementation's argparse
//! parser does where the contract can see it: no arguments print the help,
//! options may be abbreviated to a unique prefix and take their value as the
//! next argument or after `=`, and a usage error prints the usage line and
//! the error to stderr and exits 2.

use std::path::PathBuf;

pub const SUBCOMMANDS: &[&str] = &[
    "scan", "check", "fix", "search", "export", "breach", "watch", "version", "tools", "skill", "sync", "schedule",
    "cache", "update", "report", "harden", "mitigate", "rules", "sources", "help",
];

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
    pub json: bool,
    pub html: Option<PathBuf>,
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

/// What `mitigate` acts on.
#[derive(Debug, PartialEq)]
pub enum Target {
    /// The stopgaps wpantry has and the advisories with an unattended fix.
    List,
    /// Everything: `fix`.
    All,
    /// One advisory, upper-cased.
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
    Export {
        csv: Option<String>,
        jsonl: Option<String>,
        all: bool,
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
    Report {
        sections: Vec<String>,
        since_days: i64,
        format: String,
        out: Option<String>,
    },
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
    Harden {
        what: String,
        hours: u32,
        bundle: Option<PathBuf>,
    },
    Mitigate {
        target: Target,
        dry_run: bool,
        yes: bool,
        no_input: bool,
        /// `--undo` (`--remove` is the same): take the stopgap away.
        undo: bool,
        offline: bool,
        no_machine: bool,
        path: Option<Vec<PathBuf>>,
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

const TOP_USAGE: &str = "usage: wpantry [-h] {scan,check,fix,search,export,breach,watch,version,tools,skill,sync,schedule,cache,update,report,harden,mitigate,rules,sources,help} ...";

/// The scan's options in its usage line, shared by `scan`, `check` and
/// `fix` (`fix` adds `--dryrun` and `--yes` in front).
const SCAN_USAGE: [&str; 4] = [
    "[--path DIR] [--no-machine] [--refresh] [--offline] [--json] [--html FILE] [--no-input] [--jobs N]",
    "[--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]",
    "[--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-malware] [--deep]",
    "[--no-online-hash]",
];

/// The scan's options in its help, shared by `scan`, `check` and `fix`.
const SCAN_OPTIONS: &str = "  --path DIR            check only the repos at or under DIR (repeatable; default: every git repo under ~)\n  --no-machine          skip the machine inventory: repo checks only\n  --refresh             ignore cached answers and ask every source again\n  --offline             use only the local cache\n  --json                print the findings as JSON (schema 1)\n  --html FILE           also save an offline HTML report (open FILE in a browser)\n  --no-input            never prompt\n  --jobs N              gitleaks scans at once (default: half the cores, at most 4)\n  --gitleaks-config FILE\n                        policy file (default: bundled gitleaks.toml)\n  --licenses [FILE], --license [FILE]\n                        also check dependency licenses (off by default), against FILE or the bundled licenses.txt\n  --install-scripts FILE\n                        policy file (default: bundled install-scripts.txt)\n  --repo-hooks FILE     indicators of hijacked repos (default: bundled repo-hooks.txt)\n  --hooks-policy FILE   repo hooks you've read and accept, one per line (default: none)\n  --suspect-policy FILE\n                        suspicious-code ids and paths that warn instead of fail (default: none)\n  --no-posture          skip the machine's security settings (FileVault, firewall, sharing, …)\n  --posture-policy FILE\n                        posture checks to skip, one id per line (default: none)\n  --no-malware          skip the malware scan (YARA rules over Downloads, Desktop, temp, login items and repo programs)\n  --deep                the malware scan reads everything under ~ with every system's rules (slower)\n  --no-online-hash      never look up a flagged file's SHA-256 at YARAify, CIRCL or MalwareBazaar (asked once otherwise)\n  --sources FILE        your sources file for this run (default: ~/.config/wpantry/sources.toml when it exists)";

pub fn usage(cmd: &str) -> String {
    let line: &str = match cmd {
        "scan" | "check" | "fix" => {
            let pad = " ".repeat(format!("usage: wpantry {cmd} ").len());
            let fix = if cmd == "fix" { " [--dryrun] [--yes]" } else { "" };
            return format!(
                "usage: wpantry {cmd} [-h]{fix} {}\n{pad}{}\n{pad}{}\n{pad}{}",
                SCAN_USAGE[0], SCAN_USAGE[1], SCAN_USAGE[2], SCAN_USAGE[3]
            );
        }
        "search" => "usage: wpantry search [-h] [--applicable] [--limit LIMIT] [--json] query",
        "export" => "usage: wpantry export [-h] [--csv CSV] [--jsonl JSONL] [--all]",
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
            "usage: wpantry schedule [-h] [--every WHEN] [--at HH:MM] [--dry-run] {install,status,uninstall,run}"
        }
        "sync" => "usage: wpantry sync [-h] [--refresh] [--json]",
        "cache" => "usage: wpantry cache [-h] [--older-than DAYS] {prune}",
        "update" => "usage: wpantry update [-h] [--check] [--yes] [--no-input] [--offline] [--version VER]",
        "report" => {
            "usage: wpantry report [-h] [--exposure] [--remediation] [--audit] [--since DAYS] [--format FORMAT] [-o FILE]"
        }
        "harden" => "usage: wpantry harden [-h] [--hours N] [--bundle FILE] {extension-cooldown,ca-trust}",
        "mitigate" => {
            "usage: wpantry mitigate [-h] [--dry-run] [--yes] [--no-input] [--undo] [--offline] [--no-machine] [--path DIR]\n                        {list,all,ID}"
        }
        _ => TOP_USAGE,
    };
    line.to_string()
}

fn help(cmd: &str) -> String {
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
                "{}\n\nscan, then run the fixes that can run unattended and the stopgaps wpantry has for what it found, then re-check\n\noptions:\n  -h, --help            show this help message and exit\n  --dryrun              print the fix plan; change nothing\n  --yes                 run the fixes and write the stopgaps without asking\n{SCAN_OPTIONS}\n\nExit codes: 0 nothing fails after the re-check, 1 something still fails or a fix failed, 2 usage error, 3 internal error.\n",
                usage(cmd)
            );
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
            "run sync and scan on a schedule (launchd, a systemd user timer, or cron); never fixes (that is wpantry fix)\n\npositional arguments:\n  {install,status,uninstall,run}\n\noptions:\n  -h, --help         show this help message and exit\n  --every WHEN       hourly, daily (default) or weekly\n  --at HH:MM         the time of day (default 09:30; weekly: Mondays)\n  --dry-run          print the job definition without installing it"
        }
        "cache" => {
            "maintain the cache\n\npositional arguments:\n  {prune}               drop what no scan has used in a while, then compact the file\n\noptions:\n  -h, --help            show this help message and exit\n  --older-than DAYS     what counts as unused (default 90)"
        }
        "update" => {
            "check for a newer wpantry release and, after a yes, install it verified\n\noptions:\n  -h, --help       show this help message and exit\n  --check          only say whether a newer release exists (exit 10 when one does)\n  --yes            install without asking\n  --no-input       never ask: report only\n  --offline        use only the cached answer\n  --version VER    this release instead of the latest"
        }
        "report" => {
            "the exposure, remediation and audit logs kept across scans\n\noptions:\n  -h, --help        show this help message and exit\n  --exposure        what applied, from first seen to resolved (default: all three)\n  --remediation     the fixes wpantry fix ran, and the scans that verified them\n  --audit           every scan and event\n  --since DAYS      how far back (default 90)\n  --format FORMAT   md (default), json or csv (csv: the exposure log)\n  -o, --out FILE    write there instead of stdout"
        }
        "harden" => {
            "apply one of the fixes wpantry can make itself\n\npositional arguments:\n  {extension-cooldown,ca-trust}\n    extension-cooldown  set extensions.installCooldownHours in every VS Code-family editor's settings.json\n    ca-trust            distrust the leaked eMudhra roots in the system trust store (sudo asks to install the result)\n\noptions:\n  -h, --help     show this help message and exit\n  --hours N      extension-cooldown: the cooldown (default 72)\n  --bundle FILE  ca-trust: rewrite this PEM bundle instead of the system store"
        }
        "mitigate" => {
            "do what this host can about advisories\n\npositional arguments:\n  {list,all,ID}\n    list        the stopgaps wpantry has and whether each applies here, and the advisories in the last scan with an unattended fix\n    all         everything: the same as wpantry fix (a scan, the unattended fixes, every stopgap that applies, a re-check)\n    ID          one advisory (CVE-…, GHSA-…; an alias works): its unattended fixes from the last scan, wpantry's stopgap for it where one exists (CVE-2026-98432: the nftables rule, MPTCP off, the services to restart, as root), the steps that need you\n\noptions:\n  -h, --help    show this help message and exit\n  --dry-run     print what would run or be written; change nothing\n  --yes         run and write without asking\n  --no-input    never ask: the unattended fixes run, the stopgaps are skipped unless --yes\n  --undo        ID only: take wpantry's stopgap away again once the real fix is installed (--remove is the same)\n  --offline, --no-machine, --path DIR\n                all only: as for scan\n\nExit codes: 0 everything that applies here was done (or, with --dry-run, printed), 1 a step is left for you, a fix failed, or nothing is known for the id here, 2 usage error."
        }
        _ => {
            "wpantry: the vulnerabilities that apply to this computer. See README.md;\n\npositional arguments:\n  {scan,check,fix,search,export,breach,watch,version,tools,skill,sync,schedule,cache,update,report,harden,mitigate,rules,sources,help}\n    scan                scan this computer and report what applies; change nothing\n    check               the same as scan\n    fix                 scan, run the unattended fixes and the stopgaps, then re-check (--dryrun prints the plan)\n    search              search cached advisories (for agents)\n    export              write the findings as CSV or JSON Lines\n    breach              show or set consent for the email breach check\n    watch               re-check the unfixed Critical/High advisories; exit 10 when a fix has landed\n    version             print the version, implementation and JSON schema\n    tools               list the external tools this implementation uses\n    skill               print the agent skill (SKILL.md)\n    sync                refresh the cache for offline scans\n    schedule            run sync and scan on a schedule\n    cache               maintain the cache (prune)\n    update              check for a newer release and install it verified\n    report              the exposure, remediation and audit logs\n    harden              apply a fix wpantry can make itself (extension-cooldown, ca-trust)\n    mitigate            list, all, or one advisory: its unattended fixes, its stopgap, the steps left for you\n    rules               the YARA rules the malware scan uses (--update fetches)\n    sources             every outside source, when it was last fetched and what went wrong\n    help                this help, or with a command that command's (wpantry help fix)\n\noptions:\n  -h, --help            show this help message and exit\n\nExit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error."
        }
    };
    format!("{}\n\n{body}\n", usage(cmd))
}

/// Other spellings an option answers to, matched before prefixes are:
/// `--license` for `--licenses`, `--update` for the scan's old `--fix`.
const ALIASES: &[(&str, &str)] =
    &[("--license", "--licenses"), ("-o", "--out"), ("--update", "--fix"), ("--remove", "--undo")];

/// (option, takes a value) for each subcommand.
fn options(cmd: &str) -> &'static [(&'static str, bool)] {
    match cmd {
        // The scan's, with `fix`'s hidden in front: `scan --fix` (and
        // `--update`) still parse, undocumented, for scripts older than `fix`.
        // `--no-clipboard` parses and does nothing, for scripts older than
        // the clipboard self-test's removal (2026-11-05).
        "scan" | "check" => &[
            ("--help", false),
            ("--fix", false),
            ("--dryrun", false),
            ("--yes", false),
            ("--path", true),
            ("--no-machine", false),
            ("--refresh", false),
            ("--offline", false),
            ("--json", false),
            ("--html", true),
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
            ("--no-clipboard", false),
        ],
        "fix" => &[
            ("--help", false),
            ("--dryrun", false),
            ("--yes", false),
            ("--path", true),
            ("--no-machine", false),
            ("--refresh", false),
            ("--offline", false),
            ("--json", false),
            ("--html", true),
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
            ("--no-clipboard", false),
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
        "export" => &[("--help", false), ("--csv", true), ("--jsonl", true), ("--all", false)],
        "breach" => &[("--help", false), ("--enable", false), ("--disable", false)],
        "watch" => &[("--help", false), ("--offline", false), ("--json", false)],
        "version" | "tools" => &[("--help", false), ("--json", false)],
        "sources" => &[("--help", false), ("--json", false), ("--sources", true)],
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
        "harden" => &[("--help", false), ("--hours", true), ("--bundle", true)],
        "mitigate" => &[
            ("--help", false),
            ("--dry-run", false),
            ("--yes", false),
            ("--no-input", false),
            ("--undo", false),
            ("--offline", false),
            ("--no-machine", false),
            ("--path", true),
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
        "scan" | "check" | "fix" => {
            if !positional.is_empty() {
                return fail(format!("unrecognized arguments: {}", positional.join(" ")));
            }
            let mut c = Check {
                no_machine: flag("--no-machine"),
                fix: cmd == "fix" || flag("--fix"),
                yes: flag("--yes"),
                dryrun: flag("--dryrun"),
                refresh: flag("--refresh"),
                offline: flag("--offline"),
                json: flag("--json"),
                no_input: flag("--no-input"),
                check_licenses: flag("--licenses"),
                no_posture: flag("--no-posture"),
                no_malware: flag("--no-malware"),
                deep: flag("--deep"),
                no_online_hash: flag("--no-online-hash"),
                sources: value("--sources").map(|s| expand(&s)),
                ..Default::default()
            };
            if let Some(v) = value("--html") {
                if v.is_empty() || v == "-" {
                    return fail("argument --html: expected a file path, not stdout".into());
                }
                c.html = Some(expand(&v));
            }
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
        "harden" => {
            let what = match positional.as_slice() {
                [w] if w == "extension-cooldown" || w == "ca-trust" => w.clone(),
                [w] => {
                    return fail(format!(
                        "argument what: invalid choice: '{w}' (choose from extension-cooldown, ca-trust)"
                    ));
                }
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
            Command::Harden { what, hours, bundle: value("--bundle").map(|v| expand(&v)) }
        }
        "mitigate" => {
            let target = match positional.as_slice() {
                [w] if w == "list" => Target::List,
                [w] if w == "all" => Target::All,
                [id] if id.contains('-') && id.len() >= 6 => Target::Id(id.trim().to_ascii_uppercase()),
                [id] => {
                    return fail(format!(
                        "argument target: expected list, all or an advisory id such as CVE-2026-98432, got '{id}'"
                    ));
                }
                [] => return fail("the following arguments are required: target (list, all or an advisory id)".into()),
                [_, rest @ ..] => return fail(format!("unrecognized arguments: {}", rest.join(" "))),
            };
            if flag("--dry-run") && flag("--undo") {
                return fail(
                    "--dry-run and --undo can't be combined: --dry-run prints what applying would write".into(),
                );
            }
            if target == Target::All && flag("--undo") {
                return fail("--undo takes one advisory id: wpantry mitigate CVE-2026-98432 --undo".into());
            }
            let paths: Vec<PathBuf> =
                given.iter().filter(|(o, _)| *o == "--path").filter_map(|(_, v)| v.as_deref().map(expand)).collect();
            Command::Mitigate {
                target,
                dry_run: flag("--dry-run"),
                yes: flag("--yes"),
                no_input: flag("--no-input"),
                undo: flag("--undo"),
                offline: flag("--offline"),
                no_machine: flag("--no-machine"),
                path: (!paths.is_empty()).then_some(paths),
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
