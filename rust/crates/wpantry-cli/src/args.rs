//! The command line, declared with [`wcli`]: every command, option and
//! argument once, with its help; [`parse`] turns the words into a
//! [`Command`] to run. No command has a second name, no option an alias,
//! and options are spelled out: a typo is an error naming the closest.

use std::path::PathBuf;
use wcli::{Arg, Command as Cli, Exit, Matches, Opt};
use wpantry::reporters::Part;

/// Why `fix F-… --from-scan N` with no one to ask and no `--yes` is refused.
pub(crate) const FROM_SCAN_NEEDS_YES: &str =
    "--from-scan runs an approved fix only with --yes; preview it with --dry-run";

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

const FORMATS: [(Shown, &str); 6] = [
    (Shown::Txt, "the report as plain text, without colour"),
    (Shown::Json, "the findings as JSON (schema 1)"),
    (Shown::Jsonl, "one JSON object per finding, joined with its OSV record, lifecycle and fix"),
    (Shown::Csv, "one table: the findings, or the log asked for"),
    (Shown::Md, "Markdown"),
    (Shown::Html, "one offline HTML page"),
];

/// The report's options, shared by `report`, `scan` and `fix`: what it
/// covers (`report`'s word; the findings for a scan), which format, written
/// where, and how far back the logs go.
#[derive(Clone, Debug, PartialEq)]
pub struct Show {
    pub part: Part,
    pub format: Shown,
    pub out: Option<PathBuf>,
    /// `-o -`: to stdout even on a terminal. Otherwise a format other than
    /// the terminal's goes to a file (`pantry_report_<when>.<ext>`) on a
    /// terminal, and to stdout when stdout is a pipe or a file.
    pub stdout: bool,
    /// `--since DAYS`: the logs' reach.
    pub since: i64,
    /// `report --run ID`: that kept scan, not the latest.
    pub run: Option<i64>,
}

impl Default for Show {
    fn default() -> Show {
        Show {
            part: Part::Findings,
            format: Shown::Tui,
            out: None,
            stdout: false,
            since: wpantry::reporters::HISTORY_DAYS,
            run: None,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
/// The scan's options: `scan`, and `fix`.
pub struct Check {
    pub path: Option<Vec<PathBuf>>,
    pub no_machine: bool,
    /// `scan project`: one project (`path`) and the runtimes it uses,
    /// nothing else of the machine.
    pub project: bool,
    /// `scan project --changes SPEC`: only what a commit (`staged`) or a
    /// pull request (`BASE[...HEAD]`) adds, and nothing kept.
    pub changes: Option<String>,
    /// `fix`: the unattended fixes and the stopgaps, then a re-check.
    pub fix: bool,
    /// `fix --yes`: run and write without asking.
    pub yes: bool,
    /// `fix --dry-run`: print the plan, change nothing.
    pub dry_run: bool,
    pub refresh: bool,
    pub offline: bool,
    /// How the report is shown when the scan is done.
    pub show: Show,
    pub no_input: bool,
    /// `--jobs N`: CPU-bound scans at once.
    pub jobs: Option<usize>,
    pub secret_rules: Option<PathBuf>,
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
    /// `--deep`: every file of the computer, for malware with every system's
    /// rules and for secrets, as well as git history.
    pub deep: bool,
    /// `--no-personal-files`: never open Downloads, Desktop and Documents (on
    /// macOS also the other folders it asks permission for) in any pass,
    /// the repo search included (not with `--deep`).
    pub no_personal_files: bool,
    /// `--no-online-hash`: never look up a flagged file's hash online.
    pub no_online_hash: bool,
    /// `--sources FILE`: the user's sources file for this run.
    pub sources: Option<PathBuf>,
    /// `--add-sources FILE` (repeatable): sources added to the user's for this run.
    pub add_sources: Vec<PathBuf>,
    /// `--allow-sleep` (or `WPANTRY_ALLOW_SLEEP=1`): let the machine sleep
    /// during the scan.
    pub allow_sleep: bool,
    /// `scan --events`: the scan's progress as JSON Lines on stderr, no
    /// progress line and no prompts.
    pub events: bool,
}

/// What `fix list` and `fix ID` act on.
#[derive(Debug, PartialEq)]
pub enum Target {
    /// What can be fixed, from the latest scan.
    List,
    /// The first finding to fix that no fix has been tried for since the scan.
    Next,
    /// A committed secret, by finding id: take it out of history, guided.
    Secret(String),
    /// One advisory, one finding (`F-…`), or one of wpantry's own fixes
    /// by name, upper-cased.
    Id(String),
}

/// What `ignore` does.
#[derive(Debug, PartialEq)]
pub enum IgnoreAction {
    /// Write the rule that leaves a finding (`F-…`) out of future scans.
    Add { id: String, scope: wpantry::checks::ignore_edit::Scope, reason: Option<String>, all_places: bool },
    /// Every rule in your ignore file and, with `--path`, a repo's.
    List { path: Option<PathBuf> },
    /// Take out a rule (`R-…`) or the rules written for a finding (`F-…`).
    Remove { id: String, path: Option<PathBuf> },
}

#[derive(Debug, PartialEq)]
// `Scan` carries every check option; the other commands take a few fields.
// One value is built per process, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// `scan`, or `fix` (all): `fix` is set.
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
        /// `--add-sources FILE` (repeatable): sources added to it.
        added: Vec<PathBuf>,
    },
    /// `report`: the latest scan, shown.
    Report(Show),
    /// `runs`: the scans whose findings are kept.
    Runs {
        json: bool,
    },
    /// `prune ID...`: forget those scans' findings.
    Prune {
        ids: Vec<i64>,
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
        json: bool,
    },
    Cache {
        action: String,
        older_than: i64,
    },
    Update {
        check: bool,
        json: bool,
        yes: bool,
        no_input: bool,
        offline: bool,
        version: Option<String>,
    },
    /// `fix list` and `fix ID`.
    Mitigate {
        target: Target,
        dry_run: bool,
        yes: bool,
        no_input: bool,
        /// `--undo`: take the stopgap away.
        undo: bool,
        /// `--bundle FILE` (`ca-trust`) and `--hours N` (`extension-cooldown`).
        bundle: Option<PathBuf>,
        hours: u32,
        /// Only act on the automatic fix from this scan.
        from_scan: Option<i64>,
        /// `list` and `next`: as JSON.
        json: bool,
    },
    /// `ignore add | list | remove`: dismiss a finding by writing the rule
    /// for it into your ignore file or a repo's `.pantryignore`.
    Ignore {
        action: IgnoreAction,
        json: bool,
    },
    Skill,
    /// `licenses`: the third-party notices built into the binary.
    Licenses,
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

/// What parsing decided: run a command, or exit now (help or the version
/// printed, or a usage error).
#[derive(Debug, PartialEq)]
// `Run` carries the whole parsed command; the other two are one string each.
// One value is built per process, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum Parsed {
    Run(Command),
    Help(String),
    Usage(String),
}

/// The commands most people came for, first in the top-level help: what
/// scans what, as lines to copy.
const EXAMPLES: [(&str, &str); 9] = [
    ("wpantry scan", "this computer and every git repo under ~"),
    ("wpantry scan project", "the project in this directory and the runtimes it uses"),
    ("wpantry scan project ~/app", "the same, for another directory"),
    ("wpantry scan project --changes staged", "only what the next commit adds (a pre-commit hook); keeps nothing"),
    ("wpantry scan --path ~/code", "only the repos under a directory, with the machine inventory"),
    ("wpantry report --html", "the latest scan as one offline page"),
    ("wpantry runs", "the scans kept; report --run N shows one, prune N forgets one"),
    ("wpantry fix --dry-run", "what would be fixed; changes nothing"),
    ("wpantry help scan", "a command's options"),
];

/// The scan's options by what they are for, as the help groups them; the
/// rest (how the run behaves) stay under `Options:`.
const GROUPS: [(&str, &[&str]); 3] = [
    ("Scope", &["path", "no-machine", "deep", "no-personal-files", "no-posture", "no-malware", "licenses"]),
    ("Report", &["txt", "json", "jsonl", "csv", "md", "html", "out", "since"]),
    (
        "Policy",
        &[
            "secret-rules",
            "install-scripts",
            "repo-hooks",
            "hooks-policy",
            "suspect-policy",
            "posture-policy",
            "sources",
            "add-sources",
        ],
    ),
];

const EXIT_CODES: &str = "Exit codes: 0 nothing fails, 1 something fails, 2 usage error, 3 internal error.";

/// `--txt` … `--html`, at most one; `-o`; `--since`.
fn report_opts() -> Vec<Opt> {
    let mut opts: Vec<Opt> = FORMATS
        .iter()
        .map(|(f, help)| {
            let others: Vec<&str> =
                FORMATS.iter().filter(|(o, _)| o != f).map(|(o, _)| o.flag().trim_start_matches('-')).collect();
            Opt::new(f.flag(), help).conflicts(&others)
        })
        .collect();
    opts.push(Opt::new(
        "-o, --out <file>",
        "write the report there; - for stdout. Without it, a format goes to pantry_report_<when>.<ext> here when stdout is a terminal, and to stdout when it is a pipe or a file",
    ));
    opts.push(Opt::new("--since <days>", "how far back the logs go").default("14"));
    opts
}

/// The scan's options, shared by `scan` and `fix`.
fn scan_opts() -> Vec<Opt> {
    let mut opts = vec![
        Opt::new(
            "--path <dir>",
            "check only the repos and files at or under this directory, not Downloads, Desktop, Documents or temp; repeat it for more (default: every git repo under ~). The machine inventory still runs: for one project alone, scan project DIR",
        ),
        Opt::new("--no-machine", "skip the machine inventory: repo checks only"),
        Opt::new("--refresh", "ignore cached answers and ask every source again"),
        Opt::new("--offline", "use only the local cache"),
    ];
    opts.extend(report_opts());
    opts.extend([
        Opt::new("--no-input", "never prompt"),
        Opt::new("--jobs <n>", "repos scanned for secrets at once (default: half the cores, at most 4)"),
        Opt::new("--secret-rules <file>", "secret rules of your own, YARA, added to the bundled ones (default: secrets.yar in ~/.config/wpantry)"),
        // Accepted for one release so scripts written for 0.4 still run.
        Opt::new("--gitleaks-config <file>", "ignored: wpantry no longer runs gitleaks").hide(),
        Opt::new("--licenses [file]", "also check dependency licenses, against the file (default: licenses.toml in ~/.config/wpantry, else the bundled one)"),
        Opt::new("--install-scripts <file>", "install-script policy, TOML (default: install-scripts.toml in ~/.config/wpantry, else the bundled one)"),
        Opt::new("--repo-hooks <file>", "indicators of hijacked repos, TOML (default: repo-hooks.toml in ~/.config/wpantry, else the bundled one)"),
        Opt::new("--hooks-policy <file>", "repo hooks you've read and accept, TOML (default: hooks.toml in ~/.config/wpantry)"),
        Opt::new("--suspect-policy <file>", "suspicious-code ids and paths that warn instead of fail, TOML (default: suspect.toml in ~/.config/wpantry)"),
        Opt::new("--no-posture", "skip the machine's security settings (FileVault, firewall, sharing, …)"),
        Opt::new("--posture-policy <file>", "posture checks to skip, TOML (default: posture.toml in ~/.config/wpantry)"),
        Opt::new(
            "--no-malware",
            "skip the malware scan (YARA rules over Downloads, Desktop, temp, login items and repo programs)",
        ),
        Opt::new("--deep", "read everything in scope (slower): every file of the computer this user can read, ~ first (or each --path), for malware with every system's rules and for secrets; git history's files up to 256 MB with no time limit"),
        Opt::new(
            "--no-personal-files",
            "never open Downloads, Desktop or Documents in any pass, finding repos included (on macOS also the other folders it asks permission for), reported as not checked (for unattended runs)",
        )
        .conflicts(&["deep"]),
        Opt::new(
            "--no-online-hash",
            "never look up a flagged file's SHA-256 at YARAify, CIRCL or MalwareBazaar (asked once otherwise)",
        ),
        Opt::new(
            "--sources <file>",
            "your sources file for this run (default: ~/.config/wpantry/sources.toml when it exists)",
        ),
        Opt::new(
            "--add-sources <file>",
            "add this sources file's sources to yours for this run; repeat it for more (an id may be defined once)",
        ),
        Opt::new("--allow-sleep", "let the Mac idle-sleep during the scan (kept awake otherwise; or WPANTRY_ALLOW_SLEEP=1)"),
    ]);
    opts.into_iter()
        .map(|o| match GROUPS.iter().find(|(_, names)| names.contains(&o.name().as_str())) {
            Some((group, _)) => o.group(group),
            None => o,
        })
        .collect()
}

/// What a project scan never looks at, so `scan project` has no option for it.
const NOT_FOR_PROJECT: [&str; 6] =
    ["path", "no-machine", "no-posture", "posture-policy", "no-personal-files", "gitleaks-config"];

/// What `--changes` has no use for: it reads no file but the changed ones,
/// runs no malware or code check, and keeps no report.
const NOT_FOR_CHANGES: [&str; 7] =
    ["deep", "no-malware", "no-online-hash", "events", "repo-hooks", "hooks-policy", "suspect-policy"];

/// `scan project`'s options: the scan's, without the machine's, and `--changes`.
fn project_opts() -> Vec<Opt> {
    let mut opts: Vec<Opt> =
        scan_opts().into_iter().filter(|o| !NOT_FOR_PROJECT.contains(&o.name().as_str())).collect();
    opts.insert(
        0,
        Opt::new(
            "--changes <spec>",
            "scan only what a change adds, and keep nothing (the report goes to stdout): staged for the index git commit is about to record (a pre-commit hook), BASE or BASE...HEAD for the files changed from their merge base to HEAD (a pull request). Secrets in those files, and the dependency files among them against the advisories",
        )
        .group("Scope"),
    );
    opts
}

/// The whole command line.
pub fn program() -> Cli {
    EXAMPLES.iter().fold(commands(), |cli, (command, what)| cli.example(command, what))
}

fn commands() -> Cli {
    Cli::new("wpantry")
        .version(wpantry::VERSION)
        .description("The vulnerabilities, malware and risky settings that apply to this computer and its repos. See README.md.")
        .after_help("Exit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error.")
        .command(
            Cli::new("scan")
                .example("wpantry scan", "this computer and every git repo under ~")
                .example("wpantry scan project ~/app", "one project and the runtimes it uses, nothing else")
                .example("wpantry scan --path ~/code", "only the repos under a directory, with the machine inventory")
                .example("wpantry scan --json --no-input", "the findings as JSON, for tools and agents")
                .description("Scan this computer and its repos, then show the report. Changes nothing.\nFor one project and nothing else, wpantry scan project DIR. --path DIR narrows the repo checks to a directory and keeps the machine inventory; --no-machine leaves that out.")
                .summary("Scan this computer and its repos, or one project (scan project DIR), then show the report")
                .opts(scan_opts())
                .command(
                    Cli::new("project")
                        .example("wpantry scan project", "the project in this directory and the runtimes it uses")
                        .example("wpantry scan project --changes staged", "only what the next commit adds, for a pre-commit hook")
                        .example("wpantry scan project --changes origin/dev --txt", "only what a pull request adds, in CI")
                        .description("Scan one project, then show the report: its dependencies, secrets, hooks, suspect code and malware, and the runtimes it uses (the version its mise.toml, .tool-versions, .ruby-version, .nvmrc, rust-toolchain.toml or go.mod pins; with no pin, the first on PATH). Nothing else of this computer is read: no other runtime, app, setting or folder. Changes nothing.\nWith --changes, only what a commit or pull request adds: secrets in the files it changes, and the dependency files among them against the advisories, read from git, never the working tree. No run is kept: the report goes to stdout, and wpantry runs and report never see it.")
                        .summary("Scan one project and the runtimes it uses, nothing else of this computer")
                        .arg(Arg::new("[dir]", "the project's directory").default("."))
                        .opts(project_opts())
                        .after_help(EXIT_CODES),
                )
                .option(
                    "--events",
                    "write the scan's progress to stderr as JSON Lines (steps, the path being read, findings), for programs that run wpantry; implies --no-input",
                )
                .after_help(EXIT_CODES),
        )
        .command(
            Cli::new("fix")
                .description("Scan, run the fixes that can run unattended and the stopgaps wpantry has for what it found, then re-check.")
                .summary("Scan, run the unattended fixes and stopgaps, then re-check (list, or one id)")
                .arg(Arg::new(
                    "[target]",
                    "all: a scan, the unattended fixes, every stopgap that applies, a re-check. list: what can be fixed, from the latest scan, in fix order with each finding's id; nothing runs. next: the first of those no fix has been tried for since the scan (for agents, with --json). A finding id (F-…, from list or the JSON report): its fix. secret ID: take that committed secret out of git history, a step at a time, at a terminal. An advisory id (CVE-…, GHSA-…; an alias works): its unattended fixes, wpantry's stopgap for it, the steps that need you. Or one of wpantry's own fixes: ca-trust (distrust the leaked eMudhra roots), extension-cooldown (editors wait before installing a new extension version), cve-2026-98432",
                ).default("all"))
                .arg(Arg::new("[id]", "with secret: the finding id (F-…) of a committed secret"))
                .option("--dry-run", "print what would run or be written; change nothing")
                .option("--yes", "run the fixes and write the stopgaps without asking")
                .option("--from-scan <id>", "with a finding id: require this latest scan and an automatic fix")
                .option("--undo", "with an id: take wpantry's stopgap away once the real fix is installed")
                .option("--bundle <file>", "ca-trust: rewrite this PEM bundle instead of the system trust store")
                .opt(Opt::new("--hours <n>", "extension-cooldown: the cooldown").default("72"))
                .opts(scan_opts())
                .after_help("Exit codes: 0 nothing fails after the re-check, 1 something still fails or a fix failed, 2 usage error, 3 internal error."),
        )
        .command(
            Cli::new("report")
                .description("The latest scan's report, from the cache; it never scans (scan and fix show it when they finish).")
                .summary("The latest scan's report, a log, or the summary, in any format")
                .arg(Arg::new("[part]", "what the report covers").choices(&Part::NAMES).default("findings"))
                .opts(report_opts())
                .option("--run <id>", "that scan instead of the latest: one wpantry runs lists")
                .after_help("Parts:\n  findings     the latest scan's findings\n  history      the exposure, remediation and audit logs\n  exposure     what applied, from first seen to resolved\n  remediation  the fixes run: when, who, the result, the scan that verified them\n  audit        every scan and event\n  summary      one page for a CSO, an auditor or an insurer\n  all          the findings, then every log\n\nExit codes: 0 nothing fails, 1 something fails in the latest scan or there is none, 2 usage error, 3 internal error."),
        )
        .command(
            Cli::new("runs")
                .description("The scans whose findings are kept, the latest first: each one's number, when it finished, how long it took, what it covered and what it found. report shows the latest; report --run ID shows another, and prune ID forgets one. The latest 30 are kept.")
                .summary("List the scans whose findings are kept (report --run ID shows one)")
                .option("--json", "the scans as JSON"),
        )
        .command(
            Cli::new("prune")
                .description("Forget a scan's findings: one of the wrong directory, or one you didn't mean to keep. It leaves wpantry runs, and when it was the latest, report shows the scan before it again. The scan log (report audit) keeps its row, and the exposure log keeps what it saw. For the advisory cache, see cache prune.")
                .summary("Forget one scan's findings (wpantry runs lists them)")
                .argument("<id...>", "the scan's number, from wpantry runs"),
        )
        .command(
            Cli::new("search")
                .description("Search the cached advisories (for agents).")
                .argument("<query>", "an id, package or word")
                .option("--applicable", "only advisories that apply here")
                .opt(Opt::new("--limit <n>", "the most to list").default("20"))
                .option("--json", "the hits as JSON"),
        )
        .command(
            Cli::new("watch")
                .description("Ask OSV again about the advisories the last scan found with no released fix (Critical, High, exploited in the wild); exit 10 when a fix has landed.")
                .summary("Re-check the advisories with no fix yet; exit 10 when one lands")
                .option("--offline", "use only the local cache")
                .option("--json", "the watched advisories as JSON"),
        )
        .command(
            Cli::new("sync")
                .description("Refresh the cache: the feeds, and every source a scan used for what it found (end-of-life dates, OSV, CVE records, extension versions, release tags, CVE scores, the malware rules), so scan --offline has fresh answers.")
                .summary("Refresh the cache for offline scans")
                .option("--refresh", "ask every source again, even when its answer is fresh")
                .option("--json", "what was refreshed, as JSON"),
        )
        .command(
            Cli::new("schedule")
                .description("Run sync and scan on a schedule (launchd, a systemd user timer, cron, or Windows Task Scheduler); never fixes.")
                .summary("Run sync and scan on a schedule")
                .subcommand_required()
                .command(
                    Cli::new("install")
                        .description("Install the job.")
                        .opt(
                            Opt::new("--every <period>", "how often, each from the period's start: a week on Monday, a month on the 1st, a quarter on 1 January, April, July and October, a year on 1 January")
                                .choices(&crate::schedule::Every::NAMES)
                                .default("day"),
                        )
                        .opt(Opt::new("--at <time>", "the time of day, HH:MM").default("09:30"))
                        .option("--dry-run", "print the job definition without installing it"),
                )
                .command(
                    Cli::new("status")
                        .description("Whether the job is installed, and how its last run went.")
                        .option("--json", "the schedule and last run as JSON"),
                )
                .command(Cli::new("uninstall").description("Remove the job."))
                .command(Cli::new("run").description("What the job runs: sync, then scan --json --no-input (with --no-personal-files on macOS).")),
        )
        .command(
            Cli::new("rules")
                .description("The YARA rules the malware scan uses: ours, built in, and YARA Forge's, fetched into the cache directory.")
                .summary("The malware scan's YARA rules; gen writes one from samples")
                .option("--update", "fetch YARA Forge's latest package now")
                .option("--json", "the sources and counts as JSON")
                .command(
                    Cli::new("gen")
                        .description("Write a YARA rule matching what the samples share and this machine's programs don't (unreviewed: category suspicious, score 60).")
                        .argument("<sample...>", "the sample files")
                        .opt(Opt::new("--category <cat>", "the category you propose").default("malware"))
                        .option("--family <name>", "the family's name (default: the first sample's file name)")
                        .option("--name <rule>", "the rule's name (default Gen_<category>_<family>)")
                        .option("-o, --out <file>", "write the rule there, and its test file beside it (default: stdout)"),
                )
                .command(Cli::new("goodware").description("Rebuild the goodware database from this machine's system programs (gen builds it the first time).")),
        )
        .command(
            Cli::new("sources")
                .description("Every outside source wpantry reads: its kind, tier, host and licence, when it was last fetched, whether that is fresh, and what last went wrong.")
                .summary("Every outside source, when it was last fetched and what went wrong")
                .option("--json", "the sources as JSON")
                .option("--sources <file>", "your sources file (default: ~/.config/wpantry/sources.toml when it exists)")
                .option(
                    "--add-sources <file>",
                    "add this sources file's sources to yours; repeat it for more (an id may be defined once)",
                ),
        )
        .command(
            Cli::new("ignore")
                .description("Leave a finding out of future scans: write the rule for it into your ignore file or a repo's .pantryignore, list the rules in them, or take one out. It never prompts.")
                .summary("Dismiss a finding: write, list and remove ignore rules")
                .subcommand_required()
                .command(
                    Cli::new("add")
                        .description("Write the narrowest rule that leaves one finding out of the next scan: its path, under the section for its check and its rule or advisory. The finding is read from the latest scan, so add a finding that scan listed (wpantry fix list shows the ids). Adding it again changes nothing.")
                        .summary("Leave one finding out of future scans")
                        .argument("<finding>", "a finding id from the latest scan (F-…)")
                        .opt(
                            Opt::new("--scope <scope>", "user: your ignore file (the default; creates it, private, when missing). repo: the finding's repo's .pantryignore (a finding inside a repo, and not one that protects you from the repo)")
                                .choices(&["user", "repo"])
                                .default("user"),
                        )
                        .option("--reason <text>", "why, kept in a comment under the rule and in the audit log (one line)")
                        .option("--all-places", "one rule for each place the same rule or advisory was found for the same package, not only this one")
                        .option("--no-input", "never prompt (this command never does)")
                        .option("--json", "the result as JSON")
                        .after_help("Exit codes: 0 done or already done, 1 refused (nothing changed) or not found, 2 usage error, 3 internal error."),
                )
                .command(
                    Cli::new("list")
                        .description("Every rule in your ignore file and, with --path, in a repo's .pantryignore: its id, section and pattern, and for a rule `ignore add` wrote the finding it came from, when and why. A rule the log says was added and the file no longer holds is shown as removed by hand.")
                        .summary("The rules in your ignore file and a repo's")
                        .option("--path <dir>", "also list this repo's .pantryignore (the repo at or above DIR)")
                        .option("--json", "as JSON"),
                )
                .command(
                    Cli::new("remove")
                        .description("Take a rule out: R-… (any rule `list` shows, hand-written ones too) or F-… (every rule `ignore add` wrote for that finding). Only those lines go; the next scan reports the finding again.")
                        .summary("Take a rule out, so the finding is reported again")
                        .argument("<id>", "a rule id (R-…) or a finding id (F-…)")
                        .option("--path <dir>", "also look in this repo's .pantryignore (needed for a hand-written rule of a repo's)")
                        .option("--no-input", "never prompt (this command never does)")
                        .option("--json", "the result as JSON")
                        .after_help("Exit codes: 0 done or already gone, 1 nothing matches, 2 usage error, 3 internal error."),
                ),
        )
        .command(
            Cli::new("breach")
                .description("Show or set consent for the email breach check.")
                .opt(Opt::new("--enable", "allow it").conflicts(&["disable"]))
                .option("--disable", "stop it"),
        )
        .command(
            Cli::new("cache")
                .description("Maintain the cache.")
                .subcommand_required()
                .command(
                    Cli::new("prune")
                        .description("Drop what no scan has used in a while, then compact the file.")
                        .opt(Opt::new("--older-than <days>", "what counts as unused").default("90")),
                ),
        )
        .command(
            Cli::new("update")
                .description("Check for a newer wpantry release and, after a yes, install it verified.")
                .summary("Install a newer release, verified")
                .option("--check", "only say whether a newer release exists (exit 10 when one does)")
                .option("--json", "with --check: current and latest versions as JSON")
                .option("--yes", "install without asking")
                .option("--no-input", "never ask: report only")
                .option("--offline", "use only the cached answer")
                .option("--version <ver>", "this release instead of the latest"),
        )
        .command(Cli::new("version").description("Print the version, implementation and JSON schema.").option("--json", "as JSON"))
        .command(Cli::new("tools").description("List the external tools wpantry uses.").option("--json", "as JSON"))
        .command(Cli::new("skill").description("Print the agent skill (SKILL.md)."))
        .command(
            Cli::new("licenses")
                .description("Print the licences and notices of the third-party code, data and fonts built into wpantry: every crate with its licence text, then the rest. Each release ships the same text as THIRD-PARTY-NOTICES.txt.")
                .summary("Print the third-party licences built into wpantry"),
        )
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/").or(if p == "~" { Some("") } else { None }) {
        Some(rest) => wpantry::utils::files::home().join(rest),
        None => PathBuf::from(p),
    }
}

/// A count of 1 or more: `--since 30` or `30d` for days.
fn at_least_one<T: std::str::FromStr + PartialOrd + From<u8>>(
    m: &Matches,
    name: &str,
    what: &str,
) -> Result<Option<T>, Exit> {
    match m.value(name) {
        None => Ok(None),
        Some(v) => match v.trim().trim_end_matches('d').parse::<T>() {
            Ok(n) if n >= T::from(1) => Ok(Some(n)),
            _ => Err(m.error(&format!("option '--{name}' expects {what}, got '{v}'"))),
        },
    }
}

/// The report options given.
fn show(m: &Matches) -> Result<Show, Exit> {
    let format = FORMATS.iter().map(|(f, _)| *f).find(|f| m.flag(f.flag().trim_start_matches('-'))).unwrap_or_default();
    let (out, stdout) = match m.value("out") {
        Some("") => return Err(m.error("option '-o, --out <file>' expects a file path, or - for stdout")),
        Some("-") => (None, true),
        Some(v) => (Some(expand(v)), false),
        None => (None, false),
    };
    // A file gets plain text, never the terminal's colours.
    let format = if format == Shown::Tui && out.is_some() { Shown::Txt } else { format };
    let since = at_least_one::<i64>(m, "since", "a number of days")?.unwrap_or(wpantry::reporters::HISTORY_DAYS);
    let run = at_least_one::<i64>(m, "run", "a scan's number (wpantry runs lists them)")?;
    Ok(Show { part: Part::Findings, format, out, stdout, since, run })
}

fn check(m: &Matches, fix: bool) -> Result<Check, Exit> {
    check_for(m, fix, false)
}

/// [`check`]; a `project` scan reads no machine setting, so the user's
/// posture policy isn't loaded for it (a broken `posture.toml` must not
/// fail a scan that runs no posture check).
fn check_for(m: &Matches, fix: bool, project: bool) -> Result<Check, Exit> {
    let mut c = Check {
        no_machine: m.flag("no-machine"),
        fix,
        yes: fix && m.flag("yes"),
        dry_run: fix && m.flag("dry-run"),
        refresh: m.flag("refresh"),
        offline: m.flag("offline"),
        no_input: m.flag("no-input"),
        check_licenses: m.flag("licenses"),
        no_posture: m.flag("no-posture"),
        no_malware: m.flag("no-malware"),
        deep: m.flag("deep"),
        no_personal_files: m.flag("no-personal-files"),
        no_online_hash: m.flag("no-online-hash"),
        sources: m.value("sources").map(expand),
        add_sources: m.values("add-sources").into_iter().map(expand).collect(),
        allow_sleep: m.flag("allow-sleep")
            || std::env::var("WPANTRY_ALLOW_SLEEP").is_ok_and(|v| !v.is_empty() && v != "0"),
        show: show(m)?,
        jobs: at_least_one::<usize>(m, "jobs", "a number of 1 or more")?,
        ..Default::default()
    };
    let paths: Vec<PathBuf> = m.values("path").into_iter().map(expand).collect();
    c.path = (!paths.is_empty()).then_some(paths);
    if m.value("gitleaks-config").is_some() {
        eprintln!(
            "wpantry: warning: --gitleaks-config is ignored: the secret scan runs Pantry's own rules (add yours with --secret-rules)"
        );
    }
    // Each policy: the file its option names, else the user's own in the
    // config folder (`~/.config/wpantry/<file>`), else the bundled default.
    for (name, file, slot) in [
        ("secret-rules", "secrets.yar", &mut c.secret_rules),
        ("licenses", "licenses.toml", &mut c.licenses),
        ("install-scripts", "install-scripts.toml", &mut c.install_scripts),
        ("repo-hooks", "repo-hooks.toml", &mut c.repo_hooks),
        ("posture-policy", "posture.toml", &mut c.posture_policy),
        ("suspect-policy", "suspect.toml", &mut c.suspect_policy),
        ("hooks-policy", "hooks.toml", &mut c.hooks_policy),
    ] {
        if project && name == "posture-policy" {
            continue;
        }
        let p = match m.value(name) {
            Some(v) => {
                let p = expand(v);
                if !p.is_file() {
                    return Err(m.error(&format!("option '--{name}': no such file: {v}")));
                }
                p
            }
            None => match wpantry::checks::user_policy(file) {
                Some(p) => p,
                None => continue,
            },
        };
        // Secret rules are YARA; the rest are Pantry's TOML.
        let why = if name == "secret-rules" {
            wpantry::checks::secrets::rules::policy_error(&p)
        } else {
            wpantry::checks::policy_error(&p)
        };
        if let Some(why) = why {
            return Err(m.error(&format!("option '--{name}': {}: {why}", p.display())));
        }
        *slot = Some(p);
    }
    Ok(c)
}

/// A finding id as `F-` and ten lower-case hex digits, whatever its case.
fn finding_id(id: &str) -> String {
    format!("F-{}", id[2..].to_ascii_lowercase())
}

fn ignore_action(m: &Matches, action: &str) -> Result<IgnoreAction, Exit> {
    use wpantry::checks::ignore_edit::{Scope, clean_reason};
    let path = m.value("path").map(expand);
    Ok(match action {
        "add" => {
            let id = m.arg("finding").unwrap_or_default();
            if !wpantry::remediation::queue::is_id(id) {
                return Err(m.error(&format!(
                    "argument 'finding' expects a finding id such as F-3fa9c01b2e (wpantry fix list shows them), got '{id}'"
                )));
            }
            let reason = match m.value("reason") {
                None => None,
                Some(r) => {
                    Some(clean_reason(r).map_err(|e| m.error(&format!("option '--reason <text>': {}", e.message)))?)
                }
            };
            IgnoreAction::Add {
                id: finding_id(id),
                scope: Scope::parse(m.value("scope").unwrap_or("user")).expect("one of the choices"),
                reason,
                all_places: m.flag("all-places"),
            }
        }
        "list" => IgnoreAction::List { path },
        _ => {
            let id = m.arg("id").unwrap_or_default();
            let id = if wpantry::remediation::queue::is_id(id) {
                finding_id(id)
            } else if wpantry::remediation::dismiss::is_rule_id(id) {
                format!("R-{}", id[2..].to_ascii_lowercase())
            } else {
                return Err(m.error(&format!(
                    "argument 'id' expects a rule id such as R-3fa9c01b2e (wpantry ignore list shows them) or a finding id such as F-3fa9c01b2e, got '{id}'"
                )));
            };
            IgnoreAction::Remove { id, path }
        }
    })
}

fn command(m: &Matches) -> Result<Command, Exit> {
    let flag = |n: &str| m.flag(n);
    Ok(match m.path().as_slice() {
        ["scan"] => Command::Scan(Check { events: flag("events"), ..check(m, false)? }),
        ["scan", "project"] => {
            // The scan's options are in scope here too, the machine's
            // among them: one that a project scan has no use for is
            // refused, not quietly applied or dropped.
            if !m.values("path").is_empty() {
                return Err(
                    m.error("scan project takes its directory as an argument, not --path: wpantry scan project DIR")
                );
            }
            if let Some(name) =
                NOT_FOR_PROJECT.iter().find(|n| **n != "gitleaks-config" && (flag(n) || m.value(n).is_some()))
            {
                return Err(m.error(&format!(
                    "option '--{name}' is for a scan of this computer: scan project reads one project and its runtimes"
                )));
            }
            let mut c = Check { events: flag("events"), ..check_for(m, false, true)? };
            let given = m.arg("dir").unwrap_or(".");
            let dir = expand(given);
            // The whole path: the scope a project's scans are compared by.
            let Some(dir) = std::fs::canonicalize(&dir).ok().filter(|d| d.is_dir()) else {
                return Err(m.error(&format!("argument 'dir': no such directory: {given}")));
            };
            c.path = Some(vec![dir]);
            c.no_machine = true;
            c.project = true;
            if let Some(spec) = m.value("changes") {
                wpantry::checks::changes::Changes::parse(spec)
                    .map_err(|e| m.error(&format!("option '--changes <spec>': {e}")))?;
                if let Some(name) = NOT_FOR_CHANGES.iter().find(|n| flag(n)) {
                    return Err(m.error(&format!(
                        "option '--{name}' doesn't apply to --changes, which reads only the changed files, for secrets and dependencies"
                    )));
                }
                if c.show.out.is_some() {
                    return Err(m.error("--changes keeps nothing: its report goes to stdout, so drop -o FILE"));
                }
                c.changes = Some(spec.to_string());
            }
            Command::Scan(c)
        }
        ["fix"] => match m.arg("target").unwrap_or("all") {
            "all" => {
                if m.value("from-scan").is_some() {
                    return Err(m.error("--from-scan requires one finding id"));
                }
                if m.flag("undo") {
                    return Err(m.error("--undo takes one id: wpantry fix CVE-2026-98432 --undo"));
                }
                Command::Scan(check(m, true)?)
            }
            word => {
                if word != "secret" && m.arg("id").is_some() {
                    return Err(m.error("too many arguments for 'fix': only secret takes an id after it"));
                }
                let target = match word {
                    "list" => Target::List,
                    "next" => Target::Next,
                    "secret" => match m.arg("id") {
                        Some(id) if wpantry::remediation::queue::is_id(id) => Target::Secret(id.to_ascii_uppercase()),
                        Some(other) => {
                            return Err(m.error(&format!(
                                "argument 'id' expects a finding id such as F-3fa9c01b2e (wpantry fix list shows them), got '{other}'"
                            )));
                        }
                        None => return Err(m.error("secret takes a finding id: wpantry fix secret F-3fa9c01b2e")),
                    },
                    id if id.contains('-') && id.len() >= 6 => Target::Id(id.trim().to_ascii_uppercase()),
                    other => {
                        return Err(m.error(&format!(
                            "argument 'target' expects all, list, next, secret ID, a finding id such as F-3fa9c01b2e, an advisory id such as CVE-2026-98432, or ca-trust or extension-cooldown, got '{other}'"
                        )));
                    }
                };
                if flag("dry-run") && flag("undo") {
                    return Err(
                        m.error("--dry-run and --undo can't be combined: --dry-run prints what applying would write")
                    );
                }
                if matches!(target, Target::List | Target::Next | Target::Secret(_)) && flag("undo") {
                    return Err(m.error("--undo takes one id: wpantry fix CVE-2026-98432 --undo"));
                }
                let from_scan = m.get::<i64>("from-scan")?;
                if from_scan.is_some_and(|id| id < 1) {
                    return Err(m.error("--from-scan expects a positive scan id"));
                }
                if from_scan.is_some()
                    && (!matches!(&target, Target::Id(id) if wpantry::remediation::queue::is_id(id)) || flag("undo"))
                {
                    return Err(m.error("--from-scan requires one finding id and cannot be used with --undo"));
                }
                // an unattended --from-scan fix runs only when approved.
                // Oracle: `fix F-… --from-scan N --no-input` without --yes or
                // --dry-run is a usage error (exit 2) and runs nothing.
                if from_scan.is_some() && flag("no-input") && !flag("yes") && !flag("dry-run") {
                    return Err(m.error(FROM_SCAN_NEEDS_YES));
                }
                Command::Mitigate {
                    from_scan,
                    target,
                    dry_run: flag("dry-run"),
                    yes: flag("yes"),
                    no_input: flag("no-input"),
                    undo: flag("undo"),
                    bundle: m.value("bundle").map(expand),
                    hours: at_least_one::<u32>(m, "hours", "a number of hours")?
                        .unwrap_or(wpantry::remediation::editors::COOLDOWN_HOURS),
                    json: flag("json"),
                }
            }
        },
        ["report"] => {
            let part = Part::parse(m.arg("part").unwrap_or("findings")).expect("one of the choices");
            Command::Report(Show { part, ..show(m)? })
        }
        ["runs"] => Command::Runs { json: flag("json") },
        ["prune"] => {
            let mut ids = Vec::new();
            for word in m.args("id") {
                match word.trim_start_matches('#').parse::<i64>() {
                    Ok(n) if n >= 1 => ids.push(n),
                    _ => {
                        return Err(m.error(&format!(
                            "argument 'id' expects a scan's number (wpantry runs lists them), got '{word}'"
                        )));
                    }
                }
            }
            Command::Prune { ids }
        }
        ["search"] => Command::Search {
            query: m.arg("query").unwrap_or_default().to_string(),
            applicable: flag("applicable"),
            limit: m.get::<i64>("limit")?.unwrap_or(20),
            json: flag("json"),
        },
        ["watch"] => Command::Watch { json: flag("json"), offline: flag("offline") },
        ["sync"] => Command::Sync { refresh: flag("refresh"), json: flag("json") },
        ["schedule", action] => {
            let at = m.value("at").unwrap_or("09:30").to_string();
            let ok_time = at.split_once(':').is_some_and(|(h, mm)| {
                h.parse::<u32>().is_ok_and(|h| h < 24) && mm.len() == 2 && mm.parse::<u32>().is_ok_and(|mm| mm < 60)
            });
            if !ok_time {
                return Err(m.error(&format!("option '--at <time>' expects HH:MM, got '{at}'")));
            }
            Command::Schedule {
                action: action.to_string(),
                every: m.value("every").unwrap_or("day").to_string(),
                at,
                dry_run: flag("dry-run"),
                json: flag("json"),
            }
        }
        ["rules", rest @ ..] => Command::Rules {
            action: rest.first().map(|s| s.to_string()).unwrap_or_default(),
            samples: m.args("sample").into_iter().map(expand).collect(),
            update: flag("update"),
            json: flag("json"),
            category: m.value("category").unwrap_or("malware").to_string(),
            family: m.value("family").map(String::from),
            name: m.value("name").map(String::from),
            out: m.value("out").map(expand),
        },
        ["ignore", action] => Command::Ignore { action: ignore_action(m, action)?, json: flag("json") },
        ["sources"] => Command::Sources {
            json: flag("json"),
            file: m.value("sources").map(expand),
            added: m.values("add-sources").into_iter().map(expand).collect(),
        },
        ["breach"] => Command::Breach { enable: flag("enable"), disable: flag("disable") },
        ["cache", action] => Command::Cache {
            action: action.to_string(),
            older_than: at_least_one::<i64>(m, "older-than", "a number of days")?.unwrap_or(90),
        },
        ["update"] => {
            if flag("json") && (!flag("check") || m.value("version").is_some()) {
                return Err(m.error("--json requires --check and cannot be combined with --version"));
            }
            Command::Update {
                check: flag("check"),
                json: flag("json"),
                yes: flag("yes"),
                no_input: flag("no-input"),
                offline: flag("offline"),
                version: m.value("version").map(String::from),
            }
        }
        ["version"] => Command::Version { json: flag("json") },
        ["tools"] => Command::Tools { json: flag("json") },
        ["skill"] => Command::Skill,
        ["licenses"] => Command::Licenses,
        other => unreachable!("every command is matched: {other:?}"),
    })
}

pub fn parse(argv: &[String]) -> Parsed {
    match program().parse(argv).and_then(|m| command(&m)) {
        Ok(c) => Parsed::Run(c),
        Err(Exit::Help(t) | Exit::Version(t)) => Parsed::Help(t),
        // `wpantry scan ~/code/app`: say how one directory is scanned.
        Err(Exit::Error(t)) if argv.first().is_some_and(|w| w == "scan") && t.contains("error: unknown command '") => {
            Parsed::Usage(format!(
                "{t}To scan one directory: wpantry scan project DIR (or scan --path DIR, which keeps the machine inventory)\n"
            ))
        }
        Err(Exit::Error(t)) => Parsed::Usage(t),
    }
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
