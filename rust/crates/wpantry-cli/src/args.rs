//! The command line, declared with [`wcli`]: every command, option and
//! argument once, with its help; [`parse`] turns the words into a
//! [`Command`] to run. No command has a second name, no option an alias,
//! and options are spelled out: a typo is an error naming the closest.

use std::path::PathBuf;
use wcli::{Arg, Command as Cli, Exit, Matches, Opt};
use wpantry::reporters::Part;

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
    /// the terminal's goes to a file (`<when>_pantry_report.<ext>`) on a
    /// terminal, and to stdout when stdout is a pipe or a file.
    pub stdout: bool,
    /// `--since DAYS`: the logs' reach.
    pub since: i64,
}

impl Default for Show {
    fn default() -> Show {
        Show {
            part: Part::Findings,
            format: Shown::Tui,
            out: None,
            stdout: false,
            since: wpantry::reporters::HISTORY_DAYS,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
/// The scan's options: `scan`, and `fix`.
pub struct Check {
    pub path: Option<Vec<PathBuf>>,
    pub no_machine: bool,
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
    },
    /// `report`: the latest scan, shown.
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
        "write the report there; - for stdout. Without it, a format goes to <when>_pantry_report.<ext> here when stdout is a terminal, and to stdout when it is a pipe or a file",
    ));
    opts.push(Opt::new("--since <days>", "how far back the logs go").default("14"));
    opts
}

/// The scan's options, shared by `scan` and `fix`.
fn scan_opts() -> Vec<Opt> {
    let mut opts = vec![
        Opt::new(
            "--path <dir>",
            "check only the repos at or under this directory; repeat it for more (default: every git repo under ~)",
        ),
        Opt::new("--no-machine", "skip the machine inventory: repo checks only"),
        Opt::new("--refresh", "ignore cached answers and ask every source again"),
        Opt::new("--offline", "use only the local cache"),
    ];
    opts.extend(report_opts());
    opts.extend([
        Opt::new("--no-input", "never prompt"),
        Opt::new("--jobs <n>", "gitleaks scans at once (default: half the cores, at most 4)"),
        Opt::new("--gitleaks-config <file>", "gitleaks policy (default: the bundled gitleaks.toml)"),
        Opt::new("--licenses [file]", "also check dependency licenses, against the file or the bundled licenses.txt"),
        Opt::new("--install-scripts <file>", "install-script policy (default: the bundled install-scripts.txt)"),
        Opt::new("--repo-hooks <file>", "indicators of hijacked repos (default: the bundled repo-hooks.txt)"),
        Opt::new("--hooks-policy <file>", "repo hooks you've read and accept, one per line"),
        Opt::new("--suspect-policy <file>", "suspicious-code ids and paths that warn instead of fail"),
        Opt::new("--no-posture", "skip the machine's security settings (FileVault, firewall, sharing, …)"),
        Opt::new("--posture-policy <file>", "posture checks to skip, one id per line"),
        Opt::new(
            "--no-malware",
            "skip the malware scan (YARA rules over Downloads, Desktop, temp, login items and repo programs)",
        ),
        Opt::new("--deep", "the malware scan reads everything under ~ with every system's rules (slower)"),
        Opt::new(
            "--no-online-hash",
            "never look up a flagged file's SHA-256 at YARAify, CIRCL or MalwareBazaar (asked once otherwise)",
        ),
        Opt::new(
            "--sources <file>",
            "your sources file for this run (default: ~/.config/wpantry/sources.toml when it exists)",
        ),
    ]);
    opts
}

/// The whole command line.
pub fn program() -> Cli {
    Cli::new("wpantry")
        .version(wpantry::VERSION)
        .description("The vulnerabilities, malware and risky settings that apply to this computer and its repos. See README.md.")
        .after_help("Exit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error.")
        .command(
            Cli::new("scan")
                .description("Scan this computer and its repos, then show the report. Changes nothing.")
                .opts(scan_opts())
                .after_help(EXIT_CODES),
        )
        .command(
            Cli::new("fix")
                .description("Scan, run the fixes that can run unattended and the stopgaps wpantry has for what it found, then re-check.")
                .summary("Scan, run the unattended fixes and stopgaps, then re-check (list, or one id)")
                .arg(Arg::new(
                    "[target]",
                    "all: a scan, the unattended fixes, every stopgap that applies, a re-check. list: what can be fixed, from the latest scan; nothing runs. An advisory id (CVE-…, GHSA-…; an alias works): its unattended fixes, wpantry's stopgap for it, the steps that need you. Or one of wpantry's own fixes: ca-trust (distrust the leaked eMudhra roots), extension-cooldown (editors wait before installing a new extension version), cve-2026-98432",
                ).default("all"))
                .option("--dry-run", "print what would run or be written; change nothing")
                .option("--yes", "run the fixes and write the stopgaps without asking")
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
                .after_help("Parts:\n  findings     the latest scan's findings\n  history      the exposure, remediation and audit logs\n  exposure     what applied, from first seen to resolved\n  remediation  the fixes run: when, who, the result, the scan that verified them\n  audit        every scan and event\n  summary      one page for a CSO, an auditor or an insurer\n  all          the findings, then every log\n\nExit codes: 0 nothing fails, 1 something fails in the latest scan or there is none, 2 usage error, 3 internal error."),
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
                .description("Refresh the cache: the feeds, end-of-life dates and OSV answers for what was scanned before, so scan --offline has fresh answers.")
                .summary("Refresh the cache for offline scans")
                .option("--refresh", "ask every source again, even when its answer is fresh")
                .option("--json", "what was refreshed, as JSON"),
        )
        .command(
            Cli::new("schedule")
                .description("Run sync and scan on a schedule (launchd, a systemd user timer, or cron); never fixes.")
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
                .command(Cli::new("status").description("Whether the job is installed, and how its last run went."))
                .command(Cli::new("uninstall").description("Remove the job."))
                .command(Cli::new("run").description("What the job runs: sync, then scan --json --no-input.")),
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
                .option("--sources <file>", "your sources file (default: ~/.config/wpantry/sources.toml when it exists)"),
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
                .option("--yes", "install without asking")
                .option("--no-input", "never ask: report only")
                .option("--offline", "use only the cached answer")
                .option("--version <ver>", "this release instead of the latest"),
        )
        .command(Cli::new("version").description("Print the version, implementation and JSON schema.").option("--json", "as JSON"))
        .command(Cli::new("tools").description("List the external tools wpantry uses.").option("--json", "as JSON"))
        .command(Cli::new("skill").description("Print the agent skill (SKILL.md)."))
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
    Ok(Show { part: Part::Findings, format, out, stdout, since })
}

fn check(m: &Matches, fix: bool) -> Result<Check, Exit> {
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
        no_online_hash: m.flag("no-online-hash"),
        sources: m.value("sources").map(expand),
        show: show(m)?,
        jobs: at_least_one::<usize>(m, "jobs", "a number of 1 or more")?,
        ..Default::default()
    };
    let paths: Vec<PathBuf> = m.values("path").into_iter().map(expand).collect();
    c.path = (!paths.is_empty()).then_some(paths);
    for (name, slot) in [
        ("gitleaks-config", &mut c.gitleaks_config),
        ("licenses", &mut c.licenses),
        ("install-scripts", &mut c.install_scripts),
        ("repo-hooks", &mut c.repo_hooks),
        ("posture-policy", &mut c.posture_policy),
        ("suspect-policy", &mut c.suspect_policy),
        ("hooks-policy", &mut c.hooks_policy),
    ] {
        if let Some(v) = m.value(name) {
            let p = expand(v);
            if !p.is_file() {
                return Err(m.error(&format!("option '--{name}': no such file: {v}")));
            }
            *slot = Some(p);
        }
    }
    Ok(c)
}

fn command(m: &Matches) -> Result<Command, Exit> {
    let flag = |n: &str| m.flag(n);
    Ok(match m.path().as_slice() {
        ["scan"] => Command::Scan(check(m, false)?),
        ["fix"] => match m.arg("target").unwrap_or("all") {
            "all" => {
                if m.flag("undo") {
                    return Err(m.error("--undo takes one id: wpantry fix CVE-2026-98432 --undo"));
                }
                Command::Scan(check(m, true)?)
            }
            word => {
                let target = match word {
                    "list" => Target::List,
                    id if id.contains('-') && id.len() >= 6 => Target::Id(id.trim().to_ascii_uppercase()),
                    other => {
                        return Err(m.error(&format!(
                            "argument 'target' expects all, list, an advisory id such as CVE-2026-98432, or ca-trust or extension-cooldown, got '{other}'"
                        )));
                    }
                };
                if flag("dry-run") && flag("undo") {
                    return Err(
                        m.error("--dry-run and --undo can't be combined: --dry-run prints what applying would write")
                    );
                }
                if target == Target::List && flag("undo") {
                    return Err(m.error("--undo takes one id: wpantry fix CVE-2026-98432 --undo"));
                }
                Command::Mitigate {
                    target,
                    dry_run: flag("dry-run"),
                    yes: flag("yes"),
                    no_input: flag("no-input"),
                    undo: flag("undo"),
                    bundle: m.value("bundle").map(expand),
                    hours: at_least_one::<u32>(m, "hours", "a number of hours")?
                        .unwrap_or(wpantry::remediation::editors::COOLDOWN_HOURS),
                }
            }
        },
        ["report"] => {
            let part = Part::parse(m.arg("part").unwrap_or("findings")).expect("one of the choices");
            Command::Report(Show { part, ..show(m)? })
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
        ["sources"] => Command::Sources { json: flag("json"), file: m.value("sources").map(expand) },
        ["breach"] => Command::Breach { enable: flag("enable"), disable: flag("disable") },
        ["cache", action] => Command::Cache {
            action: action.to_string(),
            older_than: at_least_one::<i64>(m, "older-than", "a number of days")?.unwrap_or(90),
        },
        ["update"] => Command::Update {
            check: flag("check"),
            yes: flag("yes"),
            no_input: flag("no-input"),
            offline: flag("offline"),
            version: m.value("version").map(String::from),
        },
        ["version"] => Command::Version { json: flag("json") },
        ["tools"] => Command::Tools { json: flag("json") },
        ["skill"] => Command::Skill,
        other => unreachable!("every command is matched: {other:?}"),
    })
}

pub fn parse(argv: &[String]) -> Parsed {
    match program().parse(argv).and_then(|m| command(&m)) {
        Ok(c) => Parsed::Run(c),
        Err(Exit::Help(t) | Exit::Version(t)) => Parsed::Help(t),
        Err(Exit::Error(t)) => Parsed::Usage(t),
    }
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
