//! wpantry: the vulnerabilities that apply to this computer. The CLI
//! contract is specs/cli-contract.md; this binary owns stdout, stderr and
//! exit codes, the library does the work.
//!
//! Exit codes: 0 clean (warnings and unchecked sources included), 1 a
//! failing finding or a failed unattended fix, 2 usage error, 3 internal
//! error.

mod args;
mod progress;
mod schedule;
mod style;
mod tui;
mod update;

use args::{Check, Command, Parsed, Show, Shown, Target};
use std::io::{IsTerminal, Write};
use style::Style;
use wpantry::checks::{Options, Outcome, Policy, Scan};
use wpantry::db::{self, Cache};
use wpantry::error::Result;
use wpantry::remediation;
use wpantry::reporters::{Format, Output};
use wpantry::utils::json::{J, obj};
use wpantry::{IMPL, SCHEMA, VERSION};

const EXIT_OK: i32 = 0;
const EXIT_FAIL: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_INTERNAL: i32 = 3;
/// `update --check`: a newer release exists.
const EXIT_UPDATE_AVAILABLE: i32 = 10;
/// `watch`: a fix has landed for something that had none.
const EXIT_AVAILABLE: i32 = 10;

/// A line of text on stdout, never coloured (search results, the skill),
/// with terminal escapes from scanned content dropped.
fn say(line: &str) {
    println!("{}", style::clean(line));
}

/// JSON on stdout, as is: it escapes control characters itself.
fn emit(json: &str) {
    println!("{json}");
}

/// A one-line note on stderr (stdout stays the command's output).
fn note(line: &str) {
    eprintln!("{}", Style::stderr().line(&format!("  ℹ {}", style::clean(line))));
}

/// A line of the report on stdout, coloured by its mark on a terminal.
fn show(line: &str) {
    println!("{}", Style::stdout().line(&style::clean(line)));
}

/// One scan with a live progress line; the line is gone before this returns.
fn scan(opts: Options, json: bool, net: &dyn wpantry::utils::net::Net) -> Result<Outcome> {
    let progress = progress::Progress::start();
    let log = |m: &str| {
        if !json {
            progress.println(&Style::stdout().line(m));
        }
    };
    let note = |m: &str| progress.eprintln(&Style::stderr().line(m));
    // WPANTRY_TIMINGS=1: every step with the seconds since the scan began,
    // on stderr, so a slow run says where the time went.
    let started = std::time::Instant::now();
    let timings = std::env::var_os("WPANTRY_TIMINGS").is_some();
    // One line per step, not per file: a step whose message starts the same
    // way as the last one within a quarter second is the same step.
    let last = std::sync::Mutex::new((String::new(), std::time::Instant::now()));
    let status = |m: &str| {
        if timings {
            let head: String = m.split_whitespace().next().unwrap_or("").to_string();
            let mut last = last.lock().expect("lock");
            if head != last.0 || last.1.elapsed() > std::time::Duration::from_millis(250) {
                progress.eprintln(&format!("[{:7.2}s] {m}", started.elapsed().as_secs_f64()));
                *last = (head, std::time::Instant::now());
            }
        }
        progress.set(m);
    };
    // The library's questions default to no (the breach check's consent).
    let ask = |q: &str| progress.ask(q, false);
    let out = Scan::new(opts, Cache::open(None)?, net, &log, &note).with_status(&status).with_ask(&ask).run();
    progress.finish();
    out
}

/// Where a report goes when no `-o FILE` says: a format other than the
/// terminal's is written to `pantry_report_<when>.<ext>` in the current
/// directory when stdout is a `terminal`, and to stdout when it is a pipe
/// or a file (an agent's, `| jq`, `> out.json`) or `-o -` asked for it.
fn resolve(mut show: Show, terminal: bool, now: f64) -> Show {
    if show.out.is_none() && !show.stdout && terminal && show.format != Shown::Tui {
        let ext = show.format.flag().trim_start_matches('-');
        show.out = Some(std::path::PathBuf::from(wpantry::reporters::file_name(ext, now)));
    }
    show
}

/// Whether the report goes to stdout in a format a program reads: then
/// nothing else is printed there and nothing is asked.
fn quiet(show: &Show) -> bool {
    show.out.is_none() && !matches!(show.format, Shown::Tui | Shown::Txt)
}

fn cmd_scan(a: Check) -> Result<i32> {
    // A report file that can't be written fails now, before the scan.
    if let Some(path) = &a.show.out {
        drop(Output::new(path)?);
    }
    let net = wpantry::utils::net::Http::new();
    let quiet = quiet(&a.show);
    let opts = Options {
        paths: a.path.clone(),
        machine: !a.no_machine,
        no_posture: a.no_posture,
        no_malware: a.no_malware,
        deep: a.deep,
        no_online_hash: a.no_online_hash,
        sources: a.sources.clone(),
        policy: Policy {
            gitleaks_config: a.gitleaks_config.clone(),
            licenses: a.licenses.clone(),
            install_scripts: a.install_scripts.clone(),
            repo_hooks: a.repo_hooks.clone(),
            posture: a.posture_policy.clone(),
            suspect: a.suspect_policy.clone(),
            hooks: a.hooks_policy.clone(),
        },
        refresh: a.refresh,
        offline: a.offline,
        jobs: a.jobs,
        licenses: a.check_licenses,
        ask: !(quiet || a.dry_run || a.no_input),
    };
    let first = scan(opts.clone(), quiet, &net)?;
    // The scan is done; what it found is shown as `wpantry report` shows it.
    let status = cmd_report(&a.show)?;
    if a.show.format == Shown::Tui
        && let Some(n) = update::notice(&net, a.offline)
    {
        eprintln!("{}", Style::stderr().line(&format!("  ℹ {n}")));
    }
    if quiet || !(a.fix || a.dry_run) {
        return Ok(status);
    }
    // Before changing anything, ask, when someone is there to answer.
    let interactive = !a.no_input && std::io::stdin().is_terminal();
    let confirm = |cmds: &[String]| {
        if a.yes || !interactive {
            return true;
        }
        for c in cmds {
            show(&format!("  • {c}"));
        }
        let what = if cmds.len() == 1 { "this update".to_string() } else { format!("these {} updates", cmds.len()) };
        progress::Progress::new(false).ask(&format!("Run {what} now?"), true).unwrap_or(false)
    };
    let applied = remediation::apply(&first.findings, a.dry_run, &confirm, &mut |l| show(l));
    // then the stopgaps wpantry has, for the hosts they are for
    let (stopgap_status, stopgaps_ran) = stopgaps(&first.findings, a.dry_run, a.yes, interactive)?;
    if a.dry_run {
        return Ok(status);
    }
    if !applied.ran.is_empty() || !stopgaps_ran.is_empty() {
        let cache = Cache::open(None)?;
        for (cmd, ok) in &applied.ran {
            // The exposures this command was the fix for; the re-check verifies against them.
            let targets: Vec<String> = first
                .findings
                .iter()
                .filter(|f| f.fix_auto && f.fix_cmd == *cmd)
                .map(wpantry::history::key_of)
                .collect();
            wpantry::history::record_fix(&cache, Some(first.scan_id), cmd, "auto", *ok, &targets)?;
        }
        for (cmd, ok, targets) in &stopgaps_ran {
            wpantry::history::record_fix(&cache, Some(first.scan_id), cmd, "stopgap", *ok, targets)?;
        }
        cache.close()?;
    }
    say("\nRe-checking after the updates…");
    let again = scan(Options { refresh: false, ask: false, ..opts.clone() }, false, &net)?;
    if !applied.ran.is_empty() {
        let cache = Cache::open(None)?;
        wpantry::history::verify_fixes(&cache, first.scan_id, again.scan_id)?;
        cache.close()?;
    }
    // A fix that failed fails the run even when the re-check comes back clean.
    let rechecked = cmd_report(&a.show)?;
    Ok(if rechecked != 0 { rechecked } else { applied.status.max(stopgap_status) })
}

/// Every stopgap wpantry has, run (or, on a dry run, planned) on this
/// host: one that isn't for this host is skipped silently, one that needs
/// a yes gets it from the terminal or `--yes`, else is skipped with a
/// line. Returns the exit status (1 when one failed) and, for the
/// remediation log, each one applied as (command, ok, the findings it was
/// for).
/// One stopgap applied: the command for the log, whether it succeeded, the findings it was for.
type StopgapRun = (String, bool, Vec<String>);

fn stopgaps(
    findings: &[wpantry::finding::Finding],
    dryrun: bool,
    yes: bool,
    interactive: bool,
) -> Result<(i32, Vec<StopgapRun>)> {
    use wpantry::remediation::mitigate::{self, Done, Mode};
    let mut status = EXIT_OK;
    let mut ran = Vec::new();
    let settings = mitigate::Settings::default();
    for s in mitigate::STOPGAPS {
        // wpantry's own fixes run for what the scan found; the others check the host
        if s.when_found && !findings.iter().any(|f| f.vuln_id.eq_ignore_ascii_case(s.id)) {
            continue;
        }
        let mut lines: Vec<String> = Vec::new();
        let confirm = |what: &str| {
            if yes {
                return true;
            }
            if !interactive {
                show(&format!("  · skipped: pass --yes to {what} without asking (wpantry fix {} --yes)", s.name));
                return false;
            }
            progress::Progress::new(false).ask(&format!("{what}?"), false).unwrap_or(false)
        };
        let mode = if dryrun { Mode::DryRun } else { Mode::Apply };
        let command = format!("wpantry fix {} --yes", s.name);
        let targets: Vec<String> =
            findings.iter().filter(|f| f.vuln_id.eq_ignore_ascii_case(s.id)).map(wpantry::history::key_of).collect();
        // the lines are shown only once the stopgap turns out to be for this host
        let done = (s.run)(&mitigate::Real, &settings, mode, &confirm, &mut |l| lines.push(l.to_string()));
        if matches!(done, Ok(Done::NotHere(_))) {
            continue;
        }
        show(&format!("\n==> {}: {}{}", s.name, s.what, if dryrun { " (dry run)" } else { "" }));
        for l in &lines {
            show(l);
        }
        match done {
            Ok(Done::Applied) if !dryrun => ran.push((command, true, targets)),
            Ok(Done::Applied) | Ok(Done::Declined) => {}
            Ok(Done::Nothing(why)) => show(&format!("  ✓ {why}")),
            Ok(Done::NotHere(_)) => unreachable!("skipped above"),
            Err(e) => {
                show(&format!("  ✗ {e}"));
                status = EXIT_FAIL;
                ran.push((command, false, targets));
            }
        }
    }
    Ok((status, ran))
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn cmd_search(query: &str, applicable_only: bool, limit: i64, json: bool) -> Result<i32> {
    let cache = Cache::open(None)?;
    let applicable: std::collections::HashSet<String> = {
        let mut stmt = cache.conn.prepare("SELECT vuln_id FROM findings")?;
        stmt.query_map([], |r| r.get::<_, Option<String>>(0))?.filter_map(|r| r.ok().flatten()).collect()
    };
    let kev = cache.kev_ids()?;
    let sql = if cache.fts {
        "SELECT v.id, v.aliases, v.summary, v.severity, v.url, bm25(vulns_fts) FROM vulns_fts JOIN vulns v ON v.id = vulns_fts.id \
         WHERE vulns_fts MATCH ?1 ORDER BY bm25(vulns_fts) LIMIT 500"
    } else {
        "SELECT id, aliases, summary, severity, url, 0.0 FROM vulns WHERE id LIKE ?1 OR aliases LIKE ?1 OR summary LIKE ?1 OR details LIKE ?1 LIMIT 500"
    };
    let param = if cache.fts { query.to_string() } else { format!("%{query}%") };
    let rows: Vec<(String, String, String, String, String, f64)> = {
        let mut stmt = cache.conn.prepare(sql)?;
        stmt.query_map([param], |r| {
            let s = |i: usize| -> rusqlite::Result<String> { Ok(r.get::<_, Option<String>>(i)?.unwrap_or_default()) };
            Ok((s(0)?, s(1)?, s(2)?, s(3)?, s(4)?, r.get::<_, f64>(5)?))
        })?
        .collect::<std::result::Result<_, _>>()?
    };
    let mut out = Vec::new();
    for (vid, aliases, summary, severity, url, score) in rows {
        let ids: Vec<&str> = std::iter::once(vid.as_str()).chain(aliases.split_whitespace()).collect();
        let hit = ids.iter().any(|i| applicable.contains(*i));
        if applicable_only && !hit {
            continue;
        }
        let exploited = ids.iter().any(|i| kev.contains(*i));
        // Lower is better: bm25 relevance, then what applies here, then KEV.
        let rank = score - if hit { 5.0 } else { 0.0 } - if exploited { 10.0 } else { 0.0 };
        out.push((round3(rank), vid.clone(), aliases.clone(), summary, severity, hit, exploited, url));
    }
    out.sort_by(|a, b| a.0.total_cmp(&b.0));
    let keep = if limit >= 0 { limit as usize } else { out.len().saturating_sub(limit.unsigned_abs() as usize) };
    out.truncate(keep);
    if json {
        let items: Vec<J> = out
            .iter()
            .map(|(rank, id, aliases, summary, severity, hit, kev, url)| {
                obj([
                    ("id", id.as_str().into()),
                    ("aliases", J::Arr(aliases.split_whitespace().map(J::from).collect())),
                    ("summary", summary.as_str().into()),
                    ("severity", severity.as_str().into()),
                    ("applicable", (*hit).into()),
                    ("kev", (*kev).into()),
                    ("url", url.as_str().into()),
                    ("rank", J::Float(*rank)),
                ])
            })
            .collect();
        emit(&J::Arr(items).dumps_indent(1));
    } else {
        for (_, id, _, summary, severity, hit, kev, _) in &out {
            let flags: Vec<&str> =
                [if *hit { "APPLIES" } else { "" }, if *kev { "KEV" } else { "" }, severity.as_str()]
                    .into_iter()
                    .filter(|f| !f.is_empty())
                    .collect();
            say(&format!("{id:<22} {:<22} {}", flags.join(" "), summary.chars().take(80).collect::<String>()));
        }
    }
    Ok(EXIT_OK)
}

fn cmd_breach(enable: bool, disable: bool) -> Result<i32> {
    let cache = Cache::open(None)?;
    if enable || disable {
        cache.set("breach_consent", if enable { "yes" } else { "no" })?;
        cache.close()?;
        show(&format!("✓ breach check {}", if enable { "enabled" } else { "disabled" }));
        return Ok(EXIT_OK);
    }
    let v = cache.get("breach_consent")?.filter(|v| !v.is_empty());
    say(&format!("breach check: {}", v.as_deref().unwrap_or("not decided (asked on the next interactive scan)")));
    Ok(EXIT_OK)
}

fn cmd_version(json: bool) -> Result<i32> {
    if json {
        emit(&obj([("version", VERSION.into()), ("impl", IMPL.into()), ("schema", J::Int(SCHEMA))]).dumps());
    } else {
        say(&format!("wpantry {VERSION} ({IMPL}, schema {SCHEMA})"));
    }
    Ok(EXIT_OK)
}

/// The external tools and whether they're here; fails when a required one
/// is missing, as the scan would.
fn cmd_tools(json: bool) -> Result<i32> {
    let found = wpantry::external::tools();
    if json {
        let env = obj([
            ("schema", J::Int(SCHEMA)),
            ("impl", IMPL.into()),
            ("version", VERSION.into()),
            ("tools", J::Arr(found.iter().map(|t| t.to_json()).collect())),
        ]);
        emit(&env.dumps_indent(1));
    } else {
        for t in &found {
            let mark = if t.found {
                "✓"
            } else if t.required {
                "✗"
            } else {
                "·"
            };
            let kind = if t.required { "required" } else { "optional" };
            let ver = if t.version.is_empty() { "-" } else { &t.version };
            show(&format!("  {mark} {:<12} {ver:<10} {kind:<9} {}", t.name, t.purpose));
        }
    }
    Ok(if found.iter().any(|t| t.required && !t.found) { EXIT_FAIL } else { EXIT_OK })
}

/// `report` (and `export`, and `scan` and `fix` when they finish): the latest
/// scan from the cache, as the terminal's tables or in a format, to stdout
/// or a file. 1 when something in it fails, or there is no scan yet.
fn cmd_report(show: &Show) -> Result<i32> {
    let cache = Cache::open(None)?;
    // The logs, when the report shows them; the HTML page always carries them.
    let days = (show.part.logs() || show.format == Shown::Html).then_some(show.since);
    let found = match wpantry::reporters::latest(&cache, days)? {
        // A log needs no scan: a fix can be run, and logged, before one.
        None if !show.part.findings() && show.part != wpantry::reporters::Part::Summary => {
            Some(wpantry::reporters::logs_only(&cache, show.since)?)
        }
        found => found,
    };
    let Some(mut report) = found else {
        cache.close()?;
        eprintln!("{}", Style::stderr().red("✗ wpantry: no scan yet: run wpantry scan"));
        return Ok(EXIT_FAIL);
    };
    report.part = show.part;
    let text = match show.format {
        Shown::Tui | Shown::Txt => {
            let terminal = show.format == Shown::Tui && show.out.is_none();
            let style = if terminal { Style::stdout() } else { Style::new(false) };
            let width = if terminal && std::io::stdout().is_terminal() { tui::width() } else { tui::DEFAULT_WIDTH };
            let db = db::path().to_string_lossy().into_owned();
            tui::lines(&report, &db, width).iter().map(|l| tui::paint(l, style) + "\n").collect::<String>()
        }
        Shown::Json => wpantry::reporters::render(&cache, &report, Format::Json)?,
        Shown::Jsonl => wpantry::reporters::render(&cache, &report, Format::Jsonl)?,
        Shown::Csv => wpantry::reporters::render(&cache, &report, Format::Csv)?,
        Shown::Md => wpantry::reporters::render(&cache, &report, Format::Md)?,
        Shown::Html => wpantry::reporters::render(&cache, &report, Format::Html)?,
    };
    cache.close()?;
    match &show.out {
        Some(path) => {
            Output::new(path)?.write(&text)?;
            eprintln!("{}", Style::stderr().line(&format!("✓ wrote the report to {}", path.display())));
        }
        None => {
            // A pipe that closes early (`| head`) ends the output, not the process.
            let mut out = std::io::stdout().lock();
            if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush())
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e.into());
            }
        }
    }
    Ok(report.status())
}

/// `sync`: refresh what the cache knows, with the progress line.
fn cmd_sync(refresh: bool, json: bool) -> Result<i32> {
    let net = wpantry::utils::net::Http::new();
    let progress = progress::Progress::start();
    let status = |m: &str| progress.set(m);
    let cache = Cache::open(None)?;
    let synced = wpantry::sync::run(&cache, &net, refresh, &status);
    cache.close()?;
    progress.finish();
    let synced = synced?;
    if json {
        say(&obj([
            ("refreshed", J::Arr(synced.refreshed.iter().map(|s| s.as_str().into()).collect())),
            (
                "failed",
                J::Arr(
                    synced
                        .failed
                        .iter()
                        .map(|(n, w)| obj([("source", n.as_str().into()), ("why", w.as_str().into())]))
                        .collect(),
                ),
            ),
            ("packages", J::Int(synced.packages as i64)),
        ])
        .dumps_indent(1));
    } else {
        for name in &synced.refreshed {
            show(&format!("  ✓ {name}"));
        }
        for (name, why) in &synced.failed {
            show(&format!("  ⚠ {name} - {why}"));
        }
        show(&format!(
            "{} {} sources refreshed, {} package versions re-asked of OSV{}",
            if synced.failed.is_empty() { "✓" } else { "⚠" },
            synced.refreshed.len(),
            synced.packages,
            if synced.failed.is_empty() { String::new() } else { format!(", {} unreachable", synced.failed.len()) }
        ));
    }
    Ok(if synced.failed.is_empty() { EXIT_OK } else { EXIT_FAIL })
}

fn cmd_schedule(action: &str, every: &str, at: &str, dry_run: bool) -> Result<i32> {
    match action {
        "install" => {
            let every = schedule::Every::parse(every).expect("validated");
            let (h, m) = at.split_once(':').expect("validated");
            schedule::install(every, (h.parse().expect("validated"), m.parse().expect("validated")), dry_run)
        }
        "status" => schedule::status(),
        "uninstall" => schedule::uninstall(),
        _ => schedule::run(),
    }
}

/// `cache prune`: what no scan has used in `days`, then VACUUM.
fn cmd_cache_prune(days: i64) -> Result<i32> {
    let cache = Cache::open(None)?;
    let before = std::fs::metadata(cache.file()).map(|m| m.len()).unwrap_or(0);
    let (queries, vulns, runs) = cache.prune(days as f64 * wpantry::db::DAY)?;
    let file = cache.file().to_path_buf();
    cache.close()?;
    let after = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
    say(&format!(
        "pruned {queries} package versions, {vulns} advisories and {runs} cached runs older than {days} days; {} → {} ({})",
        mb(before),
        mb(after),
        file.display()
    ));
    Ok(EXIT_OK)
}

fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1e6)
}

/// The advisories the last scan found with no released fix, asked about
/// again now; exit 10 when any has a fix.
fn cmd_watch(json: bool, offline: bool) -> Result<i32> {
    let cache = Cache::open(None)?;
    let net = wpantry::utils::net::Http::new();
    let style = Style::stderr();
    let status = |s: &str| {
        if !json && std::io::stderr().is_terminal() {
            eprintln!("{}", style.dim(s));
        }
    };
    let watched = wpantry::watch::run(&cache, &net, offline, &status)?;
    let landed = watched.iter().filter(|w| w.fixed.is_some()).count();
    if json {
        say(&wpantry::watch::report_json(&watched));
    } else if watched.is_empty() {
        say("Nothing to watch: the last scan found no Critical, High or exploited advisory without a released fix.");
    } else {
        let out = Style::stdout();
        for w in &watched {
            let (mark, state) = match &w.fixed {
                Some(v) => (out.green("✓"), out.green(&format!("FIX AVAILABLE: {} {v}", w.item.1))),
                None => (out.yellow("⚠"), out.yellow("no fix yet")),
            };
            say(&format!(
                "{mark} {} {} {} ({}) - {} {}",
                w.item.1,
                w.item.2,
                out.dim(&w.item.0),
                out.bold(&w.id),
                w.summary,
                state
            ));
            match (&w.fixed, &w.mitigation) {
                (Some(_), _) => say("    Fix: run wpantry fix --dry-run for the step"),
                (None, Some(m)) => say(&format!("    Meanwhile: {m}")),
                (None, None) => {
                    say("    Meanwhile: reduce exposure where you can and keep checking (wpantry watch, or a schedule)")
                }
            }
        }
        say(&format!(
            "{} advisories watched, {landed} with a fix now{}",
            watched.len(),
            if landed > 0 { ". Re-run wpantry scan to see the update plan" } else { "" }
        ));
    }
    Ok(if landed > 0 { EXIT_AVAILABLE } else { EXIT_OK })
}

/// What `fix ID` does: the dry run, the yes, whether it may ask, the undo,
/// and what a stopgap is told (`--bundle`, `--hours`).
struct FixOne {
    dry_run: bool,
    yes: bool,
    no_input: bool,
    undo: bool,
    settings: wpantry::remediation::mitigate::Settings,
}

/// `fix ID` (`mitigate ID`): the last scan's findings for the advisory (by
/// id or alias), their unattended fixes run, wpantry's stopgap for it (or
/// one of its own fixes, by name) run where one exists, and the steps that
/// need a person printed. Exit 1 when a step is left, a fix failed, or
/// nothing is known for the id here.
fn cmd_mitigate(id: &str, o: FixOne) -> Result<i32> {
    let FixOne { dry_run, yes, no_input, undo, ref settings } = o;
    use wpantry::remediation::mitigate::{self, Done, Mode};
    let cache = Cache::open(None)?;
    // the id, its aliases, and the records that list it as one
    let mut ids: Vec<String> = vec![id.to_string()];
    {
        let mut stmt = cache.conn.prepare("SELECT id, aliases FROM vulns WHERE id = ?1 OR aliases LIKE ?2")?;
        let rows = stmt.query_map(rusqlite::params![id, format!("%{id}%")], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))
        })?;
        for (vid, aliases) in rows.flatten() {
            let names = std::iter::once(vid.as_str()).chain(aliases.split_whitespace());
            if names.clone().any(|n| n.eq_ignore_ascii_case(id)) {
                for n in names {
                    if !ids.iter().any(|i| i.eq_ignore_ascii_case(n)) {
                        ids.push(n.to_string());
                    }
                }
            }
        }
    }
    let findings: Vec<wpantry::finding::Finding> = wpantry::reporters::jsonl::findings(&cache)?
        .into_iter()
        .filter(|f| ids.iter().any(|i| i.eq_ignore_ascii_case(&f.vuln_id)))
        .collect();
    let stopgap = mitigate::stopgap(id);
    let interactive = !no_input && std::io::stdin().is_terminal();
    let bundled = wpantry::checks::mitigation(id);
    let shown = stopgap.filter(|s| s.name.eq_ignore_ascii_case(id)).map_or(id, |s| s.name);
    show(&format!(
        "==> {shown}: {}{}",
        match findings.len() {
            0 => "not in the last scan's findings".to_string(),
            1 => format!("1 finding in the last scan ({} {})", findings[0].component, findings[0].version),
            n => format!("{n} findings in the last scan"),
        },
        if stopgap.is_some() { "; wpantry has a stopgap for it" } else { "" }
    ));
    for f in &findings {
        show(&format!(
            "  {} {} {} ({}) {}",
            if f.status == "fail" { "✗" } else { "⚠" },
            f.component,
            f.version,
            f.kind,
            f.location
        ));
    }
    let mut status = EXIT_OK;
    let mut did_something = false;
    // the unattended fixes (a version bump), the way `fix` runs them
    if findings.iter().any(|f| f.fix_auto && !f.fix_cmd.is_empty()) {
        // as `fix`: without a terminal they run; a terminal is asked
        let confirm = |cmds: &[String]| {
            if yes || !interactive {
                return true;
            }
            for c in cmds {
                show(&format!("  • {c}"));
            }
            progress::Progress::new(false).ask("Run these now?", true).unwrap_or(false)
        };
        let auto: Vec<wpantry::finding::Finding> = findings.iter().filter(|f| f.fix_auto).cloned().collect();
        let applied = remediation::apply(&auto, dry_run, &confirm, &mut |l| show(l));
        for (cmd, ok) in &applied.ran {
            let targets: Vec<String> =
                auto.iter().filter(|f| f.fix_cmd == *cmd).map(wpantry::history::key_of).collect();
            wpantry::history::record_fix(&cache, None, cmd, "mitigate", *ok, &targets)?;
        }
        did_something = dry_run || !applied.ran.is_empty();
        if applied.status != 0 {
            status = EXIT_FAIL;
        }
    }
    // wpantry's own stopgap
    if let Some(s) = stopgap {
        show(&format!("\n==> stopgap: {}{}", s.what, if undo { " (undoing)" } else { "" }));
        let mode = if undo {
            Mode::Remove
        } else if dry_run {
            Mode::DryRun
        } else {
            Mode::Apply
        };
        let confirm = |what: &str| {
            if yes {
                return true;
            }
            if !interactive {
                show(&format!("  ✗ not a terminal: pass --yes to {what} without asking (or --dry-run to look)"));
                return false;
            }
            progress::Progress::new(false).ask(&format!("{what}?"), false).unwrap_or(false)
        };
        let command = format!("wpantry fix {}", s.name);
        let targets: Vec<String> = findings.iter().map(wpantry::history::key_of).collect();
        let done = (s.run)(&mitigate::Real, settings, mode, &confirm, &mut |l| show(l));
        if !dry_run && matches!(done, Ok(Done::Applied) | Err(_)) {
            wpantry::history::record_fix(
                &cache,
                wpantry::history::latest_scan(&cache)?,
                &command,
                "stopgap",
                done.is_ok(),
                &targets,
            )?;
            // kept even when the stopgap failed and the run stops here
            cache.commit()?;
        }
        match done? {
            Done::Applied => did_something = true,
            Done::Nothing(why) => {
                show(&format!("  ✓ {why}"));
                did_something = true;
            }
            Done::NotHere(why) => show(&format!("  · {why}")),
            Done::Declined => {
                show("  nothing changed");
                status = EXIT_FAIL;
            }
        }
    }
    // what needs a person: the fix texts that aren't the stopgap's own description
    let manual: Vec<&str> = {
        let mut seen = Vec::new();
        for f in &findings {
            let c = f.fix_cmd.as_str();
            if c.is_empty() || f.fix_auto || seen.contains(&c) || (stopgap.is_some() && bundled.as_deref() == Some(c)) {
                continue;
            }
            seen.push(c);
        }
        seen
    };
    if !manual.is_empty() {
        show("\n==> Needs you:");
        for m in &manual {
            show(&format!("  • {m}"));
        }
        status = EXIT_FAIL;
    }
    if !did_something && manual.is_empty() {
        if let Some(m) = bundled.filter(|_| stopgap.is_none()) {
            show(&format!("\n==> Needs you: {m}"));
        } else if findings.is_empty() && stopgap.is_none() {
            show(&format!(
                "\n✗ nothing known for {id} here: it isn't in the last scan's findings (run wpantry scan) and wpantry has no stopgap for it"
            ));
        } else if findings.is_empty() {
            // a stopgap that was declined is still to do
            if status == EXIT_OK {
                show("  nothing to do here");
            }
            cache.close()?;
            return Ok(status);
        }
        cache.close()?;
        return Ok(EXIT_FAIL);
    }
    cache.close()?;
    Ok(status)
}

/// `mitigate list`: the stopgaps wpantry has, each with whether it applies
/// here (a dry run with the output dropped), and the advisories in the last
/// scan with an unattended fix.
/// `fix list`: what can be fixed, from the latest scan: the update plan in
/// batches, then wpantry's stopgaps and whether each applies here. Nothing
/// runs.
fn cmd_fix_list() -> Result<i32> {
    use wpantry::remediation::mitigate::{self, Done, Mode};
    let cache = Cache::open(None)?;
    let latest = wpantry::reporters::latest(&cache, None)?;
    cache.close()?;
    let Some(report) = latest else {
        eprintln!("{}", Style::stderr().red("✗ wpantry: no scan yet: run wpantry scan"));
        return Ok(EXIT_FAIL);
    };
    let findings = &report.outcome.findings;
    let view = wpantry::reporters::view::view(findings);
    show(&format!(
        "==> What wpantry fix can do, from scan #{} ({})",
        report.outcome.scan_id,
        wpantry::history::stamp(report.scan.row.finished_at)
    ));
    show("");
    show("Update plan (wpantry fix runs the automatic ones; --dry-run shows each command first):");
    if view.batches.is_empty() {
        show("  nothing to update");
    }
    for b in &view.batches {
        let mode = match b.mode {
            "auto" => "automatic",
            "manual" => "needs you",
            _ => "optional",
        };
        let cmd = if b.sudo { b.cmd.strip_prefix("sudo ").unwrap_or(&b.cmd) } else { &b.cmd };
        show(&format!("  {mode:<10} {}{cmd}  (clears {})", if b.sudo { "[sudo] " } else { "" }, b.findings));
    }
    show("");
    show("Fixes wpantry makes itself (wpantry fix NAME; wpantry fix runs the ones that apply):");
    let settings = mitigate::Settings::default();
    for s in mitigate::STOPGAPS {
        let found = findings.iter().any(|f| f.vuln_id.eq_ignore_ascii_case(s.id));
        let state = if s.when_found && !found {
            format!("not needed: the last scan didn't find {}", s.id)
        } else {
            match (s.run)(&mitigate::Real, &settings, Mode::DryRun, &|_| false, &mut |_| {}) {
                Ok(Done::Applied) => {
                    format!("needed here: wpantry fix {} --dry-run shows what it would change", s.name)
                }
                Ok(Done::Nothing(why)) | Ok(Done::NotHere(why)) => why,
                Ok(Done::Declined) => "unreachable on a dry run".into(),
                Err(e) => format!("can't tell: {e}"),
            }
        };
        show(&format!("  {:<20} {} ({})", s.name, s.what, s.id));
        show(&format!("  {:<20} {state}", ""));
    }
    Ok(EXIT_OK)
}

/// `rules`: where the malware scan's rules come from and what compiled;
/// `--update` fetches YARA Forge's package first.
fn cmd_rules(update: bool, json: bool) -> Result<i32> {
    use wpantry::checks::malware;
    let cache = Cache::open(None)?;
    let mut failed = None;
    if update {
        let net = wpantry::utils::net::Http::new();
        let progress = progress::Progress::start();
        progress.set("Fetching YARA Forge's rules");
        if let Err(e) = malware::yara::update(&cache, &net, true) {
            failed = Some(e.to_string());
        }
        progress.finish();
    }
    let dir = malware::yara::rules_dir(&cache);
    let active = |id: &str| wpantry::sources::file::active(id);
    let loaded = malware::yara::load(&dir, false, &active);
    let all = malware::yara::load(&dir, true, &active);
    cache.close()?;
    let stats = all.rules.stats();
    if json {
        let sources = all
            .sources
            .iter()
            .map(|(n, c)| obj([("source", n.as_str().into()), ("rules", J::Int(*c as i64))]))
            .collect();
        say(&obj([
            ("directory", dir.to_string_lossy().as_ref().into()),
            ("sources", J::Arr(sources)),
            ("rules", J::Int(stats.rules as i64)),
            ("this_system", J::Int(loaded.rules.rules().len() as i64)),
            ("rejected", J::Int(all.rules.rejected.len() as i64)),
            ("update_failed", failed.as_deref().map_or(J::Null, |f| f.into())),
        ])
        .dumps_indent(1));
    } else {
        show(&format!("Rules in {}", dir.display()));
        for (name, n) in &all.sources {
            show(&format!("  {n:>6}  {name}"));
        }
        show(&format!(
            "{} rules compile ({} for this system and any; --deep uses all), {} rejected",
            stats.rules,
            loaded.rules.rules().len(),
            all.rules.rejected.len()
        ));
        if let Some(f) = &failed {
            show(&format!("Not updated: {f}"));
        }
    }
    Ok(if failed.is_some() { EXIT_FAIL } else { EXIT_OK })
}

/// `sources`: every outside source and what its fetches came to.
fn cmd_sources(json: bool, file: Option<std::path::PathBuf>) -> Result<i32> {
    use wpantry::sources::file as sources;
    let path = file.clone().unwrap_or_else(sources::user_file);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && file.is_none() => None,
        Err(e) => {
            eprintln!("wpantry: error: {}: {e}", path.display());
            return Ok(EXIT_USAGE);
        }
    };
    if let Err(e) = sources::configure(text.as_deref(), false) {
        eprintln!("wpantry: error: {e}");
        return Ok(EXIT_USAGE);
    }
    let user = sources::effective().user.clone();
    let cache = Cache::open(None)?;
    let all = wpantry::sources::fetch::listing(&cache)?;
    cache.close()?;
    let now = wpantry::utils::os::now();
    let when = |t: f64| if t > 0.0 { J::Float(t) } else { J::Null };
    if json {
        let rows = all
            .iter()
            .map(|l| {
                let s = &l.source;
                obj([
                    ("id", s.id.as_str().into()),
                    ("kind", s.kind.as_str().into()),
                    ("format", s.format.as_str().into()),
                    ("tier", s.tier.as_str().into()),
                    ("host", s.host().map_or(J::Null, |h| h.as_str().into())),
                    (
                        "transport",
                        if s.transport == wpantry::sources::file::Transport::Git { "git" } else { "https" }.into(),
                    ),
                    ("user", J::Bool(user.contains(&s.id))),
                    ("license", s.license.as_str().into()),
                    ("redistribute", J::Bool(s.redistribute)),
                    ("refresh_seconds", J::Float(s.refresh)),
                    ("sends", if s.sends.is_empty() { J::Null } else { s.sends.as_str().into() }),
                    ("last_attempt", when(l.state.attempt)),
                    ("last_success", when(l.state.success)),
                    ("fresh", J::Bool(l.fresh)),
                    ("error", if l.state.error.is_empty() { J::Null } else { l.state.error.as_str().into() }),
                ])
            })
            .collect();
        say(&obj([("sources", J::Arr(rows))]).dumps_indent(1));
        return Ok(EXIT_OK);
    }
    for l in &all {
        let s = &l.source;
        let fetched = if l.state.success > 0.0 {
            format!(
                "{} ago{}",
                schedule::ago((now - l.state.success).max(0.0) as u64),
                if l.fresh { "" } else { ", stale" }
            )
        } else {
            "never fetched".to_string()
        };
        let host = s.host().unwrap_or_else(|| "git".into());
        let host = if user.contains(&s.id) { format!("{host} (yours)") } else { host };
        show(&format!("{:<28} {:<18} {:<7} {:<34} {}", s.id, s.kind, s.tier.as_str(), host, fetched));
        show(&format!(
            "{:<28} licence: {}{}",
            "",
            s.license,
            if s.redistribute { "" } else { " (fetched here, never redistributed)" }
        ));
        if !l.state.error.is_empty() {
            show(&format!("{:<28} last error: {}", "", l.state.error));
        }
    }
    Ok(EXIT_OK)
}

/// `rules goodware`: rebuild the goodware database; returns how many files it read.
fn cmd_rules_goodware() -> Result<usize> {
    let cache = Cache::open(None)?;
    let progress = progress::Progress::start();
    let status = |m: &str| progress.set(m);
    let files = wpantry::checks::malware::rulegen::goodware_files(&wpantry::checks::malware::rulegen::goodware_dirs());
    let read = wpantry::checks::malware::rulegen::build(&cache, &files, &status);
    progress.finish();
    let read = read?;
    cache.close()?;
    note(&format!("goodware: {read} system programs read"));
    Ok(read)
}

/// `rules gen`: a rule from samples, checked against the goodware.
fn cmd_rules_gen(
    samples: &[std::path::PathBuf],
    category: &str,
    family: Option<&str>,
    name: Option<&str>,
    out: Option<&std::path::Path>,
) -> Result<i32> {
    use wpantry::checks::malware::rulegen;
    if !rulegen::built(&Cache::open(None)?)? {
        cmd_rules_goodware()?;
    }
    let cache = Cache::open(None)?;
    let family = family.map(str::to_string).unwrap_or_else(|| {
        samples[0].file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "Unknown".into())
    });
    let name = name.map(str::to_string).unwrap_or_else(|| rulegen::rule_name(&family, category));
    let mut hashes = Vec::new();
    for s in samples {
        hashes.push(wpantry::utils::sha256::hex(&std::fs::read(s)?));
    }
    let date = wpantry::history::stamp(wpantry::utils::os::now());
    let describe = rulegen::Describe {
        name: &name,
        category,
        family: &family,
        author: "wpantry rules gen",
        reference: "",
        date: date.get(..10).unwrap_or(&date),
        hashes: &hashes,
    };
    let Some(output) = rulegen::run(&cache, samples, &describe)? else {
        note("no rule: the samples share nothing that this machine's programs don't also have");
        return Ok(EXIT_FAIL);
    };
    cache.close()?;
    match out {
        Some(path) => {
            std::fs::write(path, &output.text)?;
            std::fs::write(path.with_extension("test.toml"), &output.test_toml)?;
            note(&format!(
                "wrote {} ({} strings, {} code snippets) and its test file",
                path.display(),
                output.strings,
                output.opcodes
            ));
        }
        None => say(&output.text),
    }
    if !output.false_positives.is_empty() {
        for f in &output.false_positives {
            note(&format!("false positive: the rule matches {}", f.display()));
        }
        return Ok(EXIT_FAIL);
    }
    Ok(EXIT_OK)
}

fn cmd_skill() -> Result<i32> {
    let mut out = std::io::stdout().lock();
    out.write_all(wpantry::SKILL.as_bytes())?;
    out.flush()?;
    Ok(EXIT_OK)
}

fn dispatch(cmd: Command) -> Result<i32> {
    match cmd {
        Command::Scan(mut c) => {
            c.show = resolve(c.show, std::io::stdout().is_terminal(), wpantry::utils::os::now());
            cmd_scan(c)
        }
        Command::Search { query, applicable, limit, json } => cmd_search(&query, applicable, limit, json),
        Command::Breach { enable, disable } => cmd_breach(enable, disable),
        Command::Watch { json, offline } => cmd_watch(json, offline),
        Command::Version { json } => cmd_version(json),
        Command::Tools { json } => cmd_tools(json),
        Command::Skill => cmd_skill(),
        Command::Sources { json, file } => cmd_sources(json, file),
        Command::Rules { action, samples, update, json, category, family, name, out } => match action.as_str() {
            "gen" => cmd_rules_gen(&samples, &category, family.as_deref(), name.as_deref(), out.as_deref()),
            "goodware" => cmd_rules_goodware().map(|_| EXIT_OK),
            _ => cmd_rules(update, json),
        },
        Command::Report(show) => cmd_report(&resolve(show, std::io::stdout().is_terminal(), wpantry::utils::os::now())),
        Command::Sync { refresh, json } => cmd_sync(refresh, json),
        Command::Schedule { action, every, at, dry_run } => cmd_schedule(&action, &every, &at, dry_run),
        Command::Cache { action: _, older_than } => cmd_cache_prune(older_than),
        Command::Update { check, yes, no_input, offline, version } => {
            update::run(update::Update { check, yes, no_input, offline, version })
        }
        Command::Mitigate { target, dry_run, yes, no_input, undo, bundle, hours } => match target {
            Target::List => cmd_fix_list(),
            Target::Id(id) => cmd_mitigate(
                &id,
                FixOne {
                    dry_run,
                    yes,
                    no_input,
                    undo,
                    settings: wpantry::remediation::mitigate::Settings { bundle, hours },
                },
            ),
        },
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = match args::parse(&argv) {
        Parsed::Help(text) => {
            print!("{text}");
            EXIT_OK
        }
        Parsed::Usage(text) => {
            eprint!("{}", text.replace("\nerror: ", &format!("\n{} ", Style::stderr().red("error:"))));
            EXIT_USAGE
        }
        // A crash is an internal error, never "clean" or "fail".
        Parsed::Run(cmd) => match std::panic::catch_unwind(|| dispatch(cmd)) {
            Ok(Ok(code)) => code,
            // The cache can't be opened or written, a file we need is gone.
            Ok(Err(e)) => {
                eprintln!("{}", Style::stderr().red(&format!("✗ wpantry: {e}")));
                EXIT_INTERNAL
            }
            Err(_) => EXIT_INTERNAL,
        },
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
