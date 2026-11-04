//! wpantry: the vulnerabilities that apply to this computer. The CLI
//! contract is specs/cli-contract.md; this binary owns stdout, stderr and
//! exit codes, the library does the work.
//!
//! Exit codes: 0 clean (warnings and unchecked sources included), 1 a
//! failing finding or a failed unattended fix, 2 usage error, 3 internal
//! error.

mod args;
mod html;
mod progress;
mod report;
mod schedule;
mod style;
mod update;

use args::{Check, Command, Parsed, Target};
use rusqlite::types::ValueRef;
use std::io::{IsTerminal, Write};
use style::Style;
use wpantry::check::{Options, Outcome, Policy, Scan};
use wpantry::db::{self, Cache};
use wpantry::error::Result;
use wpantry::json::{J, obj};
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

/// A line of the report on stdout, coloured by its mark on a terminal.
fn show(line: &str) {
    println!("{}", Style::stdout().line(&style::clean(line)));
}

/// `scan --json`: the findings plus what was checked (schema 1).
fn envelope(scan: &Outcome) -> J {
    obj([
        ("schema", J::Int(SCHEMA)),
        ("impl", IMPL.into()),
        ("version", VERSION.into()),
        ("checked", J::Obj(scan.counts.iter().map(|(k, n)| (k.clone(), J::Int(*n))).collect())),
        ("unfixed", J::Int(scan.unfixed)),
        ("unknown_licenses", J::Int(scan.unknown_licenses)),
        ("findings", J::Arr(scan.findings.iter().map(|f| f.to_json()).collect())),
    ])
}

/// One scan with a live progress line; the line is gone before this returns.
fn scan(opts: Options, json: bool, net: &dyn wpantry::net::Net) -> Result<Outcome> {
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

fn cmd_scan(a: Check) -> Result<i32> {
    let html = a.html.as_deref().map(html::Output::new).transpose()?;
    let net = wpantry::net::Http::new();
    let opts = Options {
        paths: a.path.clone(),
        machine: !a.no_machine,
        no_posture: a.no_posture,
        no_clipboard: a.no_clipboard,
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
        ask: !(a.json || a.dryrun || a.no_input),
    };
    let first = scan(opts.clone(), a.json, &net)?;
    if a.json {
        html::finish(html, &first, &opts, "scan")?;
        emit(&envelope(&first).dumps_indent(1));
        return Ok(if first.findings.iter().any(|f| f.status == "fail") { EXIT_FAIL } else { EXIT_OK });
    }
    let db = db::path().to_string_lossy().into_owned();
    let status = report::report(&first, &db, &mut |l| show(l));
    if let Some(n) = update::notice(&net, a.offline) {
        eprintln!("{}", Style::stderr().line(&format!("  ℹ {n}")));
    }
    if !(a.fix || a.dryrun) {
        html::finish(html, &first, &opts, "scan")?;
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
    let applied = report::apply(&first.findings, a.dryrun, &confirm, &mut |l| show(l));
    // then the stopgaps wpantry has, for the hosts they are for
    let (stopgap_status, stopgaps_ran) = stopgaps(&first.findings, a.dryrun, a.yes, interactive)?;
    if a.dryrun {
        html::finish(html, &first, &opts, "before updates (dry run)")?;
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
    let rechecked = report::report(&again, &db, &mut |l| show(l));
    let phase = if applied.status == 0 { "after updates" } else { "after updates (an update command failed)" };
    html::finish(html, &again, &opts, phase)?;
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
    findings: &[wpantry::check::Finding],
    dryrun: bool,
    yes: bool,
    interactive: bool,
) -> Result<(i32, Vec<StopgapRun>)> {
    use wpantry::mitigate::{self, Done, Mode};
    let mut status = EXIT_OK;
    let mut ran = Vec::new();
    for s in mitigate::STOPGAPS {
        let mut lines: Vec<String> = Vec::new();
        let confirm = |what: &str| {
            if yes {
                return true;
            }
            if !interactive {
                show(&format!("  · skipped: pass --yes to {what} without asking (wpantry mitigate {} --yes)", s.id));
                return false;
            }
            progress::Progress::new(false).ask(&format!("{what}?"), false).unwrap_or(false)
        };
        let mode = if dryrun { Mode::DryRun } else { Mode::Apply };
        let command = format!("wpantry mitigate {} --yes", s.id);
        let targets: Vec<String> =
            findings.iter().filter(|f| f.vuln_id.eq_ignore_ascii_case(s.id)).map(wpantry::history::key_of).collect();
        // the lines are shown only once the stopgap turns out to be for this host
        let done = (s.run)(&mitigate::Real, mode, &confirm, &mut |l| lines.push(l.to_string()));
        if matches!(done, Ok(Done::NotHere(_))) {
            continue;
        }
        show(&format!("\n==> Stopgap for {}: {}{}", s.id, s.what, if dryrun { " (dry run)" } else { "" }));
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

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\r', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

fn cmd_export(csv: Option<&str>, jsonl: Option<&str>, all: bool) -> Result<i32> {
    if let Some(path) = jsonl {
        let cache = Cache::open(None)?;
        let (text, n) = wpantry::export::jsonl(&cache, all)?;
        std::fs::write(path, text)?;
        let what = if all { "findings and resolved exposures" } else { "findings" };
        show(&format!("✓ wrote {n} {what} to {path}"));
    }
    match csv {
        Some(path) => export_csv(path),
        None => Ok(EXIT_OK),
    }
}

fn export_csv(path: &str) -> Result<i32> {
    let cache = Cache::open(None)?;
    let rows: Vec<Vec<String>> = {
        let mut stmt = cache.conn.prepare(
            "SELECT f.vuln_id, v.aliases, v.url, f.component, f.kind, f.version, f.fixed, f.severity, f.kev, f.status, f.location \
             FROM findings f LEFT JOIN vulns v ON v.id = f.vuln_id OR (' ' || v.aliases || ' ') LIKE ('% ' || f.vuln_id || ' %') \
             GROUP BY f.vuln_id, f.component, f.version, f.location",
        )?;
        stmt.query_map([], |r| {
            (0..11)
                .map(|i| {
                    Ok(match r.get_ref(i)? {
                        ValueRef::Null => String::new(),
                        ValueRef::Integer(n) => n.to_string(),
                        ValueRef::Real(x) => x.to_string(),
                        ValueRef::Text(t) | ValueRef::Blob(t) => String::from_utf8_lossy(t).into_owned(),
                    })
                })
                .collect()
        })?
        .collect::<std::result::Result<_, _>>()?
    };
    let mut text =
        String::from("id,aliases,url,component,kind,affected_version,safe_version,severity,kev,status,location\r\n");
    for mut r in rows.clone() {
        if r[2].is_empty() && r[0].starts_with("CVE-") {
            r[2] = format!("https://www.cve.org/CVERecord?id={}", r[0]);
        }
        text.push_str(&r.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        text.push_str("\r\n");
    }
    std::fs::write(path, text)?;
    show(&format!("✓ wrote {} findings to {path}", rows.len()));
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

/// `report`: the exposure, remediation and audit logs from the cache's
/// history tables, as Markdown (default), JSON or CSV.
fn cmd_report(sections: &[String], since_days: i64, format: &str, out: Option<&str>) -> Result<i32> {
    use wpantry::history::{self, stamp};
    let cache = Cache::open(None)?;
    let since = wpantry::system::now() - since_days as f64 * wpantry::db::DAY;
    let want = |s: &str| sections.iter().any(|x| x == s || x == "all");
    let exposures = if want("exposure") { history::exposures(&cache, since)? } else { Vec::new() };
    let fixes = if want("remediation") { history::fixes(&cache, since)? } else { Vec::new() };
    let (scans, events) = if want("audit") {
        (history::scans(&cache, since)?, history::events(&cache, since)?)
    } else {
        (Vec::new(), Vec::new())
    };
    let text = match format {
        "json" => {
            history::report_json(&cache, want("exposure"), want("remediation"), want("audit"), since, since_days)?
        }
        "csv" => {
            let mut t = String::from(
                "kind,component,version,location,vuln_id,status,severity,kev,fixed,first_seen,last_seen,resolved,days_exposed\r\n",
            );
            for e in &exposures {
                let row = [
                    e.kind.as_str(),
                    &e.component,
                    &e.version,
                    &e.location,
                    &e.vuln_id,
                    &e.status,
                    &e.severity,
                    if e.kev { "true" } else { "false" },
                    &e.fixed,
                    &stamp(e.first_at),
                    &stamp(e.last_at),
                    &e.resolved_at.map(stamp).unwrap_or_default(),
                    &e.days_exposed.to_string(),
                ];
                t.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
                t.push_str("\r\n");
            }
            t
        }
        _ => {
            let mut t = format!(
                "# wpantry report\n\nGenerated {} by wpantry {VERSION}; the last {since_days} days.\n",
                stamp(wpantry::system::now())
            );
            if want("exposure") {
                let open = exposures.iter().filter(|e| e.resolved_at.is_none()).count();
                let closed: Vec<&history::Exposure> = exposures.iter().filter(|e| e.resolved_at.is_some()).collect();
                let median = {
                    let mut d: Vec<f64> = closed.iter().map(|e| e.days_exposed).collect();
                    d.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    d.get(d.len() / 2).copied().unwrap_or(0.0)
                };
                t.push_str(&format!(
                    "\n## Exposure log\n\n{open} open, {} resolved; median time to resolve {median} days.\n\n| Component | Version | Advisory | Severity | Status | First seen | Resolved | Days |\n|---|---|---|---|---|---|---|---|\n",
                    closed.len()
                ));
                for e in &exposures {
                    t.push_str(&format!(
                        "| {} | {} | {}{} | {} | {} | {} | {} | {} |\n",
                        md(&e.component),
                        md(&e.version),
                        md(&e.vuln_id),
                        if e.kev { " (KEV)" } else { "" },
                        md(&e.severity),
                        if e.resolved_at.is_some() { "resolved" } else { &e.status },
                        stamp(e.first_at),
                        e.resolved_at.map(stamp).unwrap_or_else(|| "open".into()),
                        e.days_exposed
                    ));
                }
            }
            if want("remediation") {
                t.push_str("\n## Remediation log\n\n| When | Command | Mode | Result | Verified by scan |\n|---|---|---|---|---|\n");
                for f in &fixes {
                    t.push_str(&format!(
                        "| {} | `{}` | {} | {} | {} |\n",
                        stamp(f.at),
                        f.command.replace('`', "'"),
                        f.mode,
                        if f.ok { "ok" } else { "failed" },
                        f.verified_scan.map(|s| format!("#{s}")).unwrap_or_else(|| "-".into())
                    ));
                }
            }
            if want("audit") {
                t.push_str("\n## Audit log\n\n### Scans\n\n| # | Finished | Host | User | wpantry | Scope | Fails | Warns | Unchecked |\n|---|---|---|---|---|---|---|---|---|\n");
                for s in &scans {
                    t.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                        s.id,
                        stamp(s.finished_at),
                        md(&s.host),
                        md(&s.user),
                        s.version,
                        md(&s.scope),
                        s.fails,
                        s.warns,
                        s.unchecked
                    ));
                }
                t.push_str("\n### Events\n\n| When | Event | Detail |\n|---|---|---|\n");
                for e in &events {
                    t.push_str(&format!("| {} | {} | {} |\n", stamp(e.at), e.kind, md(&e.detail.to_string())));
                }
            }
            t
        }
    };
    cache.close()?;
    match out {
        Some(path) => {
            std::fs::write(path, &text)?;
            show(&format!("✓ wrote the report to {path}"));
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
    Ok(EXIT_OK)
}

/// A table cell: no pipes, newlines or control characters.
fn md(s: &str) -> String {
    s.replace('|', "\\|").chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// `sync`: refresh what the cache knows, with the progress line.
fn cmd_sync(refresh: bool, json: bool) -> Result<i32> {
    let net = wpantry::net::Http::new();
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

fn cmd_schedule(action: &str, every: &str, at: &str, dry_run: bool, clipboard_guard: bool) -> Result<i32> {
    match action {
        "install" if clipboard_guard => schedule::install_guard(dry_run),
        "uninstall" if clipboard_guard => schedule::uninstall_guard(),
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

/// `clipboard`: the self-test now (exit 1 when a canary came back
/// changed; a test that couldn't run says so and exits 0, as an unchecked
/// source does), or with `--watch` the resident guard, which runs until
/// stopped, or after the first alert with `--once`. Each alert is one
/// line (or one JSON object), a desktop notification and a `clipper`
/// event in the cache. `WPANTRY_CLIPBOARD_FAKE=<file>` reads the
/// clipboard from a script instead (one line per read; the contract
/// tests' hook) and sends no notification.
fn cmd_clipboard(watch: bool, once: bool, window: f64, json: bool) -> Result<i32> {
    use wpantry::clipper::{self, Clipboard, SelfTest};
    use wpantry::guard;
    if !watch {
        let result = clipper::run_self_test();
        let (code, state, detail) = match &result {
            SelfTest::Skipped(why) => (EXIT_OK, "skipped", vec![("why", J::from(why.as_str()))]),
            SelfTest::Clean(n) => (EXIT_OK, "clean", vec![("canaries", J::Int(*n as i64))]),
            SelfTest::Swapped(swaps) => (
                EXIT_FAIL,
                "swapped",
                vec![(
                    "swaps",
                    J::Arr(
                        swaps
                            .iter()
                            .map(|s| {
                                obj([
                                    ("chain", s.chain.name().into()),
                                    ("canary", s.canary.as_str().into()),
                                    ("got", s.got.as_str().into()),
                                    ("read", J::Int(s.read as i64)),
                                ])
                            })
                            .collect(),
                    ),
                )],
            ),
        };
        if json {
            let mut pairs: Vec<(&str, J)> = vec![
                ("schema", J::Int(SCHEMA)),
                ("impl", IMPL.into()),
                ("version", VERSION.into()),
                ("self_test", state.into()),
            ];
            pairs.extend(detail);
            emit(&J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()).dumps_indent(1));
            return Ok(code);
        }
        match result {
            SelfTest::Skipped(why) => show(&format!("  ⚠ clipboard self-test not run: {why}")),
            SelfTest::Clean(n) => {
                show(&format!("  ✓ {n} canary addresses copied to the clipboard came back unchanged"))
            }
            SelfTest::Swapped(swaps) => {
                for s in &swaps {
                    show(&format!(
                        "  ✗ the {} canary {} came back as {} on read {}: something rewrites the clipboard. Don't send funds from this machine",
                        s.chain.name(),
                        s.canary,
                        s.got,
                        s.read
                    ));
                }
            }
        }
        return Ok(code);
    }
    let settings =
        guard::Settings { window: std::time::Duration::from_secs_f64(window), interval: guard::INTERVAL, once };
    let fake = std::env::var_os("WPANTRY_CLIPBOARD_FAKE").filter(|v| !v.is_empty());
    let scripted = fake.is_some();
    let mut on_alert = |a: &guard::Alert| {
        if json {
            emit(&a.to_json(wpantry::system::now()).to_string());
        } else {
            show(&format!("  ✗ {}", a.note()));
        }
        if !scripted {
            guard::notify(a);
        }
        if let Err(e) = Cache::open(None).and_then(|c| guard::record(&c, a).and_then(|()| c.close())) {
            eprintln!("{}", Style::stderr().red(&format!("✗ wpantry: the alert wasn't recorded in the cache: {e}")));
        }
    };
    match fake {
        Some(file) => {
            let script = std::fs::read_to_string(&file)?;
            guard::run_script(&script, &settings, &mut on_alert);
        }
        None => {
            let cb =
                clipper::real().map_err(|why| wpantry::Error::Failed(format!("can't guard the clipboard: {why}")))?;
            eprintln!(
                "{}",
                Style::stderr().dim(&format!(
                    "guarding the clipboard: a read every {} ms, a swap is two addresses of one chain within {window} s (Ctrl-C stops)",
                    settings.interval.as_millis()
                ))
            );
            guard::run(
                &mut || Some(cb.read()),
                &mut std::time::Instant::now,
                &std::thread::sleep,
                &settings,
                &mut on_alert,
            );
        }
    }
    Ok(EXIT_OK)
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
    let net = wpantry::net::Http::new();
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
                (Some(_), _) => say("    Fix: run wpantry fix --dryrun for the step"),
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

/// `harden ca-trust`: distrust the leaked roots in the system trust store
/// (the shell script it replaced did the same), asking for sudo only to install
/// the result.
fn cmd_harden_ca_trust(bundle: Option<&std::path::Path>) -> Result<i32> {
    wpantry::catrust::fix(bundle, &|line| show(line))?;
    if bundle.is_none() {
        show("  Re-run wpantry scan to confirm. A macOS update may restore the file: re-run this after one.");
    }
    Ok(EXIT_OK)
}

/// `harden extension-cooldown`: the one posture fix that edits files.
fn cmd_harden_cooldown(hours: u32) -> Result<i32> {
    let changed = wpantry::posture::any::tools::set_extension_cooldown(hours)?;
    if changed.is_empty() {
        let editors = wpantry::posture::any::tools::editor_settings();
        if editors.is_empty() {
            show("  no VS Code-family editor is installed");
        } else {
            show(&format!("  every editor already waits {hours} hours"));
        }
    }
    for c in &changed {
        show(&format!("  ✓ {c}"));
    }
    show("  Extensions wait that long after a version is published before it installs here (restart the editor).");
    Ok(EXIT_OK)
}

/// `mitigate ID`: the last scan's findings for the advisory (by id or
/// alias), their unattended fixes run, wpantry's stopgap for it run where
/// one exists, and the steps that need a person printed. Exit 1 when a
/// step is left, a fix failed, or nothing is known for the id here.
fn cmd_mitigate(id: &str, dry_run: bool, yes: bool, no_input: bool, undo: bool) -> Result<i32> {
    use wpantry::mitigate::{self, Done, Mode};
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
    let findings: Vec<wpantry::check::Finding> = wpantry::export::findings(&cache)?
        .into_iter()
        .filter(|f| ids.iter().any(|i| i.eq_ignore_ascii_case(&f.vuln_id)))
        .collect();
    let stopgap = mitigate::stopgap(id);
    let interactive = !no_input && std::io::stdin().is_terminal();
    let bundled = wpantry::check::mitigation(id);
    show(&format!(
        "==> {id}: {}{}",
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
        let auto: Vec<wpantry::check::Finding> = findings.iter().filter(|f| f.fix_auto).cloned().collect();
        let applied = report::apply(&auto, dry_run, &confirm, &mut |l| show(l));
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
        match (s.run)(&mitigate::Real, mode, &confirm, &mut |l| show(l))? {
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
            show("  nothing to do here");
            cache.close()?;
            return Ok(EXIT_OK);
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
fn cmd_mitigate_list() -> Result<i32> {
    use wpantry::mitigate::{self, Done, Mode};
    show("==> Stopgaps wpantry can install (wpantry mitigate ID, or all):");
    for s in mitigate::STOPGAPS {
        let state = match (s.run)(&mitigate::Real, Mode::DryRun, &|_| false, &mut |_| {}) {
            Ok(Done::Applied) => format!("needed here: wpantry mitigate {} --dry-run shows the plan", s.id),
            Ok(Done::Nothing(why)) | Ok(Done::NotHere(why)) => why,
            Ok(Done::Declined) => "unreachable on a dry run".into(),
            Err(e) => format!("can't tell: {e}"),
        };
        show(&format!("  {}  {}\n      {state}", s.id, s.what));
    }
    let cache = Cache::open(None)?;
    let findings = wpantry::export::findings(&cache)?;
    cache.close()?;
    let mut auto: Vec<&wpantry::check::Finding> =
        findings.iter().filter(|f| f.fix_auto && !f.fix_cmd.is_empty()).collect();
    auto.sort_by(|a, b| a.vuln_id.cmp(&b.vuln_id).then(a.component.cmp(&b.component)));
    auto.dedup_by(|a, b| a.vuln_id == b.vuln_id && a.component == b.component);
    show("\n==> Advisories in the last scan with an unattended fix (wpantry fix runs them):");
    if auto.is_empty() {
        show("  none");
    }
    for f in auto {
        show(&format!(
            "  {}  {} {} → {}: {}",
            f.vuln_id,
            f.component,
            f.version,
            if f.fixed.is_empty() { "?".to_string() } else { f.fixed.clone() },
            f.fix_cmd
        ));
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
        Command::Scan(c) => cmd_scan(c),
        Command::Search { query, applicable, limit, json } => cmd_search(&query, applicable, limit, json),
        Command::Export { csv, jsonl, all } => cmd_export(csv.as_deref(), jsonl.as_deref(), all),
        Command::Breach { enable, disable } => cmd_breach(enable, disable),
        Command::Watch { json, offline } => cmd_watch(json, offline),
        Command::Version { json } => cmd_version(json),
        Command::Tools { json } => cmd_tools(json),
        Command::Skill => cmd_skill(),
        Command::Report { sections, since_days, format, out } => {
            cmd_report(&sections, since_days, &format, out.as_deref())
        }
        Command::Sync { refresh, json } => cmd_sync(refresh, json),
        Command::Schedule { action, every, at, dry_run, clipboard_guard } => {
            cmd_schedule(&action, &every, &at, dry_run, clipboard_guard)
        }
        Command::Cache { action: _, older_than } => cmd_cache_prune(older_than),
        Command::Clipboard { watch, once, window, json } => cmd_clipboard(watch, once, window, json),
        Command::Update { check, yes, no_input, offline, version } => {
            update::run(update::Update { check, yes, no_input, offline, version })
        }
        Command::Harden { what, hours, bundle } => {
            if what == "ca-trust" {
                cmd_harden_ca_trust(bundle.as_deref())
            } else {
                cmd_harden_cooldown(hours)
            }
        }
        Command::Mitigate { target, dry_run, yes, no_input, undo, offline, no_machine, path } => match target {
            Target::List => cmd_mitigate_list(),
            Target::All => cmd_scan(Check {
                fix: true,
                dryrun: dry_run,
                yes,
                no_input,
                offline,
                no_machine,
                path,
                ..Default::default()
            }),
            Target::Id(id) => cmd_mitigate(&id, dry_run, yes, no_input, undo),
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
            eprint!("{}", text.replace(": error: ", &format!(": {} ", Style::stderr().red("error:"))));
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
mod tests {
    use super::*;
    use wpantry::check::Finding;

    #[test]
    fn csv_fields_quote_only_what_needs_it() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field(""), "");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_field("cr\r"), "\"cr\r\"");
    }

    #[test]
    fn table_cells_keep_one_line_without_pipes() {
        assert_eq!(md("a|b"), "a\\|b");
        assert_eq!(md("two\nlines\tand\x1b[0m"), "two lines and [0m");
        assert_eq!(md("plain"), "plain");
    }

    #[test]
    fn numbers_round_and_sizes_read_in_mb() {
        assert_eq!(round3(1.23456), 1.235);
        assert_eq!(round3(-5.0004), -5.0);
        assert_eq!(mb(0), "0.0 MB");
        assert_eq!(mb(1_250_000), "1.2 MB");
        assert_eq!(mb(12_345_678), "12.3 MB");
    }

    #[test]
    fn the_envelope_carries_the_counts_and_findings() {
        let scan = Outcome {
            scan_id: 3,
            findings: vec![Finding { vuln_id: "CVE-2026-1".into(), status: "fail".into(), ..Default::default() }],
            counts: vec![("git repos".into(), 2), ("packages".into(), 0)],
            unfixed: 1,
            unknown_licenses: 4,
        };
        let env = wpantry::json::parse(envelope(&scan).dumps().as_bytes(), wpantry::json::MAX_DOCUMENT).unwrap();
        assert_eq!(env["schema"].as_i64(), Some(SCHEMA));
        assert_eq!(env["impl"].as_str(), Some(IMPL));
        assert_eq!(env["version"].as_str(), Some(VERSION));
        assert_eq!(env["checked"]["git repos"].as_i64(), Some(2));
        assert_eq!(env["checked"]["packages"].as_i64(), Some(0));
        assert_eq!(env["unfixed"].as_i64(), Some(1));
        assert_eq!(env["unknown_licenses"].as_i64(), Some(4));
        let findings = env["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["vuln_id"].as_str(), Some("CVE-2026-1"));
    }
}
