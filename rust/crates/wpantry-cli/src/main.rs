//! wpantry: the vulnerabilities that apply to this computer. The CLI
//! contract is specs/cli-contract.md; this binary owns stdout, stderr and
//! exit codes, the library does the work.
//!
//! Exit codes: 0 clean (warnings and unchecked sources included), 1 a
//! failing finding or a failed unattended fix, 2 usage error, 3 internal
//! error.

mod args;
mod progress;
mod report;
mod style;

use args::{Check, Command, Parsed};
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

/// A line of data on stdout, never coloured (JSON, search results, the
/// skill).
fn say(line: &str) {
    println!("{line}");
}

/// A line of the report on stdout, coloured by its mark on a terminal.
fn show(line: &str) {
    println!("{}", Style::stdout().line(line));
}

/// `check --json`: the findings plus what was checked (schema 1).
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
    let status = |m: &str| progress.set(m);
    // The library's questions default to no (the breach check's consent).
    let ask = |q: &str| progress.ask(q, false);
    let out = Scan::new(opts, Cache::open(None)?, net, &log, &note).with_status(&status).with_ask(&ask).run();
    progress.finish();
    out
}

fn cmd_check(a: Check) -> Result<i32> {
    let net = wpantry::net::Http::new();
    let opts = Options {
        paths: a.path.clone(),
        machine: !a.no_machine,
        policy: Policy {
            gitleaks_config: a.gitleaks_config.clone(),
            licenses: a.licenses.clone(),
            install_scripts: a.install_scripts.clone(),
        },
        refresh: a.refresh,
        offline: a.offline,
        licenses: a.check_licenses,
        ask: !(a.json || a.dryrun || a.no_input),
    };
    let first = scan(opts.clone(), a.json, &net)?;
    if a.json {
        say(&envelope(&first).dumps_indent(1));
        return Ok(if first.findings.iter().any(|f| f.status == "fail") { EXIT_FAIL } else { EXIT_OK });
    }
    let db = db::path().to_string_lossy().into_owned();
    let status = report::report(&first, &db, &mut |l| show(l));
    if !(a.update || a.dryrun) {
        return Ok(status);
    }
    // Before changing anything, ask, when someone is there to answer.
    let interactive = !a.no_input && std::io::stdin().is_terminal();
    let confirm = |cmds: &[String]| {
        if !interactive {
            return true;
        }
        for c in cmds {
            show(&format!("  • {c}"));
        }
        let what = if cmds.len() == 1 { "this update".to_string() } else { format!("these {} updates", cmds.len()) };
        progress::Progress::new(false).ask(&format!("Run {what} now?"), true).unwrap_or(false)
    };
    let applied = report::apply(&first.findings, a.dryrun, &confirm, &mut |l| show(l));
    if a.dryrun {
        return Ok(status);
    }
    if !applied.ran.is_empty() {
        let cache = Cache::open(None)?;
        for (cmd, ok) in &applied.ran {
            wpantry::history::record_fix(&cache, Some(first.scan_id), cmd, "auto", *ok)?;
        }
        cache.close()?;
    }
    say("\nRe-checking after the updates…");
    let again = scan(Options { refresh: false, ask: false, ..opts }, false, &net)?;
    if !applied.ran.is_empty() {
        let cache = Cache::open(None)?;
        wpantry::history::verify_fixes(&cache, first.scan_id, again.scan_id)?;
        cache.close()?;
    }
    // A fix that failed fails the run even when the re-check comes back clean.
    let rechecked = report::report(&again, &db, &mut |l| show(l));
    Ok(if rechecked != 0 { rechecked } else { applied.status })
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
        say(&J::Arr(items).dumps_indent(1));
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

fn cmd_export(path: &str) -> Result<i32> {
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
    say(&format!("breach check: {}", v.as_deref().unwrap_or("not decided (asked on the next interactive check)")));
    Ok(EXIT_OK)
}

fn cmd_version(json: bool) -> Result<i32> {
    if json {
        say(&obj([("version", VERSION.into()), ("impl", IMPL.into()), ("schema", J::Int(SCHEMA))]).dumps());
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
        say(&env.dumps_indent(1));
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
                t.push_str("\n## Audit log\n\n### Scans\n\n| # | Finished | Host | User | wpantry | Scope | Fails | Warns |\n|---|---|---|---|---|---|---|---|\n");
                for s in &scans {
                    t.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                        s.id,
                        stamp(s.finished_at),
                        md(&s.host),
                        md(&s.user),
                        s.version,
                        md(&s.scope),
                        s.fails,
                        s.warns
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

fn cmd_skill() -> Result<i32> {
    let mut out = std::io::stdout().lock();
    out.write_all(wpantry::SKILL.as_bytes())?;
    out.flush()?;
    Ok(EXIT_OK)
}

fn dispatch(cmd: Command) -> Result<i32> {
    match cmd {
        Command::Check(c) => cmd_check(c),
        Command::Search { query, applicable, limit, json } => cmd_search(&query, applicable, limit, json),
        Command::Export { csv } => cmd_export(&csv),
        Command::Breach { enable, disable } => cmd_breach(enable, disable),
        Command::Version { json } => cmd_version(json),
        Command::Tools { json } => cmd_tools(json),
        Command::Skill => cmd_skill(),
        Command::Report { sections, since_days, format, out } => {
            cmd_report(&sections, since_days, &format, out.as_deref())
        }
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
