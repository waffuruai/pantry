//! How a scan is shown, always from what the cache keeps of it: `wpantry
//! report` reads the latest scan ([`latest`]) and renders it, and `scan` and
//! `fix` do the same when they finish. One grouping serves every report
//! ([`view`]: areas, rows, the fix batches). The formats here are the ones
//! another program or a file reads: JSON (the contract's envelope), JSON
//! Lines, CSV, Markdown, HTML, and YARA for `rules gen`. The terminal's is
//! the CLI's own, drawn from [`view`] with its colours and table widths.

pub mod csv;
pub mod html;
pub mod json;
pub mod jsonl;
pub mod md;
pub mod summary;
pub mod view;
pub mod yara;

use crate::checks::Outcome;
use crate::db::{Cache, DAY};
use crate::error::Result;
use crate::history::{self, Event, Exposure, Fix, ScanDetail, ScanRow};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// How far back the history goes unless `--since DAYS` says otherwise: two
/// weeks, a sprint's worth of exposure and remediation.
pub const HISTORY_DAYS: i64 = 14;

/// The exposure log's columns, in the order every format shows them: when
/// it was first seen, whether (and when) it was resolved, how bad it is,
/// what it is; then the rest. `(CSV name, heading)`.
pub const EXPOSURE_COLUMNS: [(&str, &str); 15] = [
    ("first_seen", "First seen"),
    ("resolved", "Resolved"),
    ("severity", "Severity"),
    ("component", "Component"),
    ("version", "Version"),
    ("vuln_id", "Advisory"),
    ("cvss", "CVSS"),
    ("epss", "EPSS"),
    ("kev", "KEV"),
    ("status", "Status"),
    ("fixed", "Fixed in"),
    ("days_exposed", "Days exposed"),
    ("last_seen", "Last seen"),
    ("kind", "Kind"),
    ("location", "Location"),
];

/// One exposure's cells, in [`EXPOSURE_COLUMNS`] order: "open" until it is
/// resolved.
pub fn exposure_cells(e: &Exposure) -> [String; 15] {
    [
        history::stamp(e.first_at),
        e.resolved_at.map(history::stamp).unwrap_or_else(|| "open".into()),
        crate::utils::cvss::word(&e.severity).to_string(),
        e.component.clone(),
        e.version.clone(),
        e.vuln_id.clone(),
        e.cvss
            .map(
                |c| if e.cvss_version.is_empty() { format!("{c:.1}") } else { format!("{c:.1} (v{})", e.cvss_version) },
            )
            .unwrap_or_default(),
        view::epss_text(e.epss.map(|s| (s, e.epss_percentile.unwrap_or(0.0)))),
        if e.kev { "yes" } else { "no" }.into(),
        e.status.clone(),
        e.fixed.clone(),
        e.days_exposed.to_string(),
        history::stamp(e.last_at),
        e.kind.clone(),
        e.location.clone(),
    ]
}

/// The logs kept across scans, for `--history`.
#[derive(Clone, Debug, Default)]
pub struct History {
    pub since_days: i64,
    pub exposures: Vec<Exposure>,
    pub fixes: Vec<Fix>,
    pub scans: Vec<ScanRow>,
    pub events: Vec<Event>,
}

/// What a report covers: `wpantry report [WHAT]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Part {
    /// The latest scan's findings.
    #[default]
    Findings,
    /// The exposure, remediation and audit logs, without the findings.
    History,
    Exposure,
    Remediation,
    Audit,
    /// One page for a CSO, an auditor or an insurer.
    Summary,
    /// The findings, then every log.
    All,
}

impl Part {
    pub const NAMES: [&'static str; 7] = ["findings", "history", "exposure", "remediation", "audit", "summary", "all"];

    pub fn parse(s: &str) -> Option<Part> {
        Some(match s {
            "findings" => Part::Findings,
            "history" => Part::History,
            "exposure" => Part::Exposure,
            "remediation" => Part::Remediation,
            "audit" => Part::Audit,
            "summary" => Part::Summary,
            "all" => Part::All,
            _ => return None,
        })
    }

    pub fn findings(self) -> bool {
        matches!(self, Part::Findings | Part::All)
    }

    pub fn exposure(self) -> bool {
        matches!(self, Part::History | Part::Exposure | Part::All)
    }

    pub fn remediation(self) -> bool {
        matches!(self, Part::History | Part::Remediation | Part::All)
    }

    pub fn audit(self) -> bool {
        matches!(self, Part::History | Part::Audit | Part::All)
    }

    /// Whether it needs the logs kept across scans.
    pub fn logs(self) -> bool {
        self != Part::Findings
    }
}

/// One scan, as every report renders it.
#[derive(Clone, Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub scan: ScanDetail,
    /// Whether this scan verified fixes `wpantry fix` ran: the HTML report
    /// says "after updates".
    pub after_fixes: bool,
    pub history: Option<History>,
    /// What to show of it; [`Part::Findings`] unless set.
    pub part: Part,
}

impl Report {
    /// What part of a run this scan was, as the HTML report titles it.
    pub fn phase(&self) -> &'static str {
        if self.after_fixes { "after updates" } else { "scan" }
    }

    /// 1 when something fails, as `scan` exits.
    pub fn status(&self) -> i32 {
        i32::from(self.outcome.findings.iter().any(|f| f.status == "fail"))
    }
}

/// The logs of the last `days` days.
pub fn history(cache: &Cache, days: i64) -> Result<History> {
    let since = crate::utils::os::now() - days as f64 * DAY;
    Ok(History {
        since_days: days,
        exposures: history::exposures(cache, since)?,
        fixes: history::fixes(cache, since)?,
        scans: history::scans(cache, since)?,
        events: history::events(cache, since)?,
    })
}

/// The latest scan the cache recorded, with the logs of the last
/// `history_days` days when asked; `None` before the first scan.
pub fn latest(cache: &Cache, history_days: Option<i64>) -> Result<Option<Report>> {
    let Some(id) = history::latest_scan(cache)? else { return Ok(None) };
    let Some(scan) = history::scan_detail(cache, id)? else { return Ok(None) };
    let outcome = Outcome {
        scan_id: id,
        findings: jsonl::findings(cache)?,
        counts: scan.counts.clone(),
        unfixed: scan.unfixed,
        unknown_licenses: scan.unknown_licenses,
    };
    let after_fixes = history::fixes(cache, f64::MIN)?.iter().any(|f| f.verified_scan == Some(id));
    let history = history_days.map(|d| history(cache, d)).transpose()?;
    Ok(Some(Report { outcome, scan, after_fixes, history, part: Part::Findings }))
}

/// The logs alone, before any scan: what `report history` (or one log)
/// shows when the cache has fixes or events but no scan yet.
pub fn logs_only(cache: &Cache, days: i64) -> Result<Report> {
    Ok(Report {
        outcome: Outcome::default(),
        scan: ScanDetail::default(),
        after_fixes: false,
        history: Some(history(cache, days)?),
        part: Part::History,
    })
}

/// A format another program or a file reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Jsonl,
    Csv,
    Md,
    Html,
}

/// `report` in `format`. JSON Lines and CSV join what the cache knows of
/// each finding (its OSV record, aliases and lifecycle), so they read it.
///
/// CSV is one table: the findings (`findings`, `all`), the exposure log
/// (`history`, `exposure`), the fix log, the scan log, or the summary's
/// figures. JSON Lines is one object per row of the same. The HTML page is
/// the scan's page, its history included, whatever the part.
pub fn render(cache: &Cache, report: &Report, format: Format) -> Result<String> {
    let empty = History::default();
    let h = report.history.as_ref().unwrap_or(&empty);
    let lines = |rows: Vec<serde_json::Value>| rows.iter().map(|r| format!("{r}\n")).collect::<String>();
    Ok(match (format, report.part) {
        (Format::Json, _) => json::report(report).dumps_indent(1) + "\n",
        (Format::Jsonl, Part::Findings) => jsonl::jsonl(cache, false)?.0,
        (Format::Jsonl, Part::All | Part::History | Part::Exposure) => jsonl::jsonl(cache, true)?.0,
        (Format::Jsonl, Part::Remediation) => lines(h.fixes.iter().map(Fix::to_json).collect()),
        (Format::Jsonl, Part::Audit) => lines(h.scans.iter().map(ScanRow::to_json).collect()),
        (Format::Jsonl, Part::Summary) => summary::json(&summary::summary(report)).dumps() + "\n",
        (Format::Csv, Part::Findings | Part::All) => csv::findings(cache)?,
        (Format::Csv, Part::History | Part::Exposure) => csv::exposures(&h.exposures),
        (Format::Csv, Part::Remediation) => csv::fixes(&h.fixes),
        (Format::Csv, Part::Audit) => csv::scans(&h.scans),
        (Format::Csv, Part::Summary) => csv::summary(report),
        (Format::Md, _) => md::report(report),
        (Format::Html, _) => html::page(report),
    })
}

/// The reports Pantry wrote, by SHA-256: one saved in a scanned folder is
/// never a malware finding, though it names the hosts and rules it found.
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS reports_written (sha256 TEXT PRIMARY KEY, at REAL);";

/// How many written reports are remembered.
const REMEMBERED: i64 = 1000;

/// Remember `text` as a report Pantry wrote.
pub fn remember(cache: &Cache, text: &str) -> Result<()> {
    let sha = crate::utils::sha256::hex(text.as_bytes());
    cache.conn.execute(
        "INSERT OR REPLACE INTO reports_written (sha256, at) VALUES (?, ?)",
        rusqlite::params![sha, crate::utils::os::now()],
    )?;
    cache.conn.execute(
        "DELETE FROM reports_written WHERE sha256 NOT IN (SELECT sha256 FROM reports_written ORDER BY at DESC LIMIT ?)",
        [REMEMBERED],
    )?;
    Ok(())
}

/// The SHA-256 of every report Pantry remembers writing.
pub fn written(cache: &Cache) -> Result<std::collections::HashSet<String>> {
    let mut stmt = cache.conn.prepare("SELECT sha256 FROM reports_written")?;
    let out = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(out)
}

/// A file a report is written to: staged beside it and renamed into place,
/// so an error leaves any earlier copy whole; never through a symlink at
/// the destination.
/// The file a report is written to when no `-o` names one: in the current
/// directory, `pantry_report_<when>.<ext>` (`pantry_report_20261105T143000Z.html`).
pub fn file_name(ext: &str, t: f64) -> String {
    format!("pantry_report_{}.{ext}", history::file_stamp(t))
}

pub struct Output {
    destination: PathBuf,
    staging: PathBuf,
    file: File,
}

impl Output {
    pub fn new(destination: &Path) -> io::Result<Self> {
        if destination.is_dir() {
            return Err(io::Error::other("the report must be written to a file, not a directory"));
        }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let staging = parent.join(format!(".wpantry-report-{}-{nonce}.tmp", std::process::id()));
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let file = open
            .open(&staging)
            .map_err(|e| io::Error::new(e.kind(), format!("report output {}: {e}", destination.display())))?;
        Ok(Self { destination: destination.to_path_buf(), staging, file })
    }

    /// Write `text` and move it into place.
    pub fn write(mut self, text: &str) -> io::Result<()> {
        self.file.write_all(text.as_bytes())?;
        self.file.flush()?;
        std::fs::rename(&self.staging, &self.destination)
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.staging);
    }
}

#[cfg(test)]
mod tests;
