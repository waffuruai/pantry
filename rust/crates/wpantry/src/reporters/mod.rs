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
pub const EXPOSURE_COLUMNS: [(&str, &str); 13] = [
    ("first_seen", "First seen"),
    ("resolved", "Resolved"),
    ("severity", "Severity"),
    ("component", "Component"),
    ("version", "Version"),
    ("vuln_id", "Advisory"),
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
pub fn exposure_cells(e: &Exposure) -> [String; 13] {
    [
        history::stamp(e.first_at),
        e.resolved_at.map(history::stamp).unwrap_or_else(|| "open".into()),
        e.severity.clone(),
        e.component.clone(),
        e.version.clone(),
        e.vuln_id.clone(),
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

/// One scan, as every report renders it.
#[derive(Clone, Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub scan: ScanDetail,
    /// Whether this scan verified fixes `wpantry fix` ran: the HTML report
    /// says "after updates".
    pub after_fixes: bool,
    pub history: Option<History>,
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
    Ok(Some(Report { outcome, scan, after_fixes, history }))
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
pub fn render(cache: &Cache, report: &Report, format: Format) -> Result<String> {
    let with_history = report.history.is_some();
    Ok(match format {
        Format::Json => json::report(report).dumps_indent(1) + "\n",
        Format::Jsonl => jsonl::jsonl(cache, with_history)?.0,
        Format::Csv if with_history => {
            csv::exposures(report.history.as_ref().map(|h| h.exposures.as_slice()).unwrap_or_default())
        }
        Format::Csv => csv::findings(cache)?,
        Format::Md => md::report(report),
        Format::Html => html::page(report),
    })
}

/// A file a report is written to: staged beside it and renamed into place,
/// so an error leaves any earlier copy whole; never through a symlink at
/// the destination.
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
