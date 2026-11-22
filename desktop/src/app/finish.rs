//! What happens when a task ends: its result lands in the window's state.

use super::{
    App, Batch, BatchItem, BatchStage, BatchStatus, Event, FixResult, Outcome, Page, PendingFix,
    ReportResult,
};
use crate::data::{self, Schedule};
use crate::pantry::{Problem, ProblemKind, Result};
use std::sync::mpsc;

impl App {
    pub(super) fn finish(&mut self, result: std::result::Result<Event, mpsc::TryRecvError>) {
        let event = match result {
            Ok(event) => event,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.job = None;
                self.state.error = Some(Problem::from_scanner(
                    "The Pantry task stopped unexpectedly.",
                ));
                return;
            }
        };
        self.job = None;
        self.cache_seen = data::cache_stamp(&self.cache);
        match event {
            Event::Refresh {
                report,
                schedule,
                version,
            } => {
                // Whatever this scanner says now, or nothing: never a
                // version it no longer reports.
                self.state.scanner_version = version;
                self.set_report(report);
                self.set_schedule(schedule);
            }
            Event::Scan(result, report) => {
                if result.is_ok() {
                    self.state.page = Page::Attention;
                    self.state.selected = None;
                    self.state.search.clear();
                }
                if let Err(error) = &result {
                    self.state.error = Some(Problem::for_scan(error));
                } else {
                    self.message(result);
                }
                self.set_report(report);
            }
            Event::Schedule(result, schedule) => {
                if result.is_ok() {
                    self.state.editing_schedule = false;
                }
                self.message(result);
                self.set_schedule(schedule);
            }
            Event::Preview(result, id, scan) => match result {
                Ok(command) if self.state.selected.as_deref() == Some(&id) => {
                    self.state.pending_fix = Some(PendingFix { id, scan, command });
                }
                Ok(_) => {}
                Err(error) => self.state.error = Some(Problem::from_scanner(&error)),
            },
            Event::Apply {
                result,
                verify,
                report,
                key,
                component,
            } => {
                // Without a fresh report the old one still lists the
                // problem, which would read as "Still open".
                let reloaded = matches!(report, Ok(Some(_)));
                self.set_report(report);
                match result {
                    Ok(output) => {
                        self.state.last_fix_output = Some(output);
                        let outcome = match verify {
                            None => (
                                Outcome::Unconfirmed,
                                "The fix ran. Choose Scan now to check that it worked.".to_owned(),
                            ),
                            Some(Err(error)) => {
                                self.state.error = Some(Problem::for_scan(&error));
                                (
                                    Outcome::Unconfirmed,
                                    "The fix ran, but Pantry could not check it. Choose Scan now to try again.".to_owned(),
                                )
                            }
                            Some(Ok(_)) if !reloaded => (
                                Outcome::Unconfirmed,
                                "Could not confirm. Scan again.".to_owned(),
                            ),
                            Some(Ok(_)) => self.outcome(&key, &component),
                        };
                        // The banner card tells the outcome; no status line
                        // repeats it.
                        self.state.fix_result = Some(FixResult {
                            component,
                            outcome: outcome.0,
                            message: outcome.1,
                        });
                    }
                    Err(error) => self.state.error = Some(Problem::for_fix(&error)),
                }
            }
            Event::BatchReady(previews, scan) => {
                let report = self.state.report.as_ref();
                let items = previews
                    .into_iter()
                    .map(|(id, preview)| {
                        let finding = report.and_then(|r| r.findings.iter().find(|f| f.id == id));
                        let (status, command, message, details) = match preview {
                            Ok(command) => {
                                (BatchStatus::Waiting, command, String::new(), String::new())
                            }
                            Err(error) => {
                                let problem = Problem::from_scanner(&error);
                                (
                                    BatchStatus::NotReady,
                                    String::new(),
                                    problem.summary,
                                    problem.details,
                                )
                            }
                        };
                        BatchItem {
                            key: finding.map(|f| f.key_string()).unwrap_or_default(),
                            component: finding.map(|f| f.component.clone()).unwrap_or_default(),
                            id,
                            command,
                            status,
                            message,
                            details,
                            show_details: false,
                        }
                    })
                    .collect();
                self.state.batch = Some(Batch {
                    scan,
                    stage: BatchStage::Confirm,
                    items,
                    message: String::new(),
                });
            }
            Event::BatchStep(..) => {}
            Event::BatchDone { verify, report } => {
                let reloaded = matches!(report, Ok(Some(_)));
                self.set_report(report);
                let checked = match verify {
                    Some(Ok(_)) => true,
                    Some(Err(error)) => {
                        self.state.error = Some(Problem::for_scan(&error));
                        false
                    }
                    None => false,
                };
                let open: Vec<String> = self
                    .state
                    .report
                    .as_ref()
                    .map(|r| r.findings.iter().map(|f| f.key_string()).collect())
                    .unwrap_or_default();
                let complete = self.state.report.as_ref().is_some_and(|r| r.gaps() == 0);
                if let Some(batch) = self.state.batch.as_mut() {
                    batch.stage = BatchStage::Done;
                    for item in batch
                        .items
                        .iter_mut()
                        .filter(|i| i.status == BatchStatus::Ran)
                    {
                        (item.status, item.message) = if !checked {
                            (BatchStatus::Unconfirmed, "Ran. Not checked yet.".into())
                        } else if !reloaded {
                            (
                                BatchStatus::Unconfirmed,
                                "Could not confirm. Scan again.".into(),
                            )
                        } else if open.contains(&item.key) {
                            (BatchStatus::StillOpen, "Still open.".into())
                        } else if complete {
                            (BatchStatus::Fixed, "Fixed and checked.".into())
                        } else {
                            (
                                BatchStatus::Unconfirmed,
                                "Ran. Some checks did not finish, so Pantry could not confirm it."
                                    .into(),
                            )
                        };
                    }
                    let fixed = batch
                        .items
                        .iter()
                        .filter(|i| i.status == BatchStatus::Fixed)
                        .count() as i64;
                    let total = batch.items.len() as i64;
                    // Shown once, in the Fix all card, not again as the status.
                    batch.message = format!("{fixed} of {total} fixed and checked.");
                }
            }
            Event::Update(result) => match result {
                Ok(update) => {
                    self.state.scanner_version = Some(update.current.clone());
                    if !update.matches_app() {
                        self.state.error = Some(Problem::version_mismatch(&update.current));
                    }
                    self.state.update = Some(update);
                }
                Err(error) => {
                    self.state.error = Some(Problem::for_update(&error));
                    // The answer shown is now an old one.
                    if let Some(update) = self.state.update.as_mut() {
                        update.stale = true;
                    }
                }
            },
        }
    }

    /// Whether the check after a fix cleared the finding.
    fn outcome(&self, key: &str, component: &str) -> (Outcome, String) {
        let Some(report) = &self.state.report else {
            return (
                Outcome::Unconfirmed,
                "The fix ran. Choose Scan now to check that it worked.".into(),
            );
        };
        let name = if component.is_empty() {
            "This item"
        } else {
            component
        };
        // The new scan's own findings: an incomplete scan leaves older
        // history rows open, which says nothing about this fix.
        if report.findings.iter().any(|f| f.key_string() == key) {
            return (
                Outcome::StillOpen,
                format!(
                    "Still open. The fix ran, but {name} still has this problem. Follow the steps to fix it by hand."
                ),
            );
        }
        let verified = report.history.fixes.iter().any(|fix| {
            fix.ok
                && fix.verified_scan == Some(report.scan.id)
                && fix.targets.iter().any(|target| target == key)
        });
        if verified || report.gaps() == 0 {
            (
                Outcome::Fixed,
                format!("Fixed and checked. {name} no longer has this problem."),
            )
        } else {
            (
                Outcome::Unconfirmed,
                "The fix ran, but some checks did not finish, so Pantry could not confirm it yet. Scan again later.".into(),
            )
        }
    }

    fn message(&mut self, result: Result<String>) {
        match result {
            Ok(message) => self.state.status = message,
            Err(error) => self.state.error = Some(Problem::from_scanner(&error)),
        }
    }

    fn set_report(&mut self, result: ReportResult) {
        self.state.report_error = match result {
            Ok(report) => {
                let same_scan = report.as_ref().map(|r| r.scan.id)
                    == self.state.report.as_ref().map(|r| r.scan.id);
                self.state.report = report;
                if !same_scan {
                    // Both were checked against the old scan.
                    self.state.pending_fix = None;
                    if self
                        .state
                        .batch
                        .as_ref()
                        .is_some_and(|b| b.stage == BatchStage::Confirm)
                    {
                        self.state.batch = None;
                    }
                }
                if self.selected().is_none()
                    || (!same_scan
                        && self
                            .state
                            .selected
                            .as_deref()
                            .is_some_and(|id| id.starts_with("earlier-")))
                {
                    self.state.selected = None;
                }
                None
            }
            Err(error) => {
                let problem = Problem::from_scanner(&error);
                // A reload stopped by Cancel is no fault of the results:
                // keep what was there.
                if problem.kind == ProblemKind::Cancelled {
                    return;
                }
                Some(problem)
            }
        };
    }

    fn set_schedule(&mut self, result: Result<Schedule>) {
        self.state.schedule_error = match result {
            Ok(schedule) => {
                self.state.schedule = Some(schedule);
                None
            }
            Err(error) => Some(Problem::from_scanner(&error)),
        };
    }
}
