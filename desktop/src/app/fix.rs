//! Fix it and Fix all: get the scanner's exact command for one confirm,
//! run it, then scan the same scope again to check it worked.

use super::{App, BatchStage, BatchStatus, Event, JobKind};
use crate::pantry::{Problem, ProblemKind, Result};
use eframe::egui;
use std::sync::mpsc;

impl App {
    /// Fix it: ask the scanner for the exact command, shown before it runs.
    pub(super) fn preview_fix(&mut self, ctx: &egui::Context) -> Result<()> {
        self.fixes_allowed()?;
        if !self.can_fix_selected() {
            return Err("Pantry can't run this fix. Follow the steps instead.".into());
        }
        let id = self
            .state
            .selected
            .clone()
            .ok_or("Choose a finding first.")?;
        let scan = self
            .state
            .report
            .as_ref()
            .ok_or("Run a scan first.")?
            .scan
            .id;
        self.start(
            JobKind::Short,
            "Getting the fix ready…",
            ctx,
            move |pantry| Event::Preview(pantry.preview_fix(scan, &id), id, scan),
        )?;
        self.state.fix_result = None;
        Ok(())
    }

    /// Yes, fix it: run the previewed fix, then check it.
    pub(super) fn confirm_fix(&mut self, ctx: &egui::Context) -> Result<()> {
        let pending = self
            .state
            .pending_fix
            .as_ref()
            .ok_or("Choose Fix it first.")?;
        let (id, scan) = (pending.id.clone(), pending.scan);
        let finding = self.selected().ok_or("Choose a finding first.")?;
        let (key, component) = (finding.key_string(), finding.component.clone());
        let check = self.check_request();
        self.start(JobKind::Fix, "Fixing…", ctx, move |pantry| {
            let result = pantry.fix(scan, &id);
            let verify = match (&result, check) {
                (Ok(_), Some(request)) => {
                    pantry.task().set_stage("Checking the fix…");
                    Some(pantry.scan(&request))
                }
                _ => None,
            };
            Event::Apply {
                result,
                verify,
                report: pantry.reload(),
                key,
                component,
            }
        })?;
        self.state.pending_fix = None;
        Ok(())
    }

    /// Get every fix Pantry can run ready, for one confirm.
    pub(super) fn fix_all(&mut self, ctx: &egui::Context) -> Result<()> {
        self.fixes_allowed()?;
        let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
        let ids = report.fixable();
        if ids.is_empty() {
            return Err("Pantry has no fixes it can run for these results.".into());
        }
        let scan = report.scan.id;
        self.start(
            JobKind::Short,
            "Getting the fixes ready…",
            ctx,
            move |pantry| {
                let previews = ids
                    .into_iter()
                    .map(|id| {
                        let preview = pantry.preview_fix(scan, &id);
                        (id, preview)
                    })
                    .collect();
                Event::BatchReady(previews, scan)
            },
        )?;
        self.state.fix_result = None;
        Ok(())
    }

    /// Run the confirmed batch one fix at a time, reporting each, then one
    /// check scan.
    pub(super) fn confirm_fix_all(&mut self, ctx: &egui::Context) -> Result<()> {
        let batch = self
            .state
            .batch
            .as_mut()
            .filter(|b| b.stage == BatchStage::Confirm)
            .ok_or("Choose Fix all first.")?;
        let scan = batch.scan;
        let work: Vec<(usize, String)> = batch
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.status == BatchStatus::Waiting)
            .map(|(i, item)| (i, item.id.clone()))
            .collect();
        if work.is_empty() {
            return Err("None of these fixes could be prepared.".into());
        }
        let check = self.check_request();
        let (send, receive) = mpsc::channel();
        let progress = send.clone();
        self.start_with(
            JobKind::Fix,
            "Fixing…",
            ctx,
            (send, receive),
            move |pantry| {
                let step = |index, status, message, details| {
                    let _ = progress.send(Event::BatchStep(index, status, message, details));
                };
                let mut any = false;
                for (index, id) in work {
                    if pantry.task().cancelled() {
                        step(
                            index,
                            BatchStatus::Skipped,
                            "Not run: you cancelled.".into(),
                            String::new(),
                        );
                        continue;
                    }
                    step(index, BatchStatus::Running, String::new(), String::new());
                    match pantry.fix(scan, &id) {
                        Ok(_) => {
                            any = true;
                            step(index, BatchStatus::Ran, String::new(), String::new());
                        }
                        Err(error) => {
                            let problem = Problem::for_fix(&error);
                            // Stopped part way is not "Skipped": it may have
                            // changed something.
                            let status = if problem.kind == ProblemKind::FixStopped {
                                BatchStatus::Stopped
                            } else {
                                BatchStatus::Failed
                            };
                            step(index, status, problem.summary, problem.details);
                        }
                    }
                }
                let verify = match check {
                    Some(request) if any && !pantry.task().cancelled() => {
                        pantry.task().set_stage("Checking the fixes…");
                        Some(pantry.scan(&request))
                    }
                    _ => None,
                };
                Event::BatchDone {
                    verify,
                    report: pantry.reload(),
                }
            },
        )?;
        if let Some(batch) = self.state.batch.as_mut() {
            batch.stage = BatchStage::Running;
        }
        Ok(())
    }

    /// Close the Fix all card, unless its fixes are running (`running`
    /// says what to do instead).
    pub(super) fn close_batch(&mut self, running: &str) -> Result<()> {
        if self
            .state
            .batch
            .as_ref()
            .is_some_and(|b| b.stage == BatchStage::Running)
        {
            return Err(running.into());
        }
        self.state.batch = None;
        Ok(())
    }

    /// A fix needs results Pantry could read.
    fn fixes_allowed(&self) -> Result<()> {
        if self.state.report_error.is_some() {
            return Err("Reload results before running a fix.".into());
        }
        Ok(())
    }
}
