//! Scans a person starts: Scan now, Retry, Scan with saved data, and
//! scanning an earlier scan's folder again, plus dismissing an earlier
//! scan's problem.

use super::{App, Event, JobKind};
use crate::pantry::{Result, ScanRequest};
use eframe::egui;

impl App {
    /// Scan now: one folder (`path`) or the whole machine.
    pub(super) fn scan(
        &mut self,
        path: Option<String>,
        offline: bool,
        include_personal_files: Option<bool>,
        ctx: &egui::Context,
    ) -> Result<()> {
        let include = include_personal_files.unwrap_or(self.state.include_personal_files);
        let request = ScanRequest {
            machine: path.is_none(),
            paths: path.into_iter().collect(),
            include_personal_files: include,
            offline,
        };
        self.start_scan(request, "Scanning…", ctx)?;
        self.last_offline = offline;
        if !self.state.settings.personal_files_asked {
            self.state.settings.personal_files_asked = true;
            self.save_settings();
        }
        self.state.pending_fix = None;
        self.state.last_fix_output = None;
        self.state.fix_result = None;
        Ok(())
    }

    /// Scan the latest report's scope again, for checks that did not finish.
    pub(super) fn retry(&mut self, ctx: &egui::Context) -> Result<()> {
        let request = self
            .state
            .report
            .as_ref()
            .and_then(|r| self.rescan_request(&r.scan.scope))
            .ok_or("Pantry cannot repeat this scan. Choose Scan now.")?;
        self.start_scan(request, "Checking again…", ctx)?;
        self.state.fix_result = None;
        Ok(())
    }

    /// Repeat the last scan started here with saved data only. A machine
    /// scan when none was started.
    pub(super) fn retry_offline(&mut self, ctx: &egui::Context) -> Result<()> {
        let mut request = self.last_request.clone().unwrap_or(ScanRequest {
            machine: true,
            paths: Vec::new(),
            include_personal_files: self.state.include_personal_files,
            offline: true,
        });
        request.offline = true;
        self.start_scan(request, "Scanning with saved data…", ctx)?;
        self.last_offline = true;
        self.state.pending_fix = None;
        self.state.fix_result = None;
        Ok(())
    }

    /// Scan again the folder an earlier scan found this problem in.
    pub(super) fn rescan_earlier(&mut self, id: &str, ctx: &egui::Context) -> Result<()> {
        let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
        let exposure = report
            .earlier_all()
            .into_iter()
            .find(|entry| entry.finding.id == id)
            .ok_or("This problem is no longer in the results.")?;
        if !crate::pantry::missing_folders(&exposure.scope).is_empty() {
            return Err(
                "That folder is no longer there. Choose Dismiss to hide this problem.".into(),
            );
        }
        let request = self
            .rescan_request(&exposure.scope)
            .ok_or("Pantry cannot repeat that scan. Choose Scan now.")?;
        self.start_scan(request, "Scanning…", ctx)?;
        self.state.pending_fix = None;
        self.state.fix_result = None;
        Ok(())
    }

    /// Hide a problem from an earlier scan (reversible).
    pub(super) fn dismiss_earlier(&mut self, id: String) -> Result<()> {
        let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
        if !report.earlier_all().iter().any(|e| e.finding.id == id) {
            return Err("This problem is no longer in the results.".into());
        }
        if self.state.selected.as_deref() == Some(&format!("earlier-{id}")) {
            self.state.selected = None;
        }
        if !self.state.settings.dismissed.contains(&id) {
            self.state.settings.dismissed.push(id);
        }
        self.save_settings();
        self.state.status = "Dismissed. Show it again from Latest scan.".into();
        Ok(())
    }

    /// A scan of `scope` again, as a person would start it now: the
    /// personal folders choice made since applies to a machine scan.
    fn rescan_request(&self, scope: &str) -> Option<ScanRequest> {
        let mut request = ScanRequest::for_scope(scope, self.last_offline)?;
        request.include_personal_files = request.machine && self.state.include_personal_files;
        Some(request)
    }

    /// The scan that checks a fix: the latest report's scope, as it ran.
    pub(super) fn check_request(&self) -> Option<ScanRequest> {
        self.state
            .report
            .as_ref()
            .and_then(|report| ScanRequest::for_scope(&report.scan.scope, self.last_offline))
    }

    /// Start a scan a person asked for, and remember it for
    /// [`Action::RetryOffline`](super::Action::RetryOffline).
    fn start_scan(
        &mut self,
        request: ScanRequest,
        label: &'static str,
        ctx: &egui::Context,
    ) -> Result<()> {
        let remembered = request.clone();
        self.start(JobKind::Scan, label, ctx, move |pantry| {
            let result = pantry.scan(&request);
            Event::Scan(result, pantry.reload())
        })?;
        self.last_request = Some(remembered);
        Ok(())
    }
}
