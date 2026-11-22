//! The window's state and the typed action dispatcher. The egui view and
//! the `--automation` driver both go through [`App::dispatch`].

use crate::data::{self, Finding, Fix, Period, Report, Schedule, Update};
use crate::pantry::{Pantry, Problem, ProblemKind, Result, ScanRequest, Task};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

mod action;
mod dispatch;
mod finish;
mod fix;
mod scan;
mod settings;
mod state;
mod updates;

pub use action::Action;
pub use settings::Settings;
pub use state::{
    Batch, BatchItem, BatchStage, BatchStatus, Filter, FixResult, Outcome, Page, PendingFix, State,
    ThemeChoice,
};

/// Where people can download Pantry again.
pub const DOWNLOAD_URL: &str = "https://github.com/waffuruai/pantry/releases/latest";
/// How often the window looks for results written by a scheduled scan.
const WATCH_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq)]
enum JobKind {
    Scan,
    Fix,
    Short,
}

struct Job {
    kind: JobKind,
    label: &'static str,
    started: Instant,
    task: Task,
    receive: Receiver<Event>,
}

pub struct App {
    pantry: Pantry,
    pub state: State,
    job: Option<Job>,
    settings_path: Option<PathBuf>,
    /// True under `--automation`: links and system settings are reported to
    /// the driver instead of being opened.
    automation: bool,
    cache: PathBuf,
    cache_seen: Option<SystemTime>,
    last_watch: Instant,
    /// Offline mode of the last scan started here, reused by the check
    /// that follows a fix.
    last_offline: bool,
    /// The last scan a person started here, so "Scan with saved data"
    /// repeats the scan that failed, not a different one.
    last_request: Option<ScanRequest>,
}

type ReportResult = Result<Option<Report>>;

enum Event {
    /// A reload: the report, the schedule and the scanner's version.
    Refresh {
        report: ReportResult,
        schedule: Result<Schedule>,
        version: Option<String>,
    },
    Scan(Result<String>, ReportResult),
    Schedule(Result<String>, Result<Schedule>),
    Preview(Result<String>, String, i64),
    Apply {
        result: Result<String>,
        verify: Option<Result<String>>,
        report: ReportResult,
        key: String,
        component: String,
    },
    Update(Result<Update>),
    BatchReady(Vec<(String, Result<String>)>, i64),
    /// Progress inside a running batch (index, status, message, raw
    /// details); the job keeps running.
    BatchStep(usize, BatchStatus, String, String),
    BatchDone {
        verify: Option<Result<String>>,
        report: ReportResult,
    },
}

/// The palette to draw: the one someone picked, else the system's.
fn light_or_system(picked: Option<bool>, ctx: &egui::Context) -> bool {
    picked.unwrap_or(ctx.system_theme() == Some(egui::Theme::Light))
}

impl App {
    pub fn new(
        pantry: Pantry,
        ctx: &egui::Context,
        settings_path: Option<PathBuf>,
        automation: bool,
    ) -> Self {
        let settings = settings_path
            .as_deref()
            .map(Settings::load)
            .unwrap_or_default();
        let light = light_or_system(settings.light, ctx);
        let cache = data::cache_path();
        let mut app = Self {
            state: State {
                page: settings.page,
                search: String::new(),
                filter: Filter::All,
                selected: None,
                report: None,
                report_error: None,
                schedule: None,
                schedule_error: None,
                editing_schedule: false,
                period: Period::Day,
                at: "09:30".into(),
                light,
                details: settings.details,
                include_personal_files: settings.include_personal_files,
                status: String::new(),
                error: None,
                show_error_details: false,
                pending_fix: None,
                show_fix_details: false,
                last_fix_output: None,
                fix_result: None,
                batch: None,
                show_lower: false,
                update: None,
                scanner_version: None,
                scanner_found: pantry.found,
                settings,
            },
            pantry,
            job: None,
            settings_path,
            automation,
            cache_seen: data::cache_stamp(&cache),
            cache,
            last_watch: Instant::now(),
            last_offline: false,
            last_request: None,
        };
        if app.pantry.found {
            let _ = app.dispatch(Action::Refresh, ctx);
        } else {
            // Say it once, plainly, instead of two "os error 2" lines.
            app.state.report_error = Some(Problem::missing(&app.pantry.path));
        }
        app
    }

    /// The label of the running task, such as "Scanning…".
    pub fn busy(&self) -> Option<&'static str> {
        self.job
            .as_ref()
            .map(|job| job.task.stage().unwrap_or(job.label))
    }

    /// The scanner's last status line while a task runs.
    pub fn busy_note(&self) -> Option<String> {
        self.job
            .as_ref()
            .map(|job| job.task.note())
            .filter(|note| !note.is_empty())
    }

    /// True once a task has run longer than it usually does.
    pub fn slow(&self) -> bool {
        self.job.as_ref().is_some_and(|job| {
            job.started.elapsed()
                > match job.kind {
                    JobKind::Scan => Duration::from_secs(5 * 60),
                    JobKind::Fix => Duration::from_secs(3 * 60),
                    JobKind::Short => Duration::from_secs(20),
                }
        })
    }

    pub fn busy_seconds(&self) -> u64 {
        self.job
            .as_ref()
            .map_or(0, |job| job.started.elapsed().as_secs())
    }

    /// Scans and fixes can be cancelled. Quick reads finish on their own.
    pub fn cancellable(&self) -> bool {
        self.job
            .as_ref()
            .is_some_and(|job| job.kind != JobKind::Short || self.slow())
    }

    fn start(
        &mut self,
        kind: JobKind,
        label: &'static str,
        ctx: &egui::Context,
        work: impl FnOnce(Pantry) -> Event + Send + 'static,
    ) -> Result<()> {
        self.start_with(kind, label, ctx, mpsc::channel(), work)
    }

    /// Like `start`, with a channel the work may also send progress on.
    fn start_with(
        &mut self,
        kind: JobKind,
        label: &'static str,
        ctx: &egui::Context,
        (send, receive): (mpsc::Sender<Event>, Receiver<Event>),
        work: impl FnOnce(Pantry) -> Event + Send + 'static,
    ) -> Result<()> {
        if self.job.is_some() {
            return Err("Wait for Pantry to finish the current task.".into());
        }
        if !self.pantry.found {
            self.state.error = Some(Problem::missing(&self.pantry.path));
            return Ok(());
        }
        self.state.error = None;
        self.state.show_error_details = false;
        self.state.status.clear();
        let (pantry, task) = self.pantry.for_task();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = send.send(work(pantry));
            ctx.request_repaint();
        });
        self.job = Some(Job {
            kind,
            label,
            started: Instant::now(),
            task,
            receive,
        });
        Ok(())
    }

    fn save_settings(&mut self) {
        self.state.settings.page = self.state.page;
        self.state.settings.details = self.state.details;
        self.state.settings.include_personal_files = self.state.include_personal_files;
        if let Some(path) = &self.settings_path {
            // Settings are a convenience: a read-only disk must not stop Pantry.
            let _ = self.state.settings.save(path);
        }
    }

    /// Remember the window size; saved when the window closes.
    pub fn remember_window(&mut self, size: egui::Vec2) {
        let size = [size.x.round(), size.y.round()];
        if self.state.settings.window != Some(size) {
            self.state.settings.window = Some(size);
        }
    }

    pub fn flush_settings(&mut self) {
        self.save_settings();
    }

    /// Follow the system theme until someone picks one.
    pub fn follow_system_theme(&mut self, ctx: &egui::Context) {
        if self.state.settings.light.is_none()
            && let Some(theme) = ctx.system_theme()
        {
            self.state.light = theme == egui::Theme::Light;
        }
    }

    pub fn selected(&self) -> Option<&Finding> {
        let id = self.state.selected.as_deref()?;
        let report = self.state.report.as_ref()?;
        if let Some(earlier) = id.strip_prefix("earlier-") {
            return report
                .history
                .exposures
                .iter()
                .find(|entry| entry.resolved.is_none() && entry.finding.id == earlier)
                .map(|entry| &entry.finding);
        }
        report.findings.iter().find(|f| f.id == id)
    }

    /// Whether the scan that found the selected finding read the KEV list.
    /// A problem from an earlier scan was found by a scan Pantry no longer
    /// has the details of, so that is unknown (false).
    pub fn kev_checked_selected(&self) -> bool {
        let earlier = self
            .state
            .selected
            .as_deref()
            .is_some_and(|id| id.starts_with("earlier-"));
        !earlier && self.state.report.as_ref().is_some_and(Report::kev_checked)
    }

    pub fn plan(&self) -> Option<&Fix> {
        let id = self.state.selected.as_deref()?;
        self.state.report.as_ref()?.plan_for(id)
    }

    /// True when Pantry can run the selected finding's fix itself.
    pub fn can_fix_selected(&self) -> bool {
        match (
            self.state.report.as_ref(),
            self.selected(),
            self.state.selected.as_deref(),
        ) {
            (Some(report), Some(finding), Some(id)) => report.can_fix(finding, id),
            _ => false,
        }
    }

    /// The scanner as a command people can paste.
    pub fn shell_name(&self) -> String {
        self.pantry.shell_name()
    }

    pub fn copy_text(&self) -> Option<String> {
        let finding = self.selected()?;
        if let Some(preview) = &self.state.pending_fix {
            return Some(preview.command.clone());
        }
        if let Some(plan) = self.plan() {
            return Some(match plan.how.as_str() {
                "wpantry" => finding.fix_cmd.clone(),
                "terminal" => match plan.run.strip_prefix("wpantry ") {
                    Some(rest) => format!("{} {rest}", self.shell_name()),
                    None => plan.run.clone(),
                },
                _ => plan.run.clone(),
            });
        }
        (!finding.fix_cmd.is_empty()).then(|| finding.fix_cmd.clone())
    }

    fn open(&mut self, ctx: &egui::Context, url: &str) {
        ctx.open_url(egui::OpenUrl::new_tab(url));
    }

    /// Reload the report when the scanner's cache changed (a scheduled
    /// scan, or one from a terminal). Cheap: one or two `stat` calls, at
    /// most every 10 seconds unless `force`.
    pub fn watch(&mut self, ctx: &egui::Context, force: bool) {
        if self.job.is_some() || (!force && self.last_watch.elapsed() < WATCH_EVERY) {
            return;
        }
        self.last_watch = Instant::now();
        let stamp = data::cache_stamp(&self.cache);
        if stamp != self.cache_seen {
            self.cache_seen = stamp;
            let error = self.state.error.take();
            let _ = self.dispatch(Action::Refresh, ctx);
            // A background reload must not hide a message being read.
            if self.state.error.is_none() {
                self.state.error = error;
            }
        }
    }

    pub fn poll(&mut self, wait: bool) {
        loop {
            let Some(job) = &self.job else {
                return;
            };
            let result = if wait {
                job.receive.recv().map_err(Into::into)
            } else {
                job.receive.try_recv()
            };
            match result {
                Ok(Event::BatchStep(index, status, message, details)) => {
                    if let Some(item) = self
                        .state
                        .batch
                        .as_mut()
                        .and_then(|batch| batch.items.get_mut(index))
                    {
                        item.status = status;
                        item.message = message;
                        item.details = details;
                    }
                }
                other => {
                    self.finish(other);
                    return;
                }
            }
        }
    }

    /// The problem to show at the top of the page: a task's error first,
    /// then a failed report load.
    pub fn banner(&self) -> Option<&Problem> {
        self.state
            .error
            .as_ref()
            .or(self.state.report_error.as_ref())
    }

    pub fn needs_password(&self) -> bool {
        self.state
            .error
            .as_ref()
            .is_some_and(|e| e.kind == ProblemKind::NeedsPassword)
    }
}

impl App {
    /// Stop a running scan or fix and wait up to 3 seconds for it to go.
    /// Called when the window closes and when the app is dropped.
    ///
    /// Limit: this needs Pantry to run its exit code. A SIGKILL, or a
    /// SIGTERM (Pantry has no signal handler: it adds no dependency and no
    /// unsafe code), ends Pantry at once, and the scanner, which runs in a
    /// process group of its own so Cancel can stop what it starts, keeps
    /// running until its own time limit.
    pub fn shutdown(&mut self) {
        if let Some(job) = self.job.take() {
            job.task.cancel();
            let _ = job.receive.recv_timeout(Duration::from_secs(3));
        }
    }
}

impl Drop for App {
    /// Closing the window stops a running scan or fix instead of leaving it
    /// behind.
    fn drop(&mut self) {
        self.shutdown();
    }
}
