//! The window's state and the typed action dispatcher. The egui view and
//! the `--automation` driver both go through [`App::dispatch`].

use crate::data::{self, Finding, Fix, Period, Report, Schedule, Update};
use crate::pantry::{Pantry, Problem, ProblemKind, Result, ScanRequest, Task, valid_time};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

/// Where people can download Pantry again.
pub const DOWNLOAD_URL: &str = "https://github.com/waffuruai/pantry/releases/latest";
const FULL_DISK_ACCESS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
/// How often the window looks for results written by a scheduled scan.
const WATCH_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Page {
    #[default]
    Attention,
    Results,
    History,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filter {
    #[default]
    All,
    Fixable,
}

/// What the window remembers between launches (`settings.json` in the
/// state folder). Every field has a default, and a missing or damaged
/// file means "all defaults".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None` follows the system theme.
    pub light: Option<bool>,
    pub include_personal_files: bool,
    /// True once someone has answered the personal folders question.
    pub personal_files_asked: bool,
    pub window: Option<[f32; 2]>,
    pub page: Page,
    pub details: bool,
    /// Ids of problems from earlier scans the person dismissed. Only the
    /// window hides them; the scanner's history keeps them.
    pub dismissed: Vec<String>,
}

impl Settings {
    pub const MIN_WINDOW: [f32; 2] = [820.0, 480.0];

    pub fn load(path: &Path) -> Self {
        let mut settings: Self = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        settings.window = settings.window.filter(|[w, h]| {
            w.is_finite()
                && h.is_finite()
                && *w >= 100.0
                && *h >= 100.0
                && *w < 20_000.0
                && *h < 20_000.0
        });
        settings
    }

    /// Write through a temporary file so a crash never leaves half a file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staged = path.with_extension("json.tmp");
        std::fs::write(&staged, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(staged, path)
    }

    /// The window size to open with, never below the minimum.
    pub fn window_size(&self) -> [f32; 2] {
        let [w, h] = self.window.unwrap_or([1080.0, 740.0]);
        [w.max(Self::MIN_WINDOW[0]), h.max(Self::MIN_WINDOW[1])]
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Refresh,
    Scan {
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        offline: bool,
        #[serde(default)]
        include_personal_files: Option<bool>,
    },
    /// Scan the latest report's scope again, for checks that did not finish.
    Retry,
    /// Repeat the last scan started here with saved data only, after it
    /// could not reach the internet. A machine scan when none was started.
    RetryOffline,
    Cancel,
    SetPersonalFiles {
        include: bool,
    },
    OpenScanAccess,
    Show {
        page: Page,
    },
    Search {
        text: String,
    },
    SetFilter {
        filter: Filter,
    },
    Select {
        id: String,
    },
    CloseFinding,
    SetLight {
        light: bool,
    },
    SetDetails {
        on: bool,
    },
    EditSchedule {
        open: bool,
    },
    SetPeriod {
        every: Period,
    },
    SetTime {
        at: String,
    },
    SaveSchedule,
    RemoveSchedule,
    #[serde(alias = "fix_it")]
    PreviewFix,
    ConfirmFix,
    /// Get every fix Pantry can run ready, for one confirm.
    FixAll,
    ConfirmFixAll,
    CancelFixAll,
    DismissFixAll,
    ShowLowerPriority {
        open: bool,
    },
    /// `system`, `light` or `dark`.
    SetTheme {
        theme: ThemeChoice,
    },
    CancelFix,
    ToggleFixDetails,
    CopyFix,
    CopyWatchCommand,
    /// Open the security notice for one of the selected finding's public
    /// ids (its own or an alias) in the browser.
    OpenAdvisory {
        id: String,
    },
    /// Copy the selected finding's main public id (CVE first).
    CopyId,
    /// Scan again the folder an earlier scan found this problem in.
    RescanEarlier {
        id: String,
    },
    /// Hide a problem from an earlier scan (reversible).
    DismissEarlier {
        id: String,
    },
    /// Show a dismissed problem from an earlier scan again.
    RestoreEarlier {
        id: String,
    },
    /// Show or hide one Fix all item's raw output.
    ToggleBatchDetails {
        id: String,
    },
    DismissError,
    ToggleErrorDetails,
    DismissFixResult,
    CheckCache,
    CheckUpdates,
    CopyUpdate,
    OpenRelease,
    OpenDownload,
    #[serde(rename = "open_github")]
    OpenGitHub,
    OpenSupport,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// The dry run failed, so it will not run.
    NotReady,
    Waiting,
    Running,
    /// The fix command finished; the check comes after the last one.
    Ran,
    Failed,
    /// Cancelled or out of time part way: it may have partly run.
    Stopped,
    Skipped,
    Fixed,
    StillOpen,
    Unconfirmed,
}

#[derive(Serialize)]
pub struct BatchItem {
    pub id: String,
    pub key: String,
    pub component: String,
    pub command: String,
    pub status: BatchStatus,
    pub message: String,
    /// What the scanner said when this item did not work, for Show details.
    pub details: String,
    pub show_details: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStage {
    Confirm,
    Running,
    Done,
}

/// "Fix all": every fix Pantry can run, confirmed once, run one at a time
/// through the same single-fix path, then one check scan.
#[derive(Serialize)]
pub struct Batch {
    pub scan: i64,
    pub stage: BatchStage,
    pub items: Vec<BatchItem>,
    pub message: String,
}

#[derive(Serialize)]
pub struct PendingFix {
    pub id: String,
    pub scan: i64,
    pub command: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A complete scan of the same scope no longer finds it.
    Fixed,
    StillOpen,
    /// The fix ran, but the check could not confirm it.
    Unconfirmed,
}

#[derive(Serialize)]
pub struct FixResult {
    pub component: String,
    pub outcome: Outcome,
    pub message: String,
}

#[derive(Serialize)]
pub struct State {
    pub page: Page,
    pub search: String,
    pub filter: Filter,
    pub selected: Option<String>,
    pub report: Option<Report>,
    pub report_error: Option<Problem>,
    pub schedule: Option<Schedule>,
    pub schedule_error: Option<Problem>,
    pub editing_schedule: bool,
    pub period: Period,
    pub at: String,
    pub light: bool,
    pub details: bool,
    pub include_personal_files: bool,
    pub status: String,
    pub error: Option<Problem>,
    pub show_error_details: bool,
    pub pending_fix: Option<PendingFix>,
    pub show_fix_details: bool,
    pub last_fix_output: Option<String>,
    pub fix_result: Option<FixResult>,
    pub batch: Option<Batch>,
    pub show_lower: bool,
    pub update: Option<Update>,
    pub settings: Settings,
    pub scanner_found: bool,
}

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
    Refresh(ReportResult, Result<Schedule>),
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
        let light = settings
            .light
            .unwrap_or(ctx.system_theme() == Some(egui::Theme::Light));
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

    /// Start a scan a person asked for, and remember it for
    /// [`Action::RetryOffline`].
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

    fn open(&mut self, ctx: &egui::Context, url: &str) {
        ctx.open_url(egui::OpenUrl::new_tab(url));
    }

    pub fn dispatch(&mut self, action: Action, ctx: &egui::Context) -> Result<()> {
        match action {
            Action::Refresh => self.start(JobKind::Short, "Loading results…", ctx, |pantry| {
                Event::Refresh(pantry.report(), pantry.schedule())
            }),
            Action::Scan {
                path,
                offline,
                include_personal_files,
            } => {
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
            Action::Retry => {
                let mut request = self
                    .state
                    .report
                    .as_ref()
                    .and_then(|r| ScanRequest::for_scope(&r.scan.scope, self.last_offline))
                    .ok_or("Pantry cannot repeat this scan. Choose Scan now.")?;
                // The personal folders choice made since applies here too.
                request.include_personal_files =
                    request.machine && self.state.include_personal_files;
                self.start_scan(request, "Checking again…", ctx)?;
                self.state.fix_result = None;
                Ok(())
            }
            Action::RetryOffline => {
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
            Action::RescanEarlier { id } => {
                let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
                let exposure = report
                    .earlier_all()
                    .into_iter()
                    .find(|entry| entry.finding.id == id)
                    .ok_or("This problem is no longer in the results.")?;
                if !crate::pantry::missing_folders(&exposure.scope).is_empty() {
                    return Err(
                        "That folder is no longer there. Choose Dismiss to hide this problem."
                            .into(),
                    );
                }
                let mut request = ScanRequest::for_scope(&exposure.scope, self.last_offline)
                    .ok_or("Pantry cannot repeat that scan. Choose Scan now.")?;
                request.include_personal_files =
                    request.machine && self.state.include_personal_files;
                self.start_scan(request, "Scanning…", ctx)?;
                self.state.pending_fix = None;
                self.state.fix_result = None;
                Ok(())
            }
            Action::DismissEarlier { id } => {
                let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
                if !report.earlier_all().iter().any(|e| e.finding.id == id) {
                    return Err("This problem is no longer in the results.".into());
                }
                if !self.state.settings.dismissed.contains(&id) {
                    self.state.settings.dismissed.push(id.clone());
                }
                if self.state.selected.as_deref() == Some(&format!("earlier-{id}")) {
                    self.state.selected = None;
                }
                self.save_settings();
                self.state.status = "Dismissed. Show it again from Latest scan.".into();
                Ok(())
            }
            Action::RestoreEarlier { id } => {
                let before = self.state.settings.dismissed.len();
                self.state.settings.dismissed.retain(|item| item != &id);
                if self.state.settings.dismissed.len() == before {
                    return Err("That problem is not dismissed.".into());
                }
                self.save_settings();
                Ok(())
            }
            Action::ToggleBatchDetails { id } => {
                let item = self
                    .state
                    .batch
                    .as_mut()
                    .and_then(|b| b.items.iter_mut().find(|i| i.id == id))
                    .filter(|i| !i.details.is_empty())
                    .ok_or("There are no details for that fix.")?;
                item.show_details = !item.show_details;
                Ok(())
            }
            Action::Cancel => {
                let job = self.job.as_ref().ok_or("Nothing is running.")?;
                job.task.cancel();
                Ok(())
            }
            Action::SetPersonalFiles { include } => {
                self.state.include_personal_files = include;
                self.state.settings.personal_files_asked = true;
                self.save_settings();
                Ok(())
            }
            Action::OpenScanAccess => {
                if cfg!(target_os = "macos") && !self.automation {
                    // ctx.open_url hands this to the default browser, which
                    // can't open System Settings. `open` can.
                    std::process::Command::new("/usr/bin/open")
                        .arg(FULL_DISK_ACCESS)
                        .spawn()
                        .map_err(|error| format!("Could not open System Settings. {error}"))?;
                } else {
                    self.open(ctx, FULL_DISK_ACCESS);
                }
                Ok(())
            }
            Action::Show { page } => {
                self.state.page = page;
                self.state.status.clear();
                self.state.selected = None;
                self.state.pending_fix = None;
                self.state.search.clear();
                self.state.error = None;
                self.save_settings();
                Ok(())
            }
            Action::Search { text } => {
                self.state.search = text;
                Ok(())
            }
            Action::SetFilter { filter } => {
                self.state.filter = filter;
                Ok(())
            }
            Action::Select { id } => {
                let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
                let exists = report.findings.iter().any(|item| item.id == id)
                    || id.strip_prefix("earlier-").is_some_and(|earlier| {
                        report.earlier_all().iter().any(|e| e.finding.id == earlier)
                    });
                if !exists {
                    return Err("This finding is no longer in the report.".into());
                }
                self.state.selected = Some(id);
                self.state.status.clear();
                self.state.pending_fix = None;
                self.state.show_fix_details = false;
                self.state.last_fix_output = None;
                self.state.error = None;
                Ok(())
            }
            Action::CloseFinding => {
                self.state.selected = None;
                self.state.status.clear();
                self.state.pending_fix = None;
                self.state.error = None;
                Ok(())
            }
            Action::SetLight { light } => {
                self.state.light = light;
                self.state.settings.light = Some(light);
                self.save_settings();
                Ok(())
            }
            Action::SetDetails { on } => {
                self.state.details = on;
                self.save_settings();
                Ok(())
            }
            Action::EditSchedule { open } => {
                if open {
                    let schedule = self.state.schedule.as_ref();
                    self.state.period = schedule.and_then(|s| s.every).unwrap_or_default();
                    self.state.at = schedule
                        .and_then(|s| s.at.clone())
                        .filter(|at| valid_time(at))
                        .unwrap_or_else(|| "09:30".into());
                }
                self.state.editing_schedule = open;
                Ok(())
            }
            Action::SetPeriod { every } => {
                self.state.period = every;
                Ok(())
            }
            Action::SetTime { at } => {
                self.state.at = at;
                Ok(())
            }
            Action::SaveSchedule => {
                let every = self.state.period;
                let at = self.state.at.clone();
                if !valid_time(&at) {
                    return Err("Enter a time in 24-hour format, such as 09:30.".into());
                }
                self.start(JobKind::Short, "Saving schedule…", ctx, move |pantry| {
                    let change = pantry.save_schedule(every, &at);
                    Event::Schedule(
                        change.map(|_| "Scan schedule saved.".into()),
                        pantry.schedule(),
                    )
                })
            }
            Action::RemoveSchedule => self.start(
                JobKind::Short,
                "Turning off scheduled scans…",
                ctx,
                |pantry| {
                    let change = pantry.remove_schedule();
                    Event::Schedule(
                        change.map(|_| "Scheduled scans turned off.".into()),
                        pantry.schedule(),
                    )
                },
            ),
            Action::PreviewFix => {
                if self.state.report_error.is_some() {
                    return Err("Reload results before running a fix.".into());
                }
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
            Action::ConfirmFix => {
                let pending = self
                    .state
                    .pending_fix
                    .as_ref()
                    .ok_or("Choose Fix it first.")?;
                let (id, scan) = (pending.id.clone(), pending.scan);
                let finding = self.selected().ok_or("Choose a finding first.")?;
                let (key, component) = (finding.key_string(), finding.component.clone());
                let check = self.state.report.as_ref().and_then(|report| {
                    ScanRequest::for_scope(&report.scan.scope, self.last_offline)
                });
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
            Action::FixAll => {
                if self.state.report_error.is_some() {
                    return Err("Reload results before running a fix.".into());
                }
                let report = self.state.report.as_ref().ok_or("Run a scan first.")?;
                let ids: Vec<String> = report
                    .open()
                    .into_iter()
                    .filter(|(finding, id)| report.can_fix(finding, id))
                    .map(|(_, id)| id)
                    .collect();
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
            Action::ConfirmFixAll => {
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
                let check = self.state.report.as_ref().and_then(|report| {
                    ScanRequest::for_scope(&report.scan.scope, self.last_offline)
                });
                let (send, receive) = mpsc::channel();
                let progress = send.clone();
                self.start_with(
                    JobKind::Fix,
                    "Fixing…",
                    ctx,
                    (send, receive),
                    move |pantry| {
                        let mut any = false;
                        for (index, id) in work {
                            if pantry.task().cancelled() {
                                let _ = progress.send(Event::BatchStep(
                                    index,
                                    BatchStatus::Skipped,
                                    "Not run: you cancelled.".into(),
                                    String::new(),
                                ));
                                continue;
                            }
                            let _ = progress.send(Event::BatchStep(
                                index,
                                BatchStatus::Running,
                                String::new(),
                                String::new(),
                            ));
                            match pantry.fix(scan, &id) {
                                Ok(_) => {
                                    any = true;
                                    let _ = progress.send(Event::BatchStep(
                                        index,
                                        BatchStatus::Ran,
                                        String::new(),
                                        String::new(),
                                    ));
                                }
                                Err(error) => {
                                    let problem = Problem::for_fix(&error);
                                    // Stopped part way is not "Skipped": it
                                    // may have changed something.
                                    let status = if problem.kind == ProblemKind::FixStopped {
                                        BatchStatus::Stopped
                                    } else {
                                        BatchStatus::Failed
                                    };
                                    let _ = progress.send(Event::BatchStep(
                                        index,
                                        status,
                                        problem.summary,
                                        problem.details,
                                    ));
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
            Action::CancelFixAll => {
                if self
                    .state
                    .batch
                    .as_ref()
                    .is_some_and(|b| b.stage == BatchStage::Running)
                {
                    return Err("Use Cancel to stop the fixes that are running.".into());
                }
                self.state.batch = None;
                Ok(())
            }
            Action::DismissFixAll => {
                if self
                    .state
                    .batch
                    .as_ref()
                    .is_some_and(|b| b.stage == BatchStage::Running)
                {
                    return Err("Wait for the fixes to finish, or use Cancel.".into());
                }
                self.state.batch = None;
                Ok(())
            }
            Action::ShowLowerPriority { open } => {
                self.state.show_lower = open;
                Ok(())
            }
            Action::SetTheme { theme } => {
                self.state.settings.light = match theme {
                    ThemeChoice::System => None,
                    ThemeChoice::Light => Some(true),
                    ThemeChoice::Dark => Some(false),
                };
                self.state.light = self
                    .state
                    .settings
                    .light
                    .unwrap_or(ctx.system_theme() == Some(egui::Theme::Light));
                self.save_settings();
                Ok(())
            }
            Action::CancelFix => {
                self.state.pending_fix = None;
                Ok(())
            }
            Action::ToggleFixDetails => {
                self.state.show_fix_details = !self.state.show_fix_details;
                Ok(())
            }
            Action::CopyFix => {
                let text = self.copy_text().ok_or("There is no fix to copy.")?;
                ctx.copy_text(text);
                self.state.status = "Copied.".into();
                Ok(())
            }
            Action::OpenAdvisory { id } => {
                // Only an id the finding lists, and only its known notice
                // address: the driver can't open an arbitrary URL.
                let finding = self.selected().ok_or("Choose a finding first.")?;
                let url = crate::explain::identifiers(finding)
                    .into_iter()
                    .find(|item| item.id == id)
                    .and_then(|item| item.url)
                    .ok_or("This finding has no public notice with that ID.")?;
                self.open(ctx, &url);
                Ok(())
            }
            Action::CopyId => {
                let finding = self.selected().ok_or("Choose a finding first.")?;
                let id = crate::explain::identifiers(finding)
                    .into_iter()
                    .next()
                    .ok_or("This finding has no public ID to copy.")?
                    .id;
                ctx.copy_text(id);
                self.state.status = "Copied.".into();
                Ok(())
            }
            Action::CopyWatchCommand => {
                ctx.copy_text(format!("{} watch", self.shell_name()));
                self.state.status = "Copied.".into();
                Ok(())
            }
            Action::DismissError => {
                // Every banner but a missing scanner, which no click mends.
                self.state.error = None;
                if self
                    .state
                    .report_error
                    .as_ref()
                    .is_some_and(|e| e.kind != ProblemKind::ScannerMissing)
                {
                    self.state.report_error = None;
                }
                self.state.schedule_error = None;
                self.state.show_error_details = false;
                Ok(())
            }
            Action::ToggleErrorDetails => {
                self.state.show_error_details = !self.state.show_error_details;
                Ok(())
            }
            Action::DismissFixResult => {
                self.state.fix_result = None;
                Ok(())
            }
            Action::CheckCache => {
                self.watch(ctx, true);
                Ok(())
            }
            Action::CheckUpdates => {
                // The last answer stays until a new one comes, so a failed
                // check can say when Pantry last checked.
                self.start(JobKind::Short, "Checking for updates…", ctx, |pantry| {
                    Event::Update(pantry.check_updates())
                })
            }
            Action::CopyUpdate => {
                let (tag, asset) = self
                    .release()
                    .ok_or("No newer desktop release is available for this platform.")?;
                ctx.copy_text(format!(
                    "gh release download {tag} --repo waffuruai/pantry --pattern {asset}\n\
                     gh attestation verify {asset} --repo waffuruai/pantry --signer-workflow waffuruai/pantry/.github/workflows/release.yml --source-ref refs/tags/{tag}"
                ));
                self.state.status = "Copied download and verification commands.".into();
                Ok(())
            }
            Action::OpenGitHub => {
                self.open(ctx, "https://github.com/waffuruai/pantry");
                Ok(())
            }
            Action::OpenSupport => {
                ctx.open_url(egui::OpenUrl::same_tab("mailto:support@waffuru.ai"));
                Ok(())
            }
            Action::OpenDownload => {
                self.open(ctx, DOWNLOAD_URL);
                Ok(())
            }
            Action::OpenRelease => {
                let (tag, asset) = self
                    .release()
                    .ok_or("No newer desktop release is available for this platform.")?;
                self.open(
                    ctx,
                    &format!("https://github.com/waffuruai/pantry/releases/download/{tag}/{asset}"),
                );
                Ok(())
            }
        }
    }

    pub fn release(&self) -> Option<(String, &'static str)> {
        let update = self.state.update.as_ref()?;
        let candidates = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", _) => [
                "wpantry-setup-universal-apple-darwin.zip",
                "wpantry-desktop-universal-apple-darwin.zip",
            ],
            ("linux", "aarch64") => [
                "wpantry-setup-aarch64-unknown-linux-gnu.tar.gz",
                "wpantry-desktop-aarch64-unknown-linux-gnu.zip",
            ],
            ("linux", "x86_64") => [
                "wpantry-setup-x86_64-unknown-linux-gnu.tar.gz",
                "wpantry-desktop-x86_64-unknown-linux-gnu.zip",
            ],
            ("windows", "x86_64") => [
                "wpantry-setup-x86_64-pc-windows-msvc.exe",
                "wpantry-desktop-x86_64-pc-windows-msvc.zip",
            ],
            _ => return None,
        };
        if update.current != env!("CARGO_PKG_VERSION")
            || !update.available
            || update.latest.split('.').count() != 3
            || !update
                .latest
                .split('.')
                .all(|part| part.parse::<u32>().is_ok() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let assets = update.assets.as_ref()?;
        let asset = candidates
            .into_iter()
            .find(|candidate| assets.iter().any(|asset| asset == candidate))?;
        Some((format!("v{}", update.latest), asset))
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

    fn finish(&mut self, result: std::result::Result<Event, mpsc::TryRecvError>) {
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
            Event::Refresh(report, schedule) => {
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
                    if update.current != env!("CARGO_PKG_VERSION") {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pantry-desktop-settings-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn settings_round_trip() {
        let dir = scratch("round-trip");
        let path = dir.join("state/settings.json");
        let settings = Settings {
            light: Some(true),
            include_personal_files: true,
            personal_files_asked: true,
            window: Some([900.0, 600.0]),
            page: Page::History,
            details: true,
            dismissed: vec!["F-1".into()],
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Known-bad inputs: a missing file, garbage, wrong types, nonsense
    /// sizes. Each must load as defaults (or drop just the bad size).
    #[test]
    fn settings_tolerate_missing_and_corrupt_files() {
        let dir = scratch("corrupt");
        let path = dir.join("settings.json");
        assert_eq!(Settings::load(&path), Settings::default());
        for text in [
            "",
            "{",
            "not json",
            "[1,2]",
            "{\"light\": \"yes\"}",
            "\u{0}\u{1}",
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(Settings::load(&path), Settings::default(), "{text:?}");
        }
        std::fs::write(&path, "{\"details\": true, \"future_field\": 3}").unwrap();
        assert!(Settings::load(&path).details, "unknown fields are ignored");
        std::fs::write(&path, "{\"window\": [1e30, 5]}").unwrap();
        assert_eq!(Settings::load(&path).window, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn window_size_never_drops_below_the_minimum() {
        let settings = Settings {
            window: Some([400.0, 300.0]),
            ..Settings::default()
        };
        assert_eq!(settings.window_size(), Settings::MIN_WINDOW);
        assert_eq!(Settings::default().window_size(), [1080.0, 740.0]);
    }
}
