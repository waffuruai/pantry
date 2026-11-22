//! The typed action dispatcher: every click and every `--automation`
//! `dispatch` goes through [`App::dispatch`]. Short actions are handled
//! here; scans, fixes and updates have their own files.

use super::{Action, App, DOWNLOAD_URL, Event, JobKind, ThemeChoice, light_or_system};
use crate::pantry::{ProblemKind, Result, valid_time};
use eframe::egui;

/// macOS's Full Disk Access page in System Settings.
const FULL_DISK_ACCESS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
/// The project's home on GitHub.
pub(super) const GITHUB: &str = "https://github.com/waffuruai/pantry";

impl App {
    /// Do what a person (or the automation driver) asked.
    ///
    /// Example: `app.dispatch(Action::Show { page: Page::History }, ctx)?;`
    pub fn dispatch(&mut self, action: Action, ctx: &egui::Context) -> Result<()> {
        match action {
            Action::Refresh => self.start(JobKind::Short, "Loading results…", ctx, |pantry| {
                // Asked first, so a reload still ends with the report and
                // the schedule.
                let version = pantry.version().ok();
                Event::Refresh {
                    report: pantry.report(),
                    schedule: pantry.schedule(),
                    version,
                }
            }),
            Action::Scan {
                path,
                offline,
                include_personal_files,
            } => self.scan(path, offline, include_personal_files, ctx),
            Action::Retry => self.retry(ctx),
            Action::RetryOffline => self.retry_offline(ctx),
            Action::RescanEarlier { id } => self.rescan_earlier(&id, ctx),
            Action::DismissEarlier { id } => self.dismiss_earlier(id),
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
            Action::PreviewFix => self.preview_fix(ctx),
            Action::ConfirmFix => self.confirm_fix(ctx),
            Action::FixAll => self.fix_all(ctx),
            Action::ConfirmFixAll => self.confirm_fix_all(ctx),
            Action::CancelFixAll => {
                self.close_batch("Use Cancel to stop the fixes that are running.")
            }
            Action::DismissFixAll => {
                self.close_batch("Wait for the fixes to finish, or use Cancel.")
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
                self.state.light = light_or_system(self.state.settings.light, ctx);
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
                self.copy(ctx, text, "Copied.");
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
                self.copy(ctx, id, "Copied.");
                Ok(())
            }
            Action::CopyWatchCommand => {
                let command = format!("{} watch", self.shell_name());
                self.copy(ctx, command, "Copied.");
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
            Action::CopyUpdate => self.copy_update(ctx),
            Action::OpenGitHub => {
                self.open(ctx, GITHUB);
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
            Action::OpenRelease => self.open_release(ctx),
        }
    }

    /// Put text on the clipboard and say so in the status line.
    pub(super) fn copy(&mut self, ctx: &egui::Context, text: String, status: &str) {
        ctx.copy_text(text);
        self.state.status = status.into();
    }
}
