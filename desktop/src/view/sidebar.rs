//! The sidebar: navigation, theme, personal folders, scan schedule,
//! updates and the help links.

use super::text::one_line;
use super::widgets::{button, dispatch, link, muted, section, tag};
use crate::app::{Action, App};
use crate::brand::Palette;
use crate::data::{Period, local_time};
use eframe::egui::{self, Frame, RichText, Ui};

pub(super) fn sidebar(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    egui::Panel::left("pantry.sidebar")
        .exact_size(236.0)
        .resizable(false)
        .frame(
            Frame::NONE
                .fill(p.side)
                .inner_margin(egui::Margin::symmetric(18, 20)),
        )
        .show(ui, |ui| {
            // The help links stay pinned at the bottom; everything above
            // them scrolls, so at the 820 x 480 minimum every control can
            // still be reached. The bar is solid (not the hover-only kind)
            // so people can see there is more below.
            egui::Panel::bottom("pantry.help")
                .frame(Frame::NONE.inner_margin(egui::Margin {
                    top: 10,
                    ..egui::Margin::ZERO
                }))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if link(ui, "help.github", "GitHub") {
                            dispatch(ui, app, Action::OpenGitHub);
                        }
                        if link(ui, "help.support", "support@waffuru.ai") {
                            dispatch(ui, app, Action::OpenSupport);
                        }
                    });
                });
            ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
            let scroll = egui::ScrollArea::vertical()
                .id_salt("sidebar")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    schedule(ui, app, p, enabled);
                    if cfg!(target_os = "macos") && app.state.report.is_some() {
                        ui.add_space(10.0);
                        ui.separator();
                        section(ui, "Personal folders");
                        personal_folders(ui, app, p, enabled);
                    }
                    ui.add_space(10.0);
                    ui.separator();
                    section(ui, "Updates");
                    // The scanner's own version, so it can't drift from the
                    // back end; nothing until the scanner has said.
                    if let Some(version) = &app.state.scanner_version {
                        let shown = muted(ui, p, format!("Pantry {}", one_line(version, 40)));
                        tag(ui, &shown, "updates.version");
                    }
                    if button(ui, p, "updates.check", "Check for updates", enabled, false) {
                        dispatch(ui, app, Action::CheckUpdates);
                    }
                    updates(ui, app, p);
                    ui.add_space(10.0);
                    ui.separator();
                    section(ui, "Display");
                    let light = !app.state.light;
                    if button(
                        ui,
                        p,
                        "theme.toggle",
                        if light { "Light theme" } else { "Dark theme" },
                        true,
                        false,
                    ) {
                        dispatch(ui, app, Action::SetLight { light });
                    }
                    let mut details = app.state.details;
                    let toggle =
                        ui.add(egui::Checkbox::new(&mut details, "Show technical details"));
                    tag(ui, &toggle, "view.details");
                    if toggle.changed() {
                        dispatch(ui, app, Action::SetDetails { on: details });
                    }
                    if app.state.details {
                        muted(
                            ui,
                            p,
                            "Shows commands, IDs such as CVE numbers, and scan numbers.",
                        );
                        if button(
                            ui,
                            p,
                            "scan.refresh",
                            "Reload results",
                            enabled && app.state.scanner_found,
                            false,
                        ) {
                            dispatch(ui, app, Action::Refresh);
                        }
                    }
                });
            scroll_region(ui, "sidebar.scroll", scroll.inner_rect);
        });
}

/// Report a scroll area's visible rectangle to automation as a ScrollView
/// node, so tests can check that a control sits inside it.
fn scroll_region(ui: &Ui, id: &str, rect: egui::Rect) {
    let node = egui::Id::unique(("pantry.scroll", id));
    ui.ctx().accesskit_node_builder(node, |builder| {
        builder.set_role(egui::accesskit::Role::ScrollView);
        builder.set_author_id(id.to_owned());
        builder.set_bounds(egui::accesskit::Rect {
            x0: rect.min.x.into(),
            y0: rect.min.y.into(),
            x1: rect.max.x.into(),
            y1: rect.max.y.into(),
        });
    });
}

fn updates(ui: &mut Ui, app: &mut App, p: &Palette) {
    let Some(update) = app.state.update.as_ref() else {
        return;
    };
    if update.stale {
        // An old answer: never "You're up to date" from it.
        let text = match &update.checked_at {
            Some(when) => format!(
                "Could not check for updates. Last checked {}.",
                local_time(when)
            ),
            None => "Could not check for updates.".to_owned(),
        };
        let note = ui.label(text);
        tag(ui, &note, "updates.stale");
        if !update.available {
            return;
        }
    }
    if !update.matches_app() {
        ui.label("The scanner in this copy of Pantry is from another version.");
        if button(ui, p, "updates.reinstall", "Download Pantry", true, false) {
            dispatch(ui, app, Action::OpenDownload);
        }
    } else if !update.available {
        ui.label("You're up to date.");
    } else if app.release().is_some() {
        ui.label(format!("Version {} is available.", update.latest));
        muted(ui, p, "Quit Pantry before installing the update.");
        if button(ui, p, "updates.open", "Download update", true, false) {
            dispatch(ui, app, Action::OpenRelease);
        }
        if app.state.details && button(ui, p, "updates.copy", "Copy commands", true, false) {
            dispatch(ui, app, Action::CopyUpdate);
        }
    } else {
        ui.label("This release has no download for your computer yet.");
    }
}

pub(super) fn personal_folders(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    let mut include = app.state.include_personal_files;
    let access = ui.add_enabled(
        enabled,
        egui::Checkbox::new(&mut include, "Also check Documents, Desktop and Downloads"),
    );
    tag(ui, &access, "scan.personal");
    if access.changed() {
        dispatch(ui, app, Action::SetPersonalFiles { include });
    }
    if include {
        muted(ui, p, "macOS asks you to allow this once:");
        for (n, step) in [
            "Choose Open Full Disk Access.",
            "Turn on Pantry in the list. If it is not there, choose the + button and pick Pantry from Applications.",
            "Come back to Pantry and scan.",
        ]
        .iter()
        .enumerate()
        {
            ui.label(format!("{}. {step}", n + 1));
        }
        if button(ui, p, "scan.access", "Open Full Disk Access", true, false) {
            dispatch(ui, app, Action::OpenScanAccess);
        }
    } else {
        muted(ui, p, "Pantry skips these folders unless you allow it.");
    }
}

fn schedule(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    section(ui, "Scan schedule");
    let schedule = app.state.schedule.as_ref();
    let installed = schedule.is_some_and(|s| s.installed);
    let custom_hour = schedule.is_some_and(|s| matches!(s.backend.as_str(), "cron" | "windows"));
    // A job launchd still runs although its file is gone: not "off".
    let stray = schedule.is_some_and(|s| !s.installed && s.loaded == Some(true));
    let interval = match schedule {
        Some(s) if s.enabled == Some(false) => "Schedule is paused",
        Some(s) if s.installed => s.interval.as_deref().unwrap_or("Custom scan schedule"),
        Some(_) if stray => "A scheduled scan is still registered",
        Some(_) => "Scheduled scans are off",
        None => "Schedule unavailable",
    };
    let heading = ui.label(RichText::new(interval).strong());
    tag(ui, &heading, "schedule.state");
    if stray {
        muted(
            ui,
            p,
            "An earlier removal did not finish, so it may still run. Choose Remove it to try again.",
        );
        if button(
            ui,
            p,
            "schedule.remove_stray",
            "Remove it",
            enabled && app.state.scanner_found,
            true,
        ) {
            dispatch(ui, app, Action::RemoveSchedule);
            return;
        }
    }
    let schedule = app.state.schedule.as_ref();
    if let Some(schedule) = schedule {
        if schedule.enabled == Some(false)
            && let Some(interval) = &schedule.interval
        {
            ui.label(interval);
        }
        let time = schedule
            .last_run
            .as_deref()
            .map(local_time)
            .unwrap_or_else(|| "Never".into());
        muted(ui, p, format!("Last scheduled scan\n{time}"));
    }
    // The same problem as the page banner is not repeated here.
    if let Some(error) = &app.state.schedule_error
        && app.state.report_error.as_ref().map(|e| e.kind) != Some(error.kind)
    {
        ui.label(RichText::new(error.summary.as_str()).color(p.goldtx));
    }
    if !app.state.editing_schedule {
        if button(
            ui,
            p,
            "schedule.edit",
            if installed {
                "Change schedule"
            } else {
                "Set up schedule"
            },
            enabled && app.state.scanner_found,
            false,
        ) {
            dispatch(ui, app, Action::EditSchedule { open: true });
        }
        return;
    }
    let period = app.state.period;
    let response = egui::ComboBox::from_id_salt("schedule.every")
        .selected_text(period.label())
        .show_ui(ui, |ui| {
            for every in Period::ALL {
                let response = ui.selectable_label(period == every, every.label());
                tag(ui, &response, &format!("schedule.every.{}", every.name()));
                if response.clicked() {
                    dispatch(ui, app, Action::SetPeriod { every });
                }
            }
        })
        .response;
    tag(ui, &response, "schedule.every");
    let hourly = app.state.period == Period::Hour;
    if !hourly || custom_hour {
        muted(
            ui,
            p,
            if hourly {
                "Minutes past the hour"
            } else {
                "Time of day (24-hour clock)"
            },
        );
        let (hour, minute) = app
            .state
            .at
            .split_once(':')
            .map_or(("09", "30"), |(h, m)| (h, m));
        let (hour, minute) = (hour.to_owned(), minute.to_owned());
        ui.horizontal(|ui| {
            if !hourly {
                let choice = time_combo(
                    ui,
                    "schedule.hour",
                    &hour,
                    (0..24).map(|h| format!("{h:02}")),
                );
                if let Some(hour) = choice {
                    dispatch(
                        ui,
                        app,
                        Action::SetTime {
                            at: format!("{hour}:{minute}"),
                        },
                    );
                }
                ui.label(":");
            }
            let mut minutes: Vec<String> = (0..60).step_by(5).map(|m| format!("{m:02}")).collect();
            if !minutes.contains(&minute) && minute.len() == 2 {
                minutes.push(minute.clone());
                minutes.sort();
            }
            if let Some(minute) = time_combo(ui, "schedule.minute", &minute, minutes.into_iter()) {
                dispatch(
                    ui,
                    app,
                    Action::SetTime {
                        at: format!("{hour}:{minute}"),
                    },
                );
            }
        });
    }
    ui.horizontal(|ui| {
        if button(ui, p, "schedule.save", "Save", enabled, true) {
            dispatch(ui, app, Action::SaveSchedule);
        }
        if button(ui, p, "schedule.cancel", "Cancel", true, false) {
            dispatch(ui, app, Action::EditSchedule { open: false });
        }
    });
    if installed
        && button(
            ui,
            p,
            "schedule.remove",
            "Turn off scheduled scans",
            enabled,
            false,
        )
    {
        dispatch(ui, app, Action::RemoveSchedule);
    }
}

/// An hour or minute dropdown. Items are tagged `<id>.<value>`.
fn time_combo(
    ui: &mut Ui,
    id: &str,
    current: &str,
    values: impl Iterator<Item = String>,
) -> Option<String> {
    let mut choice = None;
    let response = egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .width(56.0)
        .height(240.0)
        .show_ui(ui, |ui| {
            for value in values {
                let item = ui.selectable_label(value == current, &value);
                tag(ui, &item, &format!("{id}.{value}"));
                if item.clicked() {
                    choice = Some(value);
                }
            }
        })
        .response;
    tag(ui, &response, id);
    choice
}
