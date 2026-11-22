//! What sits above the page: the running task, a problem, and the result
//! of a fix.

use super::widgets::{Shape, button, card, dispatch, muted, paint_shape, tag};
use crate::app::{Action, App, Outcome};
use crate::brand::Palette;
use crate::pantry::ProblemKind;
use eframe::egui::{self, RichText, Sense, Ui, Vec2, accesskit as ax};

/// The running task: what it is doing, for how long, and Cancel.
pub(super) fn progress(ui: &mut Ui, app: &mut App, p: &Palette) {
    let Some(label) = app.busy() else {
        return;
    };
    let mut cancel = false;
    card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.spinner();
            let text = ui.label(RichText::new(label).strong());
            tag(ui, &text, "task.label");
            let seconds = app.busy_seconds();
            if seconds >= 5 {
                muted(ui, p, format!("{}:{:02}", seconds / 60, seconds % 60));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if app.cancellable() && button(ui, p, "task.cancel", "Cancel", true, false) {
                    cancel = true;
                }
            });
        });
        if app.slow() {
            let slow = ui.label(
                RichText::new("Taking longer than expected. You can keep waiting or cancel.")
                    .color(p.goldtx),
            );
            tag(ui, &slow, "task.slow");
        }
        if let Some(note) = app.busy_note() {
            let note =
                ui.add(egui::Label::new(RichText::new(note).color(p.ink2).small()).truncate());
            tag(ui, &note, "task.note");
        }
    });
    ui.add_space(6.0);
    if cancel {
        dispatch(ui, app, Action::Cancel);
    }
}

/// The friendly error banner. Raw scanner text sits behind Show details.
pub(super) fn problem(ui: &mut Ui, app: &mut App, p: &Palette) {
    let Some(problem) = app.banner().cloned() else {
        return;
    };
    // Every banner can be dismissed but a missing scanner.
    let dismissable = problem.kind != ProblemKind::ScannerMissing;
    let mut action = None;
    card(ui, p, |ui| {
        ui.horizontal(|ui| {
            let color = match problem.kind {
                ProblemKind::Cancelled => p.ink2,
                ProblemKind::FixStopped => p.goldtx,
                _ => p.red,
            };
            let (rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 20.0), Sense::hover());
            paint_shape(ui.painter(), rect.center(), Shape::Diamond, color);
            let message =
                ui.add(egui::Label::new(RichText::new(problem.summary.as_str()).strong()).wrap());
            ui.ctx().accesskit_node_builder(message.id, |node| {
                node.set_author_id("error.message".to_owned());
                node.set_live(ax::Live::Assertive);
            });
        });
        ui.horizontal_wrapped(|ui| {
            if problem.needs_reinstall()
                && button(ui, p, "error.download", "Download Pantry", true, true)
            {
                action = Some(Action::OpenDownload);
            }
            if problem.kind == ProblemKind::Offline
                && button(
                    ui,
                    p,
                    "error.offline",
                    "Scan with saved data",
                    app.busy().is_none(),
                    false,
                )
            {
                action = Some(Action::RetryOffline);
            }
            if problem.kind == ProblemKind::Permission
                && cfg!(target_os = "macos")
                && button(ui, p, "error.access", "Open Full Disk Access", true, false)
            {
                action = Some(Action::OpenScanAccess);
            }
            if !problem.details.is_empty() {
                let label = if app.state.show_error_details {
                    "Hide details"
                } else {
                    "Show details"
                };
                if button(ui, p, "error.details", label, true, false) {
                    action = Some(Action::ToggleErrorDetails);
                }
            }
            if problem.kind == ProblemKind::FixStopped
                && button(
                    ui,
                    p,
                    "error.scan",
                    "Scan now",
                    app.busy().is_none() && app.state.scanner_found,
                    true,
                )
            {
                // The same ground as the latest scan when it can repeat it.
                let repeat = app.state.report.as_ref().is_some_and(|r| {
                    crate::pantry::ScanRequest::for_scope(&r.scan.scope, false).is_some()
                });
                action = Some(if repeat {
                    Action::Retry
                } else {
                    Action::Scan {
                        path: None,
                        offline: false,
                        include_personal_files: None,
                    }
                });
            }
            if dismissable && button(ui, p, "error.dismiss", "Dismiss", true, false) {
                action = Some(Action::DismissError);
            }
        });
        if app.state.show_error_details && !problem.details.is_empty() {
            let raw = ui.add(
                egui::Label::new(
                    RichText::new(problem.details.as_str())
                        .monospace()
                        .color(p.ink2),
                )
                .selectable(true),
            );
            tag(ui, &raw, "error.raw");
        }
    });
    ui.add_space(6.0);
    if let Some(action) = action {
        dispatch(ui, app, action);
    }
}

pub(super) fn fix_result(ui: &mut Ui, app: &mut App, p: &Palette) {
    let Some(result) = &app.state.fix_result else {
        return;
    };
    let (color, shape) = match result.outcome {
        Outcome::Fixed => (p.green, Shape::Dot),
        Outcome::StillOpen => (p.red, Shape::Diamond),
        Outcome::Unconfirmed => (p.goldtx, Shape::Ring),
    };
    let message = result.message.clone();
    let mut dismiss = false;
    card(ui, p, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 20.0), Sense::hover());
            paint_shape(ui.painter(), rect.center(), shape, color);
            let label = ui.add(egui::Label::new(RichText::new(message).strong()).wrap());
            ui.ctx().accesskit_node_builder(label.id, |node| {
                node.set_author_id("fix.result".to_owned());
                node.set_live(ax::Live::Polite);
            });
        });
        dismiss = button(ui, p, "fix.result.dismiss", "Dismiss", true, false);
    });
    ui.add_space(6.0);
    if dismiss {
        dispatch(ui, app, Action::DismissFixResult);
    }
}
