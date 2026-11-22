//! The Fix all card: one confirm, then each fix's status.

use super::text::{NAME_MAX, one_line};
use super::theme::semibold;
use super::widgets::{button, card, link, muted, plural, section, tag};
use crate::app::{Action, App};
use crate::brand::Palette;
use eframe::egui::{self, FontId, RichText, Ui};

pub(super) const FIX_REQUESTED: &str = "pantry.fix_requested";

pub(super) fn fix_requested(ui: &Ui) -> bool {
    ui.ctx()
        .data_mut(|d| d.remove_temp::<bool>(egui::Id::unique(FIX_REQUESTED)))
        .unwrap_or(false)
}

/// The "Fix all" confirm, progress and results.
pub(super) fn batch(ui: &mut Ui, app: &App, p: &Palette, action: &mut Option<Action>) {
    let Some(batch) = &app.state.batch else {
        return;
    };
    use crate::app::{BatchStage, BatchStatus};
    let details = app.state.details;
    let enabled = app.busy().is_none();
    card(ui, p, |ui| {
        let ready = batch
            .items
            .iter()
            .filter(|i| i.status == BatchStatus::Waiting)
            .count();
        match batch.stage {
            BatchStage::Confirm => {
                section(
                    ui,
                    &format!("Pantry will fix {}", plural(ready as i64, "item", "items")),
                );
                ui.label("Each one runs in turn. Then Pantry scans once to check them.");
            }
            BatchStage::Running => section(ui, "Fixing…"),
            BatchStage::Done => {
                let done = ui.label(
                    RichText::new(batch.message.as_str()).font(FontId::new(16.0, semibold())),
                );
                tag(ui, &done, "fix.all.result");
            }
        }
        for (n, item) in batch.items.iter().enumerate() {
            let (word, color) = match item.status {
                BatchStatus::NotReady => ("Can't run", p.ink2),
                BatchStatus::Waiting => ("Ready", p.ink2),
                BatchStatus::Running => ("Running", p.goldtx),
                BatchStatus::Ran => ("Ran", p.ink2),
                BatchStatus::Failed => ("Did not work", p.red),
                BatchStatus::Stopped => ("Stopped", p.goldtx),
                BatchStatus::Skipped => ("Skipped", p.ink2),
                BatchStatus::Fixed => ("Fixed", p.green),
                BatchStatus::StillOpen => ("Still open", p.red),
                BatchStatus::Unconfirmed => ("Not confirmed", p.goldtx),
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{}. {}",
                    n + 1,
                    if item.component.is_empty() {
                        "Item".to_owned()
                    } else {
                        one_line(&item.component, NAME_MAX)
                    }
                ));
                let status = ui.label(RichText::new(word).color(color).strong());
                tag(ui, &status, &format!("fix.all.item.{}", item.id));
                if !item.message.is_empty() && item.status != BatchStatus::Fixed {
                    muted(ui, p, item.message.as_str());
                }
                if !item.details.is_empty() {
                    let label = if item.show_details {
                        "Hide details"
                    } else {
                        "Show details"
                    };
                    if link(ui, &format!("fix.all.item.{}.details", item.id), label) {
                        *action = Some(Action::ToggleBatchDetails {
                            id: item.id.clone(),
                        });
                    }
                }
            });
            if item.show_details && !item.details.is_empty() {
                let raw = ui.add(
                    egui::Label::new(RichText::new(&item.details).monospace().color(p.ink2))
                        .selectable(true),
                );
                tag(ui, &raw, &format!("fix.all.item.{}.raw", item.id));
            }
            if (details || app.state.show_fix_details) && !item.command.is_empty() {
                let command = ui.add(
                    egui::Label::new(RichText::new(&item.command).monospace().color(p.ink2))
                        .selectable(true),
                );
                tag(ui, &command, &format!("fix.all.item.{}.command", item.id));
            }
        }
        ui.horizontal(|ui| match batch.stage {
            BatchStage::Confirm => {
                if button(
                    ui,
                    p,
                    "fix.all.confirm",
                    &format!("Yes, fix {ready}"),
                    enabled && ready > 0,
                    true,
                ) {
                    *action = Some(Action::ConfirmFixAll);
                }
                if button(ui, p, "fix.all.cancel", "Not now", true, false) {
                    *action = Some(Action::CancelFixAll);
                }
            }
            BatchStage::Running => {}
            BatchStage::Done => {
                // A fix stopped part way may have changed something, so the
                // way to see where things stand is right here.
                let stopped = batch.items.iter().any(|i| i.status == BatchStatus::Stopped);
                if stopped
                    && button(
                        ui,
                        p,
                        "fix.all.scan",
                        "Scan now",
                        enabled && app.state.scanner_found,
                        true,
                    )
                {
                    *action = Some(Action::Retry);
                }
                if button(ui, p, "fix.all.dismiss", "Done", true, false) {
                    *action = Some(Action::DismissFixAll);
                }
            }
        });
        // The exact commands are always one click away.
        if !details && batch.stage != BatchStage::Running {
            let label = if app.state.show_fix_details {
                "Hide the commands"
            } else {
                "Show the commands"
            };
            if link(ui, "fix.all.commands", label) {
                *action = Some(Action::ToggleFixDetails);
            }
        }
    });
    ui.add_space(4.0);
}
