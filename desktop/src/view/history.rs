//! History: recent scans, fixes and confirmed fixes.

use super::text::scope;
use super::widgets::{card, muted, plural, section};
use crate::app::App;
use crate::brand::Palette;
use crate::data::local_time;
use eframe::egui::{self, RichText, Ui};

pub(super) fn history(ui: &mut Ui, app: &mut App, p: &Palette) {
    let details = app.state.details;
    let report = app.state.report.as_ref().expect("report shown");
    ui.heading("History");
    muted(ui, p, "Activity from the last 14 days");
    section(ui, "Fixes");
    if report.history.fixes.is_empty() {
        muted(ui, p, "No fixes yet.");
    }
    let components = report.components_by_key();
    for fix in report.history.fixes.iter().rev() {
        card(ui, p, |ui| {
            let names = fix.target_names(&components);
            if !names.is_empty() {
                section(ui, &names.join(", "));
            }
            let (status, color) = match (fix.ok, fix.verified_scan) {
                (false, _) => ("Fix did not work".to_owned(), p.red),
                (true, Some(scan)) if details => {
                    (format!("Fixed and checked · scan #{scan}"), p.green)
                }
                (true, Some(_)) => ("Fixed and checked".to_owned(), p.green),
                (true, None) => ("Fix ran, not checked yet".to_owned(), p.goldtx),
            };
            ui.label(RichText::new(status).color(color));
            muted(ui, p, local_time(&fix.when));
            if details {
                ui.add(egui::Label::new(RichText::new(&fix.command).monospace()).selectable(true));
            }
        });
    }
    ui.add_space(8.0);
    section(ui, "Scans");
    for scan in report.history.scans.iter().rev() {
        card(ui, p, |ui| {
            ui.label(RichText::new(local_time(&scan.when)).strong());
            muted(ui, p, scope(&scan.scope, details));
            ui.label(format!(
                "{} · {} · {}",
                plural(scan.fails, "problem", "problems"),
                plural(scan.warns, "warning", "warnings"),
                plural(
                    scan.unchecked,
                    "check did not finish",
                    "checks did not finish"
                ),
            ));
        });
    }
    if report.history.scans.is_empty() {
        ui.label("There are no scans in this time range.");
    }
    ui.add_space(8.0);
    section(ui, "Fixed problems");
    let mut found = false;
    for exposure in report.history.exposures.iter().rev() {
        if let Some(when) = exposure.resolved.as_deref() {
            found = true;
            card(ui, p, |ui| {
                ui.label(RichText::new(&exposure.finding.component).strong());
                let when = local_time(when);
                muted(
                    ui,
                    p,
                    if details {
                        format!("{} · {when}", exposure.finding.vuln_id)
                    } else {
                        format!("No longer found since {when}")
                    },
                );
            });
        }
    }
    if !found {
        ui.label("No problems were confirmed fixed in this time range.");
    }
}
