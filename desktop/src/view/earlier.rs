//! Problems from earlier scans of other folders, and the dismissed ones.

use super::plain_sentence;
use super::text::scope_place;
use super::theme::semibold;
use super::widgets::{button, card, dispatch, link, muted, pill, severity, tag};
use crate::app::{Action, App};
use crate::brand::Palette;
use eframe::egui::{FontId, RichText, Ui};

/// "From earlier scans": problems earlier scans found that no scan has
/// cleared since. Never in the headline; each can be scanned again or
/// dismissed (Latest scan shows the dismissed ones again). One that
/// attackers are using carries the same pill as a home row, so it stands
/// out although it is not counted.
pub(super) fn earlier(
    ui: &mut Ui,
    app: &App,
    p: &Palette,
    enabled: bool,
    action: &mut Option<Action>,
) {
    let Some(report) = app.state.report.as_ref() else {
        return;
    };
    let rows = report.earlier(&app.state.settings.dismissed);
    if rows.is_empty() {
        return;
    }
    ui.add_space(10.0);
    let heading = ui.label(RichText::new("From earlier scans").font(FontId::new(16.0, semibold())));
    tag(ui, &heading, "earlier.heading");
    let intro = muted(
        ui,
        p,
        "Earlier scans found these, and no scan has checked them again since. They are not in the count above.",
    );
    tag(ui, &intro, "earlier.intro");
    for exposure in rows {
        let id = &exposure.finding.id;
        let missing = crate::pantry::missing_folders(&exposure.scope);
        let repeatable = crate::pantry::ScanRequest::for_scope(&exposure.scope, false).is_some();
        let machine = exposure.scope.starts_with("machine:");
        ui.push_id(("earlier", id), |ui| {
            card(ui, p, |ui| {
                let (level, color, shape) = severity(p, &exposure.finding);
                ui.horizontal_wrapped(|ui| {
                    pill(ui, level, color, Some(shape));
                    let text = ui.label(plain_sentence(&exposure.finding));
                    tag(ui, &text, &format!("earlier.{id}"));
                });
                let found = if exposure.scope.is_empty() {
                    "Found by an earlier scan.".to_owned()
                } else {
                    format!("Found in: {}", scope_place(&exposure.scope))
                };
                let found = muted(ui, p, found);
                tag(ui, &found, &format!("earlier.{id}.scope"));
                if !missing.is_empty() {
                    let gone = ui.label(
                        RichText::new(
                            "That folder is no longer there. Choose Dismiss to hide this.",
                        )
                        .color(p.goldtx),
                    );
                    tag(ui, &gone, &format!("earlier.{id}.missing"));
                }
                if missing.is_empty() && !repeatable {
                    let why = muted(
                        ui,
                        p,
                        "Pantry cannot repeat this kind of scan from here. Choose Scan now at the top to check this computer again.",
                    );
                    tag(ui, &why, &format!("earlier.{id}.cannot_repeat"));
                }
                ui.horizontal_wrapped(|ui| {
                    if missing.is_empty()
                        && repeatable
                        && button(
                            ui,
                            p,
                            &format!("earlier.{id}.rescan"),
                            if machine {
                                "Scan this computer again"
                            } else {
                                "Scan that folder again"
                            },
                            enabled && app.state.scanner_found,
                            false,
                        )
                    {
                        *action = Some(Action::RescanEarlier { id: id.clone() });
                    }
                    if button(
                        ui,
                        p,
                        &format!("earlier.{id}.dismiss"),
                        "Dismiss",
                        true,
                        false,
                    ) {
                        *action = Some(Action::DismissEarlier { id: id.clone() });
                    }
                    if link(ui, &format!("earlier.{id}.how"), "Show me how") {
                        *action = Some(Action::Select {
                            id: format!("earlier-{id}"),
                        });
                    }
                });
            });
        });
    }
}

/// Dismissed problems from earlier scans, with the way to show them again.
pub(super) fn dismissed(ui: &mut Ui, app: &mut App, p: &Palette) {
    let Some(report) = app.state.report.as_ref() else {
        return;
    };
    let hidden: Vec<(String, String)> = report
        .earlier_all()
        .into_iter()
        .filter(|e| app.state.settings.dismissed.contains(&e.finding.id))
        .map(|e| (e.finding.id.clone(), plain_sentence(&e.finding)))
        .collect();
    if hidden.is_empty() {
        return;
    }
    let mut action = None;
    card(ui, p, |ui| {
        let title = ui.label(format!("Dismissed from earlier scans ({})", hidden.len()));
        tag(ui, &title, "earlier.dismissed");
        muted(
            ui,
            p,
            "Pantry hides these on the home page. The scan history still has them.",
        );
        for (id, sentence) in &hidden {
            ui.horizontal_wrapped(|ui| {
                ui.label(sentence.as_str());
                if button(
                    ui,
                    p,
                    &format!("earlier.{id}.restore"),
                    "Show again",
                    true,
                    false,
                ) {
                    action = Some(Action::RestoreEarlier { id: id.clone() });
                }
            });
        }
    });
    ui.add_space(4.0);
    if let Some(action) = action {
        dispatch(ui, app, action);
    }
}
