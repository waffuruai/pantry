//! Latest scan: every finding the last scan saw, with the filters and the
//! summary.

use super::earlier::dismissed;
use super::history::history;
use super::home::home;
use super::text::{display_name, display_path, home_dir, matches_search, one_line, scope};
use super::theme::semibold;
use super::widgets::{card, dispatch, layout, muted, paint_pill, plural, severity, tag};
use super::{FOCUS_SEARCH, SEARCH_ID};
use crate::app::{Action, App, Filter, Page};
use crate::brand::Palette;
use crate::data::{Finding, Report, local_time};
use eframe::egui::{self, FontId, RichText, Sense, Stroke, Ui, Vec2};

pub(super) fn filters(
    ui: &mut Ui,
    app: &App,
    p: &Palette,
    total: usize,
    fixable: usize,
    action: &mut Option<Action>,
) {
    ui.horizontal_wrapped(|ui| {
        for (id, filter, label) in [
            ("findings.filter.all", Filter::All, format!("All ({total})")),
            (
                "findings.filter.fixable",
                Filter::Fixable,
                format!("Can fix ({fixable})"),
            ),
        ] {
            let on = app.state.filter == filter;
            let chip = egui::Button::new(if on {
                RichText::new(label).color(p.ink).strong()
            } else {
                RichText::new(label).color(p.ink2)
            })
            .corner_radius(14)
            .fill(if on { p.sel } else { p.card })
            .stroke(Stroke::new(1.0, if on { p.goldtx } else { p.line2 }));
            let response = ui.push_id(id, |ui| ui.add(chip)).inner;
            tag(ui, &response, id);
            if response.clicked() {
                *action = Some(Action::SetFilter { filter });
            }
        }
        ui.add_space(8.0);
        let mut search = app.state.search.clone();
        let response = ui.add(
            egui::TextEdit::singleline(&mut search)
                .id(egui::Id::unique(SEARCH_ID))
                .hint_text("Search")
                .desired_width(200.0),
        );
        response.widget_info(|| {
            egui::WidgetInfo::labeled(egui::Role::TextInput, true, "Search findings")
        });
        tag(ui, &response, "findings.search");
        if ui
            .ctx()
            .data_mut(|d| d.remove_temp::<bool>(egui::Id::unique(FOCUS_SEARCH)))
            .unwrap_or(false)
        {
            response.request_focus();
        }
        if response.changed() {
            *action = Some(Action::Search { text: search });
        }
    });
}

pub(super) fn results(ui: &mut Ui, app: &mut App, p: &Palette) {
    if app.state.page == Page::History {
        history(ui, app, p);
        return;
    }
    if app.state.page == Page::Attention {
        home(ui, app, p);
        return;
    }
    let attention = false;
    ui.heading("Latest scan");
    let report = app.state.report.as_ref().expect("report shown");
    summary(ui, p, report, attention, app.state.details);
    if !report.skipped().is_empty() {
        skipped(ui, app, p);
    }
    dismissed(ui, app, p);
    let report = app.state.report.as_ref().expect("report shown");
    let mut items: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| !finding.is_skipped())
        .map(|finding| (finding, finding.id.clone()))
        .collect();
    items.sort_by_key(|(finding, _)| finding.priority());
    let fixable = items
        .iter()
        .filter(|(finding, id)| report.can_fix(finding, id))
        .count();
    let total = items.len();
    let mut action = None;
    filters(ui, app, p, total, fixable, &mut action);
    let search = app.state.search.to_lowercase();
    let filter = app.state.filter;
    items.retain(|(finding, id)| {
        matches_search(finding, &search) && (filter == Filter::All || report.can_fix(finding, id))
    });
    if items.is_empty() {
        ui.label(match (total, attention, report.gaps() > 0) {
            (n, _, _) if n > 0 && filter == Filter::Fixable && search.is_empty() => {
                "Nothing here can be fixed automatically. Open a finding to see the steps."
            }
            (n, _, _) if n > 0 => "Nothing matches your search.",
            (_, true, true) => "No open problems. Some checks did not finish.",
            (_, true, false) => "No open problems. You're all set.",
            _ => "This scan found nothing.",
        });
    }
    let mut selected = None;
    // Every row is laid out, inside the page's own scroll area, so each one
    // is in the accessibility tree (screen readers and automation can
    // reach and scroll to rows below the fold) and the page never nests a
    // second scroll area. Rows are painted shapes, cheap even by the
    // thousand.
    // TODO: if reports with tens of thousands of rows show up, page them
    // (with a visible "Show more") rather than hide rows from assistive
    // technology.
    ui.spacing_mut().item_spacing.y = 6.0;
    let details = app.state.details;
    for (finding, id) in &items {
        ui.push_id(id, |ui| {
            if row(ui, p, finding, id, report.can_fix(finding, id), details) {
                selected = Some(id.clone());
            }
        });
    }
    if let Some(id) = selected {
        action = Some(Action::Select { id });
    }
    if let Some(action) = action {
        dispatch(ui, app, action);
    }
}

/// Areas the user chose to leave out, shown once and calmly: not a problem
/// and not an unfinished check. The checkbox is the way back in.
fn skipped(ui: &mut Ui, app: &mut App, p: &Palette) {
    let enabled = app.busy().is_none();
    let mut include = app.state.include_personal_files;
    let mut changed = false;
    card(ui, p, |ui| {
        let note = ui.label("Skipped by your choice: personal folders");
        tag(ui, &note, "scan.skipped");
        muted(
            ui,
            p,
            "Documents, Desktop and Downloads were not checked because you asked Pantry to skip them.",
        );
        let access = ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut include, "Include them in the next scan"),
        );
        tag(ui, &access, "scan.skipped.include");
        changed = access.changed();
    });
    ui.add_space(4.0);
    if changed {
        dispatch(ui, app, Action::SetPersonalFiles { include });
    }
}

fn summary(ui: &mut Ui, p: &Palette, report: &Report, attention: bool, details: bool) {
    card(ui, p, |ui| {
        let when = local_time(&report.scan.when);
        muted(
            ui,
            p,
            if details {
                format!(
                    "{} · {when} · scan #{}",
                    scope(&report.scan.scope, true),
                    report.scan.id
                )
            } else {
                format!("Last scan {when}")
            },
        );
        if attention {
            let count = report.open().len() as i64;
            ui.label(RichText::new(plural(count, "open problem", "open problems")).strong());
        } else {
            ui.label(format!(
                "{} · {}",
                plural(report.scan.fails, "problem", "problems"),
                plural(report.warnings(), "warning", "warnings")
            ));
        }
        if report.gaps() > 0 {
            let count = report.gaps();
            ui.label(
                RichText::new(format!(
                    "{} in the latest scan",
                    plural(count, "check did not finish", "checks did not finish")
                ))
                .color(p.goldtx),
            );
        }
        if report.unfixed > 0 {
            ui.label(format!(
                "{} no fix released yet",
                plural(
                    report.unfixed,
                    "security notice has",
                    "security notices have"
                )
            ));
        }
        if !attention && !report.checked.is_empty() {
            muted(
                ui,
                p,
                report
                    .checked
                    .iter()
                    .map(|(label, count)| format!("{count} {label}"))
                    .collect::<Vec<_>>()
                    .join(" · "),
            );
        }
    });
    ui.add_space(4.0);
}

fn row(
    ui: &mut Ui,
    p: &Palette,
    finding: &Finding,
    id: &str,
    fixable: bool,
    details: bool,
) -> bool {
    let name = if finding.component.trim().is_empty() {
        one_line(&finding.vuln_id, 80)
    } else {
        display_name(finding)
    };
    let name = name.as_str();
    let (level, color, shape) = severity(p, finding);
    let place = display_path(&one_line(&finding.location, 400), home_dir().as_deref(), 80);
    let secondary = if finding.location.is_empty() {
        if details {
            one_line(&finding.vuln_id, 80)
        } else {
            String::new()
        }
    } else if details && !finding.vuln_id.is_empty() {
        format!("{place} · {}", one_line(&finding.vuln_id, 80))
    } else {
        place
    };
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 58.0), Sense::click());
    let hovered = response.hovered() || response.has_focus();
    let painter = ui.painter();
    painter.rect(
        rect,
        10.0,
        if hovered { p.sel } else { p.panel },
        Stroke::new(1.0, if hovered { p.line2 } else { p.line }),
        egui::StrokeKind::Inside,
    );
    // Right side: severity, then the Can fix badge.
    let mut right = rect.right() - 12.0;
    let pill_width = |text: &str, dot: bool| {
        layout(ui, text, FontId::proportional(12.5), color, 400.0)
            .size()
            .x
            + if dot { 34.0 } else { 20.0 }
    };
    let level_width = pill_width(level, true);
    right -= level_width;
    paint_pill(
        ui,
        egui::pos2(right, rect.center().y),
        level,
        color,
        Some(shape),
    );
    if fixable {
        let width = pill_width("Can fix", false);
        right -= width + 6.0;
        paint_pill(
            ui,
            egui::pos2(right, rect.center().y),
            "Can fix",
            p.green,
            None,
        );
    }
    let text_width = right - rect.left() - 28.0;
    let title = layout(ui, name, FontId::new(15.0, semibold()), p.ink, text_width);
    let painter = ui.painter();
    let top = if secondary.is_empty() {
        rect.center().y - title.size().y / 2.0
    } else {
        rect.top() + 9.0
    };
    painter.galley(egui::pos2(rect.left() + 14.0, top), title, p.ink);
    if !secondary.is_empty() {
        let line = layout(
            ui,
            &secondary,
            FontId::proportional(12.5),
            p.ink2,
            text_width,
        );
        ui.painter().galley(
            egui::pos2(rect.left() + 14.0, rect.top() + 32.0),
            line,
            p.ink2,
        );
    }
    let label = format!("{name}, {level}{}", if fixable { ", can fix" } else { "" });
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
    tag(ui, &response, &format!("finding.{id}"));
    response.clicked()
}
