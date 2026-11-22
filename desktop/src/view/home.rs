//! The first-run welcome and the home page: the headline and one row per
//! problem.

use super::batch::{FIX_REQUESTED, batch, fix_requested};
use super::earlier::earlier;
use super::plain_sentence;
use super::results::filters;
use super::sidebar::personal_folders;
use super::text::{display_path, home_dir, matches_search, one_line, scope, urgent};
use super::theme::semibold;
use super::widgets::{
    button, card, dispatch, layout, layout_rows, muted, paint_pill, plural, section, severity, tag,
};
use crate::app::{Action, App, Filter};
use crate::brand::Palette;
use crate::data::{Finding, local_time};
use eframe::egui::{self, FontId, RichText, Sense, Stroke, Ui, Vec2};

/// First run: what Pantry checks, what it won't do, and one big button.
pub(super) fn welcome(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    if app.state.report_error.is_some() {
        return;
    }
    let mut start = false;
    card(ui, p, |ui| {
        ui.heading("Welcome to Pantry");
        ui.label("Pantry looks for known security problems on this computer:");
        for line in [
            "Apps you installed",
            "Developer tools and their versions",
            "Your projects and the packages they use",
            "Secrets such as passwords or keys saved in project files",
        ] {
            ui.label(format!("  •  {line}"));
        }
        ui.add_space(8.0);
        // The button comes before the longer text, so it stays in view at
        // the smallest window size with the personal folders list shown.
        let response = ui
            .push_id("scan.first", |ui| {
                ui.add_enabled(
                    enabled && app.state.scanner_found,
                    egui::Button::new(
                        RichText::new("Run first scan")
                            .size(17.0)
                            .color(p.on_gold)
                            .strong(),
                    )
                    .fill(p.gold)
                    .stroke(Stroke::NONE)
                    .min_size(Vec2::new(200.0, 44.0)),
                )
            })
            .inner;
        muted(
            ui,
            p,
            "The first scan can take a few minutes. You can keep using your computer.",
        );
        if cfg!(target_os = "macos") {
            ui.add_space(4.0);
            section(ui, "Personal folders");
            personal_folders(ui, app, p, enabled);
        }
        ui.add_space(4.0);
        section(ui, "What Pantry won't do");
        ui.label("It never changes anything without your OK. Every fix asks you first.");
        ui.label("Your results stay on this computer. To look up security notices, Pantry sends the names and versions of what it finds to public advisory services. It sends no usage data.");
        tag(ui, &response, "scan.first");
        start = response.clicked();
    });
    if start {
        dispatch(
            ui,
            app,
            Action::Scan {
                path: None,
                offline: false,
                include_personal_files: None,
            },
        );
    }
}

/// The home page: am I OK, what is wrong, how do I fix it.
pub(super) fn home(ui: &mut Ui, app: &mut App, p: &Palette) {
    // Only the rows drawn this frame are recorded.
    ui.ctx()
        .data_mut(|d| d.remove::<RowText>(egui::Id::unique(ROW_TEXT)));
    let enabled = app.busy().is_none();
    let details = app.state.details;
    let report = app.state.report.as_ref().expect("report shown");
    let mut rows: Vec<_> = report
        .open()
        .into_iter()
        .map(|(finding, id)| {
            let fixable = report.can_fix(finding, &id);
            (finding, id, fixable)
        })
        .collect();
    rows.sort_by_key(|(finding, _, fixable)| {
        let (kev, _, severity) = finding.priority();
        (kev, severity, !fixable, finding.status != "fail")
    });
    let fixable = rows.iter().filter(|(_, _, fixable)| *fixable).count();
    let count = rows.len() as i64;
    let mut action = None;
    card(ui, p, |ui| {
        let headline = if count == 0 {
            "Everything checked is up to date".to_owned()
        } else if count == 1 {
            "1 thing needs your attention".to_owned()
        } else {
            format!("{count} things need your attention")
        };
        let title = ui.label(RichText::new(headline).font(FontId::new(24.0, semibold())));
        tag(ui, &title, "home.headline");
        let mut when = format!("Last scan {}", local_time(&report.scan.when));
        if details {
            when.push_str(&format!(
                " · {} · scan #{}",
                scope(&report.scan.scope, true),
                report.scan.id
            ));
        }
        muted(ui, p, when);
        if report.gaps() > 0 {
            ui.label(
                RichText::new(format!(
                    "{}, so this may not be the whole picture.",
                    plural(
                        report.gaps(),
                        "check did not finish",
                        "checks did not finish"
                    )
                ))
                .color(p.goldtx),
            );
        }
        if fixable > 0
            && app.state.batch.is_none()
            && button(
                ui,
                p,
                "fix.all",
                &if fixable == 1 {
                    "Fix the 1 that Pantry can fix".to_owned()
                } else {
                    format!("Fix all {fixable} that Pantry can fix")
                },
                enabled && app.state.report_error.is_none(),
                true,
            )
        {
            action = Some(Action::FixAll);
        }
    });
    batch(ui, app, p, &mut action);
    let search = app.state.search.to_lowercase();
    if count > 0 {
        filters(ui, app, p, rows.len(), fixable, &mut action);
    }
    let filter = app.state.filter;
    rows.retain(|(finding, _, can)| {
        matches_search(finding, &search) && (filter == Filter::All || *can)
    });
    // Rows that would read the same (one advisory in two projects) say
    // where each one is.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (finding, _, _) in &rows {
        *seen.entry(plain_sentence(finding)).or_default() += 1;
    }
    let place = |finding: &Finding| -> Option<String> {
        (seen.get(&plain_sentence(finding)).copied().unwrap_or(0) > 1
            && !finding.location.trim().is_empty())
        .then(|| {
            format!(
                "In {}",
                display_path(&one_line(&finding.location, 400), home_dir().as_deref(), 60)
            )
        })
    };
    let (now, later): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(f, _, _)| urgent(f));
    if count > 0 && now.is_empty() && later.is_empty() {
        ui.label("Nothing matches.");
    }
    ui.spacing_mut().item_spacing.y = 6.0;
    for (finding, id, can) in &now {
        let place = place(finding);
        ui.push_id(id, |ui| {
            if let Some(a) = home_row(ui, p, finding, id, *can, details, enabled, place.as_deref())
            {
                action = Some(a);
            }
        });
    }
    if !later.is_empty() {
        ui.add_space(6.0);
        let open = app.state.show_lower || now.is_empty();
        let label = format!(
            "{} lower priority ({})",
            if open { "Hide" } else { "Show" },
            later.len()
        );
        if !now.is_empty() && button(ui, p, "findings.lower", &label, true, false) {
            action = Some(Action::ShowLowerPriority { open: !open });
        }
        if open {
            for (finding, id, can) in &later {
                let place = place(finding);
                ui.push_id(id, |ui| {
                    if let Some(a) =
                        home_row(ui, p, finding, id, *can, details, enabled, place.as_deref())
                    {
                        action = Some(a);
                    }
                });
            }
        }
    }
    earlier(ui, app, p, enabled, &mut action);
    if let Some(action) = action {
        let preview = matches!(action, Action::Select { .. }) && fix_requested(ui);
        dispatch(ui, app, action);
        if preview {
            dispatch(ui, app, Action::PreviewFix);
        }
    }
}

/// Lines a home row's sentence may take before it is cut.
pub const ROW_LINES: usize = 2;
/// Where each home row records how its sentence was laid out, for the
/// automation driver: finding id to (lines, cut short).
pub const ROW_TEXT: &str = "pantry.row_text";
pub type RowText = std::collections::BTreeMap<String, (usize, bool)>;

/// A home row: one sentence, how serious, and its own action. `place`
/// ("In ~/Projects/site") tells apart rows that would otherwise read the
/// same.
#[allow(clippy::too_many_arguments)]
fn home_row(
    ui: &mut Ui,
    p: &Palette,
    finding: &Finding,
    id: &str,
    fixable: bool,
    details: bool,
    enabled: bool,
    place: Option<&str>,
) -> Option<Action> {
    let (level, color, shape) = severity(p, finding);
    let sentence = plain_sentence(finding);
    let secondary = if details {
        let location = display_path(&one_line(&finding.location, 400), home_dir().as_deref(), 80);
        [
            one_line(&finding.vuln_id, 80),
            one_line(&finding.version, 40),
            location,
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
    } else {
        place.unwrap_or_default().to_owned()
    };
    // The row's own button, on the right.
    let (label, button_id) = if fixable {
        ("Fix it", format!("finding.{id}.fix"))
    } else {
        ("Show me how", format!("finding.{id}.how"))
    };
    let galley_width = layout(ui, label, FontId::proportional(14.0), p.ink, 300.0)
        .size()
        .x;
    // The sentence wraps to two lines and is cut only past that, so the
    // consequence stays readable at the smallest window. The row grows to
    // fit; the button stays centred.
    let text_width = ui.available_width() - 14.0 - (galley_width + 36.0) - 12.0;
    let line = layout_rows(
        ui,
        &sentence,
        FontId::proportional(14.5),
        p.ink,
        text_width,
        ROW_LINES,
    );
    let lines = line.rows.len().max(1);
    let extra = line.size().y - line.size().y / lines as f32;
    ui.ctx().data_mut(|d| {
        d.get_temp_mut_or_default::<RowText>(egui::Id::unique(ROW_TEXT))
            .insert(id.to_owned(), (lines, line.elided));
    });
    let height = if secondary.is_empty() { 60.0 } else { 74.0 } + extra;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());
    let hovered = response.hovered() || response.has_focus();
    ui.painter().rect(
        rect,
        10.0,
        if hovered { p.sel } else { p.panel },
        Stroke::new(1.0, if hovered { p.line2 } else { p.line }),
        egui::StrokeKind::Inside,
    );
    let button_rect = egui::Rect::from_min_size(
        egui::pos2(rect.right() - galley_width - 36.0, rect.center().y - 16.0),
        Vec2::new(galley_width + 24.0, 32.0),
    );
    let action_button = if fixable && enabled {
        egui::Button::new(RichText::new(label).color(p.on_gold).strong())
            .fill(p.gold)
            .stroke(Stroke::NONE)
    } else {
        egui::Button::new(label)
    };
    let action_button = action_button.wrap_mode(egui::TextWrapMode::Extend);
    let pressed = ui
        .push_id("action", |ui| {
            // While a task runs, Fix it is disabled for clicks and for
            // assistive technology alike.
            if fixable && !enabled {
                ui.disable();
            }
            ui.put(button_rect, action_button)
        })
        .inner;
    tag(ui, &pressed, &button_id);
    let left = rect.left() + 14.0;
    let text_right = button_rect.left() - 12.0;
    let width = paint_pill(
        ui,
        egui::pos2(left, rect.top() + 18.0),
        level,
        color,
        Some(shape),
    );
    let mut chips = left + width + 6.0;
    if fixable {
        chips += paint_pill(
            ui,
            egui::pos2(chips, rect.top() + 18.0),
            "Can fix",
            p.green,
            None,
        ) + 6.0;
    }
    // The public id, quietly, so people can search for it.
    let public_id = crate::explain::identifiers(finding)
        .into_iter()
        .next()
        .map(|i| i.id);
    if let Some(public_id) = &public_id {
        paint_pill(
            ui,
            egui::pos2(chips, rect.top() + 18.0),
            public_id,
            p.ink2,
            None,
        );
    }
    ui.painter()
        .galley(egui::pos2(left, rect.top() + 32.0), line, p.ink);
    if !secondary.is_empty() {
        let small = layout(
            ui,
            &secondary,
            FontId::proportional(12.0),
            p.ink2,
            text_right - left,
        );
        ui.painter()
            .galley(egui::pos2(left, rect.top() + 52.0 + extra), small, p.ink2);
    }
    let label = format!(
        "{sentence} {level}.{}{}{}",
        place.map(|place| format!(" {place}.")).unwrap_or_default(),
        if fixable { " Pantry can fix this." } else { "" },
        public_id.map(|id| format!(" {id}.")).unwrap_or_default()
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
    tag(ui, &response, &format!("finding.{id}"));
    // Past two lines the sentence is cut; the whole of it is on hover.
    let response = response.on_hover_text(&sentence);
    if pressed.clicked() {
        if fixable {
            ui.ctx()
                .data_mut(|d| d.insert_temp(egui::Id::unique(FIX_REQUESTED), true));
        }
        return Some(Action::Select { id: id.to_owned() });
    }
    response
        .clicked()
        .then(|| Action::Select { id: id.to_owned() })
}
