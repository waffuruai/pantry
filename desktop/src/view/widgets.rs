//! Small drawing helpers every page uses: tagged buttons and links, cards,
//! severity shapes and pills, wrapped text.

use super::theme::semibold;
use crate::app::{Action, App};
use crate::brand::{Palette, tint};
use crate::data::Finding;
use eframe::egui::{self, Color32, FontId, Frame, RichText, Sense, Stroke, Ui, Vec2};
use std::sync::Arc;

/// Put an automation id on a widget's AccessKit node.
pub(super) fn tag(ui: &Ui, response: &egui::Response, id: &str) {
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_author_id(id.to_owned()));
}

pub(super) fn section(ui: &mut Ui, label: &str) {
    ui.label(RichText::new(label).font(FontId::new(16.0, semibold())));
}

pub(super) fn muted(ui: &mut Ui, p: &Palette, text: impl Into<String>) -> egui::Response {
    ui.label(RichText::new(text.into()).color(p.ink2))
}

pub(super) fn plural(count: i64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

pub(super) fn button(
    ui: &mut Ui,
    p: &Palette,
    id: &str,
    label: &str,
    enabled: bool,
    primary: bool,
) -> bool {
    let text = RichText::new(label);
    let button = if primary && enabled {
        egui::Button::new(text.color(p.on_gold).strong())
            .fill(p.gold)
            .stroke(Stroke::NONE)
    } else {
        egui::Button::new(text)
    };
    let response = ui
        .push_id(id, |ui| {
            ui.add_enabled(enabled, button.min_size(Vec2::new(0.0, 32.0)))
        })
        .inner;
    tag(ui, &response, id);
    response.clicked()
}

/// A text link. It never wraps: a short label like "Hide details" broken
/// over two lines in a row reads as two links.
pub(super) fn link(ui: &mut Ui, id: &str, label: &str) -> bool {
    let response = ui
        .push_id(id, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            ui.link(label)
        })
        .inner;
    tag(ui, &response, id);
    response.clicked()
}

pub(super) fn dispatch(ui: &Ui, app: &mut App, action: Action) {
    if let Err(error) = app.dispatch(action, ui.ctx()) {
        app.state.error = Some(crate::pantry::Problem::notice(error));
    }
}

pub(super) fn card<R>(ui: &mut Ui, p: &Palette, body: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::NONE
        .fill(p.panel)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(14)
        .inner_margin(18)
        .shadow(egui::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(if p.dark { 60 } else { 18 }),
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            body(ui)
        })
        .inner
}

/// A severity in words, colour and shape, so it never relies on colour.
#[derive(Clone, Copy)]
pub(super) enum Shape {
    Diamond,
    Dot,
    Ring,
    Small,
}

pub(super) fn severity(p: &Palette, finding: &Finding) -> (&'static str, Color32, Shape) {
    if finding.kind == "unchecked" {
        return ("Not checked", p.ink2, Shape::Ring);
    }
    if crate::explain::is_malicious(finding) {
        return ("Known harmful", p.red, Shape::Diamond);
    }
    if finding.kev {
        return ("Being used in attacks now", p.red, Shape::Diamond);
    }
    match finding.severity.to_ascii_lowercase().as_str() {
        "critical" => ("Critical", p.red, Shape::Diamond),
        "high" => ("High", p.goldtx, Shape::Dot),
        "medium" => ("Medium", p.blue, Shape::Ring),
        "low" => ("Low", p.ink2, Shape::Small),
        _ => ("Notice", p.ink2, Shape::Small),
    }
}

pub(super) fn paint_shape(
    painter: &egui::Painter,
    center: egui::Pos2,
    shape: Shape,
    color: Color32,
) {
    match shape {
        Shape::Diamond => {
            let r = 4.5;
            painter.add(egui::Shape::convex_polygon(
                vec![
                    center + Vec2::new(0.0, -r),
                    center + Vec2::new(r, 0.0),
                    center + Vec2::new(0.0, r),
                    center + Vec2::new(-r, 0.0),
                ],
                color,
                Stroke::NONE,
            ));
        }
        Shape::Dot => {
            painter.circle_filled(center, 4.0, color);
        }
        Shape::Ring => {
            painter.circle_stroke(center, 3.5, Stroke::new(1.5, color));
        }
        Shape::Small => {
            painter.circle_filled(center, 2.5, color);
        }
    }
}

pub(super) fn layout(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    width: f32,
) -> Arc<egui::Galley> {
    layout_rows(ui, text, font, color, width, 1)
}

/// Lay out `text` in at most `rows` lines of `width`, ending in "…" only
/// when it needs more than that.
pub(super) fn layout_rows(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    width: f32,
    rows: usize,
) -> Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat {
            font_id: font,
            color,
            ..Default::default()
        },
    );
    job.wrap = egui::text::TextWrapping {
        max_rows: rows.max(1),
        // One line cuts anywhere; more lines break between words.
        break_anywhere: rows <= 1,
        ..egui::text::TextWrapping::truncate_at_width(width.max(1.0))
    };
    ui.ctx().fonts_mut(|fonts| fonts.layout_job(job))
}

/// Paint a pill at `left_center`; returns its width.
pub(super) fn paint_pill(
    ui: &Ui,
    left_center: egui::Pos2,
    text: &str,
    color: Color32,
    shape: Option<Shape>,
) -> f32 {
    let galley = layout(ui, text, FontId::proportional(12.5), color, 400.0);
    let dot = if shape.is_some() { 14.0 } else { 0.0 };
    let size = Vec2::new(galley.size().x + dot + 20.0, 22.0);
    let rect = egui::Rect::from_min_size(left_center - Vec2::new(0.0, size.y / 2.0), size);
    let painter = ui.painter();
    painter.rect_filled(rect, 11.0, tint(color, 0.14));
    if let Some(shape) = shape {
        paint_shape(
            painter,
            rect.left_center() + Vec2::new(14.0, 0.0),
            shape,
            color,
        );
    }
    painter.galley(
        rect.left_center() + Vec2::new(10.0 + dot, -galley.size().y / 2.0),
        galley,
        color,
    );
    size.x
}

/// A pill as its own labelled (non-interactive) widget.
pub(super) fn pill(ui: &mut Ui, text: &str, color: Color32, shape: Option<Shape>) {
    let width = layout(ui, text, FontId::proportional(12.5), color, 400.0)
        .size()
        .x
        + if shape.is_some() { 34.0 } else { 20.0 };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::hover());
    paint_pill(ui, rect.left_center(), text, color, shape);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
}
