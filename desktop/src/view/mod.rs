//! The egui view. Every interactive control carries an AccessKit author id
//! (see `tag`), which the `--automation` driver and screen readers use.
//! Layout and tokens follow Uchi: blue-slate surfaces, gold primary
//! buttons, 14 px cards, dotted pills.

use crate::app::{Action, App, Page};
use crate::brand::Palette;
use banners::{fix_result, problem, progress};
use detail::detail;
use eframe::egui::{self, FontId, Frame, Key, KeyboardShortcut, Modifiers, RichText, Stroke, Ui};
use home::welcome;
use results::results;
use sidebar::sidebar;
use theme::{semibold, visuals};
use widgets::{button, dispatch, tag};

mod banners;
mod batch;
mod detail;
mod earlier;
mod history;
mod home;
mod results;
mod sidebar;
mod text;
mod theme;
mod widgets;

pub use home::{ROW_TEXT, RowText};
pub use text::plain_sentence;
pub use theme::setup;

const ANIMATE: &str = "pantry.animate";
const FOCUS_SEARCH: &str = "pantry.focus_search";
pub const SEARCH_ID: &str = "pantry.search";

pub fn draw(ui: &mut Ui, app: &mut App) {
    let ctx = ui.ctx().clone();
    app.follow_system_theme(&ctx);
    let animate = ctx.data(|d| {
        d.get_temp::<bool>(egui::Id::unique(ANIMATE))
            .unwrap_or(true)
    });
    let target = if app.state.light { 1.0 } else { 0.0 };
    let t = if animate {
        ctx.animate_value_with_time(egui::Id::unique("pantry.theme"), target, 0.22)
    } else {
        target
    };
    let p = Palette::lerp(&Palette::dark(), &Palette::light(), t);
    ctx.set_visuals(visuals(&p));
    shortcuts(ui, app);
    let enabled = app.busy().is_none();
    header(ui, app, &p, enabled);
    sidebar(ui, app, &p, enabled);
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(p.bg).inner_margin(22))
        .show(ui, |ui| {
            progress(ui, app, &p);
            problem(ui, app, &p);
            fix_result(ui, app, &p);
            if app.busy().is_none() && !app.state.status.is_empty() {
                let status = ui.label(RichText::new(app.state.status.as_str()).color(p.ink2));
                tag(ui, &status, "status.message");
            }
            let scroll_key = match app.state.selected.as_deref() {
                Some(id) => egui::IdSalt::new(("detail", id)),
                None => egui::IdSalt::new(("page", app.state.page as u8)),
            };
            egui::ScrollArea::vertical()
                .id_salt(scroll_key)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if app.selected().is_some() {
                        detail(ui, app, &p, enabled);
                    } else if app.state.report.is_none() {
                        welcome(ui, app, &p, enabled);
                    } else {
                        results(ui, app, &p);
                    }
                });
        });
}

/// Esc goes back or closes, Cmd/Ctrl+R scans, Cmd/Ctrl+F finds.
fn shortcuts(ui: &Ui, app: &mut App) {
    let (escape, scan, find) = ui.ctx().input_mut(|input| {
        (
            input.consume_key(Modifiers::NONE, Key::Escape),
            input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::R)),
            input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::F)),
        )
    });
    if escape {
        let action = if app.state.pending_fix.is_some() {
            Some(Action::CancelFix)
        } else if app
            .state
            .batch
            .as_ref()
            .is_some_and(|b| b.stage == crate::app::BatchStage::Confirm)
        {
            Some(Action::CancelFixAll)
        } else if app.state.selected.is_some() {
            Some(Action::CloseFinding)
        } else if app.state.editing_schedule {
            Some(Action::EditSchedule { open: false })
        } else if app.state.error.is_some() {
            Some(Action::DismissError)
        } else {
            None
        };
        if let Some(action) = action {
            dispatch(ui, app, action);
        }
    }
    if scan && app.busy().is_none() && app.state.scanner_found {
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
    if find && app.state.report.is_some() {
        if app.state.selected.is_some() {
            dispatch(ui, app, Action::CloseFinding);
        }
        if app.state.page == Page::History {
            dispatch(
                ui,
                app,
                Action::Show {
                    page: Page::Attention,
                },
            );
        }
        ui.ctx()
            .data_mut(|d| d.insert_temp(egui::Id::unique(FOCUS_SEARCH), true));
    }
}

fn header(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    egui::Panel::top("pantry.header")
        .frame(
            Frame::NONE
                .fill(p.panel)
                .stroke(Stroke::new(1.0, p.line))
                .inner_margin(egui::Margin::symmetric(20, 12)),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                crate::brand::draw(ui);
                ui.label(RichText::new("Pantry").font(FontId::new(20.0, semibold())));
                ui.add_space(14.0);
                let open = app.state.report.as_ref().map_or(0, |r| r.open().len());
                for (id, page, label) in [
                    (
                        "nav.attention",
                        Page::Attention,
                        if open > 0 {
                            format!("Needs attention ({open})")
                        } else {
                            "Needs attention".to_owned()
                        },
                    ),
                    ("nav.results", Page::Results, "Latest scan".to_owned()),
                    ("nav.history", Page::History, "History".to_owned()),
                ] {
                    let selected = app.state.page == page && app.state.selected.is_none();
                    let text = if selected {
                        RichText::new(label).color(p.ink).strong()
                    } else {
                        RichText::new(label).color(p.ink2)
                    };
                    let tab = egui::Button::new(text).frame_when_inactive(selected);
                    let tab = if selected { tab.fill(p.sel) } else { tab };
                    let response = ui.push_id(id, |ui| ui.add(tab)).inner;
                    tag(ui, &response, id);
                    if selected {
                        ui.ctx().accesskit_node_builder(response.id, |node| {
                            node.set_description("Current page");
                        });
                    }
                    if response.clicked() {
                        dispatch(ui, app, Action::Show { page });
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if button(
                        ui,
                        p,
                        "scan.run",
                        "Scan now",
                        enabled && app.state.scanner_found,
                        true,
                    ) {
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
                });
            });
        });
}
