//! The egui view. Every interactive control carries an AccessKit author id
//! (see `tag`), which the `--automation` driver and screen readers use.
//! Layout and tokens follow Uchi: blue-slate surfaces, gold primary
//! buttons, 14 px cards, dotted pills.

use crate::app::{Action, App, Filter, Outcome, Page};
use crate::brand::{Palette, tint};
use crate::data::{Finding, Period, Report, local_time};
use crate::pantry::ProblemKind;
use eframe::egui::{
    self, Color32, FontFamily, FontId, Frame, Key, KeyboardShortcut, Modifiers, RichText, Sense,
    Stroke, TextStyle, Ui, Vec2, accesskit as ax, epaint::text::FontInsert,
};
use std::sync::{Arc, OnceLock};

const ANIMATE: &str = "pantry.animate";
const FOCUS_SEARCH: &str = "pantry.focus_search";
pub const SEARCH_ID: &str = "pantry.search";

fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

/// Bundled Geist covers Latin. egui's defaults (Ubuntu-Light, Hack) add
/// Greek and Cyrillic. For anything else, such as a Japanese folder name,
/// a system font is loaded only when a missing character first appears.
const FALLBACK_FONTS: &[(&str, u32)] = &[
    ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0),
    ("/System/Library/Fonts/Hiragino Sans GB.ttc", 0),
    ("C:\\Windows\\Fonts\\segoeui.ttf", 0),
    ("C:\\Windows\\Fonts\\msyh.ttc", 0),
    ("C:\\Windows\\Fonts\\YuGothR.ttc", 0),
    ("C:\\Windows\\Fonts\\malgun.ttf", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", 0),
    (
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        0,
    ),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),
];

fn fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let sets: [(&str, FontFamily, &[u8]); 3] = [
        (
            "geist",
            FontFamily::Proportional,
            include_bytes!("../fonts/geist-latin-wght-normal.ttf"),
        ),
        (
            "geist-semibold",
            semibold(),
            include_bytes!("../fonts/geist-latin-semibold.ttf"),
        ),
        (
            "geist-mono",
            FontFamily::Monospace,
            include_bytes!("../fonts/geist-mono-latin-wght-normal.ttf"),
        ),
    ];
    fonts.families.insert(
        semibold(),
        fonts.families[&FontFamily::Proportional].clone(),
    );
    for (name, family, data) in sets {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(egui::FontData::from_static(data)));
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, name.to_owned());
    }
    ctx.set_fonts(fonts);
    // One provider per candidate file: epaint skips a font without the
    // glyph and asks the next provider.
    for (index, (path, face)) in FALLBACK_FONTS.iter().enumerate() {
        static LOADED: [OnceLock<Option<&'static [u8]>>; 10] = [const { OnceLock::new() }; 10];
        let (path, face) = (*path, *face);
        ctx.add_font_provider(Arc::new(
            move |_: &egui::epaint::text::FallbackRequest<'_>| -> Option<FontInsert> {
                // Read once, keep for the life of the app; never on the
                // common all-Latin path.
                let bytes: &'static [u8] = (*LOADED[index].get_or_init(|| {
                    std::fs::read(path)
                        .ok()
                        .map(|bytes| &*Box::leak(bytes.into_boxed_slice()))
                }))?;
                let mut data = egui::FontData::from_static(bytes);
                data.index = face;
                Some(FontInsert::new(&format!("system:{path}"), data, Vec::new()))
            },
        ));
    }
}

/// Fonts, icon and text styles. `animate` is false under automation, so
/// the theme switches at once.
pub fn setup(ctx: &egui::Context, animate: bool) {
    fonts(ctx);
    crate::brand::setup(ctx);
    ctx.data_mut(|d| d.insert_temp(egui::Id::unique(ANIMATE), animate));
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.style_mut_of(theme, |style| {
            style
                .text_styles
                .insert(TextStyle::Body, FontId::proportional(15.0));
            style
                .text_styles
                .insert(TextStyle::Button, FontId::proportional(14.0));
            style
                .text_styles
                .insert(TextStyle::Small, FontId::proportional(12.5));
            style
                .text_styles
                .insert(TextStyle::Heading, FontId::new(24.0, semibold()));
            style
                .text_styles
                .insert(TextStyle::Monospace, FontId::monospace(13.0));
            style.spacing.item_spacing = Vec2::new(8.0, 8.0);
            style.spacing.button_padding = Vec2::new(12.0, 6.0);
            style.spacing.interact_size.y = 30.0;
        });
    }
}

/// egui visuals matching the palette (Uchi's `theme::visuals`, plus
/// Pantry's button colours).
fn visuals(p: &Palette) -> egui::Visuals {
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.panel;
    v.window_stroke = Stroke::new(1.0, p.line2);
    v.override_text_color = Some(p.ink);
    v.hyperlink_color = p.goldtx;
    v.selection.bg_fill = tint(p.gold, 0.35);
    v.selection.stroke = Stroke::new(1.0, p.goldtx);
    v.text_cursor.stroke = Stroke::new(1.5, p.ink);
    v.extreme_bg_color = p.field;
    v.faint_bg_color = p.card;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
    v.widgets.noninteractive.fg_stroke.color = p.ink2;
    for (widget, fill, stroke) in [
        (&mut v.widgets.inactive, p.card, p.line2),
        (&mut v.widgets.hovered, p.sel, p.goldtx),
        (&mut v.widgets.active, p.sel, p.goldtx),
        (&mut v.widgets.open, p.sel, p.line2),
    ] {
        widget.bg_fill = fill;
        widget.weak_bg_fill = fill;
        widget.bg_stroke = Stroke::new(1.0, stroke);
        widget.fg_stroke.color = p.ink;
        widget.corner_radius = 8.into();
        widget.expansion = 0.0;
    }
    v
}

/// Put an automation id on a widget's AccessKit node.
fn tag(ui: &Ui, response: &egui::Response, id: &str) {
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_author_id(id.to_owned()));
}

fn section(ui: &mut Ui, label: &str) {
    ui.label(RichText::new(label).font(FontId::new(16.0, semibold())));
}

fn muted(ui: &mut Ui, p: &Palette, text: impl Into<String>) -> egui::Response {
    ui.label(RichText::new(text.into()).color(p.ink2))
}

fn plural(count: i64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn button(ui: &mut Ui, p: &Palette, id: &str, label: &str, enabled: bool, primary: bool) -> bool {
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
fn link(ui: &mut Ui, id: &str, label: &str) -> bool {
    let response = ui
        .push_id(id, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            ui.link(label)
        })
        .inner;
    tag(ui, &response, id);
    response.clicked()
}

fn dispatch(ui: &Ui, app: &mut App, action: Action) {
    if let Err(error) = app.dispatch(action, ui.ctx()) {
        app.state.error = Some(crate::pantry::Problem::notice(error));
    }
}

fn card<R>(ui: &mut Ui, p: &Palette, body: impl FnOnce(&mut Ui) -> R) -> R {
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
enum Shape {
    Diamond,
    Dot,
    Ring,
    Small,
}

fn severity(p: &Palette, finding: &Finding) -> (&'static str, Color32, Shape) {
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

fn paint_shape(painter: &egui::Painter, center: egui::Pos2, shape: Shape, color: Color32) {
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

fn layout(ui: &Ui, text: &str, font: FontId, color: Color32, width: f32) -> Arc<egui::Galley> {
    layout_rows(ui, text, font, color, width, 1)
}

/// Lay out `text` in at most `rows` lines of `width`, ending in "…" only
/// when it needs more than that.
fn layout_rows(
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
fn paint_pill(
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
fn pill(ui: &mut Ui, text: &str, color: Color32, shape: Option<Shape>) {
    let width = layout(ui, text, FontId::proportional(12.5), color, 400.0)
        .size()
        .x
        + if shape.is_some() { 34.0 } else { 20.0 };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::hover());
    paint_pill(ui, rect.left_center(), text, color, shape);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
}

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

fn sidebar(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
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
                    muted(ui, p, format!("Pantry {}", env!("CARGO_PKG_VERSION")));
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
    if update.current != env!("CARGO_PKG_VERSION") {
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

fn personal_folders(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
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

/// The running task: what it is doing, for how long, and Cancel.
fn progress(ui: &mut Ui, app: &mut App, p: &Palette) {
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
fn problem(ui: &mut Ui, app: &mut App, p: &Palette) {
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

fn fix_result(ui: &mut Ui, app: &mut App, p: &Palette) {
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

/// First run: what Pantry checks, what it won't do, and one big button.
fn welcome(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
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

fn history(ui: &mut Ui, app: &mut App, p: &Palette) {
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

/// This account's home folder, for showing paths as `~/...`.
fn home_dir() -> Option<String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).ok().filter(|home| home.len() > 1)
}

/// A path as people should read it: the home folder as `~`, and when it is
/// still longer than `max` characters, the middle replaced by `…` so the
/// start and the folder name at the end both stay visible.
///
/// ```ignore
/// display_path("/Users/sam/Projects/site", Some("/Users/sam"), 56) == "~/Projects/site"
/// display_path("/var/folders/y2/abcdefghijklmnop/T/build-1234/project", None, 30)
///     == "/var/folders/…uild-1234/project"
/// ```
pub fn display_path(path: &str, home: Option<&str>, max: usize) -> String {
    let short = home
        .and_then(|home| {
            let rest = path.strip_prefix(home.trim_end_matches(['/', '\\']))?;
            (rest.is_empty() || rest.starts_with(['/', '\\'])).then(|| format!("~{rest}"))
        })
        .unwrap_or_else(|| path.to_owned());
    let chars: Vec<char> = short.chars().collect();
    if chars.len() <= max || max < 8 {
        return short;
    }
    // Keep more of the end: it names the project or file.
    let head = (max - 1) * 2 / 5;
    let tail = max - 1 - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// The longest component name a sentence quotes, in characters.
const NAME_MAX: usize = 40;

/// Scanner text for one line: hidden characters gone, every run of
/// whitespace (newlines included) one space, and at most `max` characters,
/// cut at a word with "…" when longer.
///
/// ```ignore
/// one_line("a\n\n b", 80) == "a b"
/// one_line("one two three", 8) == "one two…"
/// ```
pub fn one_line(text: &str, max: usize) -> String {
    let clean = crate::pantry::clean(text);
    let joined = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max {
        return joined;
    }
    let cut: String = joined.chars().take(max.saturating_sub(1)).collect();
    let cut = match cut.rfind(' ') {
        Some(at) if at > cut.len() / 2 => &cut[..at],
        _ => cut.as_str(),
    };
    format!("{}…", cut.trim_end_matches([' ', ',', ';', ':', '.']))
}

/// A finding's name as sentences quote it: on one line and short, so a
/// long or multi-line name never pushes the rest out of view.
pub fn display_name(finding: &Finding) -> String {
    let name = one_line(&finding.component, NAME_MAX);
    if name.is_empty() {
        "This item".to_owned()
    } else {
        name
    }
}

/// One plain sentence for a finding: what it is and why it matters.
///
/// The "security flaw" and "no fix yet" words belong to published
/// advisories only ([`crate::explain::is_advisory`]); Pantry's own checks
/// lead with what the check found ([`crate::explain::own_lead`]).
pub fn plain_sentence(finding: &Finding) -> String {
    let name = display_name(finding);
    let name = name.as_str();
    let first_sentence = || {
        let note = one_line(&finding.note, 400);
        let end = note.find(". ").map_or(note.len(), |i| i + 1);
        let text = one_line(&note[..end], 160);
        if text.is_empty() {
            format!("{name} needs a look.")
        } else {
            text
        }
    };
    if let Some(lead) = (finding.kind != "unchecked")
        .then(|| crate::explain::own_lead(finding, name))
        .flatten()
    {
        return lead;
    }
    match finding.kind.as_str() {
        "unchecked" => format!("{name} could not be checked this time."),
        "secret" => format!(
            "A password or key is saved in a file in {name}. Anyone who can read the project can use it."
        ),
        "malware" | "suspect-code" => format!("{name} looks like known harmful software."),
        "posture" | "config" | "persistence" | "license" | "hidden-text" | "install-script"
        | "repo-hook" | "document" | "queue" => first_sentence(),
        _ if !crate::explain::is_advisory(finding) => first_sentence(),
        // What the flaw lets someone do, when the advisory says.
        _ => match crate::explain::short_consequence(finding) {
            Some(consequence) => format!("{} {consequence}", advisory_lead(finding, name)),
            None => advisory_lead(finding, name),
        },
    }
}

/// The lead every published-advisory row starts with, on the home page and
/// under "From earlier scans" alike:
///
/// ```text
/// left-pad has a security flaw with no fix yet.
/// left-pad is out of date and has a security flaw that attackers are using.
/// ```
fn advisory_lead(finding: &Finding, name: &str) -> String {
    let exploited = if finding.kev {
        " that attackers are using"
    } else {
        ""
    };
    if finding.fixed.is_empty() {
        let comma = if finding.kev { "," } else { "" };
        format!("{name} has a security flaw{exploited}{comma} with no fix yet.")
    } else {
        format!("{name} is out of date and has a security flaw{exploited}.")
    }
}

/// Needs attention now: exploited, critical, high, or a failing check.
fn urgent(finding: &Finding) -> bool {
    finding.kind != "unchecked"
        && (finding.kev
            || matches!(
                finding.severity.to_ascii_lowercase().as_str(),
                "critical" | "high"
            )
            || (finding.status == "fail" && finding.severity.is_empty()))
}

/// The home page: am I OK, what is wrong, how do I fix it.
fn home(ui: &mut Ui, app: &mut App, p: &Palette) {
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

/// "From earlier scans": problems earlier scans found that no scan has
/// cleared since. Never in the headline; each can be scanned again or
/// dismissed (Latest scan shows the dismissed ones again). One that
/// attackers are using carries the same pill as a home row, so it stands
/// out although it is not counted.
fn earlier(ui: &mut Ui, app: &App, p: &Palette, enabled: bool, action: &mut Option<Action>) {
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
fn dismissed(ui: &mut Ui, app: &mut App, p: &Palette) {
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

const FIX_REQUESTED: &str = "pantry.fix_requested";

fn fix_requested(ui: &Ui) -> bool {
    ui.ctx()
        .data_mut(|d| d.remove_temp::<bool>(egui::Id::unique(FIX_REQUESTED)))
        .unwrap_or(false)
}

fn filters(
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

/// The "Fix all" confirm, progress and results.
fn batch(ui: &mut Ui, app: &App, p: &Palette, action: &mut Option<Action>) {
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

fn results(ui: &mut Ui, app: &mut App, p: &Palette) {
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

/// True when a finding matches the search text (already lower-cased): its
/// name, place, ids (its own, its aliases, its weakness types), kind,
/// severity, the scanner's note, the advisory's summary, and the plain
/// sentences the window shows for it.
pub fn matches_search(f: &Finding, search: &str) -> bool {
    if search.is_empty() {
        return true;
    }
    let shown = [plain_sentence(f), crate::explain::explain(f).sentence];
    [
        &f.component,
        &f.location,
        &f.vuln_id,
        &f.kind,
        &f.severity,
        &f.note,
        &f.summary,
    ]
    .into_iter()
    .chain(&f.aliases)
    .chain(&f.cwe)
    .chain(&shown)
    .any(|s| s.to_lowercase().contains(search))
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

/// Where a scan looked, for people: the fixed scopes in words, folders
/// with the home folder as `~` and long paths shortened in the middle.
///
/// ```ignore
/// scope_place("repos:/Users/sam/site,/Users/sam/app") == "~/site, ~/app"
/// ```
fn scope_place(raw: &str) -> String {
    let named = scope(raw, false);
    if named != "Selected folders" && named != "This computer" {
        return named;
    }
    let base = raw.split([';', '+']).next().unwrap_or("");
    let Some((_, paths)) = base.split_once(':') else {
        return named;
    };
    let home = home_dir();
    let shown: Vec<String> = paths
        .split(',')
        .filter(|path| !path.is_empty())
        .map(|path| display_path(&one_line(path, 400), home.as_deref(), 48))
        .collect();
    if shown.is_empty() {
        named
    } else {
        shown.join(", ")
    }
}

fn scope(scope: &str, details: bool) -> String {
    match scope {
        "machine:~" => "This computer and your projects".into(),
        "machine:~;no-personal-files" => {
            "This computer and your projects, personal folders skipped".into()
        }
        "repos:~" => "Your projects".into(),
        _ if details => scope.strip_prefix("repos:").unwrap_or(scope).to_owned(),
        _ if scope.starts_with("machine:") => "This computer".into(),
        _ => "Selected folders".into(),
    }
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

fn command_purpose(command: &str) -> Option<&'static str> {
    [
        ("brew upgrade ", "update it with Homebrew"),
        ("mise upgrade ", "update it with mise"),
        ("mise install ", "install the fixed version with mise"),
        ("cargo update ", "update the project's Cargo lockfile"),
        ("npm install ", "install the fixed version with npm"),
        (
            "wpantry fix secret ",
            "walk you through removing the saved secret",
        ),
    ]
    .into_iter()
    .find_map(|(prefix, purpose)| command.starts_with(prefix).then_some(purpose))
}

/// A word in a fix command that Pantry can describe: letters, digits and
/// the punctuation package names and versions use. Never a quote, a shell
/// operator or a space.
fn plain_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@:/+-".contains(&b))
}

/// What a fix command will do, only when the whole command has exactly the
/// shape Pantry knows for that tool: the tool, its verb, this component
/// (and the fixed version, where the tool names one), and nothing else.
/// The scanner runs the command's words without a shell, so any extra word
/// is another package or argument, and the specific sentence would promise
/// less than the command does.
///
/// ```text
/// npm install left-pad@2.0                 -> install the fixed version with npm
/// npm install left-pad@2.0; touch marker   -> None
/// npm install left-pad@2.0 other           -> None
/// ```
fn specific_purpose(finding: &Finding, command: &str) -> Option<(&'static str, bool)> {
    let name = finding.component.as_str();
    let fixed = finding.fixed.as_str();
    // Look-alike or non-ASCII names are shown, never vouched for.
    if !plain_word(name) {
        return None;
    }
    let words: Vec<&str> = command.split(' ').collect();
    if !words.iter().all(|w| plain_word(w)) {
        return None;
    }
    let spec = format!("{name}@{fixed}");
    let with_fixed = !fixed.is_empty() && plain_word(fixed);
    // (purpose, whether the command names the fixed version)
    match words.as_slice() {
        ["npm", "install", s] if with_fixed && *s == spec => {
            Some(("install the fixed version with npm", true))
        }
        ["mise", "install", s] if with_fixed && *s == spec => {
            Some(("install the fixed version with mise", true))
        }
        ["cargo", "update", "-p", n, "--precise", v] if *n == name && with_fixed && *v == fixed => {
            Some(("update the project's Cargo lockfile", true))
        }
        ["brew", "upgrade", n] | ["brew", "upgrade", "--cask", n] if *n == name => {
            Some(("update it with Homebrew", false))
        }
        ["mise", "upgrade", n] if *n == name || n.strip_prefix("brew:") == Some(name) => {
            Some(("update it with mise", false))
        }
        ["wpantry", "fix", "secret", id] if *id == finding.id => {
            Some(("walk you through removing the saved secret", false))
        }
        _ => None,
    }
}

/// One plain sentence for what a fix will do. The specific sentence needs
/// [`specific_purpose`]; anything else says only that one command runs,
/// and the command is shown beside it.
fn fix_sentence(finding: &Finding, command: &str) -> String {
    let Some((purpose, names_fixed)) = specific_purpose(finding, command) else {
        return "Pantry will run one command.".into();
    };
    let name = finding.component.as_str();
    let target = match (finding.version.is_empty(), names_fixed) {
        (false, true) => format!(" from version {} to {}", finding.version, finding.fixed),
        (true, true) => format!(" to version {}", finding.fixed),
        _ => String::new(),
    };
    format!("Pantry will update {name}{target}. To do this it will {purpose}.")
}

/// How to open a terminal, for people who never have.
fn terminal_step() -> &'static str {
    if cfg!(target_os = "macos") {
        "Open Terminal: press Command and Space together, type Terminal, then press Return."
    } else if cfg!(windows) {
        "Open Terminal: select Start, type Terminal, then press Enter."
    } else {
        "Open your Terminal app from the applications menu."
    }
}

fn paste_step() -> &'static str {
    if cfg!(target_os = "macos") {
        "Choose Copy command below. In Terminal, press Command and V to paste it, then press Return."
    } else if cfg!(windows) {
        "Choose Copy command below. In Terminal, right-click to paste it, then press Enter."
    } else {
        "Choose Copy command below. In the terminal, press Ctrl, Shift and V to paste it, then press Enter."
    }
}

/// The longest advisory summary the detail card quotes, in characters.
const QUOTE_MAX: usize = 300;

/// An advisory's summary as the detail card quotes it: on one line, at
/// most [`QUOTE_MAX`] characters cut at a word, and with its own quote
/// marks turned into single ones so it cannot close the quote around it.
///
/// ```ignore
/// quoted_summary("Say \"hi\"\nnow") == "Say 'hi' now"
/// ```
pub fn quoted_summary(summary: &str) -> String {
    let flat: String = summary
        .chars()
        .map(|c| match c {
            '\u{201c}' | '\u{201d}' | '"' | '\u{201e}' | '\u{00ab}' | '\u{00bb}' => '\'',
            other => other,
        })
        .collect();
    one_line(&flat, QUOTE_MAX)
}

/// The technical details of an advisory, shown with Show technical details.
fn technical(ui: &mut Ui, p: &Palette, finding: &Finding) {
    let mut rows: Vec<(&str, String)> = Vec::new();
    if !finding.vuln_id.is_empty() {
        rows.push(("Reference", finding.vuln_id.clone()));
    }
    if !finding.affected_range.is_empty() {
        rows.push(("Affected versions", finding.affected_range.clone()));
    }
    if !finding.fixed.is_empty() {
        rows.push(("Fixed in", finding.fixed.clone()));
    }
    if let Some(score) = finding.cvss {
        let version = if finding.cvss_version.is_empty() {
            String::new()
        } else {
            format!(" (CVSS {})", finding.cvss_version)
        };
        rows.push(("Severity score", format!("{score:.1} out of 10{version}")));
    }
    // An estimate is no news next to "attackers are using this now".
    if let Some(epss) = finding.epss.filter(|_| !finding.kev) {
        rows.push((crate::explain::EPSS_LABEL, crate::explain::epss_text(epss)));
    }
    if !finding.cwe.is_empty() {
        let named: Vec<String> = finding
            .cwe
            .iter()
            .map(|cwe| match crate::explain::cwe_name(cwe) {
                Some(name) => format!("{cwe} ({name})"),
                None => cwe.clone(),
            })
            .collect();
        rows.push(("Weakness type", named.join(", ")));
    }
    if finding.kev {
        rows.push(("CISA KEV", "Listed: known to be used in attacks".into()));
    }
    let scope = match finding.dep_scope.as_str() {
        "runtime" => Some("Used when the project runs"),
        "dev" => Some("Used only while developing"),
        "optional" => Some("Optional"),
        _ => None,
    };
    let direct = match finding.dep_direct {
        Some(true) => Some("the project's own dependency"),
        Some(false) => Some("pulled in by another dependency"),
        None => None,
    };
    match (scope, direct) {
        (Some(scope), Some(direct)) => rows.push(("Dependency", format!("{scope}, {direct}"))),
        (Some(scope), None) => rows.push(("Dependency", scope.into())),
        (None, Some(direct)) => rows.push(("Dependency", direct.into())),
        (None, None) => {}
    }
    if !finding.location.is_empty() {
        rows.push(("Full path", finding.location.clone()));
    }
    if !finding.note.trim().is_empty() && finding.note.trim() != finding.summary {
        rows.push(("Scanner note", one_line(&finding.note, 600)));
    }
    ui.add_space(4.0);
    for (name, value) in rows {
        let shown = ui.add(
            egui::Label::new(RichText::new(format!("{name}: {value}")).color(p.ink2))
                .selectable(true),
        );
        let key = if name == crate::explain::EPSS_LABEL {
            "epss".to_owned()
        } else {
            name.to_ascii_lowercase().replace(' ', "_")
        };
        tag(ui, &shown, &format!("finding.tech.{key}"));
    }
}

fn detail(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    if button(ui, p, "finding.back", "Back", true, false) {
        dispatch(ui, app, Action::CloseFinding);
        return;
    }
    let details = app.state.details;
    let kev_checked = app.kev_checked_selected();
    let Some(finding) = app.selected() else {
        return;
    };
    ui.heading(if finding.component.trim().is_empty() {
        one_line(&finding.vuln_id, 80)
    } else {
        one_line(&finding.component, 120)
    });
    let (level, color, shape) = severity(p, finding);
    pill(ui, level, color, Some(shape));
    let mut action = None;
    card(ui, p, |ui| {
        section(ui, "What Pantry found");
        let (summary, missing_release) = finding
            .note
            .rsplit_once(" (no fix released for ")
            .filter(|(_, ending)| ending.ends_with(" yet)"))
            .map_or((finding.note.as_str(), false), |(summary, _)| {
                (summary, true)
            });
        // Lead with the same plain sentence the home list uses. The
        // scanner's own note (often an advisory title) is technical detail.
        let sentence = plain_sentence(finding);
        let lead = ui.label(&sentence);
        tag(ui, &lead, "finding.sentence");
        let summary = summary.trim();
        if !summary.is_empty() && !sentence.contains(summary) {
            // For a check that did not finish, the note is the reason and
            // people need it; otherwise it is a technical detail.
            // (Otherwise it is under the technical details.)
            if finding.kind == "unchecked" {
                ui.label(one_line(summary, 400));
            }
        }
        // What could happen, and whether attackers use it now.
        let explanation = crate::explain::explain(finding);
        if !sentence.contains(&explanation.sentence) && finding.kind != "unchecked" {
            let shown = ui.label(&explanation.sentence);
            tag(ui, &shown, "finding.explanation");
        }
        if let Some(attacks) = crate::explain::attacks(finding, kev_checked) {
            let shown = if finding.kev {
                ui.label(
                    RichText::new(format!("{attacks} Fix it first."))
                        .color(p.red)
                        .strong(),
                )
            } else {
                muted(ui, p, attacks)
            };
            tag(ui, &shown, "finding.attacks");
        }
        // Only a published advisory can be waiting on its maker's fix.
        if missing_release
            && crate::explain::is_advisory(finding)
            && finding.fixed.is_empty()
            && !sentence.contains("no fix yet")
        {
            muted(ui, p, "The maker has not released a fix yet.");
        }
        // The public ids, each a link to its notice, always shown.
        let ids = crate::explain::identifiers(finding);
        if !ids.is_empty() {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(if ids.len() == 1 { "Security notice ID:" } else { "Security notice IDs:" }).color(p.ink2))
                    .on_hover_text("Public IDs for this security problem. CVE IDs come from the CVE program; GHSA IDs from GitHub; others from the package's own advisory database.");
                for item in &ids {
                    let key = format!("finding.advisory.{}", item.id);
                    match &item.url {
                        Some(_) => {
                            if link(ui, &key, &item.id) {
                                action = Some(Action::OpenAdvisory { id: item.id.clone() });
                            }
                        }
                        None => {
                            let shown = ui.label(RichText::new(&item.id).monospace());
                            tag(ui, &shown, &key);
                        }
                    }
                }
                if button(ui, p, "finding.copy_id", "Copy ID", true, false) {
                    action = Some(Action::CopyId);
                }
            });
            if ids.iter().any(|item| item.id.starts_with("DEMO-")) {
                muted(ui, p, "Demo data: DEMO IDs are not in any public database.");
            }
        }
        let quote = quoted_summary(&finding.summary);
        if !quote.is_empty() && quote != sentence {
            let quoted = muted(
                ui,
                p,
                format!("From the security notice: \u{201c}{quote}\u{201d}"),
            );
            tag(ui, &quoted, "finding.summary");
        }
        if !finding.location.is_empty() {
            let shown = display_path(&finding.location, home_dir().as_deref(), 56);
            let found = muted(ui, p, format!("Found in {shown}"));
            tag(ui, &found, "finding.location");
            if shown != finding.location {
                found.on_hover_text(&finding.location);
            }
        }
        if !finding.version.is_empty() {
            muted(ui, p, format!("Installed version {}", finding.version));
        }
        if details && finding.kind != "unchecked" {
            technical(ui, p, finding);
        }
    });
    ui.add_space(4.0);
    let how = app
        .plan()
        .map(|fix| fix.how.clone())
        .unwrap_or_else(|| "you".into());
    let text = app.copy_text();
    let automatic = app.can_fix_selected() && !app.needs_password();
    let earlier = app
        .state
        .selected
        .as_deref()
        .is_some_and(|id| id.starts_with("earlier-"));
    let watch_only = text
        .as_deref()
        .is_some_and(|step| step.starts_with("No fix released for this package yet:"));
    let awaiting_fix =
        finding.fixed.is_empty() && (watch_only || finding.note.contains(" (no fix released for "));
    let fix_cmd = finding.fix_cmd.clone();
    let sentence = fix_sentence(finding, text.as_deref().unwrap_or(""));
    let unchecked = finding.kind == "unchecked";
    let fixed = finding.fixed.clone();
    card(ui, p, |ui| {
        section(
            ui,
            if unchecked {
                "What Pantry couldn't check"
            } else {
                "How to fix it"
            },
        );
        if !fixed.is_empty() && !automatic {
            ui.label(
                RichText::new(format!("Fixed in version {fixed}"))
                    .font(FontId::new(15.0, semibold())),
            );
        }
        if earlier {
            ui.label(
                "This was found by an earlier scan. Choose Scan now before you change anything.",
            );
        }
        if awaiting_fix {
            section(ui, "No fix yet");
            ui.label("The maker has not released a fixed version. Read the security notice to see which versions are affected.");
            if details {
                ui.label("Pantry can check for a fix each time it scans. Set up a schedule in the sidebar, or copy the check command to run it in a terminal.");
                if button(ui, p, "fix.watch.copy", "Copy check command", true, false) {
                    action = Some(Action::CopyWatchCommand);
                }
            } else {
                let watch = ui.label("Pantry checks for a fix each time it scans. To have it scan on its own, set up a scan schedule in the sidebar.");
                tag(ui, &watch, "fix.watch");
            }
        }
        let Some(text) = text.filter(|_| !watch_only) else {
            if !awaiting_fix {
                ui.label(if unchecked {
                    "This is usually a source that did not answer, or a folder Pantry was not allowed to read. Check your internet connection, then try again."
                } else {
                    "Pantry has no fix steps for this finding."
                });
                if unchecked && button(ui, p, "finding.retry", "Retry", enabled, true) {
                    action = Some(Action::Retry);
                }
            }
            return;
        };
        if automatic {
            match &app.state.pending_fix {
                None => {
                    ui.label(RichText::new(format!(
                        "Pantry can fix this for you. {sentence}"
                    )));
                    muted(
                        ui,
                        p,
                        "Pantry asks you before it changes anything, then scans again to check the fix.",
                    );
                    if button(
                        ui,
                        p,
                        "fix.preview",
                        "Fix it",
                        enabled && app.state.report_error.is_none(),
                        true,
                    ) {
                        action = Some(Action::PreviewFix);
                    }
                }
                Some(pending) => {
                    section(ui, "Ready to fix");
                    ui.label(format!(
                        "{sentence} Then Pantry scans again to check that the problem is gone."
                    ));
                    ui.horizontal(|ui| {
                        if button(ui, p, "fix.confirm", "Yes, fix it", enabled, true) {
                            action = Some(Action::ConfirmFix);
                        }
                        if button(ui, p, "fix.cancel", "Not now", true, false) {
                            action = Some(Action::CancelFix);
                        }
                    });
                    if details {
                        muted(
                            ui,
                            p,
                            format!("Command checked against scan #{}.", pending.scan),
                        );
                    }
                }
            }
            // A command Pantry can't describe is always shown.
            let specific = specific_purpose(finding, &text).is_some();
            let show = details || app.state.show_fix_details || !specific;
            if !details && specific {
                let label = if show {
                    "Hide the command"
                } else {
                    "Show the command"
                };
                if link(ui, "fix.details", label) {
                    action = Some(Action::ToggleFixDetails);
                }
            }
            if show {
                ui.add(egui::Label::new(RichText::new(&text).monospace()).selectable(true));
                if button(ui, p, "fix.copy", "Copy command", true, false) {
                    action = Some(Action::CopyFix);
                }
            }
            return;
        }
        // Steps people follow themselves.
        let command = if app.needs_password() { fix_cmd } else { text };
        let is_command =
            app.needs_password() || how == "terminal" || command_purpose(&command).is_some();
        let mut steps: Vec<String> = Vec::new();
        if is_command {
            steps.push(terminal_step().into());
            steps.push(paste_step().into());
            if command.starts_with("sudo ") || app.needs_password() {
                steps.push("If it asks for a password, type the password you use to sign in to this computer. Nothing shows while you type. Press Return when done.".into());
            }
            steps.push("When it finishes, come back to Pantry and choose Scan now.".into());
        } else {
            steps.push(command.clone());
            steps.push("When you're done, choose Scan now to check it.".into());
        }
        for (n, step) in steps.iter().enumerate() {
            ui.label(format!("{}. {step}", n + 1));
        }
        if is_command {
            ui.add(egui::Label::new(RichText::new(&command).monospace()).selectable(true));
        }
        let label = if is_command {
            "Copy command"
        } else {
            "Copy steps"
        };
        if button(ui, p, "fix.copy", label, true, false) {
            action = Some(Action::CopyFix);
        }
    });
    if details && let Some(output) = &app.state.last_fix_output {
        card(ui, p, |ui| {
            section(ui, "What the fix printed");
            ui.add(
                egui::Label::new(RichText::new(output).monospace().color(p.ink2)).selectable(true),
            );
        });
    }
    if let Some(action) = action {
        dispatch(ui, app, action);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        display_name, display_path, fix_sentence, matches_search, one_line, plain_sentence,
        quoted_summary,
    };
    use crate::data::Finding;

    fn finding(fields: serde_json::Value) -> Finding {
        let mut base = serde_json::json!({
            "kind": "project", "component": "demo", "version": "1.0", "location": "",
            "vuln_id": "", "status": "warn", "note": "", "fixed": "",
            "severity": "", "kev": false, "fix_cmd": "",
        });
        for (key, value) in fields.as_object().unwrap() {
            base[key] = value.clone();
        }
        serde_json::from_value(base).unwrap()
    }

    /// Oracle: "security hole" and "no fix released" belong to published
    /// advisories. Pantry's own checks lead with what the check found, and
    /// a known-harmful package says to remove it, never "worth a look".
    #[test]
    fn own_checks_never_read_as_security_holes() {
        let cases = [
            (
                serde_json::json!({"kind": "tool", "component": "node", "vuln_id": "EOL", "fix_auto": true, "fix_cmd": "brew upgrade node", "note": "node 16 reached end of life"}),
                "node no longer gets security fixes from its maker.",
            ),
            (
                serde_json::json!({"kind": "tool", "component": "brew vulns", "vuln_id": "MISSING", "note": "Homebrew formulae can't be checked", "fix_cmd": "brew update"}),
                "brew vulns is not installed, so one of Pantry's checks could not run.",
            ),
            (
                serde_json::json!({"kind": "repo-hook", "component": "site", "vuln_id": "INSTALL-HOOK", "note": "postinstall runs node x.js"}),
                "site runs its own commands when it is installed.",
            ),
            (
                serde_json::json!({"vuln_id": "MAL-2026-1", "severity": "CRITICAL", "kev": true, "component": "evil-pkg", "fix_cmd": "npm uninstall evil-pkg"}),
                "evil-pkg is a known harmful package. Remove it.",
            ),
            (
                serde_json::json!({"vuln_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["MAL-2026-2"], "severity": "CRITICAL", "kev": true, "component": "evil-pkg"}),
                "evil-pkg is a known harmful package. Remove it.",
            ),
            (
                serde_json::json!({"kind": "extension", "vuln_id": "MALICIOUS", "severity": "CRITICAL", "kev": true, "component": "bad-ext"}),
                "bad-ext is a known harmful",
            ),
            (
                serde_json::json!({"kind": "tool", "component": "git", "vuln_id": "SIGNING-OFF", "note": "git is set up to skip signature checks. Turn it on."}),
                "git is set up to skip signature checks.",
            ),
        ];
        for (fields, expected) in cases {
            let f = finding(fields);
            let sentence = plain_sentence(&f);
            assert!(sentence.contains(expected), "{sentence}");
            for word in [
                "security hole",
                "security flaw",
                "no fix yet",
                "worth a look",
            ] {
                assert!(!sentence.contains(word), "{sentence}");
            }
        }
        // A published advisory still says it.
        let advisory = finding(serde_json::json!({"vuln_id": "CVE-2026-1", "severity": "HIGH"}));
        assert!(plain_sentence(&advisory).contains("security"));
    }

    /// Oracle: the specific confirm sentence only for a command with
    /// exactly the known shape for its tool. Known-bad: extra words after
    /// the package (the scanner runs them as more packages or arguments),
    /// padding, the fixed version only inside another word, a different
    /// package, and a look-alike component name.
    #[test]
    fn confirm_sentence_promises_only_what_the_command_does() {
        let f = finding(serde_json::json!({
            "id": "F-1", "component": "pkg0", "version": "1.0", "fixed": "2.0",
        }));
        let specific = "Pantry will update pkg0 from version 1.0 to 2.0. To do this it will install the fixed version with npm.";
        assert_eq!(fix_sentence(&f, "npm install pkg0@2.0"), specific);
        assert_eq!(
            fix_sentence(&f, "cargo update -p pkg0 --precise 2.0"),
            "Pantry will update pkg0 from version 1.0 to 2.0. To do this it will update the project's Cargo lockfile."
        );
        assert_eq!(
            fix_sentence(&f, "brew upgrade --cask pkg0"),
            "Pantry will update pkg0. To do this it will update it with Homebrew."
        );
        assert!(fix_sentence(&f, "mise upgrade brew:pkg0").ends_with("update it with mise."));
        assert!(fix_sentence(&f, "wpantry fix secret F-1").ends_with("saved secret."));
        let generic = "Pantry will run one command.";
        for command in [
            "npm install pkg0@2.0; touch marker",
            "npm install pkg0@2.0 ; touch marker",
            &format!("npm install pkg0@2.0{}; touch marker", " ".repeat(300)),
            "npm install pkg0@2.0 other-package",
            "npm install pkg0@2.0 --registry=http://example.invalid",
            "npm install pkg0@12.0",
            "npm install other@2.0",
            "npm install pkg0@2.0 # 2.0",
            "brew upgrade pkg0 other",
            "wpantry fix secret F-2",
            "touch marker",
        ] {
            assert_eq!(fix_sentence(&f, command), generic, "{command:?}");
        }
        let look_alike = finding(serde_json::json!({
            "component": "\u{0440}kg0", "version": "1.0", "fixed": "2.0",
        }));
        assert_eq!(
            fix_sentence(&look_alike, "npm install \u{0440}kg0@2.0"),
            generic
        );
    }

    /// Oracle: an advisory row reads the same whether or not the notice
    /// says what the flaw does, so earlier-scan rows (often without a
    /// weakness type) match the rows above them. Known-bad: the old
    /// "known security hole" wording.
    #[test]
    fn advisory_rows_share_one_lead() {
        for (fixed, kev, lead) in [
            ("", false, "left-pad has a security flaw with no fix yet."),
            (
                "2.0",
                false,
                "left-pad is out of date and has a security flaw.",
            ),
            (
                "",
                true,
                "left-pad has a security flaw that attackers are using, with no fix yet.",
            ),
        ] {
            let bare = finding(serde_json::json!({
                "component": "left-pad", "vuln_id": "CVE-2026-1", "fixed": fixed, "kev": kev,
            }));
            let explained = finding(serde_json::json!({
                "component": "left-pad", "vuln_id": "CVE-2026-1", "fixed": fixed, "kev": kev,
                "cwe": ["CWE-787"],
            }));
            assert_eq!(plain_sentence(&bare), lead);
            let full = plain_sentence(&explained);
            assert!(full.starts_with(lead), "{full}");
            assert!(full.contains("run their own programs"), "{full}");
            for sentence in [plain_sentence(&bare), full] {
                assert!(!sentence.contains("security hole"), "{sentence}");
            }
        }
    }

    /// Oracle: search finds a row by any text people can see or copy from
    /// it: aliases, weakness ids, the explanation and the summary.
    #[test]
    fn search_matches_aliases_weaknesses_and_shown_text() {
        let f = finding(serde_json::json!({
            "vuln_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-4242"],
            "cwe": ["CWE-89"], "summary": "Quoting flaw in the query builder", "severity": "HIGH",
        }));
        for search in ["cve-2026-4242", "cwe-89", "query builder", "database"] {
            assert!(matches_search(&f, search), "{search}");
        }
        assert!(!matches_search(&f, "nothing like this"));
    }

    /// Known-bad: hidden characters, line breaks and runs of spaces in
    /// scanner text, a 1000-character summary with quote marks, and a
    /// long multi-line name. Shown text is one clean line, cut at a word.
    #[test]
    fn shown_text_is_one_clean_short_line() {
        assert_eq!(one_line("a\u{202E}b \n\n  c\td", 100), "ab c d");
        let long = "word ".repeat(200);
        let quoted = quoted_summary(&format!("He said \u{201c}hi\u{201d} and \"bye\" {long}"));
        assert!(quoted.chars().count() <= 300, "{}", quoted.chars().count());
        assert!(quoted.ends_with('…'), "{quoted}");
        assert!(
            quoted.starts_with("He said 'hi' and 'bye' word"),
            "{quoted}"
        );
        assert!(!quoted.contains(['"', '\u{201c}', '\u{201d}']));
        assert!(
            !quoted.trim_end_matches('…').ends_with("wor"),
            "cut at a word"
        );
        let name = display_name(&finding(
            serde_json::json!({"component": format!("first line\nsecond {}", "x".repeat(200))}),
        ));
        assert!(name.chars().count() <= 40, "{name}");
        assert!(!name.contains('\n'));
        let sentence = plain_sentence(&finding(
            serde_json::json!({"component": "x\n".repeat(80), "vuln_id": "CVE-2026-1", "fixed": "2"}),
        ));
        assert!(sentence.contains("is out of date"), "{sentence}");
    }

    #[test]
    fn paths_show_home_as_a_tilde_and_elide_the_middle() {
        let home = Some("/Users/sam");
        assert_eq!(
            display_path("/Users/sam/Projects/site", home, 56),
            "~/Projects/site"
        );
        // A sibling folder that only starts with the home path is not home.
        assert_eq!(
            display_path("/Users/samantha/site", home, 56),
            "/Users/samantha/site"
        );
        let long = "/var/folders/y2/mjncn_qn211bjbdr94zpzps40000gn/T/pantry-tests-4f5b/recipe-site";
        let shown = display_path(long, home, 40);
        assert_eq!(shown.chars().count(), 40);
        assert!(shown.starts_with("/var/folders/") && shown.ends_with("/recipe-site"));
        assert!(shown.contains('…'));
        // Known bad: an elided path is never returned unchanged.
        assert_ne!(shown, long);
        assert_eq!(display_path("short", None, 40), "short");
    }
}
