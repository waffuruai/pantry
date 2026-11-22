//! Fonts and egui visuals for both palettes.

use super::ANIMATE;
use crate::brand::{Palette, tint};
use eframe::egui::{self, FontFamily, FontId, Stroke, TextStyle, Vec2, epaint::text::FontInsert};
use std::sync::{Arc, OnceLock};

pub(super) fn semibold() -> FontFamily {
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
            include_bytes!("../../fonts/geist-latin-wght-normal.ttf"),
        ),
        (
            "geist-semibold",
            semibold(),
            include_bytes!("../../fonts/geist-latin-semibold.ttf"),
        ),
        (
            "geist-mono",
            FontFamily::Monospace,
            include_bytes!("../../fonts/geist-mono-latin-wght-normal.ttf"),
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
pub(super) fn visuals(p: &Palette) -> egui::Visuals {
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
