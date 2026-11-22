//! Pantry's icon and design tokens.
//!
//! The palette is the Waffuru blue-slate and gold set used by Uchi
//! (crates/whouse-app/src/theme.rs in Tom Turney's whouse repo, Apache-2.0,
//! same author). The token values and the OKLCH helpers are copied from
//! there so both apps look the same.

use eframe::egui::{self, Color32};
use std::sync::LazyLock;

const WAFFLE: &[u8] = include_bytes!("../assets/waffuru-waffle.png");
static ICON: LazyLock<egui::IconData> = LazyLock::new(|| {
    eframe::icon_data::from_png_bytes(WAFFLE).expect("decode the bundled waffle icon")
});

pub fn icon() -> &'static egui::IconData {
    &ICON
}

/// Icon handed to the window system. On macOS this is empty so eframe skips
/// `setApplicationIconImage` and the Dock keeps the bundle's `Pantry.icns`,
/// which follows the system icon grid; the raw waffle would replace it with a
/// full-bleed image. An empty `IconData` also stops eframe's default egui icon.
pub fn window_icon() -> egui::IconData {
    if cfg!(target_os = "macos") {
        egui::IconData::default()
    } else {
        icon().clone()
    }
}

pub fn setup(ctx: &egui::Context) {
    let icon = icon();
    let pixels = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    let texture = ctx.load_texture("Pantry waffle", pixels, egui::TextureOptions::LINEAR);
    ctx.data_mut(|data| data.insert_temp(egui::Id::unique("pantry.waffle"), texture));
}

pub fn draw(ui: &mut egui::Ui) {
    let texture = ui
        .ctx()
        .data(|data| data.get_temp::<egui::TextureHandle>(egui::Id::unique("pantry.waffle")));
    if let Some(texture) = texture {
        ui.image((texture.id(), egui::Vec2::splat(25.0)));
    }
}

/// Convert an OKLCH color (CSS `oklch(L C h)`, h in degrees) to sRGB.
/// Out-of-gamut values are clipped per channel.
///
/// Example: `oklch(0.78, 0.1, 235.0)` is the dark theme's blue.
pub fn oklch(l: f32, c: f32, h_deg: f32) -> Color32 {
    let h = h_deg.to_radians();
    oklab_to_srgb(l, c * h.cos(), c * h.sin())
}

/// OKLab to gamma-encoded sRGB (Björn Ottosson's reference matrices).
pub fn oklab_to_srgb(l: f32, a: f32, b: f32) -> Color32 {
    let l_ = l + 0.396_337_78 * a + 0.215_803_76 * b;
    let m_ = l - 0.105_561_346 * a - 0.063_854_17 * b;
    let s_ = l - 0.089_484_18 * a - 1.291_485_5 * b;
    let (l3, m3, s3) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_);
    let r = 4.076_741_7 * l3 - 3.307_711_6 * m3 + 0.230_969_94 * s3;
    let g = -1.268_438 * l3 + 2.609_757_4 * m3 - 0.341_319_38 * s3;
    let bl = -0.004_196_086_3 * l3 - 0.703_418_6 * m3 + 1.707_614_7 * s3;
    let enc = |v: f32| {
        let v = v.clamp(0.0, 1.0);
        let s = if v <= 0.003_130_8 {
            12.92 * v
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (s * 255.0).round() as u8
    };
    Color32::from_rgb(enc(r), enc(g), enc(bl))
}

/// `color-mix(in oklch, X pct%, transparent)`: X at the given alpha.
pub fn tint(c: Color32, alpha: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(
        c.r(),
        c.g(),
        c.b(),
        (alpha.clamp(0.0, 1.0) * 255.0).round() as u8,
    )
}

/// Linear per-channel blend used for the theme cross-fade.
pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let f = |x: u8, y: u8| {
        (x as f32 + (y as f32 - x as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    Color32::from_rgba_unmultiplied(
        f(a.r(), b.r()),
        f(a.g(), b.g()),
        f(a.b(), b.b()),
        f(a.a(), b.a()),
    )
}

#[cfg(test)]
/// WCAG 2 contrast ratio between two opaque colors (1.0 to 21.0).
pub fn contrast(a: Color32, b: Color32) -> f32 {
    let luminance = |c: Color32| {
        let channel = |u: u8| {
            let v = u as f32 / 255.0;
            if v <= 0.040_45 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
    };
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// The design tokens. `ink3` is below 4.5:1 on some surfaces, so Pantry
/// uses it only for lines and disabled controls, never for body text.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Palette {
    pub bg: Color32,
    pub side: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub line: Color32,
    pub line2: Color32,
    pub ink: Color32,
    pub ink2: Color32,
    pub ink3: Color32,
    pub sel: Color32,
    pub field: Color32,
    pub gold: Color32,
    pub goldtx: Color32,
    pub on_gold: Color32,
    pub blue: Color32,
    pub green: Color32,
    pub red: Color32,
    pub dark: bool,
}

const fn hex(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            bg: hex(0x12, 0x16, 0x1c),
            side: hex(0x0d, 0x10, 0x15),
            panel: hex(0x16, 0x1b, 0x22),
            card: hex(0x1b, 0x21, 0x2a),
            line: hex(0x23, 0x2a, 0x34),
            line2: hex(0x2e, 0x37, 0x44),
            ink: hex(0xe8, 0xed, 0xf3),
            ink2: hex(0xa3, 0xae, 0xbc),
            ink3: hex(0x7a, 0x86, 0x96),
            sel: hex(0x1f, 0x27, 0x33),
            field: hex(0x0f, 0x13, 0x18),
            gold: hex(0xe0, 0xa3, 0x41),
            goldtx: hex(0xf2, 0xc8, 0x77),
            on_gold: hex(0x12, 0x16, 0x1c),
            blue: oklch(0.78, 0.1, 235.0),
            green: oklch(0.76, 0.11, 150.0),
            red: oklch(0.72, 0.14, 25.0),
            dark: true,
        }
    }

    pub fn light() -> Self {
        Self {
            bg: hex(0xf7, 0xf8, 0xfa),
            side: hex(0xee, 0xf1, 0xf4),
            panel: hex(0xff, 0xff, 0xff),
            card: hex(0xf2, 0xf4, 0xf7),
            line: hex(0xe4, 0xe8, 0xed),
            line2: hex(0xd4, 0xda, 0xe2),
            ink: hex(0x15, 0x1a, 0x21),
            ink2: hex(0x4b, 0x55, 0x63),
            ink3: hex(0x6b, 0x76, 0x85),
            sel: hex(0xfd, 0xf4, 0xe3),
            field: hex(0xff, 0xff, 0xff),
            gold: hex(0xe0, 0xa3, 0x41),
            goldtx: hex(0x7c, 0x50, 0x0c),
            on_gold: hex(0x15, 0x1a, 0x21),
            // Uchi uses L 0.55, which is 4.2:1 on `side`. Pantry draws
            // these as text, also on a 14% tint of themselves in pills,
            // so they are darker here (see the pill contrast test).
            blue: oklch(0.45, 0.12, 235.0),
            green: oklch(0.45, 0.11, 150.0),
            red: oklch(0.48, 0.16, 25.0),
            dark: false,
        }
    }

    /// Blend two palettes (`t` = 0 -> a, 1 -> b) for the theme cross-fade.
    pub fn lerp(a: &Self, b: &Self, t: f32) -> Self {
        let l = |x: Color32, y: Color32| lerp_color(x, y, t);
        Self {
            bg: l(a.bg, b.bg),
            side: l(a.side, b.side),
            panel: l(a.panel, b.panel),
            card: l(a.card, b.card),
            line: l(a.line, b.line),
            line2: l(a.line2, b.line2),
            ink: l(a.ink, b.ink),
            ink2: l(a.ink2, b.ink2),
            ink3: l(a.ink3, b.ink3),
            sel: l(a.sel, b.sel),
            field: l(a.field, b.field),
            gold: l(a.gold, b.gold),
            goldtx: l(a.goldtx, b.goldtx),
            on_gold: l(a.on_gold, b.on_gold),
            blue: l(a.blue, b.blue),
            green: l(a.green, b.green),
            red: l(a.red, b.red),
            dark: if t < 0.5 { a.dark } else { b.dark },
        }
    }

    #[cfg(test)]
    /// Every surface text is drawn on.
    pub fn surfaces(&self) -> [(&'static str, Color32); 6] {
        [
            ("bg", self.bg),
            ("side", self.side),
            ("panel", self.panel),
            ("card", self.card),
            ("sel", self.sel),
            ("field", self.field),
        ]
    }

    #[cfg(test)]
    /// Every color Pantry draws text in.
    pub fn text_colors(&self) -> [(&'static str, Color32); 6] {
        [
            ("ink", self.ink),
            ("ink2", self.ink2),
            ("goldtx", self.goldtx),
            ("blue", self.blue),
            ("green", self.green),
            ("red", self.red),
        ]
    }
}

#[cfg(test)]
#[path = "brand_tests.rs"]
mod tests;
