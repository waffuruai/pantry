use super::*;

/// Oracle: WCAG 2 AA asks 4.5:1 for body text. Every text color on
/// every surface it can sit on, in both palettes, and the label on
/// gold buttons.
#[test]
fn body_text_meets_contrast_in_both_palettes() {
    for palette in [Palette::dark(), Palette::light()] {
        for (surface, background) in palette.surfaces() {
            for (name, color) in palette.text_colors() {
                let ratio = contrast(color, background);
                assert!(
                    ratio >= 4.5,
                    "{name} on {surface} (dark={}) is {ratio:.2}:1",
                    palette.dark
                );
            }
        }
        assert!(contrast(palette.on_gold, palette.gold) >= 4.5);
    }
}

/// A see-through color laid over an opaque one, as egui paints it:
/// `Color32` holds premultiplied channels, blended in gamma space.
fn over(top: Color32, below: Color32) -> Color32 {
    let a = top.a() as f32 / 255.0;
    let mix = |t: u8, b: u8| (t as f32 + b as f32 * (1.0 - a)).round().min(255.0) as u8;
    Color32::from_rgb(
        mix(top.r(), below.r()),
        mix(top.g(), below.g()),
        mix(top.b(), below.b()),
    )
}

/// Oracle: a pill's words ("Being used in attacks now", "Can fix",
/// "High") are drawn in its color on a 14% tint of that same color,
/// so each text color must reach 4.5:1 on its own tint over every
/// surface, in both palettes.
#[test]
fn pill_text_meets_contrast_on_its_own_tint() {
    let mut low = Vec::new();
    for palette in [Palette::dark(), Palette::light()] {
        for (surface, background) in palette.surfaces() {
            for (name, color) in palette.text_colors() {
                let fill = over(tint(color, 0.14), background);
                let ratio = contrast(color, fill);
                if ratio < 4.5 {
                    low.push(format!(
                        "{name} pill on {surface} (dark={}) is {ratio:.2}:1",
                        palette.dark
                    ));
                }
            }
        }
    }
    assert!(low.is_empty(), "{low:#?}");
    // Known-bad: the light red before this check was 4.29:1 on card.
    let old_red = oklch(0.55, 0.16, 25.0);
    let card = Palette::light().card;
    assert!(contrast(old_red, over(tint(old_red, 0.14), card)) < 4.5);
}

/// Known-bad check for the ratio itself: ink3 is the token the module
/// docs say fails, and black on white is the 21:1 maximum.
#[test]
fn contrast_math_matches_known_values() {
    assert!((contrast(Color32::BLACK, Color32::WHITE) - 21.0).abs() < 0.01);
    assert!((contrast(Color32::WHITE, Color32::WHITE) - 1.0).abs() < 0.001);
    let light = Palette::light();
    assert!(contrast(light.ink3, light.side) < 4.5);
}

#[test]
fn oklch_matches_reference_points() {
    // oklch(1 0 0) is white and oklch(0 0 0) is black.
    assert_eq!(oklch(1.0, 0.0, 0.0), Color32::WHITE);
    assert_eq!(oklch(0.0, 0.0, 0.0), Color32::BLACK);
    let mid = Palette::lerp(&Palette::dark(), &Palette::light(), 0.0);
    assert_eq!(mid, Palette::dark());
}
