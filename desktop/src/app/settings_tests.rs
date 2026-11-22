use super::*;
use crate::app::Page;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pantry-desktop-settings-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn settings_round_trip() {
    let dir = scratch("round-trip");
    let path = dir.join("state/settings.json");
    let settings = Settings {
        light: Some(true),
        include_personal_files: true,
        personal_files_asked: true,
        window: Some([900.0, 600.0]),
        page: Page::History,
        details: true,
        dismissed: vec!["F-1".into()],
    };
    settings.save(&path).unwrap();
    assert_eq!(Settings::load(&path), settings);
    let _ = std::fs::remove_dir_all(dir);
}

/// Known-bad inputs: a missing file, garbage, wrong types, nonsense
/// sizes. Each must load as defaults (or drop just the bad size).
#[test]
fn settings_tolerate_missing_and_corrupt_files() {
    let dir = scratch("corrupt");
    let path = dir.join("settings.json");
    assert_eq!(Settings::load(&path), Settings::default());
    for text in [
        "",
        "{",
        "not json",
        "[1,2]",
        "{\"light\": \"yes\"}",
        "\u{0}\u{1}",
    ] {
        std::fs::write(&path, text).unwrap();
        assert_eq!(Settings::load(&path), Settings::default(), "{text:?}");
    }
    std::fs::write(&path, "{\"details\": true, \"future_field\": 3}").unwrap();
    assert!(Settings::load(&path).details, "unknown fields are ignored");
    std::fs::write(&path, "{\"window\": [1e30, 5]}").unwrap();
    assert_eq!(Settings::load(&path).window, None);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn window_size_never_drops_below_the_minimum() {
    let settings = Settings {
        window: Some([400.0, 300.0]),
        ..Settings::default()
    };
    assert_eq!(settings.window_size(), Settings::MIN_WINDOW);
    assert_eq!(Settings::default().window_size(), [1080.0, 740.0]);
}
