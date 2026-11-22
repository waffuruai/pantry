//! What the window remembers between launches.

use super::Page;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// What the window remembers between launches (`settings.json` in the
/// state folder). Every field has a default, and a missing or damaged
/// file means "all defaults".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None` follows the system theme.
    pub light: Option<bool>,
    pub include_personal_files: bool,
    /// True once someone has answered the personal folders question.
    pub personal_files_asked: bool,
    pub window: Option<[f32; 2]>,
    pub page: Page,
    pub details: bool,
    /// Ids of problems from earlier scans the person dismissed. Only the
    /// window hides them; the scanner's history keeps them.
    pub dismissed: Vec<String>,
}

impl Settings {
    pub const MIN_WINDOW: [f32; 2] = [820.0, 480.0];

    pub fn load(path: &Path) -> Self {
        let mut settings: Self = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        settings.window = settings.window.filter(|[w, h]| {
            w.is_finite()
                && h.is_finite()
                && *w >= 100.0
                && *h >= 100.0
                && *w < 20_000.0
                && *h < 20_000.0
        });
        settings
    }

    /// Write through a temporary file so a crash never leaves half a file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staged = path.with_extension("json.tmp");
        std::fs::write(&staged, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(staged, path)
    }

    /// The window size to open with, never below the minimum.
    pub fn window_size(&self) -> [f32; 2] {
        let [w, h] = self.window.unwrap_or([1080.0, 740.0]);
        [w.max(Self::MIN_WINDOW[0]), h.max(Self::MIN_WINDOW[1])]
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
