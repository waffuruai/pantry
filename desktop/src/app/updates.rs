//! The update check's answer: which release download fits this computer,
//! and copying or opening it.

use super::App;
use super::dispatch::GITHUB;
use crate::pantry::Result;
use eframe::egui;

impl App {
    /// The newer release's tag and the download for this computer: Setup
    /// first, else the portable ZIP. `None` when there is none, or when the
    /// scanner is from another version than the app.
    pub fn release(&self) -> Option<(String, &'static str)> {
        let update = self.state.update.as_ref()?;
        let candidates = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", _) => [
                "wpantry-setup-universal-apple-darwin.zip",
                "wpantry-desktop-universal-apple-darwin.zip",
            ],
            ("linux", "aarch64") => [
                "wpantry-setup-aarch64-unknown-linux-gnu.tar.gz",
                "wpantry-desktop-aarch64-unknown-linux-gnu.zip",
            ],
            ("linux", "x86_64") => [
                "wpantry-setup-x86_64-unknown-linux-gnu.tar.gz",
                "wpantry-desktop-x86_64-unknown-linux-gnu.zip",
            ],
            ("windows", "x86_64") => [
                "wpantry-setup-x86_64-pc-windows-msvc.exe",
                "wpantry-desktop-x86_64-pc-windows-msvc.zip",
            ],
            _ => return None,
        };
        if !update.matches_app()
            || !update.available
            || update.latest.split('.').count() != 3
            || !update
                .latest
                .split('.')
                .all(|part| part.parse::<u32>().is_ok() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let assets = update.assets.as_ref()?;
        let asset = candidates
            .into_iter()
            .find(|candidate| assets.iter().any(|asset| asset == candidate))?;
        Some((format!("v{}", update.latest), asset))
    }

    /// Copy the commands that download the release and verify it.
    pub(super) fn copy_update(&mut self, ctx: &egui::Context) -> Result<()> {
        let (tag, asset) = self.release_or_say()?;
        let commands = format!(
            "gh release download {tag} --repo waffuruai/pantry --pattern {asset}\n\
             gh attestation verify {asset} --repo waffuruai/pantry --signer-workflow waffuruai/pantry/.github/workflows/release.yml --source-ref refs/tags/{tag}"
        );
        self.copy(ctx, commands, "Copied download and verification commands.");
        Ok(())
    }

    /// Open the release download in the browser.
    pub(super) fn open_release(&mut self, ctx: &egui::Context) -> Result<()> {
        let (tag, asset) = self.release_or_say()?;
        self.open(ctx, &format!("{GITHUB}/releases/download/{tag}/{asset}"));
        Ok(())
    }

    /// [`App::release`], or why there is nothing to download.
    fn release_or_say(&self) -> Result<(String, &'static str)> {
        self.release()
            .ok_or_else(|| "No newer desktop release is available for this platform.".into())
    }
}
