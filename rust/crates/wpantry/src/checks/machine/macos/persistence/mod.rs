//! macOS's own places to persist, beside the launch agents, cron, at and
//! startup files every OS shares ([`crate::checks::machine::any::persistence`]):
//! [`login_items`] apps carry, the plugin and system [`extensions`] the
//! system loads, [`periodic`] and emond, and the session's
//! `DYLD_INSERT_LIBRARIES`.

use crate::checks::machine::any::persistence::{Inventory, Item, Roots, Source};
use std::path::Path;

mod extensions;
mod login_items;
mod periodic;

/// Read every macOS-only source into `inv`.
pub(crate) fn collect(r: &Roots, inv: &mut Inventory) {
    login_items::login_items(r, inv);
    extensions::bundles(r, inv);
    extensions::system_extensions(r, inv);
    periodic::periodic_and_emond(r, inv);
    launchd_env(r, inv);
}

/// `launchctl setenv DYLD_INSERT_LIBRARIES`: every app the session starts
/// loads the library.
fn launchd_env(r: &Roots, inv: &mut Inventory) {
    let value = (r.runner)(&["launchctl", "getenv", "DYLD_INSERT_LIBRARIES"]);
    let value = value.trim();
    if !value.is_empty() {
        inv.items.push(Item {
            source: Source::LaunchdEnv,
            location: "launchctl getenv DYLD_INSERT_LIBRARIES".into(),
            ident: value.to_string(),
            program: Some(r.rebase(Path::new(value.split(':').next().unwrap_or(value)))).filter(|p| p.exists()),
            injects: vec!["DYLD_INSERT_LIBRARIES".into()],
            line: 0,
        });
    }
    inv.read.push(Source::LaunchdEnv);
}

#[cfg(test)]
mod tests;
