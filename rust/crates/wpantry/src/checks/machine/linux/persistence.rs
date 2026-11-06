//! Linux's own place to persist, beside the units, cron, at and startup
//! files every OS shares ([`crate::checks::machine::any::persistence`]):
//! `/etc/ld.so.preload`.

use crate::checks::machine::any::persistence::{Inventory, Item, Roots, Source};
use crate::utils::files;
use std::path::Path;

/// Read every Linux-only source into `inv`.
pub(crate) fn collect(r: &Roots, inv: &mut Inventory) {
    preload(r, inv);
}

/// `/etc/ld.so.preload`: libraries the dynamic linker loads into every
/// program on the system.
fn preload(r: &Roots, inv: &mut Inventory) {
    let path = r.sys("/etc/ld.so.preload");
    if let Ok(text) = files::read_capped(&path, 1 << 20) {
        for (i, lib) in text.lines().map(str::trim).enumerate() {
            if lib.is_empty() || lib.starts_with('#') {
                continue;
            }
            inv.items.push(Item {
                source: Source::Preload,
                location: r.show(&path),
                ident: lib.to_string(),
                program: Some(r.rebase(Path::new(lib))).filter(|p| p.exists()),
                injects: vec!["ld.so.preload".into()],
                line: i + 1,
            });
        }
    }
    inv.read.push(Source::Preload);
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;
