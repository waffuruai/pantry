//! Checks for this machine: tools, runtimes and their packages, apps and
//! browsers, OS updates and OS packages, Homebrew formulae, and the
//! certificate authorities it trusts.
//!
//! One file per behaviour: the inventory (`tools`, `catalog`, `packages`,
//! `apps`, `editors`, `harnesses`, `images`, `os_packages`, `cellar`), what
//! is judged of it (`components`, `app_updates`, `os_updates`,
//! `brew_vulns`, `ca_trust`, `clipper`, `downloads`), and the security
//! settings (`settings` over `any/`, `macos/` and `linux/`, persistence
//! included). This file is the index: [`run`], the probes in order.

use crate::checks::Scan;
use crate::component::Component;
use crate::error::Result;
use crate::utils::process;
use any::persistence::findings::persistence;
use apps as apps_mod;
use brew_vulns::brew;
use catalog::TOOLS;
use settings::posture;

pub mod any;
pub mod app_updates;
pub mod apps;
pub mod brew_vulns;
pub mod ca_trust;
pub mod catalog;
pub mod cellar;
pub mod clipper;
pub mod components;
pub mod downloads;
pub mod editors;
pub mod harnesses;
pub mod images;
pub mod linux;
pub mod macos;
pub mod os_packages;
pub mod os_updates;
pub mod packages;
pub mod settings;
#[cfg(test)]
pub(crate) mod testing;
pub mod tools;

/// A browser release younger than this only warns.
pub const GRACE: f64 = 3.0 * 86400.0;

/// Formulae `wpantry fix` must not upgrade either: their catalog fix.
pub(crate) fn manual(formula: &str) -> Option<&'static str> {
    TOOLS.iter().find(|t| t.name == formula && !t.fix.is_empty()).map(|t| t.fix)
}

/// The machine checks; returns what the inventory found, for the
/// supply-chain sweep.
pub fn run(scan: &mut Scan) -> Result<Vec<Component>> {
    // The probes that need nothing from the scan run beside it: the trust
    // stores and Software Update's last scan, seconds of subprocesses each.
    // brew vulns takes minutes on a first run: it starts now, beside the
    // inventory and the OSV round trips, and is read at the end.
    let brew_job = brew_vulns::brew_job(&scan.cache, scan.opts.refresh, scan.opts.offline)?;
    std::thread::scope(|s| {
        let trust = s.spawn(ca_trust::check);
        let updates = s.spawn(apps_mod::macos_updates);
        let home = scan.home.clone();
        let persist = s.spawn(move || {
            crate::checks::machine::any::persistence::gather(&crate::checks::machine::any::persistence::Roots::real(
                home,
            ))
        });
        let brew_ran = brew_job.as_ref().filter(|j| j.stale).map(|j| s.spawn(move || brew_vulns::brew_scan(j)));
        let found = inventory(scan);
        components::components(scan, &found)?;
        app_updates::apps(scan)?;
        os_updates::os_updates(scan, joined(updates))?;
        brew(scan, brew_job.as_ref(), brew_ran.map(joined))?;
        downloads::downloads(scan);
        ca_trust::ca_trust(scan, joined(trust));
        if !scan.opts.no_posture {
            posture(scan);
        }
        persistence(scan, joined(persist));
        clipper::clipper(scan);
        Ok(found)
    })
}

/// A probe's result; its panic, if it had one, carries on here.
fn joined<T>(probe: std::thread::ScopedJoinHandle<'_, T>) -> T {
    probe.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

pub fn inventory(scan: &mut Scan) -> Vec<Component> {
    std::thread::scope(|s| {
        let docker = s.spawn(apps_mod::docker);
        let mut found = inventory_local(scan);
        scan.status("Asking Docker for its engine version");
        found.extend(joined(docker));
        scan.count("tools, runtimes and packages", found.len() as i64);
        found
    })
}

/// What the machine has installed, without Docker's engine.
fn inventory_local(scan: &mut Scan) -> Vec<Component> {
    scan.status("Finding installed tools, runtimes and package managers");
    let mut found = tools::tools();
    // Bottles poured without the `brew` command (mise's brew: engine): read
    // from the Cellar, since `brew vulns` can't run and `tools` leaves
    // Cellar-owned binaries to it. With brew present, brew vulns covers them.
    if process::which("brew").is_none() {
        scan.status("Reading the Homebrew Cellar (no brew)");
        if let Some((cellar, inv)) = cellar::inventory() {
            scan.count("Homebrew formulae (Cellar, no brew)", inv.components.len() as i64);
            if !inv.unmapped.is_empty() {
                let shown: Vec<&str> = inv.unmapped.iter().take(6).map(String::as_str).collect();
                let more = if inv.unmapped.len() > 6 { ", …" } else { "" };
                scan.unchecked(
                    "Homebrew formulae wpantry can't map to OSV",
                    &format!(
                        "{} formulae in {} ({}{more}) have no catalog entry",
                        inv.unmapped.len(),
                        cellar.display(),
                        shown.join(", ")
                    ),
                );
            }
            found.extend(inv.components);
        }
    }
    scan.status("Listing Python installs and their pip packages");
    let (pythons, unread) = packages::pythons();
    found.extend(pythons);
    for (py, why) in unread {
        scan.unchecked(&format!("pip packages of {py}"), &why.join("; "));
    }
    scan.status("Listing global npm packages");
    let npm = packages::node_packages(&found);
    found.extend(npm);
    scan.status("Listing Ruby gems, cargo installs and pipx tools");
    let gems = packages::gems(&found);
    found.extend(gems);
    found.extend(packages::cargo_installs());
    found.extend(packages::pipx_packages());
    found
}

#[cfg(test)]
mod tests;
