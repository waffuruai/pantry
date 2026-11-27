//! The container images behind running containers and the ones the repos
//! build from or run, read through the local engine
//! ([`crate::checks::machine::images`]).
//!
//! The engine is asked once, with a short timeout, before anything else
//! (see [`images_with_limits`]): an engine that is installed but does not
//! answer costs one probe and one gap, not 20 s per image ref.

use crate::checks::Scan;
use crate::checks::machine::images::{self as engine_images, Local, Timeouts};
use crate::checks::supply_chain::repos;
use crate::checks::supply_chain::repos::Repo;
use crate::component::Component;
use crate::error::{Error, Result};
use crate::sources::osv;
use crate::sources::osv::Item;
use crate::utils::files::short;
use std::path::PathBuf;

/// The gap's name: one for the whole step, since one cause (the engine)
/// leaves every image unchecked.
const GAP: &str = "container images";

/// Images behind running containers (machine scans), and the ones the repos
/// build from or run, when they exist locally (pulling is left to the user),
/// scanned with the same extractors as everything else (F12).
pub fn images(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    images_with(scan, repos, crate::checks::machine::images::engine())
}

/// As [`images`], with the engine given (None: not installed).
pub fn images_with(scan: &mut Scan, repos: &[Repo], engine: Option<PathBuf>) -> Result<()> {
    images_with_limits(scan, repos, engine, Timeouts::default())
}

/// As [`images_with`], with the engine's time limits given (the tests').
///
/// 1. The refs the repos name are collected first (no engine involved).
/// 2. With refs to check, or on a machine scan (which also lists the running
///    containers' images), the engine is probed once. If it does not answer,
///    the step records one gap and does nothing else.
/// 3. Each ref is asked in turn. "Not pulled here" is only the engine saying
///    so. The first timeout stops the loop: the engine is no longer
///    answering, and the refs from there on are one gap, with their count.
pub fn images_with_limits(scan: &mut Scan, repos: &[Repo], engine: Option<PathBuf>, limits: Timeouts) -> Result<()> {
    let Some(engine) = engine else { return Ok(()) };
    scan.status("Looking for container images");
    let mut repo_refs: Vec<(String, String)> = Vec::new();
    for (r, f) in repos::repo_images(repos) {
        if !repo_refs.iter().any(|(x, _)| *x == r) {
            let fix = format!(
                "docker pull {r} (the tag may already carry the fixes); if not, bump it in {}; then rebuild",
                short(&f.to_string_lossy())
            );
            repo_refs.push((r, fix));
        }
    }
    if repo_refs.is_empty() && !scan.opts.machine {
        return Ok(());
    }
    let name = engine_images::engine_name(&engine);
    let mut running: Vec<String> = Vec::new();
    if repo_refs.is_empty() {
        // Only the running containers to check: the listing is the question, with the probe's
        // time. Nothing listed (no daemon, so nothing running; nothing running; no answer) is
        // nothing to check: no probe, and no gap about zero refs.
        scan.status(&format!("Asking {name} for its running containers"));
        running = engine_images::running(&engine, limits.probe).unwrap_or_default();
        if running.is_empty() {
            return Ok(());
        }
    } else {
        scan.status(&format!("Asking {name} whether it answers"));
        if let Err(why) = engine_images::probe(&engine, limits.probe) {
            let running =
                if scan.opts.machine { "; the running containers' images were not listed either" } else { "" };
            let n = repo_refs.len();
            scan.unchecked(
                GAP,
                &format!(
                    "{name} is installed but is not answering ({why}), so {n} image ref{} the repos name were not checked{running}",
                    if n == 1 { "" } else { "s" }
                ),
            );
            return Ok(());
        }
        if scan.opts.machine {
            running = engine_images::running(&engine, limits.inspect).unwrap_or_default();
        }
    }
    // Running containers first: their fix is a pull and a recreate.
    let mut refs: Vec<(String, String)> = Vec::new();
    for r in running {
        refs.push((r.clone(), format!("{name} pull {r}, then recreate its containers")));
    }
    for (r, fix) in repo_refs {
        if !refs.iter().any(|(x, _)| *x == r) {
            refs.push((r, fix));
        }
    }
    refs.sort();
    let total = refs.len();
    for (done, (r, fix)) in refs.into_iter().enumerate() {
        let id = match engine_images::local_image(&engine, &r, limits.inspect) {
            Local::Pulled(id) => id,
            Local::NotHere => continue,
            Local::TimedOut => {
                let left = total - done;
                scan.unchecked(
                    GAP,
                    &format!(
                        "{name} stopped answering after {done} of {total} image ref{} (asking about {r} timed out after {} s); {left} not checked",
                        if total == 1 { "" } else { "s" },
                        limits.inspect.as_secs().max(1)
                    ),
                );
                return Ok(());
            }
            Local::Failed(why) => {
                scan.unchecked(&format!("image {r}"), &format!("{name} image inspect failed: {why}"));
                continue;
            }
        };
        scan.status(&format!("Reading image {r}"));
        let (pkgs, gaps) = match crate::checks::machine::images::packages(
            &scan.cache,
            &engine,
            &r,
            &id,
            scan.opts.refresh,
            scan.opts.offline,
        ) {
            Ok(p) => p,
            Err(e) if e.is_source() || matches!(e, Error::Missing(_)) => {
                scan.missed(&format!("image {r}"), &e);
                continue;
            }
            Err(e) => return Err(e),
        };
        if !gaps.is_empty() {
            scan.unchecked(&format!("image {r}"), &gaps.join("; "));
        }
        let pkgs: Vec<_> = pkgs.into_iter().filter(|p| !crate::checks::machine::images::host_kernel(p)).collect();
        scan.count("image packages", pkgs.len() as i64);
        // A Go binary in an image carries the standard library, not the
        // toolchain that built it: its `stdlib` isn't asked as `toolchain`.
        let items: Vec<Item> = pkgs.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())).collect();
        let answers = scan.lookup(&items, &format!("image {r} against OSV"))?;
        for (p, item) in pkgs.iter().zip(items) {
            let Some(recs) = answers.get(&item).filter(|x| !x.is_empty()) else { continue };
            let mut c = Component::new("image", &format!("{r} › {}", p.name), &p.version, &p.source);
            c.fix = fix.clone();
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "fail", Some(osv::group_by_alias(recs)));
        }
    }
    Ok(())
}

// Its one test fakes the container engine with a shell script.
#[cfg(all(test, unix))]
#[path = "images_tests.rs"]
mod tests;
