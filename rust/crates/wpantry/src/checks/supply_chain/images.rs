//! The container images behind running containers and the ones the repos
//! build from or run, read through the local engine
//! ([`crate::checks::machine::images`]).

use crate::checks::Scan;
use crate::checks::supply_chain::repos;
use crate::checks::supply_chain::repos::Repo;
use crate::component::Component;
use crate::error::{Error, Result};
use crate::sources::osv;
use crate::sources::osv::Item;
use crate::utils::files::short;
use std::path::PathBuf;

/// Images behind running containers (machine scans), and the ones the repos
/// build from or run, when they exist locally (pulling is left to the user),
/// scanned with the same extractors as everything else (F12).
pub fn images(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    images_with(scan, repos, crate::checks::machine::images::engine())
}

/// As [`images`], with the engine given (None: not installed).
pub fn images_with(scan: &mut Scan, repos: &[Repo], engine: Option<PathBuf>) -> Result<()> {
    let Some(engine) = engine else { return Ok(()) };
    scan.status("Looking for container images");
    let mut refs: Vec<(String, String)> = Vec::new();
    if scan.opts.machine {
        for r in crate::checks::machine::apps::running_images() {
            refs.push((r.clone(), format!("docker pull {r}, then recreate its containers")));
        }
    }
    for (r, f) in repos::repo_images(repos) {
        if !refs.iter().any(|(x, _)| *x == r) {
            let fix = format!(
                "docker pull {r} (the tag may already carry the fixes); if not, bump it in {}; then rebuild",
                short(&f.to_string_lossy())
            );
            refs.push((r, fix));
        }
    }
    refs.sort();
    for (r, fix) in refs {
        let id = crate::checks::machine::images::image_id(&engine, &r);
        if id.is_empty() {
            continue;
        }
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
                scan.unchecked(&format!("image {r}"), &e.to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        if !gaps.is_empty() {
            scan.unchecked(&format!("image {r}"), &gaps.join("; "));
        }
        let pkgs: Vec<_> = pkgs.into_iter().filter(|p| !crate::checks::machine::images::host_kernel(p)).collect();
        scan.count("image packages", pkgs.len() as i64);
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

#[cfg(test)]
#[path = "images_tests.rs"]
mod tests;
