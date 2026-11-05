//! Editor extensions against the lists VS Code itself uses, OSV and their
//! marketplace's latest, and the npm packages bundled in extensions,
//! harness plugins and desktop extensions.

use crate::checks::supply_chain::repos;
use crate::checks::{Scan, lockfiles};
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv;
use crate::sources::osv::Item;
use crate::utils::files::short;
use std::path::{Path, PathBuf};

// Editors and AI harnesses ----------------------------------------------------

/// Malicious or deprecated per the lists VS Code itself uses (and OSV),
/// behind their marketplace's latest, and the npm packages they bundle.
pub fn extensions(scan: &mut Scan) -> Result<Vec<Component>> {
    scan.status("Reading editor extensions");
    extensions_with(scan, crate::checks::machine::editors::extensions())
}

/// As [`extensions`], over the extensions found (`editors::extensions`).
pub fn extensions_with(scan: &mut Scan, mut exts: Vec<Component>) -> Result<Vec<Component>> {
    if exts.is_empty() {
        return Ok(exts);
    }
    scan.count("editor extensions", exts.len() as i64);
    scan.status("Fetching VS Code's malicious-extension list");
    let r = crate::sources::extensions::vscode_lists(&scan.cache, scan.net, scan.opts.offline).map(Some);
    let lists = scan.guard("VS Code's malicious-extension list", r, None)?;
    let items: Vec<Item> = exts.iter().filter_map(|e| e.osv.clone()).collect();
    let answers = scan.lookup(&items, "editor extensions against OSV")?;
    let mut latest: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for market in ["vscode", "openvsx"] {
        let ids: Vec<String> = exts
            .iter()
            .filter(|e| e.extra.get("market").map(String::as_str) == Some(market))
            .map(|e| e.name.clone())
            .collect();
        if !ids.is_empty() {
            scan.status(&format!("Fetching the latest extension versions ({market})"));
            let r = crate::sources::extensions::latest_extensions(
                &scan.cache,
                scan.net,
                &ids,
                market == "openvsx",
                scan.opts.offline,
            );
            latest.extend(scan.guard(&format!("latest extension versions ({market})"), r, Default::default())?);
        }
    }
    for e in &mut exts {
        let id = e.extra.get("id").cloned().unwrap_or_default();
        let editor = e.extra.get("editor").cloned().unwrap_or_default();
        let cli = e.extra.get("cli").cloned().unwrap_or_default();
        let lower = id.to_lowercase();
        e.name = format!("{id} ({editor})"); // how the report names it
        let uninstall = format!("{cli} --uninstall-extension {id}");
        if lists.as_ref().is_some_and(|l| l.malicious.contains(&lower)) {
            scan.add(Finding {
                vuln_id: "MALICIOUS".into(),
                status: "fail".into(),
                kev: true,
                severity: "MALICIOUS".into(),
                fix_cmd: uninstall,
                fix_auto: true,
                note: "known malicious extension (removed from the marketplace)".into(),
                ..Finding::of(e)
            });
            continue;
        }
        (e.fix, e.auto) = (uninstall.clone(), true);
        let recs = e.osv.as_ref().and_then(|o| answers.get(o)).cloned().unwrap_or_default();
        if scan.advisories(e, &recs, None, "fail", None) {
            continue;
        }
        e.fix = format!("{cli} --install-extension {id} --force");
        if let Some(repl) = lists.as_ref().and_then(|l| l.deprecated.get(&lower)) {
            scan.add(Finding {
                vuln_id: "DEPRECATED".into(),
                status: "warn".into(),
                note: if repl.is_empty() { "deprecated".into() } else { format!("deprecated; use {repl}") },
                fix_cmd: uninstall,
                ..Finding::of(e)
            });
        }
        if let Some(newest) = latest.get(&lower)
            && !crate::checks::ecosystems::versions::same_or_newer(&e.version, newest)
        {
            scan.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: newest.clone(),
                note: format!("latest release is {newest}"),
                fix_cmd: e.fix.clone(),
                fix_auto: true,
                ..Finding::of(e)
            });
        }
    }
    Ok(exts)
}

/// npm packages bundled in editor extensions, harness plugins and desktop
/// extensions, plus lockfiles shipped in those and in skills. A vulnerable
/// bundle warns (only its vendor can fix it); malicious fails.
pub fn bundles(scan: &mut Scan, exts: &[Component]) -> Result<()> {
    scan.status("Reading the packages extensions and plugins bundle");
    let mut dirs: Vec<(String, String, String)> =
        exts.iter().map(|e| (e.name.clone(), e.extra.get("dir").cloned().unwrap_or_default(), e.fix.clone())).collect();
    for (h, d) in crate::checks::machine::harnesses::plugin_dirs() {
        let base = Path::new(&d).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        dirs.push((
            format!("{h} plugin {base}"),
            d.clone(),
            format!("Update or remove the {h} plugin in {}", short(&d)),
        ));
    }
    let pkgs: Vec<Vec<(String, String)>> =
        dirs.iter().map(|(_, d, _)| crate::checks::machine::editors::bundled_npm(Path::new(d))).collect();
    let items: Vec<Item> = pkgs.iter().flatten().map(|(n, v)| ("npm".to_string(), n.clone(), v.clone())).collect();
    let answers = scan.lookup(&items, "bundled npm packages against OSV")?;
    for ((label, d, fix), ps) in dirs.iter().zip(&pkgs) {
        for (n, v) in ps {
            let item = ("npm".to_string(), n.clone(), v.clone());
            let mut c = Component::new("bundled", &format!("{label} › {n}"), v, d);
            c.fix = fix.clone();
            let recs = answers.get(&item).cloned().unwrap_or_default();
            c.osv = Some(item);
            scan.advisories(&c, &recs, None, "warn", None);
        }
    }
    let mut roots: Vec<String> = dirs.iter().map(|(_, d, _)| d.clone()).collect();
    roots.extend(crate::checks::machine::harnesses::skill_dirs().into_iter().map(|(_, d)| d));
    let mut read: Vec<(PathBuf, Vec<lockfiles::Package>)> = Vec::new();
    for root in &roots {
        for f in repos::lockfiles(Path::new(root)) {
            if let Ok(Some(p)) = lockfiles::extract(&f) {
                read.push((f, p));
            }
        }
    }
    scan.count("packages in extension, plugin and skill lockfiles", read.iter().map(|(_, p)| p.len() as i64).sum());
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    let answers = scan.lookup(&items, "lockfiles inside extensions, plugins and skills")?;
    for (f, ps) in &read {
        let parent = short(&f.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
        for p in ps {
            let item = (p.ecosystem.clone(), p.name.clone(), p.version.clone());
            let Some(recs) = answers.get(&item).filter(|r| !r.is_empty()) else { continue };
            let mut c = Component::new("bundled", &format!("{parent} › {}", p.name), &p.version, &f.to_string_lossy());
            c.fix = format!("Update or remove what ships {}", short(&f.to_string_lossy()));
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "warn", Some(osv::group_by_alias(recs)));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "extensions_tests.rs"]
mod tests;
