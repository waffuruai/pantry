//! MCP servers the repos start through a package runner: pinned ones are
//! checked like any package, unpinned ones warn.

use crate::checks::Scan;
use crate::checks::machine::harnesses;
use crate::checks::supply_chain::repos::Repo;
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv::Item;
use crate::utils::files::short;

/// MCP servers the repos start through a package runner. Pinned ones are
/// checked like any package; unpinned ones run whatever is latest on every
/// launch, so they warn (and fail if the name is known malicious).
pub fn mcp(scan: &mut Scan, repos: &[Repo]) -> Result<Vec<Component>> {
    scan.status("Reading the repos' MCP server configs");
    let servers = harnesses::mcp_servers(repos, scan.opts.machine);
    scan.count("MCP servers", servers.len() as i64);
    let mut refs = Vec::new();
    for s in &servers {
        let Some((eco, name, ver)) = harnesses::package_ref(&s.command, &s.args) else { continue };
        let mut c = Component::new(
            "mcp",
            &format!("{name} ({}: {})", s.harness, s.name),
            if ver.is_empty() { "unpinned" } else { &ver },
            &s.file,
        );
        if !ver.is_empty() {
            c.osv = Some((eco.clone(), name.clone(), ver.clone()));
        }
        c.extra.insert("eco".into(), eco.clone());
        c.extra.insert("pkg".into(), name.clone());
        c.extra.insert("ver".into(), ver.clone());
        c.fix = format!(
            "Pin {name} to a reviewed version in {}{}",
            short(&s.file),
            if ver.is_empty() { "" } else { " ({safe} fixes it)" }
        );
        if ver.is_empty() {
            scan.add(Finding {
                vuln_id: "UNPINNED".into(),
                status: "warn".into(),
                fix_cmd: c.fix.clone(),
                note: format!("`{} {name}` runs the latest release on every launch", s.command),
                ..Finding::of(&c)
            });
        }
        refs.push(c);
    }
    let items: Vec<Item> = refs.iter().filter_map(|c| c.osv.clone()).collect();
    let answers = scan.lookup(&items, "MCP server packages against OSV")?;
    if scan.opts.machine {
        scan.count("harness skills", crate::checks::machine::harnesses::skill_dirs().len() as i64);
    }
    for c in &refs {
        if let Some(item) = &c.osv {
            let recs = answers.get(item).cloned().unwrap_or_default();
            scan.advisories(c, &recs, None, "fail", None);
        }
    }
    Ok(refs)
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
