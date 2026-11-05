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
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::utils::files;
    use crate::utils::temp::TempDir;

    /// MCP servers started through a package runner: a pinned one is a
    /// package to check, an unpinned one warns, a local script is nothing.
    #[test]
    fn mcp_servers_pinned_and_unpinned() {
        let _home = crate::utils::files::test_home();
        let home = files::home();
        let d = TempDir::new("mcp").unwrap();
        let net = testing::osv_net(&[("npm", "@mcp/fs")]);
        let mut s = testing::scan(&net, &d, Options { machine: true, ..Default::default() });
        let (name, root) = testing::repo(&d, "app");
        testing::write(
            &root,
            ".mcp.json",
            r#"{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs@1.0.0"]}, "git": {"command": "uvx", "args": ["mcp-server-git"]}, "local": {"command": "node", "args": ["x.js"]}}}"#,
        );
        std::fs::create_dir_all(home.join(".claude/skills/s1")).unwrap();
        let refs = mcp(&mut s, &[(name, root.clone())]).unwrap();
        assert_eq!(refs.len(), 2, "{refs:?}");
        assert!(s.counts.contains(&("MCP servers".to_string(), 3)), "{:?}", s.counts);
        assert!(s.counts.contains(&("harness skills".to_string(), 1)), "{:?}", s.counts);
        let fs = &refs[0];
        assert_eq!(
            (fs.kind.as_str(), fs.name.as_str(), fs.version.as_str()),
            ("mcp", "@mcp/fs (project: fs)", "1.0.0")
        );
        assert_eq!(fs.osv, Some(("npm".into(), "@mcp/fs".into(), "1.0.0".into())));
        assert_eq!(
            fs.fix,
            format!(
                "Pin @mcp/fs to a reviewed version in {} ({{safe}} fixes it)",
                short(&root.join(".mcp.json").to_string_lossy())
            )
        );
        let git = &refs[1];
        assert_eq!((git.name.as_str(), git.version.as_str()), ("mcp-server-git (project: git)", "unpinned"));
        assert!(git.osv.is_none());
        assert_eq!(
            (git.extra["eco"].as_str(), git.extra["pkg"].as_str(), git.extra["ver"].as_str()),
            ("PyPI", "mcp-server-git", "")
        );
        let unpinned = testing::by_id(&s, "UNPINNED");
        assert_eq!(unpinned.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (unpinned[0].component.as_str(), unpinned[0].status.as_str(), unpinned[0].note.as_str()),
            ("mcp-server-git (project: git)", "warn", "`uvx mcp-server-git` runs the latest release on every launch")
        );
        let hit = testing::by_id(&s, "GHSA-@mcp/fs");
        assert_eq!(hit.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (hit[0].component.as_str(), hit[0].status.as_str(), hit[0].fix_cmd.as_str()),
            ("@mcp/fs (project: fs)", "fail", fs.fix.replace("{safe}", "9.9.9").as_str())
        );
    }
}
