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
    assert_eq!((fs.kind.as_str(), fs.name.as_str(), fs.version.as_str()), ("mcp", "@mcp/fs (project: fs)", "1.0.0"));
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
