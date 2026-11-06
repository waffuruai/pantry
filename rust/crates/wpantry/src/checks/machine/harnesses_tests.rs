use super::*;

#[test]
fn jsonc_line_comments_end_at_their_line() {
    let d = crate::utils::temp::TempDir::new("jsonc").unwrap();
    let f = d.path().join("opencode.jsonc");
    std::fs::write(&f, "// header\n{\n  // the servers\n  \"mcp\": {\"db\": {\"command\": \"bunx\"}} /* c */\n}\n")
        .unwrap();
    let v = load(&f, "json");
    assert_eq!(v["mcp"]["db"]["command"], "bunx", "{v}");
}

type Ref = Option<(String, String, String)>;

fn r(c: &str, a: &[&str]) -> Ref {
    package_ref(c, &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

fn t(e: &str, n: &str, v: &str) -> Ref {
    Some((e.into(), n.into(), v.into()))
}

// The test vectors the Python implementation had (`Harnesses`).
#[test]
fn package_runners() {
    assert_eq!(
        r("npx", &["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"]),
        t("npm", "@modelcontextprotocol/server-filesystem", "2025.1.14")
    );
    assert_eq!(r("/usr/local/bin/npx", &["-y", "mcp-server-x"]), t("npm", "mcp-server-x", ""));
    assert_eq!(r("npx", &["-p", "pkg@1.2.3", "bin-name"]), t("npm", "pkg", "1.2.3"));
    assert_eq!(r("pnpm", &["dlx", "some-mcp@latest"]), t("npm", "some-mcp", ""));
    assert_eq!(r("uvx", &["mcp-server-fetch==2025.4.7"]), t("PyPI", "mcp-server-fetch", "2025.4.7"));
    assert_eq!(r("uvx", &["--from", "git-mcp[cli]@1.0.0", "git-mcp"]), t("PyPI", "git-mcp", "1.0.0"));
    assert_eq!(r("uv", &["tool", "run", "mcp-x"]), t("PyPI", "mcp-x", ""));
    assert_eq!(r("/Applications/ChatGPT.app/node_repl", &[]), None);
    assert_eq!(r("node", &["server.js"]), None);
}

// The test vectors the Python implementation had (`Harnesses`).
#[test]
fn configs_across_harnesses() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    for (f, text) in [
        (
            ".cursor/mcp.json",
            r#"{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-mcp"]}, "remote": {"url": "https://example.com/mcp"}}}"#,
        ),
        (
            ".codex/config.toml",
            "[mcp_servers.fetch]\ncommand = \"uvx\"\nargs = [\"mcp-server-fetch\"]\n[mcp_servers.fetch.env]\nX = \"1\"\n",
        ),
        (
            ".hermes/config.yaml",
            "model: x\nmcp_servers:\n  gh:\n    command: npx\n    args:\n      - -y\n      - gh-mcp@2.0.0\n",
        ),
        ("repo/.mcp.json", r#"{"mcpServers": {"db": {"command": "bunx", "args": ["db-mcp"]}}}"#),
    ] {
        std::fs::create_dir_all(home.join(f).parent().unwrap()).unwrap();
        std::fs::write(home.join(f), text).unwrap();
    }
    let mut got: Vec<(String, String, Ref)> = mcp_servers(&[("repo".into(), home.join("repo"))], true)
        .iter()
        .map(|s| (s.harness.clone(), s.name.clone(), package_ref(&s.command, &s.args)))
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("Codex".to_string(), "fetch".to_string(), t("PyPI", "mcp-server-fetch", "")),
            ("Cursor".to_string(), "fs".to_string(), t("npm", "fs-mcp", "")),
            ("Hermes".to_string(), "gh".to_string(), t("npm", "gh-mcp", "2.0.0")),
            ("project".to_string(), "db".to_string(), t("npm", "db-mcp", "")),
        ]
    );
    assert_eq!(mcp_servers(&[], false), [], "no machine configs without a machine scan");
}

#[test]
fn toml_quoted_tables() {
    let d = crate::utils::temp::TempDir::new("toml").unwrap();
    let f = d.path().join("c.toml");
    std::fs::write(
        &f,
        "[mcp_servers.\"my server\"]\ncommand = \"npx\"\nargs = [\"-y\", \"x@1.0.0\"]\n[other]\nk = 1\n",
    )
    .unwrap();
    assert_eq!(
        toml_servers(&f),
        serde_json::json!({"mcp_servers": {"my server": {"command": "npx", "args": ["-y", "x@1.0.0"]}}})
    );
}

#[test]
fn project_mcp_files() {
    let d = crate::utils::temp::TempDir::new("mcp").unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".vscode")).unwrap();
    std::fs::write(repo.join(".mcp.json"), r#"{"mcpServers": {"db": {"command": "bunx", "args": ["db-mcp"]}, "remote": {"url": "https://example.com/mcp"}}}"#).unwrap();
    std::fs::write(
        repo.join(".vscode/mcp.json"),
        r#"{"servers": {"oc": {"command": ["npx", "-y"], "args": ["oc-mcp@1.0.0"]}}}"#,
    )
    .unwrap();
    let got: Vec<(String, Ref)> = mcp_servers(&[("repo".into(), repo)], false)
        .iter()
        .map(|s| (s.name.clone(), package_ref(&s.command, &s.args)))
        .collect();
    assert_eq!(got, [("db".to_string(), t("npm", "db-mcp", "")), ("oc".to_string(), t("npm", "oc-mcp", "1.0.0"))]);
}

#[test]
fn plugin_and_skill_dirs_are_the_installed_ones() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    for d in [".claude/skills/review", ".codex/skills/x", ".pi/agent", ".claude/plugins/cache/mk/p1"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    std::fs::write(home.join(".claude/skills/README.md"), "").unwrap();
    let skills: Vec<(String, String)> = skill_dirs();
    assert_eq!(
        skills,
        [
            ("Claude Code".to_string(), home.join(".claude/skills/review").to_string_lossy().into_owned()),
            ("Codex".to_string(), home.join(".codex/skills/x").to_string_lossy().into_owned()),
            ("pi".to_string(), home.join(".pi/agent/skills").to_string_lossy().into_owned()),
        ]
        .into_iter()
        .filter(|(h, _)| h != "pi")
        .collect::<Vec<_>>(),
        "a file in the skills folder isn't a skill"
    );
    assert_eq!(
        plugin_dirs(),
        [
            ("Claude Code".to_string(), home.join(".claude/plugins/cache/mk/p1").to_string_lossy().into_owned()),
            ("pi".to_string(), home.join(".pi/agent").to_string_lossy().into_owned()),
        ]
    );
}

#[test]
fn claude_code_projects_fan_out_and_later_projects_win() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers": {"top": {"command": "npx", "args": ["top-mcp"]}},
                "projects": {"/a": {"mcpServers": {"fs": {"command": "npx", "args": ["fs-mcp@1.0.0"]}}},
                             "/b": {"mcpServers": {"fs": {"command": "npx", "args": ["fs-mcp@2.0.0", 3]}, "none": {"command": null}, "sse": {"type": "sse"}}},
                             "/c": {"other": 1}}}"#,
    )
    .unwrap();
    let mut got: Vec<(String, Vec<String>)> = mcp_servers(&[], true).into_iter().map(|s| (s.name, s.args)).collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("fs".to_string(), vec!["fs-mcp@2.0.0".to_string(), "3".to_string()]),
            ("top".to_string(), vec!["top-mcp".to_string()])
        ]
    );
}

#[test]
fn jsonc_with_only_comments_is_empty() {
    let d = crate::utils::temp::TempDir::new("jsonc").unwrap();
    let f = d.path().join("opencode.jsonc");
    std::fs::write(&f, "// nothing here\n/* or here */\n").unwrap();
    assert_eq!(load(&f, "json"), serde_json::json!({}));
    assert_eq!(load(&d.path().join("missing.json"), "json"), Value::Null);
}

#[test]
fn more_package_runners() {
    assert_eq!(r("pipx", &["run", "mcp-x==1.2"]), t("PyPI", "mcp-x", "1.2"));
    assert_eq!(r("pipx", &["install", "mcp-x"]), None);
    assert_eq!(r("uvx", &["--python", "3.12", "--", "mcp-x"]), t("PyPI", "mcp-x", ""));
    assert_eq!(r("uvx", &["--python"]), None, "a flag with no value names no package");
    assert_eq!(r("uvx", &["==1.0"]), t("PyPI", "==1.0", ""), "no name before the version");
    assert_eq!(r("uvx", &["mcp-x@latest"]), t("PyPI", "mcp-x", ""));
    assert_eq!(r("uvx", &["mcp-x==>1"]), t("PyPI", "mcp-x", ""), "a range isn't a version");
    assert_eq!(r("npx", &["@scope/pkg"]), t("npm", "@scope/pkg", ""));
    assert_eq!(r("npm", &["exec", "pkg@1.0.0"]), t("npm", "pkg", "1.0.0"));
    assert_eq!(r("yarn", &["dlx"]), None);
}

#[test]
fn codex_toml_values_and_comments() {
    let d = crate::utils::temp::TempDir::new("toml").unwrap();
    let f = d.path().join("c.toml");
    std::fs::write(
        &f,
        "[mcp_servers.a]\ncommand = \"npx\"\nargs = [\n  # the package\n  \"-y\", 'x@1.0.0',\n]\ntimeout = 5\n[[mcp_servers.b]]\ncommand = \"x\"\n",
    )
    .unwrap();
    assert_eq!(
        toml_servers(&f),
        serde_json::json!({"mcp_servers": {"a": {"command": "npx", "args": ["-y", "x@1.0.0"], "timeout": "5"}}})
    );
    assert_eq!(dotted("a.\"b.c\".d"), ["a", "b.c", "d"]);
    assert_eq!(dotted("\"open"), Vec::<String>::new());
    assert_eq!(toml_strings("not an array"), Vec::<Value>::new());
}

#[test]
fn hermes_yaml_flow_lists_and_scalars() {
    let d = crate::utils::temp::TempDir::new("yaml").unwrap();
    let f = d.path().join("config.yaml");
    std::fs::write(
        &f,
        "# config\nmodel: x\n  unrelated: 1\nmcp_servers:\n\n    early: 1\n  fs:\n    command: \"npx\"\n    args: ['-y', fs-mcp]\n    env:\n    junk\n  remote:\n    url: https://example.com\n  - stray\nother:\n  k: v\n",
    )
    .unwrap();
    assert_eq!(
        yaml_servers(&f),
        serde_json::json!({"fs": {"command": "npx", "args": ["-y", "fs-mcp"]}, "remote": {"url": "https://example.com"}})
    );
    let v = load(&f, "yaml");
    assert_eq!(v["mcp_servers"]["fs"]["command"], "npx");
}
