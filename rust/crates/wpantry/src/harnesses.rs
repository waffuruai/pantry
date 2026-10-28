//! What AI coding harnesses load, the attack surface beyond their own
//! version: MCP servers (often `npx some-package` with no version pinned),
//! plugins and desktop extensions that bundle npm packages, and skills.
//!
//! Covers Claude Code and Claude Desktop, Codex, Cursor, Windsurf, VS Code,
//! Gemini CLI, Antigravity, Kiro, opencode, OpenClaw, pi and Hermes, plus the
//! project-level MCP files the scanned repos carry. The harness binaries
//! themselves are in the catalog (or the npm and pipx listings).

use crate::json::{self, str_at};
use crate::lockfiles::toml;
use crate::repos::Repo;
use crate::system::expand;
use serde_json::{Map, Value};
use std::path::Path;

/// (harness, config file glob, format, where the servers live: dotted keys,
/// "*" matches any key, "" the top level)
pub const MCP_CONFIGS: &[(&str, &str, &str, &[&str])] = &[
    ("Claude Code", "~/.claude.json", "json", &["mcpServers", "projects.*.mcpServers"]),
    ("Claude Code", "~/.claude/plugins/**/.mcp.json", "json", &["mcpServers", ""]),
    ("Claude Desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "json", &["mcpServers"]),
    ("Claude Desktop", "~/.config/Claude/claude_desktop_config.json", "json", &["mcpServers"]),
    ("Codex", "~/.codex/config.toml", "toml", &["mcp_servers"]),
    ("Cursor", "~/.cursor/mcp.json", "json", &["mcpServers"]),
    ("Windsurf", "~/.codeium/windsurf/mcp_config.json", "json", &["mcpServers"]),
    ("VS Code", "~/Library/Application Support/Code/User/mcp.json", "json", &["servers"]),
    ("VS Code", "~/.config/Code/User/mcp.json", "json", &["servers"]),
    ("Gemini CLI", "~/.gemini/settings.json", "json", &["mcpServers"]),
    ("Gemini CLI", "~/.gemini/extensions/*/gemini-extension.json", "json", &["mcpServers"]),
    ("Antigravity", "~/.gemini/antigravity/mcp_config.json", "json", &["mcpServers"]),
    ("Kiro", "~/.kiro/settings/mcp.json", "json", &["mcpServers"]),
    ("opencode", "~/.config/opencode/opencode.json*", "json", &["mcp"]),
    ("OpenClaw", "~/.openclaw/openclaw.json", "json", &["mcpServers", "mcp.servers"]),
    ("Hermes", "~/.hermes/config.yaml", "yaml", &["mcp_servers"]),
];

/// Where harnesses keep plugins and extensions that ship node_modules.
pub const PLUGIN_DIRS: &[(&str, &str)] = &[
    ("Claude Desktop", "~/Library/Application Support/Claude/Claude Extensions/*"),
    ("Claude Desktop", "~/.config/Claude/Claude Extensions/*"),
    ("Claude Code", "~/.claude/plugins/cache/*/*"),
    ("Gemini CLI", "~/.gemini/extensions/*"),
    ("opencode", "~/.cache/opencode"),
    ("opencode", "~/.config/opencode"),
    ("OpenClaw", "~/.openclaw/extensions/*"),
    ("pi", "~/.pi/agent"),
    ("Hermes", "~/.hermes/plugins/*"),
];

pub const SKILL_DIRS: &[(&str, &str)] = &[
    ("Claude Code", "~/.claude/skills/*"),
    ("Codex", "~/.codex/skills/*"),
    ("opencode", "~/.config/opencode/skills/*"),
    ("OpenClaw", "~/.openclaw/skills/*"),
    ("OpenClaw", "~/.openclaw/workspace/skills/*"),
    ("Hermes", "~/.hermes/skills/*"),
    ("pi", "~/.pi/agent/skills/*"),
];

fn dirs(table: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (h, g) in table {
        for d in expand(&[g]) {
            if Path::new(&d).is_dir() {
                out.push((h.to_string(), d));
            }
        }
    }
    out
}

/// (harness, dir) of every installed plugin or desktop extension.
pub fn plugin_dirs() -> Vec<(String, String)> {
    dirs(PLUGIN_DIRS)
}

/// (harness, dir) of every installed skill.
pub fn skill_dirs() -> Vec<(String, String)> {
    dirs(SKILL_DIRS)
}

pub const REPO_MCP_FILES: &[&str] = &[".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json"];

/// A locally run MCP server.
#[derive(Clone, Debug, PartialEq)]
pub struct Server {
    pub harness: String,
    pub name: String,
    pub file: String,
    pub command: String,
    pub args: Vec<String>,
}

/// Every locally run MCP server the repos configure and, when `machine`,
/// the harnesses' own configs (remote URL servers run nothing here).
pub fn mcp_servers(repos: &[Repo], machine: bool) -> Vec<Server> {
    let mut configs: Vec<(String, String, &str, Vec<&str>)> = Vec::new();
    if machine {
        for (h, g, fmt, keys) in MCP_CONFIGS {
            for f in expand(&[g]) {
                configs.push((h.to_string(), f, fmt, keys.to_vec()));
            }
        }
    }
    for (_, root) in repos {
        for rel in REPO_MCP_FILES {
            let path = root.join(rel);
            if path.is_file() {
                configs.push((
                    "project".into(),
                    path.to_string_lossy().into_owned(),
                    "json",
                    vec!["mcpServers", "servers"],
                ));
            }
        }
    }
    let mut out = Vec::new();
    for (harness, path, fmt, keys) in configs {
        let data = load(Path::new(&path), fmt);
        for key in keys {
            let parts: Vec<&str> = if key.is_empty() { Vec::new() } else { key.split('.').collect() };
            for (name, spec) in servers(&data, &parts) {
                if let Some((command, args)) = command(&spec) {
                    out.push(Server { harness: harness.clone(), name, file: path.clone(), command, args });
                }
            }
        }
    }
    out
}

fn load(path: &Path, fmt: &str) -> Value {
    match fmt {
        "toml" => toml_servers(path),
        "yaml" => {
            let mut m = Map::new();
            m.insert("mcp_servers".into(), yaml_servers(path));
            Value::Object(m)
        }
        _ => {
            let v = read_json(path);
            if v.is_null() && path.to_string_lossy().ends_with(".jsonc") {
                let text = std::fs::read_to_string(path).unwrap_or_default();
                let text = crate::re::Regex::with_flags(r"^\s*//.*$|/\*.*?\*/", "ms").replace_all(&text, "");
                return if text.trim().is_empty() {
                    Value::Object(Map::new())
                } else {
                    serde_json::from_str(&text).unwrap_or(Value::Null)
                };
            }
            v
        }
    }
}

/// The {name: spec} objects at a dotted path; "*" fans out over every key.
fn servers(data: &Value, keys: &[&str]) -> Vec<(String, Value)> {
    let Some(obj) = data.as_object() else { return Vec::new() };
    let Some((head, rest)) = keys.split_first() else {
        return obj.iter().filter(|(_, v)| v.is_object()).map(|(k, v)| (k.clone(), v.clone())).collect();
    };
    if *head == "*" {
        let mut merged: Vec<(String, Value)> = Vec::new();
        for v in obj.values() {
            for (k, spec) in servers(v, rest) {
                merged.retain(|(n, _)| *n != k);
                merged.push((k, spec));
            }
        }
        return merged;
    }
    obj.get(*head).map(|v| servers(v, rest)).unwrap_or_default()
}

fn read_json(path: &Path) -> Value {
    std::fs::read(path).ok().and_then(|b| json::parse(&b, 16 << 20).ok()).unwrap_or(Value::Null)
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// (command, args) for a local server; None for a remote one.
fn command(spec: &Value) -> Option<(String, Vec<String>)> {
    let truthy = |v: Option<&Value>| v.is_some_and(|v| !matches!(v, Value::Null | Value::Bool(false)) && v != "");
    if truthy(spec.get("url")) || matches!(str_at(spec, "type"), "remote" | "http" | "sse") {
        return None;
    }
    let mut args: Vec<String> = json::arr_at(spec, "args").iter().map(as_text).collect();
    let cmd = match spec.get("command") {
        // opencode: "command": ["npx", "-y", "pkg"]
        Some(Value::Array(parts)) => {
            let (first, rest) = parts.split_first()?;
            let mut all: Vec<String> = rest.iter().map(as_text).collect();
            all.append(&mut args);
            args = all;
            as_text(first)
        }
        Some(Value::Null) | None => String::new(),
        Some(v) => as_text(v),
    };
    (!cmd.is_empty()).then_some((cmd, args))
}

/// A package runner's own flags that take a value before the package spec.
const VALUE_FLAGS: &[&str] =
    &["-p", "--package", "--from", "--with", "--python", "-c", "--call", "--registry", "--index-url"];

/// (ecosystem, name, version or "") for an MCP server started through a
/// package runner (npx, bunx, pnpm dlx, yarn dlx, npm exec, uvx, uv tool
/// run, pipx run), or None for a local binary or script.
pub fn package_ref(command: &str, args: &[String]) -> Option<(String, String, String)> {
    let cmd = command.rsplit('/').next().unwrap_or(command);
    let first = args.first().map(String::as_str);
    let (eco, argv): (&str, &[String]) = if (matches!(cmd, "pnpm" | "yarn") && first == Some("dlx"))
        || (cmd == "npm" && matches!(first, Some("exec") | Some("x")))
    {
        ("npm", &args[1..])
    } else if matches!(cmd, "npx" | "bunx" | "pnpx") {
        ("npm", args)
    } else if cmd == "uvx" {
        ("PyPI", args)
    } else if cmd == "uv" && args.len() >= 2 && args[0] == "tool" && args[1] == "run" {
        ("PyPI", &args[2..])
    } else if cmd == "pipx" && first == Some("run") {
        ("PyPI", &args[1..])
    } else {
        return None;
    };
    let mut spec = "";
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if matches!(a, "--package" | "-p" | "--from") && i + 1 < argv.len() {
            spec = &argv[i + 1]; // the package to run is named explicitly
            break;
        }
        if VALUE_FLAGS.contains(&a) {
            i += 2;
            continue;
        }
        if a == "--" || a.starts_with('-') {
            i += 1;
            continue;
        }
        spec = a;
        break;
    }
    (!spec.is_empty()).then(|| split_spec(eco, spec))
}

fn split_spec(eco: &str, spec: &str) -> (String, String, String) {
    let (name, ver) = if eco == "npm" {
        match spec.rfind('@') {
            Some(i) if i > 0 => (&spec[..i], &spec[i + 1..]),
            _ => (spec, ""),
        }
    } else {
        // name[extras](==|@)version
        let name_end =
            spec.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))).unwrap_or(spec.len());
        if name_end == 0 {
            (spec, "")
        } else {
            let mut rest = &spec[name_end..];
            if rest.starts_with('[') {
                rest = rest.find(']').map(|j| &rest[j + 1..]).unwrap_or(rest);
            }
            let ver = rest.strip_prefix("==").or_else(|| rest.strip_prefix('@')).unwrap_or("");
            let ver_end = ver
                .find(|c: char| matches!(c, ',' | ';' | '<' | '>' | '=' | '!' | '~') || c.is_whitespace())
                .unwrap_or(ver.len());
            (&spec[..name_end], &ver[..ver_end])
        }
    };
    let ver = if matches!(ver, "latest" | "next" | "*") { "" } else { ver };
    let ver = if ver.as_bytes().first().is_some_and(u8::is_ascii_digit) { ver } else { "" };
    (eco.to_string(), name.to_string(), ver.to_string())
}

/// A dotted TOML table name split into keys (`mcp_servers."my server"`).
fn dotted(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = name.trim();
    while !rest.is_empty() {
        if rest.starts_with('"') || rest.starts_with('\'') {
            let Some((k, r)) = toml::string(rest) else { break };
            out.push(k);
            rest = r.trim_start().strip_prefix('.').unwrap_or(r).trim_start();
        } else {
            let end = rest.find('.').unwrap_or(rest.len());
            out.push(rest[..end].trim().to_string());
            rest = rest[end..].strip_prefix('.').unwrap_or("").trim_start();
        }
    }
    out
}

/// The strings in a TOML array's raw text (`["-y", "x@1.0.0"]`).
fn toml_strings(raw: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut rest = raw.trim().strip_prefix('[').unwrap_or("");
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if rest.starts_with('#') {
            rest = rest.split_once('\n').map(|(_, r)| r).unwrap_or("");
            continue;
        }
        match toml::string(rest) {
            Some((v, r)) => {
                out.push(Value::String(v));
                rest = r;
            }
            None => return out,
        }
    }
}

/// `[mcp_servers.<name>]` tables of a TOML config (Codex), as {"mcp_servers":
/// {name: {command, args}}}; nested tables (`.env`) are ignored.
fn toml_servers(path: &Path) -> Value {
    let mut servers = Map::new();
    let text = crate::system::read_capped(path, 16 << 20).unwrap_or_default();
    for t in toml::parse(&text).unwrap_or_default() {
        let keys = dotted(&t.name);
        if keys.len() != 2 || keys[0] != "mcp_servers" || t.array {
            continue;
        }
        let mut spec = Map::new();
        for (k, v) in &t.entries {
            let value = match v {
                toml::Val::Str(s) => Value::String(s.clone()),
                toml::Val::Raw(r) if r.trim_start().starts_with('[') => Value::Array(toml_strings(r)),
                toml::Val::Raw(r) => Value::String(r.trim().to_string()),
            };
            spec.insert(k.clone(), value);
        }
        servers.insert(keys[1].clone(), Value::Object(spec));
    }
    let mut m = Map::new();
    m.insert("mcp_servers".into(), Value::Object(servers));
    Value::Object(m)
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(['\'', '"']).to_string()
}

/// `mcp_servers:` in a YAML config: name → {command, args}, where args is a
/// flow list ([a, b]) or a block list (- a).
fn yaml_servers(path: &Path) -> Value {
    let text = crate::system::read_capped(path, 16 << 20).unwrap_or_default();
    let mut servers: Vec<(String, Map<String, Value>)> = Vec::new();
    let (mut block, mut key) = (false, String::new());
    for raw in text.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if indent == 0 {
            block = line.starts_with("mcp_servers:");
            continue;
        }
        if !block {
            continue;
        }
        if line.ends_with(':') && !line.starts_with('-') && indent <= 2 {
            servers.push((unquote(&line[..line.len() - 1]), Map::new()));
            key.clear();
        } else if let Some((_, spec)) = servers.last_mut() {
            if line.starts_with("- ") && key == "args" {
                let args = spec.entry("args").or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(a) = args {
                    a.push(Value::String(unquote(&line[2..])));
                }
            } else if let Some((k, v)) = line.split_once(':') {
                key = k.trim().to_string();
                let v = v.trim();
                if v.starts_with('[') {
                    let items = v
                        .trim_matches(['[', ']'])
                        .split(',')
                        .map(unquote)
                        .filter(|x| !x.is_empty())
                        .map(Value::String)
                        .collect();
                    spec.insert(key.clone(), Value::Array(items));
                } else if !v.is_empty() {
                    spec.insert(key.clone(), Value::String(unquote(v)));
                }
            }
        }
    }
    Value::Object(servers.into_iter().map(|(k, v)| (k, Value::Object(v))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Ref = Option<(String, String, String)>;

    fn r(c: &str, a: &[&str]) -> Ref {
        package_ref(c, &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn t(e: &str, n: &str, v: &str) -> Ref {
        Some((e.into(), n.into(), v.into()))
    }

    // The Python test vectors (python/test_wscanner.py `Harnesses`).
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

    // The Python test vectors (python/test_wscanner.py `Harnesses`).
    #[test]
    fn configs_across_harnesses() {
        let _home = crate::system::test_home();
        let home = crate::system::home();
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
        let d = crate::system::TempDir::new("toml").unwrap();
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
        let d = crate::system::TempDir::new("mcp").unwrap();
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
}
