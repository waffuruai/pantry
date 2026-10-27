//! What AI coding harnesses load: here, the MCP servers the scanned repos
//! configure (`.mcp.json` and friends), and how a server started through a
//! package runner (`npx some-package`) maps to a package. The harnesses'
//! own configs, plugins and skills are part of the machine inventory
//! (phase 2).

use crate::json::{self, str_at};
use crate::repos::Repo;
use serde_json::Value;
use std::path::Path;

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

/// Every locally run MCP server the repos configure (remote URL servers run
/// nothing here).
pub fn mcp_servers(repos: &[Repo]) -> Vec<Server> {
    let mut out = Vec::new();
    for (_, root) in repos {
        for rel in REPO_MCP_FILES {
            let path = root.join(rel);
            if !path.is_file() {
                continue;
            }
            let data = read_json(&path);
            for key in ["mcpServers", "servers"] {
                let Some(servers) = data.get(key).and_then(Value::as_object) else { continue };
                for (name, spec) in servers {
                    if !spec.is_object() {
                        continue;
                    }
                    if let Some((command, args)) = command(spec) {
                        out.push(Server {
                            harness: "project".into(),
                            name: name.clone(),
                            file: path.to_string_lossy().into_owned(),
                            command,
                            args,
                        });
                    }
                }
            }
        }
    }
    out
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
        let got: Vec<(String, Ref)> = mcp_servers(&[("repo".into(), repo)])
            .iter()
            .map(|s| (s.name.clone(), package_ref(&s.command, &s.args)))
            .collect();
        assert_eq!(got, [("db".to_string(), t("npm", "db-mcp", "")), ("oc".to_string(), t("npm", "oc-mcp", "1.0.0"))]);
    }
}
