"""What AI coding harnesses load, the attack surface beyond their own
version: MCP servers (often `npx some-package` with no version pinned),
plugins and desktop extensions that bundle npm packages, and skills.

Covers Claude Code and Claude Desktop, Codex, Cursor, Windsurf, VS Code,
Gemini CLI, Antigravity, Kiro, opencode, OpenClaw, pi and Hermes, plus the
project-level MCP files the scanned repos carry. The harness binaries themselves are
in catalog.TOOLS (or the npm and pipx listings)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .system import expand, read_json

# (harness, config file glob, format, where the servers live: dotted keys, "*" matches any key)
MCP_CONFIGS = (
    ("Claude Code", "~/.claude.json", "json", ("mcpServers", "projects.*.mcpServers")),
    ("Claude Code", "~/.claude/plugins/**/.mcp.json", "json", ("mcpServers", "")),
    ("Claude Desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "json", ("mcpServers",)),
    ("Claude Desktop", "~/.config/Claude/claude_desktop_config.json", "json", ("mcpServers",)),
    ("Codex", "~/.codex/config.toml", "toml", ("mcp_servers",)),
    ("Cursor", "~/.cursor/mcp.json", "json", ("mcpServers",)),
    ("Windsurf", "~/.codeium/windsurf/mcp_config.json", "json", ("mcpServers",)),
    ("VS Code", "~/Library/Application Support/Code/User/mcp.json", "json", ("servers",)),
    ("VS Code", "~/.config/Code/User/mcp.json", "json", ("servers",)),
    ("Gemini CLI", "~/.gemini/settings.json", "json", ("mcpServers",)),
    ("Gemini CLI", "~/.gemini/extensions/*/gemini-extension.json", "json", ("mcpServers",)),
    ("Antigravity", "~/.gemini/antigravity/mcp_config.json", "json", ("mcpServers",)),
    ("Kiro", "~/.kiro/settings/mcp.json", "json", ("mcpServers",)),
    ("opencode", "~/.config/opencode/opencode.json*", "json", ("mcp",)),
    ("OpenClaw", "~/.openclaw/openclaw.json", "json", ("mcpServers", "mcp.servers")),
    ("Hermes", "~/.hermes/config.yaml", "yaml", ("mcp_servers",)),
)
REPO_MCP_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json")

# Where harnesses keep plugins and extensions that ship node_modules.
PLUGIN_DIRS = (
    ("Claude Desktop", "~/Library/Application Support/Claude/Claude Extensions/*"),
    ("Claude Desktop", "~/.config/Claude/Claude Extensions/*"),
    ("Claude Code", "~/.claude/plugins/cache/*/*"),
    ("Gemini CLI", "~/.gemini/extensions/*"),
    ("opencode", "~/.cache/opencode"),
    ("opencode", "~/.config/opencode"),
    ("OpenClaw", "~/.openclaw/extensions/*"),
    ("pi", "~/.pi/agent"),
    ("Hermes", "~/.hermes/plugins/*"),
)
SKILL_DIRS = (
    ("Claude Code", "~/.claude/skills/*"), ("Codex", "~/.codex/skills/*"), ("opencode", "~/.config/opencode/skills/*"),
    ("OpenClaw", "~/.openclaw/skills/*"), ("OpenClaw", "~/.openclaw/workspace/skills/*"),
    ("Hermes", "~/.hermes/skills/*"), ("pi", "~/.pi/agent/skills/*"),
)


def mcp_servers(repos=(), machine=True):
    """[{harness, name, file, command, args}] for every locally run MCP server
    configured in the repos and, when `machine`, in the harnesses' own
    configs (remote URL servers run nothing here)."""
    out = []
    configs = [(h, f, fmt, keys) for h, g, fmt, keys in MCP_CONFIGS for f in expand([g])] if machine else []
    configs += [("project", str(Path(r, rel)), "json", ("mcpServers", "servers"))
                for _, r in repos for rel in REPO_MCP_FILES if Path(r, rel).is_file()]
    for harness, path, fmt, keys in configs:
        data = _load(path, fmt)
        for key in keys:
            for name, spec in _servers(data, key.split(".") if key else []).items():
                cmd, args = _command(spec)
                if cmd:
                    out.append({"harness": harness, "name": name, "file": path, "command": cmd, "args": args})
    return out


def _load(path, fmt):
    if fmt == "json":
        data = read_json(path)
        if data is None and path.endswith(".jsonc"):
            text = re.sub(r"(?m)^\s*//.*$|/\*.*?\*/", "", Path(path).read_text(errors="replace"), flags=re.S)
            data = json.loads(text) if text.strip() else {}
        return data or {}
    if fmt == "toml":
        return _toml(path)
    return {"mcp_servers": _yaml_servers(path)}


def _servers(data, keys):
    """The {name: spec} map at a dotted path; "*" fans out over every key."""
    if not keys:
        return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}
    if not isinstance(data, dict):
        return {}
    head, rest = keys[0], keys[1:]
    if head == "*":
        merged = {}
        for v in data.values():
            merged.update(_servers(v, rest))
        return merged
    return _servers(data.get(head), rest) if head in data else {}


def _command(spec):
    """(command, args) for a local server; ("", []) for a remote one."""
    if not isinstance(spec, dict) or spec.get("url") or spec.get("type") in ("remote", "http", "sse"):
        return "", []
    cmd, args = spec.get("command", ""), list(spec.get("args") or [])
    if isinstance(cmd, list):  # opencode: "command": ["npx", "-y", "pkg"]
        cmd, args = (cmd[0], cmd[1:] + args) if cmd else ("", [])
    return (str(cmd), [str(a) for a in args]) if cmd else ("", [])


# A package runner's own flags that take a value before the package spec.
VALUE_FLAGS = {"-p", "--package", "--from", "--with", "--python", "-c", "--call", "--registry", "--index-url"}


def package_ref(command: str, args):
    """(ecosystem, name, version or "") for an MCP server started through a
    package runner (npx, bunx, pnpm dlx, yarn dlx, npm exec, uvx, uv tool
    run, pipx run), or None for a local binary or script."""
    cmd, argv = os.path.basename(command), list(args)
    if cmd in ("pnpm", "yarn") and argv[:1] == ["dlx"] or cmd == "npm" and argv[:1] in (["exec"], ["x"]):
        eco, argv = "npm", argv[1:]
    elif cmd in ("npx", "bunx", "pnpx"):
        eco = "npm"
    elif cmd == "uvx" or cmd == "uv" and argv[:2] == ["tool", "run"] or cmd == "pipx" and argv[:1] == ["run"]:
        eco, argv = "PyPI", (argv[2:] if cmd == "uv" else argv[1:] if cmd == "pipx" else argv)
    else:
        return None
    spec, i = "", 0
    while i < len(argv):
        a = argv[i]
        if a in ("--package", "-p", "--from") and i + 1 < len(argv):
            spec = argv[i + 1]  # the package to run is named explicitly
            break
        if a in VALUE_FLAGS:
            i += 2
            continue
        if a == "--" or a.startswith("-"):
            i += 1
            continue
        spec = a
        break
    return _split_spec(eco, spec) if spec else None


def _split_spec(eco, spec):
    if eco == "npm":
        name, _, ver = spec.rpartition("@") if spec.rfind("@") > 0 else (spec, "", "")
    else:
        m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:(?:==|@)([^,;<>=!~\s]+))?", spec)
        name, ver = (m.group(1), m.group(2) or "") if m else (spec, "")
    ver = "" if ver in ("latest", "next", "*") else ver
    return eco, name, ver if re.match(r"^\d", ver) else ""


def plugin_dirs():
    return [(h, d) for h, g in PLUGIN_DIRS for d in expand([g]) if os.path.isdir(d)]


def skill_dirs():
    return [(h, d) for h, g in SKILL_DIRS for d in expand([g]) if os.path.isdir(d)]


# Readers for the two non-JSON formats, enough for MCP server tables --------

def _toml(path):
    try:
        import tomllib  # Python 3.11+
        with open(path, "rb") as f:
            return tomllib.load(f)
    except ImportError:
        pass
    except Exception:  # malformed: no servers
        return {}
    servers, current = {}, None
    for line in Path(path).read_text(errors="replace").splitlines():
        line = line.strip()
        m = re.match(r"^\[mcp_servers\.([^.\]]+|\"[^\"]+\")\]$", line)
        if m:
            current = servers.setdefault(m.group(1).strip('"'), {})
        elif line.startswith("["):
            current = None
        elif current is not None and "=" in line:
            k, _, v = line.partition("=")
            try:
                current[k.strip()] = json.loads(v.strip())
            except ValueError:
                current[k.strip()] = v.strip().strip("'\"")
    return {"mcp_servers": servers}


def _yaml_servers(path):
    """`mcp_servers:` in a YAML config: name → {command, args}, where args is
    a flow list ([a, b]) or a block list (- a)."""
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return {}
    servers, block, name, key = {}, False, None, None
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent, line = len(raw) - len(raw.lstrip()), raw.strip()
        if indent == 0:
            block = line.startswith("mcp_servers:")
            continue
        if not block:
            continue
        if line.endswith(":") and not line.startswith("-") and indent <= 2:
            name = line[:-1].strip().strip("'\"")
            servers[name] = {}
        elif name and line.startswith("- ") and key == "args":
            servers[name].setdefault("args", []).append(line[2:].strip().strip("'\""))
        elif name and ":" in line:
            key, _, val = (s.strip() for s in line.partition(":"))
            if val.startswith("["):
                servers[name][key] = [x.strip().strip("'\"") for x in val.strip("[]").split(",") if x.strip()]
            elif val:
                servers[name][key] = val.strip("'\"")
    return servers
