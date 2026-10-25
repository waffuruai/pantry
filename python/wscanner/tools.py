"""Find the tools in catalog.TOOLS on this machine: every copy on PATH and
every runtime a version manager has installed, active or not.

A binary is only ours to check when nothing else vouches for it (see
system.owner): Homebrew formulae go to `brew vulns`, npm and pipx installs
to their package listings, Apple's and the distro's files to the OS update
check, and binaries inside an app bundle to the app check."""

from __future__ import annotations

import os
import re

from .catalog import TOOLS
from .system import HOME, Component, github, on_path, owner, read_json, run


def tag(fmt: str, v: str) -> str:
    v3 = v if v.count(".") >= 2 else v + ".0"
    return fmt.format(v=v, v3=v3, u=v.replace(".", "_"), ssh=v.replace(".", "_").replace("p", "_P"))


# (path marker, update command, safe to run unattended). "{safe}" is the fix.
MANAGED_BY = (
    ("/.nvm/", "nvm install {safe}", False),  # nvm is a shell function
    ("/.volta/", "volta install {name}@{safe}", True),
    ("/fnm/", "fnm install {safe}", True),
    ("/.asdf/", "asdf install {name} {safe}", False),
    ("/mise/", "mise install {name}@{safe}", True),
    ("/.rustup/", "rustup update", True),
    (f"{HOME}/.cargo/bin", "rustup update", True),
    ("/uv/python/", "uv python upgrade", True),
    (f"{HOME}/.local/bin/python", "uv python upgrade", True),
    ("/.pyenv/", "pyenv install {safe}", False),
    ("/.rbenv/", "rbenv install {safe}", False),
    ("/.rvm/", "rvm install {safe}", False),
    ("conda", "conda update --name base {name}", False),
    ("/.sdkman/", "sdk install java {safe}", False),
)


def updater(path: str, name: str) -> tuple:
    """(how to update, safe to run unattended) for a binary we check."""
    for marker, cmd, auto in MANAGED_BY:
        if marker in path:
            return cmd.replace("{name}", name), auto
    return f"Upgrade {name} at {path} to {{safe}}", False


def find(t, extra_dirs=()):
    """Components for one catalog tool."""
    out = []
    for b in t.bins:
        for shown, real in on_path(b, t.paths + tuple(extra_dirs)):
            who = owner(real)
            if who and not (t.always and who in ("brew", "app")):
                continue
            m = re.search(t.pattern, run([shown, *t.args]), re.M)
            if not m:
                continue
            v = m.group(1)
            fix, auto = updater(real, t.name)
            if who == "brew":
                fix, auto = f"brew upgrade {real.split('/Cellar/')[1].split('/')[0]}", True
            elif who == "app":
                fix, auto = f"Update {re.search(r'([^/]+)[.]app/', real).group(1)}", False
            c = Component(t.kind, t.name, v, shown, fix=fix, auto=auto)
            if t.osv:
                c.osv = (t.osv[0], t.osv[1], tag(t.osv[2], v))
            if t.eol:
                c.eol = (t.eol[0], t.eol[1](v))
            out.append(c)
    return out


def tools():
    found = [c for t in TOOLS for c in find(t)] + nvm()
    return dedupe(found)


def nvm():
    """nvm is a shell function, not a binary: read its version from its repo."""
    root = os.environ.get("NVM_DIR") or os.path.join(HOME, ".nvm")
    v = (read_json(os.path.join(root, "package.json"), {}) or {}).get("version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", v):
        return []
    return [Component("manager", "nvm", v, root, osv=("GIT", github("nvm-sh/nvm"), f"v{v}"),
                      fix="Upgrade nvm: https://github.com/nvm-sh/nvm#upgrading")]


def dedupe(components):
    """One entry per install: `postgres` and `psql` from one directory, or one
    binary reached through several PATH entries, count once."""
    seen, out = set(), []
    for c in components:
        k = (c.name, c.version, os.path.dirname(os.path.realpath(c.path)) if c.path else "")
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out
