"""Packages installed into this machine's runtimes, outside any project:
every Python (with its pip packages), npm and global npm packages for every
Node, `cargo install`s, pipx-installed tools and global Ruby gems."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
from pathlib import Path

from .catalog import PYTHON_DIRS, minor
from .system import Component, expand, github, on_path, owner, read_json, run
from .tools import updater

PY_INFO = ("import json, platform, sys, sysconfig, os;"
           "print(json.dumps({'v': platform.python_version(), 'exe': sys.executable,"
           "'managed': os.path.exists(os.path.join(sysconfig.get_path('stdlib'), 'EXTERNALLY-MANAGED'))}))")


def _json_in(text: str, open_ch: str, close_ch: str, default):
    """The JSON value in tool output that may carry warnings around it."""
    try:
        return json.loads(text[text.index(open_ch):text.rindex(close_ch) + 1])
    except ValueError:
        return default


def pythons():
    """Every Python on PATH or installed by a version manager, with pip and
    its packages."""
    dirs = os.environ.get("PATH", "").split(os.pathsep) + expand(PYTHON_DIRS)
    names = ["python3"] + sorted({os.path.basename(p) for d in dirs for p in glob.glob(os.path.join(d, "python3.*"))
                                  if re.fullmatch(r"python3\.\d+", os.path.basename(p))})
    out, seen = [], set()
    for n in names:
        for shown, real in on_path(n, PYTHON_DIRS):
            if owner(real):
                continue
            lines = run([shown, "-I", "-c", PY_INFO]).strip().splitlines()
            info = _json_in(lines[-1] if lines else "", "{", "}", None)
            if not info or os.path.realpath(info["exe"]) in seen:
                continue
            seen.add(os.path.realpath(info["exe"]))
            v = info["v"]
            fix, auto = updater(real, "python")
            out.append(Component("runtime", "python", v, shown, osv=("GIT", github("python/cpython"), f"v{v}"),
                                 eol=("python", minor(v)), fix=fix, auto=auto))
            out += _pip(shown, info["managed"], (fix, auto))
    return out


def _pip(py, managed, runtime_fix):
    raw = run([py, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"], timeout=60)
    out = []
    for p in _json_in(raw, "[", "]", []):
        name, ver = p["name"], p["version"]
        if managed and "/uv/" in os.path.realpath(py):
            fix, auto = runtime_fix  # uv's Python builds bundle pip; a newer build brings a newer one
        elif managed:
            fix, auto = f"Upgrade {name} through the package manager that owns {py}", False
        else:
            fix, auto = f"{py} -m pip install --upgrade '{name}>={{safe}}'", True
        pip = name.lower() == "pip"
        out.append(Component("pkgmgr" if pip else "package", name if pip else f"pip:{name}", ver, py,
                             osv=("PyPI", name, ver), fix=fix, auto=auto))
    return out


def node_packages(found):
    """npm itself and the global npm packages of each Node in `found`."""
    out = []
    for c in [c for c in found if c.name == "node"]:
        npm = os.path.join(os.path.dirname(os.path.realpath(c.path)), "npm")
        if not os.path.exists(npm):
            continue
        lines = run([npm, "--version"]).strip().splitlines()  # npm doesn't always list itself
        m = re.match(r"(\d+\.\d+\.\d+)$", lines[-1]) if lines else None
        if m:
            out.append(Component("pkgmgr", "npm", m.group(1), npm, osv=("npm", "npm", m.group(1)),
                                 fix=f"{npm} install -g npm@{{safe}}", auto=True))
        deps = _json_in(run([npm, "ls", "-g", "--json", "--depth=0"], timeout=60), "{", "}", {})
        for name, d in (deps.get("dependencies") or {}).items():
            if name != "npm" and d.get("version"):
                kind = "pkgmgr" if name == "corepack" else "package"
                out.append(Component(kind, name if kind == "pkgmgr" else f"npm:{name}", d["version"], npm,
                                     osv=("npm", name, d["version"]),
                                     fix=f"{npm} install -g {name}@{{safe}}", auto=True))
    return out


def cargo_installs():
    f = Path(os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))) / ".crates2.json"
    out = []
    for k in (read_json(f, {}) or {}).get("installs", {}):
        m = re.match(r"(\S+) (\S+) \(registry\+", k)
        if m:
            name, ver = m.groups()
            out.append(Component("package", f"cargo:{name}", ver, str(f), osv=("crates.io", name, ver),
                                 fix=f"cargo install --locked {name}@{{safe}}", auto=True))
    return out


def pipx_packages():
    """Tools installed with pipx: each lives in its own venv."""
    exe = shutil.which("pipx")
    if not exe:
        return []
    data = _json_in(run([exe, "list", "--json"], timeout=60), "{", "}", {})
    out = []
    for name, v in (data.get("venvs") or {}).items():
        meta = ((v.get("metadata") or {}).get("main_package") or {})
        ver = meta.get("package_version")
        if ver:
            out.append(Component("package", f"pipx:{name}", ver, exe, osv=("PyPI", meta.get("package", name), ver),
                                 fix=f"{exe} upgrade {name}", auto=True))
    return out


def gems(found):
    """Global gems of each Ruby we check (Apple's system Ruby is the OS's)."""
    out = []
    for c in [c for c in found if c.name == "ruby"]:
        gem = os.path.join(os.path.dirname(os.path.realpath(c.path)), "gem")
        if not os.path.exists(gem):
            continue
        for line in run([gem, "list", "--local"], timeout=60).splitlines():
            m = re.match(r"^(\S+) \((?:default: )?([^,)\s]+)", line)
            if m:
                name, ver = m.groups()
                out.append(Component("package", f"gem:{name}", ver, gem, osv=("RubyGems", name, ver),
                                     fix=f"{gem} update {name}", auto=True))
    return out
