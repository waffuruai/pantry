"""Shared ground for the inventory: the Component every finder returns, and
small helpers for processes, paths, the OS and who owns a binary."""

from __future__ import annotations

import glob
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

MACOS = platform.system() == "Darwin"
HOME = os.path.expanduser("~")


@dataclass
class Component:
    kind: str           # runtime, compiler, manager, pkgmgr, tool, datastore, harness, package, app, …
    name: str
    version: str
    path: str = ""
    osv: tuple = ()     # (ecosystem, package, version as OSV knows it)
    eol: tuple = ()     # (endoflife.date product, cycle)
    fix: str = ""       # the command (or step) that updates it; "{safe}" is the fixed version
    auto: bool = False  # `wscanner --update` may run `fix` unattended
    extra: dict = field(default_factory=dict)


def github(repo: str) -> str:
    return f"https://github.com/{repo}.git"


def run(cmd, timeout=15) -> str:
    """stdout and stderr of cmd, or "" when it can't run."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env=dict(os.environ, NO_COLOR="1"))
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (p.stdout or "") + (p.stderr or "")


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def plist(path) -> dict:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:  # missing, unreadable or malformed: no data
        return {}


def expand(patterns):
    """Existing paths matching ~-relative globs, in order, without repeats."""
    out = []
    for g in patterns:
        for p in sorted(glob.glob(os.path.expanduser(g))):
            if p not in out:
                out.append(p)
    return out


def short(p: str) -> str:
    return "~" + p[len(HOME):] if p.startswith(HOME) else p


def fingerprint(files) -> str:
    """Changes when any file is added, removed, touched or resized."""
    h = hashlib.sha256()
    for f in files:
        try:
            st = os.stat(f)
            h.update(f"{f}:{st.st_mtime_ns}:{st.st_size}\n".encode())
        except OSError:
            pass
    return h.hexdigest()


def os_release() -> dict:
    out = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"')
    except OSError:
        pass
    return out


def os_family() -> str:
    """Which source checks this Linux distro's packages: "osv" (osv-scanner
    and the distro trackers in OSV), "dnf" (dnf's, or yum's, own security
    advisories), "arch" (the Arch security tracker), or "" when we know none."""
    rel = os_release()
    ids = set((rel.get("ID", "") + " " + rel.get("ID_LIKE", "")).split())
    if ids & {"debian", "ubuntu", "alpine", "wolfi", "chainguard", "opensuse", "opensuse-tumbleweed",
               "opensuse-leap", "sles", "suse"}:
        return "osv"
    if ids & {"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"}:
        return "dnf"
    if ids & {"arch", "archlinux"}:
        return "arch"
    return ""


def os_vouches() -> bool:
    """Whether the OS update check covers files the OS package manager owns."""
    return MACOS or bool(os_family())


SYSTEM_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/", "/System/")
APPLE_DIRS = ("/Library/Developer/CommandLineTools/", "/Applications/Xcode")


def owner(real: str) -> str:
    """Who vouches for this binary, or "" when we check it ourselves:
    brew (`brew vulns`), npm or pipx (their package listings), app (the app
    check), os (OS updates)."""
    if "/Cellar/" in real:
        return "brew"
    if "/node_modules/" in real:
        return "npm"
    if "/pipx/venvs/" in real:
        return "pipx"
    if re.search(r"\.app/Contents/", real) and not real.startswith(APPLE_DIRS):
        return "app"
    if real.startswith(SYSTEM_DIRS) or (MACOS and real.startswith(APPLE_DIRS)):
        return "os" if os_vouches() else ""
    return ""


def on_path(name: str, extra=()):
    """Every distinct executable called `name` on PATH, then in the `extra`
    directory globs, as (shown path, real path)."""
    seen = set()
    for d in os.environ.get("PATH", "").split(os.pathsep) + expand(extra):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            real = os.path.realpath(p)
            if real not in seen:
                seen.add(real)
                yield p, real


def brew_prefix() -> str:
    exe = shutil.which("brew")
    return run([exe, "--prefix"]).strip() if exe else ""


def brew_casks() -> dict:
    """{cask token: installed version} for Homebrew-installed casks."""
    exe = shutil.which("brew")
    out = {}
    for line in (run([exe, "list", "--cask", "--versions"], timeout=60) if exe else "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = parts[-1]
    return out


def app_cli(app_names, cli_rel: str) -> str:
    """A CLI shipped inside an installed macOS app, or ""."""
    for name in app_names:
        for root in ("/Applications", os.path.join(HOME, "Applications")):
            cli = os.path.join(root, f"{name}.app", "Contents", "Resources", "app", cli_rel)
            if os.path.exists(cli):
                return cli
    return ""
