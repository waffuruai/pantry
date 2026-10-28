"""The repos a scan covers: every git checkout found by a bounded walk of
$HOME (or of each --path), their lockfiles, the container images their
Dockerfiles and compose files name, and the dependencies that run code when
installed."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from .system import short

LOCKFILES = {
    "Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "deno.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "go.mod", "Package.resolved",
    "Gemfile.lock", "composer.lock", "pubspec.lock", "mix.lock", "gradle.lockfile", "pom.xml",
    "packages.lock.json", "conan.lock",
}
PRUNE = {".git", "node_modules", "target", ".build", "vendor", ".cache", "dist", "build",
         ".venv", "venv", "__pycache__", ".next"}
# The repo search also skips caches, toolchains and app data that hold other
# people's checkouts (crate sources, Go modules, npm stores) or are huge.
DISCOVER_PRUNE = PRUNE | {"Library", ".Trash", ".rustup", ".npm", ".pnpm-store"}
DISCOVER_PRUNE_PAIRS = {("go", "pkg"), (".cargo", "registry"), (".cargo", "git"), (".local", "share")}  # (parent, dir)
DISCOVER_DEPTH = 6  # ~/a/b/c/d/e/f/.git is the deepest repo found
DOCKERFILE = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|.+\.(dockerfile|containerfile)$", re.I)
COMPOSE = re.compile(r"^(docker-)?compose(\..+)?\.ya?ml$", re.I)


def _skip(parent: str, name: str) -> bool:
    return name in DISCOVER_PRUNE or name.endswith(".app") or (parent, name) in DISCOVER_PRUNE_PAIRS


def discover(root: Path, depth=DISCOVER_DEPTH):
    """Every git repo at or under root, sorted. A directory holding a `.git`
    directory is a repo and is not descended into: the repo is the unit. A
    `.git` file (a linked worktree or a submodule) also ends the descent, but
    only counts when it is root itself, so a repo's worktrees aren't each
    scanned again. Symlinks are not followed, and only directory entries are
    looked at, so the walk stays cheap even over a whole home directory."""
    found = []

    def visit(d: str, level: int):
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:  # unreadable or vanished: nothing here
            return
        git = next((e for e in entries if e.name == ".git"), None)
        if git is not None:
            if level == 0 or git.is_dir(follow_symlinks=False):
                found.append(Path(d))
            return
        if level >= depth:
            return
        parent = os.path.basename(d)
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False) and not _skip(parent, e.name):
                    visit(e.path, level + 1)
            except OSError:
                continue

    visit(str(root), 0)
    return sorted(found)


def scope(paths=None, log=print, note=None):
    """[(name, path)] for the repos a scan covers. With no paths, every git
    checkout under $HOME. With paths, the checkouts at or under each one; a
    path holding no checkout is scanned as one project (without the git
    history checks). Missing paths are skipped with a one-line note."""
    note = note or (lambda msg: print(msg, file=sys.stderr))
    roots = [Path(os.path.expanduser("~"))] if paths is None else []
    for p in paths or []:
        p = Path(p).expanduser()
        if p.is_dir():
            roots.append(p.resolve())
        else:
            note(f"· skipping --path {p}: no such directory")
    found = []
    for root in roots:
        repos = discover(root)
        found += repos or ([root] if paths is not None else [])
    unique = sorted(set(found))
    where = "under " + ", ".join(short(str(r)) for r in roots) if roots else "(no paths to search)"
    log(f"  found {sum(1 for r in unique if is_git(r))} git repos {where}")
    return [(short(str(r)), r) for r in unique]


def is_git(path: Path) -> bool:
    return (Path(path) / ".git").exists()


def walk(root: Path, depth=5):
    """(dir, files) under root, skipping build output and dependency dirs."""
    base = len(root.parts)
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in PRUNE and len(Path(d).parts) - base < depth]
        yield Path(d), files


def lockfiles(root: Path):
    return sorted(d / f for d, files in walk(root) for f in files
                  if f in LOCKFILES or re.fullmatch(r"requirements.*\.txt", f))


def repo_images(repos):
    """[(image ref, file)]: the base images the repos' Dockerfiles build FROM
    and the images their compose files run."""
    out = []
    for _, root in repos:
        for d, files in walk(root):
            for f in files:
                if DOCKERFILE.match(f):
                    out += [(ref, d / f) for ref in from_lines(d / f)]
                elif COMPOSE.match(f):
                    out += [(ref, d / f) for ref in compose_images(d / f)]
    return out


def _text(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def from_lines(path):
    stages, refs = set(), []
    for line in _text(path).splitlines():
        m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        ref, stage = m.groups()
        if ref.lower() != "scratch" and "$" not in ref and ref not in stages:
            refs.append(ref)
        if stage:
            stages.add(stage)
    return refs


def compose_images(path):
    return [m for m in re.findall(r"^\s*image:\s*['\"]?([^'\"\s#]+)", _text(path), re.M) if "$" not in m]


def install_scripts(files):
    """[(lockfile or workspace file, package)] for dependencies that run code
    at install time: npm's `hasInstallScript`, and the builds a pnpm workspace
    allows (pnpm 10+ blocks the rest)."""
    out = []
    for f in files:
        if f.name == "package-lock.json":
            try:
                pkgs = json.loads(f.read_text()).get("packages", {})
            except (OSError, ValueError):
                continue
            out += [(f, k.rsplit("node_modules/", 1)[-1]) for k, v in pkgs.items() if k and v.get("hasInstallScript")]
        elif f.name == "pnpm-lock.yaml":
            ws = f.parent / "pnpm-workspace.yaml"
            out += [(ws, name) for name in pnpm_allowed_builds(ws)]
    return sorted(set(out))


def pnpm_allowed_builds(ws: Path):
    """Names under `onlyBuiltDependencies:` (a list) or `allowBuilds:` (a map
    of true values) in pnpm-workspace.yaml."""
    out, section = [], ""
    for line in _text(ws).splitlines():
        if re.match(r"^\S", line):
            section = line.split(":", 1)[0].strip()
            continue
        item = line.strip()
        if section == "onlyBuiltDependencies" and item.startswith("- "):
            out.append(item[2:].strip().strip("'\""))
        elif section == "allowBuilds" and ":" in item:
            name, _, val = item.rpartition(":")
            if val.strip().lower() == "true":
                out.append(name.strip().strip("'\""))
    return out
