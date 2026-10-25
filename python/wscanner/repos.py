"""Our org repos: where they're cloned, their lockfiles, the container images
their Dockerfiles and compose files name, and the dependencies that run code
when installed."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

LOCKFILES = {
    "Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "deno.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "go.mod", "Package.resolved",
    "Gemfile.lock", "composer.lock", "pubspec.lock", "mix.lock", "gradle.lockfile", "pom.xml",
    "packages.lock.json", "conan.lock",
}
PRUNE = {".git", "node_modules", "target", ".build", "vendor", ".cache", "dist", "build",
         ".venv", "venv", "__pycache__", ".next"}
DOCKERFILE = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|.+\.(dockerfile|containerfile)$", re.I)
COMPOSE = re.compile(r"^(docker-)?compose(\..+)?\.ya?ml$", re.I)


def org_repos(ops: Path):
    """[(name, path)] for every org repo cloned next to ops or in WAFFURU_HOME."""
    try:
        names = re.search(r"WAFFURU_REPOS=\(([^)]*)\)", (ops / "scripts" / "lib.sh").read_text()).group(1).split()
    except (OSError, AttributeError):
        names = []
    homes = [Path(os.environ.get("WAFFURU_HOME", "~/waffuru")).expanduser(), ops.parent]
    out = []
    for n in names:
        p = next((h / n for h in homes if (h / n / ".git").exists()), None)
        if p:
            out.append((n, p))
    return out


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
    """[(image ref, file)]: the base images our Dockerfiles build FROM and the
    images our compose files run."""
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
