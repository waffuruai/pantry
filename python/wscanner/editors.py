"""Extensions of VS Code-family editors, and the npm packages they bundle.

An editor counts only when it's installed: its leftover extensions on disk
never run, so they don't apply."""

from __future__ import annotations

import json
import os
import shlex
import shutil
from pathlib import Path

from .system import Component, app_cli, expand, read_json

# (editor, extensions dir, marketplace, CLI name, app names, CLI path inside the app)
EDITORS = (
    ("VS Code", "~/.vscode/extensions", "vscode", "code", ("Visual Studio Code",), "bin/code"),
    ("VS Code Insiders", "~/.vscode-insiders/extensions", "vscode", "code-insiders",
     ("Visual Studio Code - Insiders",), "bin/code"),
    ("Cursor", "~/.cursor/extensions", "openvsx", "cursor", ("Cursor",), "bin/cursor"),
    ("Windsurf", "~/.windsurf/extensions", "openvsx", "windsurf", ("Windsurf",), "bin/windsurf"),
    ("VSCodium", "~/.vscode-oss/extensions", "openvsx", "codium", ("VSCodium",), "bin/codium"),
    ("Antigravity", "~/.antigravity/extensions", "openvsx", "antigravity", ("Antigravity",), "bin/antigravity"),
    ("Kiro", "~/.kiro/extensions", "openvsx", "kiro", ("Kiro",), "bin/kiro"),
)

ECOSYSTEM = {"vscode": "VSCode", "openvsx": "VSCode:https://open-vsx.org"}


def extensions():
    """Components with extra = {editor, market, cli, id (as published), dir}."""
    out = []
    for editor, root, market, cli_name, apps, cli_rel in EDITORS:
        root = os.path.expanduser(root)
        cli = shutil.which(cli_name) or app_cli(apps, cli_rel)
        if not (os.path.isdir(root) and cli):
            continue
        obsolete = set(read_json(os.path.join(root, ".obsolete"), {}) or {})
        for manifest in expand([os.path.join(root, "*", "package.json")]):
            ext_dir = os.path.dirname(manifest)
            pkg = read_json(manifest, {}) or {}
            if os.path.basename(ext_dir) in obsolete or not all(pkg.get(k) for k in ("publisher", "name", "version")):
                continue
            ext_id, q = f"{pkg['publisher']}.{pkg['name']}", shlex.quote(cli)
            out.append(Component("extension", ext_id.lower(), str(pkg["version"]), ext_dir,
                                 osv=(ECOSYSTEM[market], ext_id, str(pkg["version"])),
                                 fix=f"{q} --install-extension {ext_id} --force", auto=True,
                                 extra={"editor": editor, "market": market, "cli": q, "id": ext_id, "dir": ext_dir}))
    return out


def bundled_npm(root: str):
    """(name, version) of every npm package shipped in node_modules under
    root: an editor extension, a harness plugin, a desktop extension."""
    found = set()
    for d, dirs, files in os.walk(root):
        if os.path.relpath(d, root).count("node_modules") > 6:
            dirs[:] = []
            continue
        parent = os.path.basename(os.path.dirname(d))
        grand = os.path.basename(os.path.dirname(os.path.dirname(d)))
        if (parent == "node_modules" or (parent.startswith("@") and grand == "node_modules")) \
                and "package.json" in files:
            try:
                pkg = json.loads(Path(d, "package.json").read_text())
            except (OSError, ValueError):
                continue
            if pkg.get("name") and pkg.get("version"):
                found.add((pkg["name"], str(pkg["version"])))
    return sorted(found)
