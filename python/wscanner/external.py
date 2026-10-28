"""The external tools this implementation runs, for `wscanner tools`.

A missing required tool makes the scan report that area as failing (with how
to install it); a missing optional one just means there is nothing of that
kind to check here."""

from __future__ import annotations

import re
import shutil

from .system import run

# (name, required, version arguments, what wscanner uses it for)
TOOLS = (
    ("osv-scanner", True, ("--version",), "repo lockfiles, Linux OS packages, container images, licenses"),
    ("gitleaks", True, ("version",), "secrets in the repos' git history"),
    ("git", True, ("--version",), "repo HEADs, upstream release tags, the malicious-package index"),
    ("openssl", True, ("version",), "the CA trust check (bin/wscanner)"),
    ("brew", False, ("--version",), "Homebrew formulae (brew vulns), casks, updates"),
    ("docker", False, ("--version",), "the Docker engine and local container images"),
)
VERSION = re.compile(r"\d+(?:\.\d+)+")


def tools():
    """[{name, required, found, path, version, purpose}] in TOOLS order."""
    out = []
    for name, required, args, purpose in TOOLS:
        exe = shutil.which(name) or ""
        m = VERSION.search(run([exe, *args])) if exe else None
        out.append({"name": name, "required": required, "found": bool(exe), "path": exe,
                    "version": m.group(0) if m else "", "purpose": purpose})
    return out
