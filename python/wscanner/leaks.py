"""Secrets committed to the scanned repos' history, found with gitleaks.

Each repo's full history is scanned once per new HEAD (and when gitleaks,
the config or the repo's .gitleaksignore changes), then cached. Findings are
redacted: the cache and the report hold the rule, file, line, commit and
fingerprint, never the secret."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .scanners import Missing
from .system import fingerprint, run

# Rules too broad to fail on their own: their hits are reviewed, not trusted.
GENERIC = {"generic-api-key", "generic-secret", "hashicorp-tf-password", "curl-auth-header", "curl-auth-user"}


def scan(cache, repo: Path, default_config: Path, refresh=False, offline=False):
    """[{rule, file, line, commit, fingerprint, description}] for one repo.
    The repo's own .gitleaks.toml replaces `default_config`."""
    exe = shutil.which("gitleaks")
    if not exe:
        raise Missing("gitleaks")
    head = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).strip()
    own = repo / ".gitleaks.toml"
    config = own if own.is_file() else default_config
    fp = f"{head}:{run([exe, 'version']).strip()}:{fingerprint([config, repo / '.gitleaksignore'])}"

    def gitleaks():
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            cmd = [exe, "git", str(repo), "--redact", "--no-banner", "--log-level", "error", "--exit-code", "0",
                   "--report-format", "json", "--report-path", out]
            if config.is_file():
                cmd += ["--config", str(config)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            if p.returncode != 0:
                raise RuntimeError(f"gitleaks exited {p.returncode}: {(p.stderr or '').strip()[-200:]}")
            found = json.loads(Path(out).read_text() or "[]")
        return [{"rule": f["RuleID"], "file": f["File"], "line": f["StartLine"], "commit": f["Commit"][:12],
                 "fingerprint": f["Fingerprint"], "description": f.get("Description", "")} for f in found]
    return cache.memo(f"gitleaks:{repo}", gitleaks, max_age=7 * 86400, fingerprint=fp, refresh=refresh,
                      offline=offline)
