"""Vet the GitHub Actions the workflows use, the way cargo vet vets crates.

Every `uses:` in .github/workflows/ must pin an action by commit, name its
version in a comment, and have an audit recorded in .github/actions-audits.toml
for that exact commit; an entry nothing uses is a leftover. With network, the
tag the comment names must resolve to the pinned commit (annotated tags are
dereferenced) and be at least 72 hours old (docs/internal/dependencies.md),
unless the entry says why it is adopted sooner. Standard library only:

    python3 scripts/vet_actions.py [--offline]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RECORD = ROOT / ".github" / "actions-audits.toml"
API = "https://api.github.com"
# The dependency age rule: a release is adopted no sooner than this after it is published.
MIN_AGE = timedelta(hours=72)
FIELDS = ("action", "sha", "version", "who", "date", "notes")

USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^\s'"#]+)['"]?\s*(?:#\s*(\S+))?\s*$""")
COMMIT = re.compile(r"^[0-9a-f]{40}$")

Fetch = Callable[[str], dict | None]


@dataclass(frozen=True)
class Use:
    """One `uses:` line: the action (owner/repo), its ref and its version comment."""

    file: str
    line: int
    action: str
    ref: str
    version: str | None

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}"


def uses_in(workflows: Path) -> list[Use]:
    """Every action the workflow files use; local (`./`) and docker actions are not pinned this way."""
    out = []
    for f in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            target, version = m.groups()
            if target.startswith("./") or target.startswith("docker://"):
                continue
            name, _, ref = target.partition("@")
            action = "/".join(name.split("/")[:2])
            out.append(Use(f.name, n, action, ref, version))
    return out


def record_in(path: Path) -> tuple[dict[tuple[str, str], dict], list[str]]:
    """The audit entries by (action, sha), and what is wrong with the file."""
    problems: list[str] = []
    entries: dict[tuple[str, str], dict] = {}
    for e in tomllib.loads(path.read_text()).get("audit", []):
        missing = [k for k in FIELDS if not e.get(k)]
        if missing:
            problems.append(f"{path.name}: an entry lacks {', '.join(missing)}: {e}")
            continue
        key = (e["action"], e["sha"])
        if key in entries:
            problems.append(f"{path.name}: {e['action']}@{e['sha']} is recorded twice")
        entries[key] = e
    return entries, problems


def fetch_json(url: str) -> dict | None:
    """A GitHub API document, None for 404. GH_TOKEN or GITHUB_TOKEN raises the rate limit."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "wpantry-vet-actions"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def resolve(action: str, version: str, fetch: Fetch) -> tuple[str | None, datetime | None]:
    """The commit the tag `version` points at (through an annotated tag), and when it was
    published: the release date, else the tag's date, else the commit's."""
    ref = fetch(f"{API}/repos/{action}/git/ref/tags/{version}")
    if ref is None:
        return None, None
    obj = ref["object"]
    tagged = None
    if obj["type"] == "tag":
        tag = fetch(f"{API}/repos/{action}/git/tags/{obj['sha']}") or {}
        obj = tag.get("object", obj)
        tagged = tag.get("tagger", {}).get("date")
    sha = obj["sha"]
    release = fetch(f"{API}/repos/{action}/releases/tags/{version}") or {}
    when = release.get("published_at") or tagged
    if not when:
        commit = fetch(f"{API}/repos/{action}/commits/{sha}") or {}
        when = commit.get("commit", {}).get("committer", {}).get("date")
    return sha, datetime.fromisoformat(when.replace("Z", "+00:00")) if when else None


def check(
    uses: list[Use],
    entries: dict[tuple[str, str], dict],
    fetch: Fetch | None,
    now: datetime | None = None,
) -> list[str]:
    """Everything that stops the workflows' actions from counting as vetted."""
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for u in uses:
        if not COMMIT.match(u.ref):
            problems.append(f"{u.where}: {u.action}@{u.ref} is not pinned by a full commit SHA")
            continue
        if not u.version:
            problems.append(f"{u.where}: {u.action}@{u.ref} has no version comment (`# vX.Y.Z`)")
            continue
        key = (u.action, u.ref)
        seen.add(key)
        entry = entries.get(key)
        if entry is None:
            problems.append(
                f"{u.where}: {u.action}@{u.ref} ({u.version}) is not in {RECORD.name}: "
                "read its diff from the version it replaces and record the audit"
            )
        elif entry["version"] != u.version:
            problems.append(
                f"{u.where}: {u.action}@{u.ref} is {u.version} in the workflow and "
                f"{entry['version']} in {RECORD.name}"
            )
    for (action, sha), e in entries.items():
        if (action, sha) not in seen:
            problems.append(f"{RECORD.name}: nothing uses {action}@{sha} ({e['version']}): remove it")
    if fetch is None or problems:
        return problems
    now = now or datetime.now(timezone.utc)
    for action, sha in sorted(seen):
        version = entries[(action, sha)]["version"]
        resolved, published = resolve(action, version, fetch)
        if resolved is None:
            problems.append(f"{action}: tag {version} does not exist")
        elif resolved != sha:
            problems.append(f"{action}: tag {version} is commit {resolved}, not the pinned {sha}")
        elif published is None:
            problems.append(f"{action}: no date found for {version}; cannot apply the {MIN_AGE} age rule")
        elif now - published < MIN_AGE and not entries[(action, sha)].get("age_exempt"):
            hours = (now - published).total_seconds() / 3600
            problems.append(
                f"{action}: {version} was published {hours:.0f} hours ago; the rule is {MIN_AGE} "
                "(set age_exempt on its entry with the reason, for a security fix)"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--offline", action="store_true", help="skip the tag and age checks that need api.github.com")
    p.add_argument("--workflows", type=Path, default=WORKFLOWS)
    p.add_argument("--record", type=Path, default=RECORD)
    a = p.parse_args(argv)
    uses = uses_in(a.workflows)
    entries, problems = record_in(a.record)
    try:
        problems += check(uses, entries, None if a.offline else fetch_json)
    except (urllib.error.URLError, OSError) as e:
        problems.append(f"could not reach {API} ({e}); run with --offline to skip the tag and age checks")
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        return 1
    actions = {(u.action, u.ref) for u in uses}
    mode = "pins and record checked" if a.offline else "pins, record, tags and ages checked"
    print(f"{len(actions)} actions in {len(uses)} uses: {mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
