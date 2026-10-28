"""A local index of every known malicious package name, from the OpenSSF
malicious-packages repo (about 240,000 reports: npm, PyPI, RubyGems, NuGet,
crates, Go, Maven, Packagist, VS Code and Open VSX extensions).

The repo lays reports out as osv/malicious/<ecosystem>/<package>/MAL-….json,
so a blob-less clone (about 30 MB, seconds) gives every name without
downloading a single report; `git fetch` keeps it current. A name match
fetches just that report, to check whether the version here is affected:
some reports cover every version, others only a few compromised releases of
a legitimate package. This is what catches packages we only know by name (an
unpinned `npx some-mcp-server`) and keeps working offline."""

from __future__ import annotations

import re
import subprocess

from . import db, net
from .versions import lt

REPO = "https://github.com/ossf/malicious-packages.git"
DIRS = {"npm": "npm", "PyPI": "pypi", "RubyGems": "rubygems", "crates.io": "crates.io", "Go": "go",
        "NuGet": "nuget", "Maven": "maven", "Packagist": "packagist", "VSCode": "vscode",
        "VSCode:https://open-vsx.org": "vscode:open-vsx.org"}


def _norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name.lower()


def sync(cache, offline=False):
    """Refresh the index at most daily. Raises net.Offline only when it can't
    be refreshed and there is no earlier index to fall back on."""
    have = cache.conn.execute("SELECT COUNT(*) FROM malicious").fetchone()[0]
    if have and (offline or cache.fresh("malicious_at", db.DAY)):
        return have
    if offline:
        raise net.Offline("the malicious-package index is offline and not cached")
    clone = db.path().parent / "malicious-packages"
    git = ["git", "-C", str(clone)]
    if (clone / ".git").exists():
        cmd = git + ["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", "HEAD"]
        ref = "FETCH_HEAD"
    else:
        cmd = ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "--depth", "1", REPO, str(clone)]
        ref = "HEAD"
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=300)
        listing = subprocess.run(git + ["ls-tree", "-r", "--name-only", ref, "osv/malicious"], check=True,
                                 capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError) as e:
        if have:
            return have
        raise net.Offline(f"couldn't fetch {REPO}: {e}") from e
    rows = []
    for path in listing.splitlines():
        parts = path.split("/")
        if len(parts) >= 5 and parts[-1].startswith("MAL-"):
            eco_dir, name = parts[2], "/".join(parts[3:-1])  # npm scopes add a level: @scope/name
            rows.append((eco_dir, name.lower(), parts[-1][:-5]))
    with cache.conn:
        cache.conn.execute("DELETE FROM malicious")
        cache.conn.executemany("INSERT INTO malicious VALUES (?, ?, ?)", rows)
    cache.touch("malicious_at")
    cache.conn.commit()
    return len(rows)


def reports(cache, eco: str, name: str, version: str):
    """The malicious-package reports that cover this package at this version
    (any version when `version` is ""), fetched and cached on first use."""
    eco_dir = DIRS.get(eco)
    if not eco_dir:
        return []
    ids = [r[0] for r in cache.conn.execute("SELECT id FROM malicious WHERE ecosystem = ? AND name = ?",
                                            (eco_dir, _norm(eco, name)))]
    out = []
    for i in ids:
        rec = cache.vuln(i)
        if rec is None:
            try:
                rec = net.get_json(f"https://api.osv.dev/v1/vulns/{i}")
            except net.Offline:
                rec = {"id": i, "summary": f"Malicious code in {name} ({eco})", "affected": []}
            if rec:
                cache.put_vuln(rec)
        if rec and (not version or applies(rec, version)):
            out.append(rec)
    return out


def applies(rec, version: str) -> bool:
    """Whether `version` is among those a report covers (every version when
    the report lists no ranges or versions)."""
    affected = rec.get("affected") or []
    if not affected:
        return True
    for a in affected:
        if version in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            ev = r.get("events") or []
            intro = next((e["introduced"] for e in ev if "introduced" in e), "0")
            fixed = next((e["fixed"] for e in ev if "fixed" in e), "")
            last = next((e["last_affected"] for e in ev if "last_affected" in e), "")
            if (intro == "0" or not lt(version, intro)) and (not fixed or lt(version, fixed)) \
                    and (not last or not lt(last, version)):
                return True
        if not a.get("versions") and not a.get("ranges"):
            return True
    return False
