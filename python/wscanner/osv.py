"""OSV.dev lookups for the components we inventory ourselves.

One querybatch call answers "which advisories affect each (ecosystem,
package, version)" with ids and modified times only; we download a record
only when we have never seen it or OSV changed it since. Answers are reused
for a day, so a second run the same day makes no OSV calls at all."""

from __future__ import annotations

import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import net, versions

API = "https://api.osv.dev/v1"
QUERY_TTL = 86400
TAGS_TTL = 7 * 86400
BATCH = 1000


def lookup(cache, items, refresh=False, offline=False, log=print):
    """items: iterable of (ecosystem, package, version). Returns
    {item: [record, ...]} for every item we have an answer for, cached or
    fresh; items never answered (offline on first run) are left out."""
    items = sorted(set(items))
    stale = []
    for it in items:
        row = cache.query(*it)
        if refresh or row is None or row[0] < time.time() - QUERY_TTL:
            stale.append(it)
    if stale and not offline:
        try:
            _refresh(cache, stale)
        except net.Offline as e:
            log(f"  ⚠ OSV unreachable, using cached answers ({e})")
    out = {}
    for it in items:
        row = cache.query(*it)
        if row is None:
            continue
        recs = [cache.vuln(v) for v in row[1].split() if v]
        out[it] = [r for r in recs if r and not r.get("withdrawn")]
    return out


def _refresh(cache, stale):
    answers = {}
    for i in range(0, len(stale), BATCH):
        chunk = stale[i:i + BATCH]
        body = {"queries": [_q(*it) for it in chunk]}
        res = net.post_json(f"{API}/querybatch", body)["results"]
        for it, r in zip(chunk, res):
            vulns = list(r.get("vulns") or [])
            token = r.get("next_page_token")
            while token:  # rare: more than one page of advisories
                page = net.post_json(f"{API}/query", dict(_q(*it), page_token=token))
                vulns += [{"id": v["id"], "modified": v.get("modified")} for v in page.get("vulns", [])]
                token = page.get("next_page_token")
            answers[it] = vulns

    need = {v["id"] for vs in answers.values() for v in vs
            if cache.modified(v["id"]) != v.get("modified")}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for rec in pool.map(lambda vid: net.get_json(f"{API}/vulns/{vid}"), sorted(need)):
            if rec:
                cache.put_vuln(rec)
    for it, vulns in answers.items():
        cache.put_query(*it, [v["id"] for v in vulns])
    cache.conn.commit()


def _q(eco, pkg, ver):
    return {"package": {"ecosystem": eco, "name": pkg}, "version": ver}


def _matches(affected, eco, pkg):
    p = affected.get("package") or {}
    if eco == "GIT":
        repos = {_norm_repo(r.get("repo", "")) for r in affected.get("ranges", [])}
        return _norm_repo(pkg) in repos or _norm_repo(p.get("name", "")) == _norm_repo(pkg)
    if p.get("name") != pkg:
        return False
    # A distro release ("Debian:13", "Ubuntu:24.04") only takes fixes for
    # that release, however the record suffixes it ("Ubuntu:24.04:LTS"; not
    # "Ubuntu:Pro:…", which needs a subscription). A plain ecosystem
    # ("PyPI") matches however the record qualifies it.
    have = p.get("ecosystem", "")
    if ":" in eco:
        return have == eco or have.startswith(eco + ":")
    return have.split(":")[0] == eco


def _norm_repo(url):
    return re.sub(r"(\.git)?/?$", "", url.lower())


def fixed_versions(rec, eco, pkg, installed, newer=None):
    """Released versions that fix rec for this package (choose one with
    versions.pick_safe). Empty when no release fixes it: an advisory whose
    only fix is a commit counts as unfixed.

    For an upstream git repo, `newer` is {tag: advisory ids OSV reports for
    that tag} for the releases after `installed` (see candidates()); a tag
    fixes rec when OSV no longer reports rec for it."""
    out = []
    for a in rec.get("affected", []):
        if not _matches(a, eco, pkg):
            continue
        for r in a.get("ranges", []):
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                out += [e["fixed"] for e in r.get("events", []) if "fixed" in e and released(e["fixed"])]
    if eco == "GIT" and not out and newer:
        ids = {rec["id"], *(rec.get("aliases") or [])}
        out = [t for t, found in newer.items() if not ids & set(found)]
    return out


def candidates(cache, repo, installed, per_line=25, lines=6):
    """Release tags after `installed` worth asking OSV about: the rest of its
    release line, plus the newest tag of each later line."""
    shape = _shape(installed)
    newer = [t for t in tags(cache, repo) if _shape(t) == shape and versions.lt(installed, t)]
    n = max(1, len(versions.numbers(installed)) - 1)
    same = sorted([t for t in newer if versions.common_prefix(installed, t) >= n], key=versions.key)
    later = {}
    for t in newer:
        if versions.common_prefix(installed, t) < n:
            line = tuple(versions.numbers(t)[:n])
            if line not in later or versions.lt(later[line], t):
                later[line] = t
    return same[:per_line] + sorted(later.values(), key=versions.key)[:lines]


def released(version: str) -> bool:
    """A version string, not a commit hash standing in for an unreleased fix."""
    return bool(version) and not re.fullmatch(r"[0-9a-f]{12,40}", version)


def _shape(tag):
    return re.sub(r"\d+", "N", tag)


def tags(cache, repo):
    """Release tags of an upstream repo, from `git ls-remote`, cached a week."""
    def fetch():
        try:
            out = subprocess.run(["git", "ls-remote", "--tags", "--refs", repo], capture_output=True, text=True,
                                 timeout=60, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
        except (OSError, subprocess.TimeoutExpired) as e:
            raise net.Offline(str(e)) from e
        if out.returncode != 0:
            raise net.Offline(out.stderr.strip()[:200])
        return [line.split("refs/tags/", 1)[1] for line in out.stdout.splitlines() if "refs/tags/" in line]
    try:
        return cache.memo(f"tags:{repo}", fetch, max_age=TAGS_TTL)
    except net.Offline:
        return []
