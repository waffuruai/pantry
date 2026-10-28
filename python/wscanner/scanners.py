"""The scanners we delegate to rather than reimplement: osv-scanner (the
repos' lockfiles, Linux OS packages, container images, and the lockfiles
inside plugins, skills and extensions) and `brew vulns` (Homebrew
formulae). Each reruns only when what it scans changed or a day passed."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from .system import fingerprint

# Linux package databases osv-scanner's artifact extractors read.
OS_DATABASES = ("/var/lib/dpkg/status", "/lib/apk/db/installed", "/var/lib/rpm/rpmdb.sqlite",
                "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages")
EMPTY = {"packages": 0, "vulnerable": [], "licenses": [], "unknown_licenses": 0}


class Missing(Exception):
    """The scanner isn't installed (or is too old)."""


def _osv_scanner(cache, args):
    """Run osv-scanner with JSON output; store its records; return compact()."""
    exe = shutil.which("osv-scanner")
    if not exe:
        raise Missing("osv-scanner")
    p = subprocess.run([exe, *args[:2], "--format", "json", "--all-packages", *args[2:]],
                       capture_output=True, text=True, timeout=1800)
    if p.returncode not in (0, 1, 128):  # 1: findings; 128: nothing to scan
        tail = (p.stderr or "").strip().splitlines()[-1:] or [""]
        raise RuntimeError(f"osv-scanner exited {p.returncode}: {tail[0]}")
    return compact(cache, json.loads(p.stdout) if p.stdout.strip() else {"results": []})


def compact(cache, data):
    """{"packages": n, "vulnerable": [{source, ecosystem, name, version,
    groups: [[id, …]]}], "licenses": [{source, name, version, violations}],
    "unknown_licenses": n}, storing every advisory record in the cache."""
    out, count, lic, unknown = [], 0, [], 0
    for r in data.get("results", []):
        for pk in r.get("packages", []):
            count += 1
            info = pk["package"]
            bad = pk.get("license_violations") or []
            if bad == ["UNKNOWN"]:
                unknown += 1  # unpublished workspace crates and the like: nothing to judge
            elif bad:
                lic.append({"source": r["source"]["path"], "name": info["name"],
                            "version": info.get("version", ""), "violations": bad})
            vulns = pk.get("vulnerabilities") or []
            for v in vulns:
                cache.put_vuln(v)
            if vulns:
                out.append({"source": r["source"]["path"], "ecosystem": info.get("ecosystem", ""),
                            "name": info["name"], "version": info.get("version", ""),
                            "groups": [g["ids"] for g in pk.get("groups", [])] or [[v["id"]] for v in vulns]})
    return {"packages": count, "vulnerable": out, "licenses": lic, "unknown_licenses": unknown}


def source(cache, key, targets, files, refresh=False, offline=False, licenses=(), extra=()):
    """osv-scanner over directories, rerun when `files` change or daily."""
    if not targets:
        return EMPTY

    def scan():
        lic = [f"--licenses={','.join(licenses)}"] if licenses else []
        try:
            return _osv_scanner(cache, ["scan", "source", *lic, *extra, *map(str, targets)])
        except RuntimeError as e:
            if not lic or "--licenses" not in str(e):
                raise
            # A bad allowlist entry shouldn't cost us the vulnerability scan.
            print(f"  ⚠ {e} (the licenses allowlist, --licenses); scanning without it")
            return _osv_scanner(cache, ["scan", "source", *extra, *map(str, targets)])
    return cache.memo(key, scan, fingerprint=fingerprint(files), refresh=refresh, offline=offline)


def image(cache, ref, image_id, refresh=False, offline=False):
    """One local image, cached by id: an id never changes content, so it is
    only rescanned (daily) for new advisories."""
    tagged = ref if "@" in ref or ":" in ref.rsplit("/", 1)[-1] else f"{ref}:latest"
    return cache.memo(f"image:{image_id}", lambda: _osv_scanner(cache, ["scan", "image", tagged]),
                      fingerprint=image_id, refresh=refresh, offline=offline)


def os_packages(cache, refresh=False, offline=False):
    """Linux OS packages, via the package database (none on macOS)."""
    dbs = [Path(d) for d in OS_DATABASES if Path(d).exists()]
    return source(cache, "osv-scanner:os", [d.parent for d in dbs], dbs, refresh, offline,
                  extra=("--x-plugins", "artifact")) if dbs else EMPTY


def brew_vulns(cache, refresh=False, offline=False):
    """`brew vulns --json` findings, or None without Homebrew. Raises Missing
    when this Homebrew predates `brew vulns`."""
    exe = shutil.which("brew")
    if not exe:
        return None
    listing = subprocess.run([exe, "list", "--versions"], capture_output=True, text=True).stdout

    def scan():
        p = subprocess.run([exe, "vulns", "--json"], capture_output=True, text=True, timeout=900)
        if "Unknown command" in p.stderr or "Invalid usage" in p.stderr:
            raise Missing("brew vulns (run: brew update)")
        try:
            data = json.loads(p.stdout)
        except ValueError:
            tail = (p.stderr or "").strip().splitlines()[-1:] or [""]
            raise RuntimeError(f"brew vulns failed: {tail[0]}")
        for f in data.get("findings", []):
            for v in f.get("vulnerabilities", []):
                if not cache.vuln(v["id"]):
                    cache.put_vuln({"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary", ""),
                                    "affected": [{"package": {"ecosystem": "Homebrew", "name": f["formula"]}}],
                                    "database_specific": {"severity": v.get("severity", "")}})
        return {"findings": data.get("findings", []), "checked": data.get("checked", 0)}
    return cache.memo("brew-vulns", scan, fingerprint=hashlib.sha256(listing.encode()).hexdigest(),
                      refresh=refresh, offline=offline)
