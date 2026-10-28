"""Linux distros whose advisories aren't in OSV, through their own sources:
dnf's (or yum's) security advisories for Fedora, RHEL, CentOS, Rocky, Alma,
Oracle and Amazon Linux, and the Arch security tracker. Plus how to update
an OS package on each distro."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess

from .net import Offline
from .system import os_release
from .versions import lt

DNF4_LINE = re.compile(r"^(\S+)\s+(\S+)/Sec\.\s+(\S+)$")  # dnf4 and yum


def split_nevra(nevra: str):
    """("openssl-libs", "1:3.5.9-1.fc44") from "openssl-libs-1:3.5.9-1.fc44.aarch64"."""
    m = re.match(r"^(.+)-((?:\d+:)?[^-]+-[^-]+)\.[^.]+$", nevra)
    return (m.group(1), m.group(2)) if m else ("", "")


def dnf_advisories(cache, refresh=False, offline=False):
    """{"packages": n, "vulnerable": [{name, installed, fixed, advisory,
    severity}]}: advisories dnf says apply to installed packages and have an
    update. dnf5 answers in JSON; dnf4 and yum in text. A failure (no repo
    metadata, no network) is never cached as a clean result."""
    dnf, yum, rpm = shutil.which("dnf"), shutil.which("yum"), shutil.which("rpm")
    if not ((dnf or yum) and rpm):
        raise Offline("neither dnf nor yum is installed")
    installed = {}
    for line in subprocess.run([rpm, "-qa", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"],
                               capture_output=True, text=True).stdout.splitlines():
        name, _, ver = line.partition(" ")
        installed[name] = ver[2:] if ver.startswith("0:") else ver

    def scan():
        rows = []
        p = subprocess.run([dnf, "-q", "advisory", "list", "--security", "--updates", "--json"],
                           capture_output=True, text=True, timeout=900) if dnf else None
        if p and p.returncode == 0 and p.stdout.strip().startswith("["):
            rows = [(a["name"], a.get("severity", ""), a["nevra"]) for a in json.loads(p.stdout)]
        else:  # dnf4 or yum (a dnf5 that failed fails the same way here)
            cmd = [dnf, "-q", "updateinfo", "list", "--security", "--available"] if dnf else \
                [yum, "-q", "updateinfo", "list", "security"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            if p.returncode != 0:
                tail = (p.stderr or "").strip().splitlines()[-1:] or ["no output"]
                raise Offline(f"dnf couldn't load security advisories: {tail[0]}")
            rows = [m.groups() for m in (DNF4_LINE.match(x.strip()) for x in p.stdout.splitlines()) if m]
        out = []
        for advisory, severity, nevra in rows:
            name, fixed = split_nevra(nevra)
            if name in installed:
                out.append({"name": name, "installed": installed[name], "fixed": fixed,
                            "advisory": advisory, "severity": severity.upper()})
        return {"packages": len(installed), "vulnerable": out}
    fp = hashlib.sha256("\n".join(sorted(f"{k} {v}" for k, v in installed.items())).encode()).hexdigest()
    return cache.memo("dnf", scan, fingerprint=fp, refresh=refresh, offline=offline)


def arch_advisories(cache, groups):
    """{"packages": n, "vulnerable": [{name, installed, fixed, advisory,
    severity, issues}], "unfixed": n}: tracker groups that apply to installed
    packages, compared with pacman's own vercmp."""
    pacman, vercmp = shutil.which("pacman"), shutil.which("vercmp")
    if not pacman:
        raise Offline("pacman isn't installed")
    installed = dict(line.split(" ", 1) for line in
                     subprocess.run([pacman, "-Q"], capture_output=True, text=True).stdout.splitlines() if " " in line)

    def older(a, b):
        if not vercmp:
            return lt(a, b)
        return int(subprocess.run([vercmp, a, b], capture_output=True, text=True).stdout.strip() or 0) < 0

    out, unfixed = [], 0
    for g in groups:
        for name in g.get("packages", []):
            have = installed.get(name)
            if not have:
                continue
            if g.get("fixed") and older(have, g["fixed"]):
                out.append({"name": name, "installed": have, "fixed": g["fixed"], "advisory": g["name"],
                            "severity": (g.get("severity") or "").upper(), "issues": g.get("issues", [])})
                cache.put_vuln({"id": g["name"], "aliases": g.get("issues", []),
                                "summary": f"{g.get('type', 'vulnerability')} in {name}",
                                "affected": [{"package": {"ecosystem": "Arch", "name": name}}],
                                "database_specific": {"severity": g.get("severity", "")}})
            elif not g.get("fixed") and g.get("status") == "Vulnerable" and g.get("affected") \
                    and not older(have, g["affected"]):
                unfixed += 1
    cache.conn.commit()
    return {"packages": len(installed), "vulnerable": out, "unfixed": unfixed}


def os_fix(name: str) -> str:
    rel = os_release()
    ids = set((rel.get("ID", "") + " " + rel.get("ID_LIKE", "")).split())
    if ids & {"debian", "ubuntu"}:
        return f"sudo apt-get update && sudo apt-get install --only-upgrade {name}"
    if ids & {"alpine", "wolfi", "chainguard"}:
        return f"sudo apk upgrade {name}"
    if any("suse" in i for i in ids):
        return f"sudo zypper update {name}"
    if ids & {"arch", "archlinux"}:
        return "sudo pacman -Syu"  # Arch doesn't support partial upgrades
    return f"sudo {'dnf' if shutil.which('dnf') else 'yum'} upgrade {name}"
