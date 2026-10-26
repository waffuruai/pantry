"""Checks for this machine: tools, runtimes and their packages, apps and
browsers, OS updates and OS packages, and Homebrew formulae."""

from __future__ import annotations

import time

from . import apps as apps_mod
from . import distros, feeds, osv, packages, scanners, tools, versions
from .catalog import MISE_REPO, TOOLS
from .check import REMOVE, display_id, fill, is_kev, is_malicious
from .db import severity_of
from .system import MACOS, Component, brew_casks, os_family, os_release

GRACE = 3 * 86400  # a browser release younger than this only warns
MANUAL = {t.name: t.fix for t in TOOLS if t.fix}  # formulae `--update` must not upgrade either


def inventory(scan):
    found = tools.tools()
    found += packages.pythons()
    found += packages.node_packages(found)
    found += packages.gems(found)
    found += packages.cargo_installs()
    found += packages.pipx_packages()
    found += apps_mod.docker()
    scan.count("tools, runtimes and packages", len(found))
    return found


def components(scan, found):
    """OSV, end of life and (PostgreSQL) the project's own table."""
    items = [c.osv for c in found if c.osv]
    answers = scan.lookup(items, "tools, runtimes and packages against OSV")
    # For upstream repos, ask OSV about the newer release tags too: the first
    # one it stops reporting an advisory for is the fix.
    newer = {c.osv: osv.candidates(scan.cache, c.osv[1], c.osv[2])
             for c in found if c.osv and c.osv[0] == "GIT" and answers.get(c.osv)}
    later = scan.lookup([("GIT", k[1], t) for k, ts in newer.items() for t in ts],
                        "which releases fix upstream-repo advisories")
    newer = {k: {t: [r["id"] for r in later[("GIT", k[1], t)]] for t in ts if ("GIT", k[1], t) in later}
             for k, ts in newer.items()}
    pg = []
    if any(c.name == "postgres" for c in found):
        pg = scan.guard("PostgreSQL (postgresql.org security table)",
                        lambda: feeds.postgres(scan.cache, scan.offline), [])
    for c in found:
        failing = scan.advisories(c, answers.get(c.osv, []) if c.osv else [], newer.get(c.osv))
        if c.name == "postgres":
            failing = postgres(scan, c, pg) or failing
        if c.name == "mise":
            mise(scan, c)
        if c.eol:
            scan.eol(c, failing)


def mise(scan, c):
    """A newer mise release only warns (OSV decides failures): a human bumps
    it in ops, so the fix is never unattended."""
    latest = scan.guard("latest mise release (GitHub)",
                        lambda: feeds.github_latest(scan.cache, MISE_REPO, scan.offline), "")
    if latest and not versions.same_or_newer(c.version, latest):
        scan.add(c, vuln_id="OUTDATED", status="warn", fixed=latest, fix_cmd=c.fix, fix_auto=False,
                 note=f"mise {c.version} is behind {latest}. mise is foundational infrastructure: bump "
                      "MISE_VERSION in ops and run make install-mise; wscanner never updates it.")


def postgres(scan, c, advisories):
    """An advisory applies when the installed major is listed and the install
    is older than that major's fixed release."""
    major, failing = c.version.split(".")[0], False
    for a in advisories:
        fixed = next((f for f in a["fixed"] if f.split(".")[0] == major), "")
        if major not in a["majors"] or not fixed or not versions.lt(c.version, fixed):
            continue
        sev = feeds.severity_from_score(a["score"])
        if not scan.cache.vuln(a["cve"]):
            scan.cache.put_vuln({"id": a["cve"], "summary": a["summary"], "database_specific": {"severity": sev},
                                 "affected": [{"package": {"ecosystem": "PostgreSQL", "name": "postgresql"}}]})
        scan.add(c, vuln_id=a["cve"], status="fail", fixed=fixed, kev=a["cve"] in scan.kev, severity=sev,
                 note=f"{a['summary']} ({a['component']})", fix_cmd=fill(c.fix, fixed), fix_auto=c.auto)
        failing = True
    return failing


# Apps and browsers ---------------------------------------------------------

def apps(scan):
    found = apps_mod.apps()
    if not found:
        return
    scan.count("apps", len(found))
    catalog = scan.guard("latest app versions (Homebrew cask catalog)",
                         lambda: feeds.casks(scan.cache, scan.offline), {})
    casks = brew_casks()
    electron = scan.lookup([("npm", "electron", a.extra["electron"]) for a in found if "electron" in a.extra],
                           "apps' bundled Electron against OSV")
    for a in found:
        token, latest = catalog.get(a.extra["bundle"], ("", ""))
        a.fix, a.auto = (f"brew upgrade --cask {token}", True) if token in casks else (
            f"Update {a.name} from its vendor (or its own updater)", False)
        behind = bool(latest) and not versions.same_or_newer(a.version, latest)
        if a.kind == "browser":
            browser(scan, a, behind, latest)
        elif "electron" in a.extra and _electron(scan, a, electron.get(("npm", "electron", a.extra["electron"]), []),
                                                 behind, latest):
            continue
        elif behind:
            scan.add(a, vuln_id="OUTDATED", status="warn", fixed=latest, note=f"latest release is {latest}",
                     fix_cmd=a.fix, fix_auto=a.auto)


def _electron(scan, a, recs, behind, latest):
    """Findings for an app's bundled Electron; False when it has none."""
    ev = a.extra["electron"]
    bad = [r for r in recs if is_malicious(r) or osv.fixed_versions(r, "npm", "electron", ev)]
    if not bad:
        return False
    ids = sorted({display_id(r) for r in bad})
    if behind:
        scan.add(a, vuln_id=ids[0], status="fail", fixed=latest, kev=any(is_kev(r, scan.kev) for r in bad),
                 note=f"bundles Electron {ev} ({len(ids)} fixed advisories); {latest} is out",
                 fix_cmd=a.fix, fix_auto=a.auto)
    else:
        scan.add(a, vuln_id=ids[0], status="warn", kev=any(is_kev(r, scan.kev) for r in bad),
                 note=f"bundles Electron {ev} ({len(ids)} fixed advisories); no newer app release yet",
                 fix_cmd=f"Ask the {a.name} vendor to ship a newer Electron")
    return True


def browser(scan, a, behind, latest):
    which = a.extra["browser"]
    target, start, how = "", 0, ""
    if which == "chrome":
        releases = scan.guard("Chrome (Google's release feed)", lambda: feeds.chrome(scan.cache, "mac", scan.offline), [])
        newer = [(v, t) for v, t in releases if versions.lt(a.version, v)]
        if newer:
            target, start = max(newer, key=lambda r: versions.key(r[0]))
        how = "Chrome menu → About Google Chrome, then Relaunch"
    elif which == "firefox":
        ff = scan.guard("Firefox (Mozilla's release feed)", lambda: feeds.firefox(scan.cache, scan.offline), {})
        line = [e for e in ff.get("esr", []) if e.split(".")[0] == a.version.split(".")[0]]
        target = line[0] if line else ff.get("latest", "")
        start = ff.get("dates", {}).get(target, 0)
        how = "Firefox menu → About Firefox, then Restart to Update"
    elif behind:
        scan.add(a, vuln_id="OUTDATED", status="warn", fixed=latest, note=f"latest release is {latest}",
                 fix_cmd=a.fix, fix_auto=a.auto)
        return
    if target and versions.lt(a.version, target):
        old = bool(start) and start < time.time() - GRACE
        scan.add(a, vuln_id="BROWSER", status="fail" if old else "warn", fixed=target,
                 note=f"{a.name} {target} is out; its releases carry security fixes",
                 fix_cmd=a.fix if a.auto else how, fix_auto=a.auto)


# OS ------------------------------------------------------------------------

def os_updates(scan):
    if MACOS:
        _macos(scan)
        return
    family = os_family()
    if family == "osv":
        res = scan.guard("OS packages", lambda: scanners.os_packages(scan.cache, scan.refresh, scan.offline))
        if res:
            scan.scanned(res, "os", lambda p, safe: distros.os_fix(p["name"]), what="OS packages")
    elif family in ("dnf", "arch"):
        res = scan.guard("OS packages", lambda: distros.dnf_advisories(scan.cache, scan.refresh, scan.offline)
                         if family == "dnf" else distros.arch_advisories(scan.cache, feeds.arch(scan.cache, scan.offline)))
        if res:
            _distro(scan, res)
    else:
        rel = os_release()
        scan.unchecked(f"OS packages ({rel.get('PRETTY_NAME') or rel.get('ID') or 'this distro'})",
                       "no advisory source for this distro yet; binaries in system paths are checked "
                       "against upstream versions instead")


def _macos(scan):
    updates, last = apps_mod.macos_updates()
    for title, ver in updates:
        scan.add(kind="os", component=title.strip(), version="", location="softwareupdate", vuln_id="OS-UPDATE",
                 status="fail", fixed=ver.strip(), note="macOS updates (and Safari) carry security fixes",
                 fix_cmd="System Settings → General → Software Update (or: sudo softwareupdate -i -a)")
    try:
        age = time.time() - time.mktime(time.strptime(last[:19], "%Y-%m-%d %H:%M:%S")) + time.timezone
    except ValueError:
        age = 0
    if age > 14 * 86400:
        scan.add(kind="os", component="macOS", version="", location="softwareupdate", vuln_id="OS-UPDATE",
                 status="warn", note=f"Software Update last checked {last[:10]}; results may be stale",
                 fix_cmd="softwareupdate --list")


def _distro(scan, res):
    scan.count("OS packages", res["packages"])
    scan.unfixed += res.get("unfixed", 0)
    for p in res["vulnerable"]:
        issues = p.get("issues", [])
        scan.add(kind="os", component=p["name"], version=p["installed"], location="system packages",
                 vuln_id=p["advisory"], status="fail", fixed=p["fixed"], kev=any(i in scan.kev for i in issues),
                 severity=p["severity"], note=", ".join(issues[:4]), fix_cmd=distros.os_fix(p["name"]))


# Homebrew ------------------------------------------------------------------

def brew(scan):
    try:
        res = scanners.brew_vulns(scan.cache, scan.refresh, scan.offline)
    except scanners.Missing:
        scan.add(kind="tool", component="brew vulns", version="", location="", vuln_id="MISSING", status="fail",
                 note="Homebrew formulae can't be checked", fix_cmd="brew update", fix_auto=True)
        return
    except Exception as e:  # noqa: BLE001  (Offline, RuntimeError: report, don't crash the scan)
        scan.unchecked("Homebrew formulae (brew vulns)", e)
        return
    if res is None:
        return
    scan.count("Homebrew formulae", res.get("checked", 0))
    for f in res.get("findings", []):
        fix, auto = (MANUAL[f["formula"]], False) if f["formula"] in MANUAL else (f"brew upgrade {f['formula']}", True)
        c = Component("brew", f["formula"], f["version"], "Homebrew", fix=fix, auto=auto)
        for v in f.get("vulnerabilities", []):
            rec = {"id": v["id"], "aliases": v.get("aliases", [])}
            fixes = [x for x in v.get("fixed_versions") or [] if osv.released(x)]
            if is_malicious(rec):
                scan.add(c, vuln_id=v["id"], status="fail", kev=True, severity="MALICIOUS",
                         note=v.get("summary", ""), fix_cmd=REMOVE.format(f["formula"]))
            elif not fixes:
                scan.unfixed += 1
            else:
                scan.add(c, vuln_id=display_id(rec), status="fail", kev=is_kev(rec, scan.kev),
                         fixed=versions.pick_safe(f["version"], fixes) or fixes[0],
                         severity=(v.get("severity") or "").upper() or severity_of(rec),
                         note=v.get("summary", ""), fix_cmd=c.fix, fix_auto=c.auto)
