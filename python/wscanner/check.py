"""The scan: gather the inventory, ask each source only about what is here,
and turn the answers into findings. Areas live in check_machine.py and
check_supply.py; report.py prints the findings and the update plan.

A finding fails when it applies to something on this machine or in our repos
and a released version fixes it, when the component is past end of life, or
when it's a known malicious package (whose fix is removing it). Everything
else that applies is a warning. A source that can't be reached is reported
"not checked", never clean. Nothing that isn't installed is reported."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import feeds, osv, versions
from .db import Cache, severity_of
from .net import Offline
from .system import Component

HERE = Path(__file__).resolve().parent.parent
REMOVE = "Remove {} now, then rotate any credentials this machine holds"


@dataclass
class Finding:
    kind: str
    component: str
    version: str
    location: str
    vuln_id: str
    status: str          # fail | warn
    fixed: str = ""
    kev: bool = False
    severity: str = ""
    note: str = ""
    fix_cmd: str = ""
    fix_auto: bool = False


def listed(name: str):
    """Entries of a one-per-line list in security/ (comments start with #)."""
    try:
        lines = (HERE / name).read_text().splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def ids_of(rec) -> list:
    """The record's id, aliases and (distro records) upstream CVE ids."""
    return [rec.get("id", "")] + list(rec.get("aliases") or []) + list(rec.get("upstream") or [])


def display_id(rec) -> str:
    return next((a for a in [rec.get("id", "")] + list(rec.get("aliases") or []) if a.startswith("CVE-")),
                rec.get("id", ""))


def is_kev(rec, kev) -> bool:
    return any(a in kev for a in ids_of(rec))


def is_malicious(rec) -> bool:
    """OpenSSF malicious-package reports (MAL-…)."""
    return any(i.startswith("MAL-") for i in ids_of(rec))


def fill(cmd: str, safe: str) -> str:
    return cmd.replace("{safe}", safe or "latest")


class Scan:
    def __init__(self, ops: Path, refresh=False, offline=False, ask=True, log=print):
        self.ops, self.refresh, self.offline, self.ask, self.log = ops, refresh, offline, ask, log
        self.cache = Cache()
        self.findings: list = []
        self.counts: dict = {}
        self.unfixed = 0
        self.unknown_licenses = 0
        self.kev: set = set()

    # helpers ---------------------------------------------------------------
    def add(self, c: Component = None, **kw):
        """A finding; with a Component, its kind, name, version and path."""
        if c is not None:
            kw = dict(dict(kind=c.kind, component=c.name, version=c.version, location=c.path), **kw)
        self.findings.append(Finding(**kw))

    def unchecked(self, what: str, why):
        """A source we couldn't reach: say so, rather than report it clean."""
        if not any(f.kind == "unchecked" and f.component == what for f in self.findings):
            note = str(why).splitlines()[0][:160] if str(why) else "unavailable"
            self.add(kind="unchecked", component=what, version="", location="", vuln_id="UNCHECKED",
                     status="warn", note=note)

    def guard(self, what: str, fetch, default=None):
        """fetch(), or `default` with the source reported unchecked."""
        try:
            return fetch()
        except (Offline, RuntimeError, ValueError) as e:
            self.unchecked(what, e)
            return default

    def count(self, what: str, n: int):
        if what and n:
            self.counts[what] = self.counts.get(what, 0) + n

    def lookup(self, items, what: str):
        """OSV answers for (ecosystem, package, version) items; any it can't
        answer are reported unchecked."""
        answers = osv.lookup(self.cache, items, self.refresh, self.offline, self.log)
        if any(it not in answers for it in items):
            self.unchecked(what, "OSV unreachable and not cached")
        return answers

    # the scan --------------------------------------------------------------
    def run(self):
        from . import check_machine, check_supply  # the areas; they import this module
        self.kev = self.guard("CISA KEV (exploited-in-the-wild marks)", lambda: feeds.kev(self.cache, self.offline),
                              set())
        found = check_machine.inventory(self)
        check_machine.components(self, found)
        check_machine.apps(self)
        check_machine.os_updates(self)
        check_machine.brew(self)
        check_supply.run(self, found)
        self.cache.replace_findings(self.findings)
        self.cache.close()
        return self.findings

    # shared by the areas ---------------------------------------------------
    def advisories(self, c: Component, recs, newer=None, status="fail", groups=None):
        """Findings for one component from its OSV records; returns whether
        any failed. `groups` bundles records that are aliases of one
        vulnerability (osv-scanner groups them); otherwise each record is its
        own, deduplicated by CVE id. `newer` (upstream repos) maps later
        release tags to the advisories OSV still reports for them."""
        eco, pkg, qver = c.osv or ("", "", "")
        failing, seen = False, set()
        for group in groups or [[r] for r in recs]:
            main = next((r for r in group if display_id(r).startswith("CVE-")), group[0])
            if display_id(main) in seen:  # the same CVE from two databases
                continue
            seen.add(display_id(main))
            bad = next((r for r in group if is_malicious(r)), None)
            if bad:
                failing = True
                self.add(c, vuln_id=bad["id"], status="fail", kev=True, severity="MALICIOUS",
                         note=bad.get("summary") or "known malicious package",
                         fix_cmd=REMOVE.format(c.osv[1] if c.osv else c.name))
                continue
            fixes = [f for r in group for f in osv.fixed_versions(r, eco, pkg, qver, newer)]
            if not fixes:
                self.unfixed += 1
                continue
            safe = versions.pick_safe(qver, fixes) or sorted(fixes, key=versions.key)[-1]
            failing = failing or status == "fail"
            self.add(c, vuln_id=display_id(main), status=status, fixed=safe,
                     kev=any(is_kev(r, self.kev) for r in group), severity=severity_of(main),
                     note=main.get("summary", ""), fix_cmd=fill(c.fix, safe), fix_auto=c.auto)
        return failing

    def scanned(self, res, kind, fix_for, label=None, status="fail", what=""):
        """Findings from an osv-scanner result. `label` names a package in the
        report; `status` is what a fixable advisory counts as."""
        self.count(what, res.get("packages", 0))
        seen = set()
        for p in res.get("vulnerable", []):
            key = (p["name"], p["version"], p["source"])
            if key in seen:  # one source package, several binary packages
                continue
            seen.add(key)
            groups = [g for g in ([r for r in (self.cache.vuln(i) for i in ids) if r] for ids in p["groups"]) if g]
            c = Component(kind, label(p) if label else p["name"], p["version"], p["source"],
                          osv=(p["ecosystem"], p["name"], p["version"]), fix=fix_for(p, "{safe}"))
            self.advisories(c, [], status=status, groups=groups)

    def eol(self, c: Component, failing: bool):
        product, cycle = c.eol
        res = self.guard(f"end of life for {product}",
                         lambda: feeds.eol(self.cache, product, c.version, cycle, self.offline))
        if not res:
            return
        _, ended, latest, supported = res
        if ended:
            self.add(c, vuln_id="EOL", status="fail", fix_cmd=fill(c.fix, supported[0] if supported else ""),
                     note=f"{product} {cycle} reached end of life on {ended}; supported: {', '.join(supported[:4])}")
        elif latest and not failing and not versions.same_or_newer(c.version, latest):
            self.add(c, vuln_id="OUTDATED", status="warn", fixed=latest, fix_cmd=fill(c.fix, latest), fix_auto=c.auto,
                     note=f"behind {latest}, the latest {product} {cycle} release")
