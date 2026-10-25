"""Print the findings, and plan or apply the fixes (`wscanner --update`)."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from . import versions
from .db import path as db_path
from .system import short

MARK = {"fail": "✗", "warn": "⚠"}
BUNDLES = {"image": "image", "bundled": "bundles"}  # many packages inside one thing: one entry per thing


def covering(fs):
    """Of one component's findings, the one whose fix covers them all: the
    highest fixed version (each advisory's own fix is the lowest clearing it)."""
    with_fix = [f for f in fs if f.fixed]
    return max(with_fix, key=lambda f: versions.key(f.fixed)) if with_fix else fs[0]


def group(findings):
    """Report entries: (status, kind, name, version, location) → findings."""
    by = {}
    for f in findings:
        if f.kind in BUNDLES:
            key = (f.status, f.kind, f.component.split(" › ", 1)[0], "", "")
        elif f.kind == "license":
            key = (f.status, f.kind, f.note, "", "")
        elif f.vuln_id == "OUTDATED" and f.kind in ("app", "extension"):
            editor = f.component.rsplit("(", 1)[-1].rstrip(")") if f.kind == "extension" else "apps"
            key = (f.status, "outdated", editor, "", "")
        else:
            key = (f.status, f.kind, f.component, f.version, f.location)
        by.setdefault(key, []).append(f)
    return by


def report(scan, findings, out=print):
    out("")
    out(f"==> Security scan ({db_path()})")
    covered = ", ".join(f"{n} {what}" for what, n in scan.counts.items())
    out(f"  checked {covered}" if covered else "  nothing to check")
    by = group(findings)
    for (status, kind, comp, ver, loc), fs in sorted(by.items(), key=lambda kv: (kv[0][0] != "fail", kv[0][1:])):
        if kind in BUNDLES:
            _bundle(status, BUNDLES[kind], comp, fs, out)
        elif kind == "license":
            _license(status, fs, out)
        elif kind == "outdated":
            _outdated(status, comp, fs, out)
        elif kind == "unchecked":
            out(f"  ⚠ not checked: {comp}  ({fs[0].note})")
        else:
            _entry(status, kind, f"{comp} {ver}".strip(), loc, fs, out)
    fails = sum(1 for k in by if k[0] == "fail")
    gaps = sum(1 for k in by if k[1] == "unchecked")
    warns = sum(1 for k in by if k[0] == "warn") - gaps
    if scan.unfixed:
        out(f"  · {scan.unfixed} applicable advisories have no released fix yet (wscanner search --applicable)")
    if scan.unknown_licenses:
        out(f"  · {scan.unknown_licenses} project dependencies have no license osv-scanner can identify")
    out("")
    incomplete = f" Incomplete: {gaps} source(s) couldn't be checked (offline?); re-run when they're reachable." \
        if gaps else ""
    if fails:
        out(f"✗ {fails} thing(s) to update ({sum(1 for f in findings if f.status == 'fail')} advisories), "
            f"{warns} warning(s). See the plan: wscanner --update --dryrun{incomplete}")
    elif gaps:
        out(f"⚠ nothing with a released fix found in what could be checked.{incomplete}")
    elif warns:
        out(f"✓ nothing with a released fix applies; {warns} warning(s) above")
    else:
        out("✓ nothing with a released fix applies to what was scanned")
    return 1 if fails else 0


def _entry(status, kind, head, loc, fs, out):
    out(f"  {MARK[status]} {kind:<8} {head}{f'  ({short(loc)})' if loc else ''}")
    shown = sorted(fs, key=lambda f: (not f.kev, f.vuln_id))
    for f in shown[:4]:
        tags = " ".join(t for t in ("KEV" if f.kev and f.severity != "MALICIOUS" else "", f.severity) if t)
        out(f"      {f.vuln_id}{' ' + tags if tags else ''}  {f.note[:90]}")
    if len(shown) > 4:
        out(f"      … and {len(shown) - 4} more")
    fixed = covering(fs).fixed
    if fixed:
        out(f"      fixed in {fixed}")
    cmd = covering(fs).fix_cmd or next((f.fix_cmd for f in fs if f.fix_cmd), "")
    if cmd:
        out(f"      fix: {cmd}")


def _bundle(status, label, ref, fs, out):
    pkgs = {}
    for f in fs:
        pkgs.setdefault((f.component.split(" › ", 1)[-1], f.version), []).append(f)
    out(f"  {MARK[status]} {label:<8} {ref}  ({len(pkgs)} packages, {len(fs)} advisories)")
    ranked = sorted(pkgs.items(), key=lambda kv: (not any(f.kev for f in kv[1]), -len(kv[1])))
    for (pkg, ver), pfs in ranked[:5]:
        fixed = covering(pfs).fixed
        kev = " KEV" if any(f.kev for f in pfs) else ""
        out(f"      {pkg} {ver}{' → ' + fixed if fixed else ''}  ({len(pfs)} advisories{kev})")
    if len(ranked) > 5:
        out(f"      … and {len(ranked) - 5} more packages")
    out(f"      fix: {fs[0].fix_cmd}")


def _outdated(status, grp, fs, out):
    out(f"  {MARK[status]} outdated {len(fs)} {'apps' if grp == 'apps' else grp + ' extensions'} "
        "behind their latest release")
    shown = [f"{f.component.split(' (')[0]} {f.version} → {f.fixed}" for f in fs[:6]]
    out("      " + ", ".join(shown) + (f" and {len(fs) - 6} more" if len(fs) > 6 else ""))
    auto = sum(1 for f in fs if f.fix_auto)
    out(f"      fix: wscanner --update updates {auto} of them" if auto else
        "      fix: update them from their vendors (or their own updaters)")


def _license(status, fs, out):
    names = sorted({f.component for f in fs})
    where = sorted({short(str(Path(f.location).parent)) for f in fs})
    out(f"  {MARK[status]} license  {fs[0].note.replace('license ', '', 1)}")
    out(f"      {len(names)} packages in {', '.join(where)}: {', '.join(names[:4])}"
        + (f" and {len(names) - 4} more" if len(names) > 4 else ""))
    out("      fix: replace them, or approve the license in the licenses allowlist (--licenses)")


def plan(findings):
    """(unattended, needs you, also worth doing): one fix per component, the
    one covering all its advisories, failures before warnings."""
    groups = {}
    for f in findings:
        groups.setdefault((f.kind, f.component, f.version, f.location), []).append(f)
    seen, auto, manual, optional = set(), [], [], []
    for fs in sorted(groups.values(), key=lambda fs: min(f.status != "fail" for f in fs)):
        f = covering(fs)
        if not f.fix_cmd or f.fix_cmd in seen:
            continue
        seen.add(f.fix_cmd)
        (auto if f.fix_auto else manual if any(x.status == "fail" for x in fs) else optional).append(f.fix_cmd)
    return auto, manual, optional


def apply(findings, dryrun: bool, out=print):
    auto, manual, optional = plan(findings)
    if not (auto or manual or optional):
        out("Nothing to update.")
        return 0
    out("")
    out("==> Update plan" + (" (dry run: nothing is changed)" if dryrun else ""))
    status = 0
    for cmd in auto:
        if dryrun:
            out(f"  would run: {cmd}")
            continue
        out(f"  → {cmd}")
        if subprocess.run(shlex.split(cmd)).returncode != 0:
            out(f"  ✗ failed: {cmd}")
            status = 1
    for title, cmds in (("Needs you (sudo, a shell function, a vendor update, or a change in a repo, made on a branch):",
                         manual), ("Also worth doing (warnings: outdated, or waiting on a vendor):", optional)):
        if cmds:
            out(f"  {title}")
            for cmd in cmds:
                out(f"    • {cmd}")
    return status
