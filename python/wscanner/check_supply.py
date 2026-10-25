"""Supply-chain checks: our repos' dependencies, licenses and install
scripts, container images, editor extensions, what AI harnesses load (MCP
servers, plugins, skills), every package name against the malicious-package
index, and the opt-in breach check."""

from __future__ import annotations

import shlex
from pathlib import Path

from . import apps as apps_mod
from . import breach, editors, feeds, harnesses, leaks, malicious, repos, scanners, versions
from .check import HERE, REMOVE, listed
from .system import Component, brew_prefix, short
from .system import run as sh


def run(scan, found):
    org = repos.org_repos(scan.ops)
    projects(scan, org)
    secrets(scan, org)
    install_scripts(scan, org, found)
    images(scan, org)
    exts = extensions(scan)
    refs = mcp(scan, org)
    bundles(scan, exts)
    sweep(scan, found, exts, refs)
    _breach(scan)


def _missing_osv_scanner(scan, what):
    has_brew = bool(brew_prefix())
    scan.add(kind="tool", component="osv-scanner", version="", location="", vuln_id="MISSING", status="fail",
             note=f"{what} can't be checked", fix_auto=has_brew,
             fix_cmd="brew install osv-scanner" if has_brew else "make install-osv-scanner")


def _osv_source(scan, what, key, targets, files, **kw):
    try:
        return scanners.source(scan.cache, key, targets, files, scan.refresh, scan.offline, **kw)
    except scanners.Missing:
        _missing_osv_scanner(scan, what)
    except Exception as e:  # noqa: BLE001  (Offline, RuntimeError, bad JSON: report, don't crash)
        scan.unchecked(f"{what} (osv-scanner)", e)
    return None


# Our repos -----------------------------------------------------------------

def project_fix(p, safe):
    lock = Path(p["source"])
    d, name, eco = shlex.quote(str(lock.parent)), p["name"], p["ecosystem"]
    if eco == "crates.io":
        return f"cd {d} && cargo update -p {name} --precise {safe}"
    if lock.name == "pnpm-lock.yaml":
        return f"cd {d} && pnpm update {name}@{safe}"
    if eco == "npm":
        return f"cd {d} && npm install {name}@{safe}"
    if eco == "PyPI" and lock.name == "uv.lock":
        return f"cd {d} && uv lock --upgrade-package {name}=={safe}"
    if eco == "Go":
        return f"cd {d} && go get {name}@v{safe.lstrip('v')} && go mod tidy"
    return f"Update {name} to {safe} in {lock}"


def projects(scan, org):
    files = [f for _, r in org for f in repos.lockfiles(r)]
    res = _osv_source(scan, "our repos' dependencies", "osv-scanner:repos", sorted({f.parent for f in files}),
                      files + [HERE / "licenses.txt"], licenses=listed("licenses.txt")) if files else None
    if not res:
        return
    scan.scanned(res, "project", project_fix, what="project dependencies")
    for v in res.get("licenses", []):
        scan.add(kind="license", component=v["name"], version=v["version"], location=v["source"], vuln_id="LICENSE",
                 status="warn", note=f"license {', '.join(v['violations'])} isn't in security/licenses.txt",
                 fix_cmd=f"Review {v['name']}: replace it, or approve its license in security/licenses.txt")
    scan.unknown_licenses = res.get("unknown_licenses", 0)


def secrets(scan, org):
    """Secrets committed anywhere in our repos' history. A provider-specific
    rule (AWS, GitHub, OpenAI, …) fails; a generic one asks for review."""
    for name, root in org:
        try:
            found = leaks.scan(scan.cache, root, HERE / "gitleaks.toml", scan.refresh, scan.offline)
        except scanners.Missing:
            has_brew = bool(brew_prefix())
            scan.add(kind="tool", component="gitleaks", version="", location="", vuln_id="MISSING", status="fail",
                     note="secrets in our repos (and staged commits) can't be checked", fix_auto=has_brew,
                     fix_cmd="brew install gitleaks" if has_brew else "make install-gitleaks")
            return
        except Exception as e:  # noqa: BLE001  (Offline, RuntimeError: report, don't crash)
            scan.unchecked(f"secrets in {name}'s history (gitleaks)", e)
            continue
        scan.count("repos scanned for secrets", 1)
        for f in found:
            generic = f["rule"] in leaks.GENERIC
            scan.add(kind="secret", component=f"{name}/{f['file']}", version="", location=f"line {f['line']}, "
                     f"commit {f['commit']}", vuln_id=f["rule"], status="warn" if generic else "fail",
                     note=f"{f['description']}{' (review: generic rule)' if generic else ''}",
                     fix_cmd=f"If it's real: rotate it, then purge it from history. If not: add "
                             f"{f['fingerprint']} to {short(str(root))}/.gitleaksignore")


def install_scripts(scan, org, found):
    """Dependencies that run code at install time, and whether npm runs them
    by default on this machine."""
    allowed = set(listed("install-scripts.txt"))
    for where, name in repos.install_scripts([f for _, r in org for f in repos.lockfiles(r)]):
        if name not in allowed:
            scan.add(kind="install-script", component=name, version="", location=str(where),
                     vuln_id="INSTALL-SCRIPT", status="warn", note="runs code when installed",
                     fix_cmd=f"Check what {name}'s install script does; then allow it in security/install-scripts.txt, "
                             "or drop it from the build allowlist")
    npm = next((c.path for c in found if c.name == "npm" and c.path), "")
    if npm and sh([npm, "config", "get", "ignore-scripts"]).strip().endswith("false"):
        scan.add(kind="config", component="npm ignore-scripts", version="", location=npm, vuln_id="NPM-SCRIPTS",
                 status="warn", note="npm runs every dependency's install scripts (how most npm attacks run)",
                 fix_cmd=f"{npm} config set ignore-scripts true  (then allow builds per project)")


def images(scan, org):
    """Images behind running containers, and the ones our repos build from or
    run, when they exist locally (pulling is left to the user)."""
    refs = {r: f"docker pull {r}, then recreate its containers" for r in apps_mod.running_images()}
    for ref, f in repos.repo_images(org):
        refs.setdefault(ref, f"docker pull {ref} (the tag may already carry the fixes); if not, bump it in "
                             f"{short(str(f))}; then rebuild")
    for ref in sorted(refs):
        image_id = apps_mod.image_id(ref)
        if not image_id:
            continue
        try:
            res = scanners.image(scan.cache, ref, image_id, scan.refresh, scan.offline)
        except scanners.Missing:
            _missing_osv_scanner(scan, "container images")
            return
        except Exception as e:  # noqa: BLE001
            scan.unchecked(f"image {ref} (osv-scanner)", e)
            continue
        scan.scanned(res, "image", lambda p, safe, fix=refs[ref]: fix, label=lambda p, ref=ref: f"{ref} › {p['name']}",
                     what="image packages")


# Editors and AI harnesses --------------------------------------------------

def extensions(scan):
    """Malicious or deprecated per the lists VS Code itself uses (and OSV),
    behind their marketplace's latest, and the npm packages they bundle."""
    exts = editors.extensions()
    if not exts:
        return []
    scan.count("editor extensions", len(exts))
    lists = scan.guard("VS Code's malicious-extension list", lambda: feeds.vscode_lists(scan.cache, scan.offline),
                       {"malicious": set(), "deprecated": {}})
    answers = scan.lookup([e.osv for e in exts], "editor extensions against OSV")
    latest = {}
    for market in ("vscode", "openvsx"):
        ids = [e.name for e in exts if e.extra["market"] == market]
        if ids:
            latest.update(scan.guard(f"latest extension versions ({market})",
                                     lambda ids=ids, m=market: feeds.latest_extensions(scan.cache, ids, m == "openvsx",
                                                                                       scan.offline), {}))
    for e in exts:
        e.name = f"{e.extra['id']} ({e.extra['editor']})"  # how the report names it
        uninstall = f"{e.extra['cli']} --uninstall-extension {e.extra['id']}"
        if e.extra["id"].lower() in lists["malicious"]:
            scan.add(e, vuln_id="MALICIOUS", status="fail", kev=True, severity="MALICIOUS", fix_cmd=uninstall,
                     fix_auto=True, note="known malicious extension (removed from the marketplace)")
            continue
        e.fix, e.auto = uninstall, True
        if scan.advisories(e, answers.get(e.osv, [])):
            continue
        e.fix = f"{e.extra['cli']} --install-extension {e.extra['id']} --force"
        if e.extra["id"].lower() in lists["deprecated"]:
            repl = lists["deprecated"][e.extra["id"].lower()]
            scan.add(e, vuln_id="DEPRECATED", status="warn", note="deprecated" + (f"; use {repl}" if repl else ""),
                     fix_cmd=uninstall)
        newest = latest.get(e.extra["id"].lower())
        if newest and not versions.same_or_newer(e.version, newest):
            scan.add(e, vuln_id="OUTDATED", status="warn", fixed=newest, note=f"latest release is {newest}",
                     fix_cmd=e.fix, fix_auto=True)
    return exts


def mcp(scan, org):
    """MCP servers the harnesses start through a package runner. Pinned ones
    are checked like any package; unpinned ones run whatever is latest on
    every launch, so they warn (and fail if the name is known malicious)."""
    servers = harnesses.mcp_servers(org)
    scan.count("MCP servers", len(servers))
    refs = []
    for s in servers:
        ref = harnesses.package_ref(s["command"], s["args"])
        if not ref:
            continue
        eco, name, ver = ref
        c = Component("mcp", f"{name} ({s['harness']}: {s['name']})", ver or "unpinned", s["file"],
                      osv=(eco, name, ver) if ver else (), extra={"eco": eco, "pkg": name, "ver": ver})
        c.fix = f"Pin {name} to a reviewed version in {short(s['file'])}" + (" ({safe} fixes it)" if ver else "")
        refs.append(c)
        if not ver:
            scan.add(c, vuln_id="UNPINNED", status="warn", fix_cmd=c.fix,
                     note=f"`{s['command']} {name}` runs the latest release on every launch")
    answers = scan.lookup([c.osv for c in refs if c.osv], "MCP server packages against OSV")
    for c in refs:
        if c.osv:
            scan.advisories(c, answers.get(c.osv, []))
    scan.count("harness skills", len(harnesses.skill_dirs()))
    return refs


def bundles(scan, exts):
    """npm packages bundled in editor extensions, harness plugins and desktop
    extensions, plus lockfiles and SBOMs shipped in those and in skills. A
    vulnerable bundle warns (only its vendor can fix it); malicious fails."""
    dirs = [(f"{e.name}", e.extra["dir"], e.fix) for e in exts]
    dirs += [(f"{h} plugin {Path(d).name}", d, f"Update or remove the {h} plugin in {short(d)}")
             for h, d in harnesses.plugin_dirs()]
    pkgs = {d: editors.bundled_npm(d) for _, d, _ in dirs}
    answers = scan.lookup([("npm", n, v) for ps in pkgs.values() for n, v in ps], "bundled npm packages against OSV")
    for label, d, fix in dirs:
        for n, v in pkgs[d]:
            c = Component("bundled", f"{label} › {n}", v, d, osv=("npm", n, v), fix=fix)
            scan.advisories(c, answers.get(c.osv, []), status="warn")
    roots = [d for _, d, _ in dirs] + [d for _, d in harnesses.skill_dirs()]
    files = [f for r in roots for f in repos.lockfiles(Path(r))]
    if files:
        res = _osv_source(scan, "lockfiles inside extensions, plugins and skills", "osv-scanner:bundles",
                          sorted({str(f.parent) for f in files}), files)
        if res:
            scan.scanned(res, "bundled", lambda p, safe: f"Update or remove what ships {short(p['source'])}",
                         label=lambda p: f"{short(str(Path(p['source']).parent))} › {p['name']}", status="warn",
                         what="packages in extension, plugin and skill lockfiles")


def sweep(scan, found, exts, refs):
    """Every package name we know against the local malicious-package index,
    which also covers what OSV couldn't be asked about (offline, unpinned)."""
    if scan.guard("malicious-package index (OpenSSF)", lambda: malicious.sync(scan.cache, scan.offline)) is None:
        return
    flagged = {(f.component, f.vuln_id) for f in scan.findings}
    items = [(c, c.osv[0], c.osv[1], c.osv[2]) for c in found + exts if c.osv]
    items += [(c, c.extra["eco"], c.extra["pkg"], c.extra["ver"]) for c in refs]
    for c, eco, name, ver in items:
        for rec in malicious.reports(scan.cache, eco, name, ver):
            if (c.name, rec["id"]) not in flagged:
                flagged.add((c.name, rec["id"]))
                scan.add(c, vuln_id=rec["id"], status="fail", kev=True, severity="MALICIOUS",
                         note=rec.get("summary") or f"known malicious package {name}", fix_cmd=REMOVE.format(name))


def _breach(scan):
    if not breach.consent(scan.cache, scan.ask):
        return
    for email, names in breach.check(scan.cache, scan.offline).items():
        shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        scan.add(kind="account", component=email, version="", location="breach data", vuln_id="BREACH", status="warn",
                 note=f"in {len(names)} breaches: {shown}", fix_cmd="Change any password reused from those sites; turn on 2FA")
