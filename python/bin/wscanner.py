#!/usr/bin/env python3
"""wscanner: the vulnerabilities that apply to this computer. See README.md;
the CLI contract is specs/cli-contract.md.

  wscanner [check] [--path DIR]... [--no-machine] [--update] [--dryrun] [--refresh] [--offline]
                   [--json] [--no-input] [--gitleaks-config F] [--licenses F] [--install-scripts F]
  wscanner search QUERY [--applicable] [--limit N] [--json]
  wscanner export --csv FILE
  wscanner breach [--enable | --disable]
  wscanner version [--json]
  wscanner tools [--json]
  wscanner skill

Exit codes: 0 clean (warnings and unchecked sources included), 1 a failing
finding or a failed unattended fix, 2 usage error, 3 internal error.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import traceback
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # ahead of bin/, so `wscanner` is the package, not this script

from wscanner import IMPL, SCHEMA, __version__  # noqa: E402
from wscanner import check as checks  # noqa: E402
from wscanner import external, report  # noqa: E402
from wscanner.db import Cache  # noqa: E402

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_INTERNAL, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
SKILL = ROOT / "skill" / "wscanner" / "SKILL.md"
SUBCOMMANDS = ("check", "search", "export", "breach", "version", "tools", "skill")


def envelope(scan, findings) -> dict:
    """`check --json`: the findings plus what was checked (schema 1)."""
    return {"schema": SCHEMA, "impl": IMPL, "version": __version__, "checked": dict(scan.counts),
            "unfixed": scan.unfixed, "unknown_licenses": scan.unknown_licenses,
            "findings": [asdict(f) for f in findings]}


def cmd_check(a) -> int:
    log = (lambda *_: None) if a.json else print
    given = (("gitleaks_config", a.gitleaks_config), ("licenses", a.licenses), ("install_scripts", a.install_scripts))
    policy = checks.Policy(**{k: v for k, v in given if v})

    def scan(**kw):
        return checks.Scan(a.path, machine=not a.no_machine, policy=policy, offline=a.offline, **kw)

    first = scan(refresh=a.refresh, ask=not (a.json or a.dryrun or a.no_input), log=log)
    findings = first.run()
    if a.json:
        print(json.dumps(envelope(first, findings), indent=1))
        return EXIT_FAIL if any(f.status == "fail" for f in findings) else EXIT_OK
    status = report.report(first, findings)
    if not (a.update or a.dryrun):
        return status
    applied = report.apply(findings, dryrun=a.dryrun)
    if a.dryrun:
        return status
    print("\nRe-checking after the updates…")
    again = scan(ask=False)
    # A fix that failed fails the run even when the re-check comes back clean.
    return report.report(again, again.run()) or applied


def cmd_search(a) -> int:
    cache = Cache()
    applicable = {r[0] for r in cache.conn.execute("SELECT vuln_id FROM findings")}
    kev = cache.kev_ids()
    if cache.fts:
        rows = cache.conn.execute(
            "SELECT v.id, v.aliases, v.summary, v.severity, v.url, bm25(vulns_fts) "
            "FROM vulns_fts JOIN vulns v ON v.id = vulns_fts.id WHERE vulns_fts MATCH ? "
            "ORDER BY bm25(vulns_fts) LIMIT 500", (a.query,)).fetchall()
    else:
        like = f"%{a.query}%"
        rows = cache.conn.execute(
            "SELECT id, aliases, summary, severity, url, 0 FROM vulns "
            "WHERE id LIKE ? OR aliases LIKE ? OR summary LIKE ? OR details LIKE ? LIMIT 500",
            (like, like, like, like)).fetchall()
    out = []
    for vid, aliases, summary, severity, url, score in rows:
        ids = {vid, *aliases.split()}
        hit = bool(ids & applicable)
        if a.applicable and not hit:
            continue
        exploited = bool(ids & kev)
        # Lower is better: bm25 relevance, then what applies here, then KEV.
        rank = score - (5 if hit else 0) - (10 if exploited else 0)
        out.append({"id": vid, "aliases": aliases.split(), "summary": summary, "severity": severity,
                    "applicable": hit, "kev": exploited, "url": url, "rank": round(rank, 3)})
    out.sort(key=lambda r: r["rank"])
    out = out[:a.limit]
    if a.json:
        print(json.dumps(out, indent=1))
    else:
        for r in out:
            flags = " ".join(f for f in ("APPLIES" if r["applicable"] else "", "KEV" if r["kev"] else "",
                                         r["severity"]) if f)
            print(f"{r['id']:<22} {flags:<22} {r['summary'][:80]}")
    return EXIT_OK


def cmd_export(a) -> int:
    cache = Cache()
    rows = cache.conn.execute(
        "SELECT f.vuln_id, v.aliases, v.url, f.component, f.kind, f.version, f.fixed, f.severity, "
        "f.kev, f.status, f.location FROM findings f LEFT JOIN vulns v "
        "ON v.id = f.vuln_id OR (' ' || v.aliases || ' ') LIKE ('% ' || f.vuln_id || ' %') "
        "GROUP BY f.vuln_id, f.component, f.version, f.location").fetchall()
    with open(a.csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "aliases", "url", "component", "kind", "affected_version", "safe_version",
                    "severity", "kev", "status", "location"])
        for r in rows:
            r = list(r)
            r[2] = r[2] or (f"https://www.cve.org/CVERecord?id={r[0]}" if r[0].startswith("CVE-") else "")
            w.writerow(r)
    print(f"✓ wrote {len(rows)} findings to {a.csv}")
    return EXIT_OK


def cmd_breach(a) -> int:
    cache = Cache()
    if a.enable or a.disable:
        cache.set("breach_consent", "yes" if a.enable else "no")
        cache.close()
        print("✓ breach check " + ("enabled" if a.enable else "disabled"))
        return EXIT_OK
    print(f"breach check: {cache.get('breach_consent') or 'not decided (asked on the next interactive check)'}")
    return EXIT_OK


def cmd_version(a) -> int:
    if a.json:
        print(json.dumps({"version": __version__, "impl": IMPL, "schema": SCHEMA}))
    else:
        print(f"wscanner {__version__} ({IMPL}, schema {SCHEMA})")
    return EXIT_OK


def cmd_tools(a) -> int:
    """The external tools and whether they're here; fails when a required
    one is missing, as the scan would."""
    found = external.tools()
    if a.json:
        print(json.dumps({"schema": SCHEMA, "impl": IMPL, "version": __version__, "tools": found}, indent=1))
    else:
        for t in found:
            mark = "✓" if t["found"] else ("✗" if t["required"] else "·")
            kind = "required" if t["required"] else "optional"
            print(f"  {mark} {t['name']:<12} {t['version'] or '-':<10} {kind:<9} {t['purpose']}")
    return EXIT_FAIL if any(t["required"] and not t["found"] for t in found) else EXIT_OK


def cmd_skill(_a) -> int:
    sys.stdout.write(SKILL.read_text())
    return EXIT_OK


def existing_file(value: str) -> Path:
    p = Path(value).expanduser()
    if not p.is_file():
        raise argparse.ArgumentTypeError(f"no such file: {value}")
    return p


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wscanner", description=__doc__.split("\n")[0],
                                epilog="Exit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error.")
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="scan this computer (default)")
    c.add_argument("--path", action="append", type=Path, metavar="DIR",
                   help="check only the repos at or under DIR (repeatable; default: every git repo under ~)")
    c.add_argument("--no-machine", action="store_true", help="skip the machine inventory: repo checks only")
    for flag, text in (("--update", "apply the fixes that can run unattended, then re-check"),
                       ("--dryrun", "print the update plan without changing anything"),
                       ("--refresh", "ignore cached answers and ask every source again"),
                       ("--offline", "use only the local cache"),
                       ("--json", "print the findings as JSON (schema 1)"),
                       ("--no-input", "never prompt")):
        c.add_argument(flag, action="store_true", help=text)
    for flag, name in (("--gitleaks-config", "gitleaks.toml"), ("--licenses", "licenses.txt"),
                       ("--install-scripts", "install-scripts.txt")):
        c.add_argument(flag, type=existing_file, metavar="FILE", help=f"policy file (default: bundled {name})")
    s = sub.add_parser("search", help="search cached advisories (for agents)")
    s.add_argument("query")
    s.add_argument("--applicable", action="store_true", help="only advisories that apply here")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("export", help="write the findings as CSV")
    e.add_argument("--csv", required=True)
    b = sub.add_parser("breach", help="show or set consent for the email breach check")
    g = b.add_mutually_exclusive_group()
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    v = sub.add_parser("version", help="print the version, implementation and JSON schema")
    v.add_argument("--json", action="store_true")
    t = sub.add_parser("tools", help="list the external tools this implementation uses")
    t.add_argument("--json", action="store_true")
    sub.add_parser("skill", help="print the agent skill (SKILL.md)")
    return p


COMMANDS = {"check": cmd_check, "search": cmd_search, "export": cmd_export, "breach": cmd_breach,
            "version": cmd_version, "tools": cmd_tools, "skill": cmd_skill}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help")):
        argv = ["check", *argv]  # `check` is the default subcommand
    try:
        args = parser().parse_args(argv)
    except SystemExit as e:  # --help (0) or a usage error (2)
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    try:
        return COMMANDS[args.cmd](args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except (sqlite3.Error, OSError) as e:  # the cache can't be opened or written, a file we need is gone
        print(f"✗ wscanner: {e}", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception:  # noqa: BLE001  (a crash is an internal error, never "clean" or "fail")
        traceback.print_exc()
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
