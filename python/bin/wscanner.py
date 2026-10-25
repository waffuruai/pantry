#!/usr/bin/env python3
"""Waffuru security scan. See security/README.md.

  secure.py [check] [--update] [--dryrun] [--refresh] [--offline] [--json]
  secure.py search QUERY [--applicable] [--limit N] [--json]
  secure.py export --csv FILE
  secure.py breach [--enable | --disable]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wscanner import check as checks  # noqa: E402
from wscanner import report  # noqa: E402
from wscanner.db import Cache  # noqa: E402

OPS = Path(__file__).resolve().parent.parent


def cmd_check(a) -> int:
    log = (lambda *_: None) if a.json else print
    scan = checks.Scan(OPS, refresh=a.refresh, offline=a.offline, ask=not (a.json or a.dryrun), log=log)
    findings = scan.run()
    if a.json:
        print(json.dumps([asdict(f) for f in findings], indent=1))
        return 1 if any(f.status == "fail" for f in findings) else 0
    status = report.report(scan, findings)
    if a.update or a.dryrun:
        status = report.apply(findings, dryrun=a.dryrun) or (0 if not a.dryrun else status)
        if a.update and not a.dryrun:
            print("\nRe-checking after the updates…")
            scan = checks.Scan(OPS, offline=a.offline, ask=False)
            status = report.report(scan, scan.run())
    return status


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
    return 0


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
    return 0


def cmd_breach(a) -> int:
    cache = Cache()
    if a.enable or a.disable:
        cache.set("breach_consent", "yes" if a.enable else "no")
        cache.close()
        print("✓ breach check " + ("enabled" if a.enable else "disabled"))
        return 0
    print(f"breach check: {cache.get('breach_consent') or 'not decided (asked on the next make secure)'}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secure.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="scan this machine and our repos (default)")
    for flag, text in (("--update", "apply the fixes that can run unattended, then re-check"),
                       ("--dryrun", "print the update plan without changing anything"),
                       ("--refresh", "ignore cached answers and ask every source again"),
                       ("--offline", "use only the local cache"),
                       ("--json", "print findings as JSON")):
        c.add_argument(flag, action="store_true", help=text)
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

    args = p.parse_args(argv)
    if args.cmd in (None, "check"):
        if args.cmd is None:
            args = c.parse_args(argv or [])
        return cmd_check(args)
    return {"search": cmd_search, "export": cmd_export, "breach": cmd_breach}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
