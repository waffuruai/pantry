"""Offline regression fixtures for the advisory boundaries checked on
2026-10-30 (tests/advisories/2026-10-30): the public OSV records as they
stood, replayed through the cache, against synthetic lockfiles that hold the
last affected and the first fixed version of each control. The binary must
report every affected control with the fix OSV names, and nothing for the
fixed ones. Standard library only, like test_contract.py:

    WPANTRY=rust/target/release/wpantry python3 -m unittest discover -s tests/contract
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("WPANTRY") or ROOT / "rust" / "target" / "release" / "wpantry")
if not BIN.is_absolute():
    BIN = (ROOT / BIN).resolve()
FIXTURES = ROOT / "tests" / "advisories" / "2026-10-30"

# (ecosystem, package as the cache keys it, affected version, fixed version, OSV record id).
# The package name is the PEP 503 normalized one for PyPI; the lockfiles spell
# some of them differently (Authlib, Twisted, langgraph_sdk) on purpose.
CONTROLS = [
    ("crates.io", "zip", "9.0.4", "9.0.5", "GHSA-m665-v7pm-7grj"),
    ("crates.io", "zip", "8.6.0", "9.0.0", "GHSA-hjqx-j4rw-g7xv"),
    ("crates.io", "wasmtime", "48.0.6", "48.0.7", "GHSA-mghf-wjfp-p5xm"),
    ("PyPI", "mlflow", "3.16.0", "3.17.0", "GHSA-26p8-2jq9-3vq9"),
    ("npm", "better-auth", "1.7.6", "1.7.7", "GHSA-965c-763c-88jm"),
    ("PyPI", "authlib", "1.8.0", "1.9.0", "GHSA-6v38-4h7w-rj9h"),
    ("npm", "@sylphx/pdf-reader-mcp", "3.0.0", "3.0.1", "GHSA-q344-5v34-gm84"),
    ("PyPI", "twisted", "26.4.0", "26.10.0rc1", "GHSA-vpp8-g58w-m8mp"),
    ("npm", "vite", "6.4.4", "6.4.5", "GHSA-8g5g-mxqh-grgj"),
    ("npm", "decode-uri-component", "0.5.0", "0.5.1", "GHSA-qr28-fpjm-wq7f"),
    ("PyPI", "langgraph-sdk", "0.4.5", "0.4.6", "GHSA-3fx2-cqw9-xr3c"),
]
# The KEV decoration control is synthetic (tests/advisories/2026-10-30/README.md):
# the CVE is in CISA's catalog, the crates.io range is invented.
KEV_CONTROL = ("crates.io", "brotli", "8.0.1", "8.0.2", "WPANTRY-TEST-KEV-1", "CVE-2026-111497")


def records() -> dict:
    out = {}
    for f in sorted((FIXTURES / "osv").glob("*.json")):
        rec = json.loads(f.read_text())
        out[rec["id"]] = rec
    return out


def applies(rec: dict, eco: str, name: str, version: str) -> bool:
    """Whether the record's own ranges put this version inside an affected
    interval, by the same reading a person would do on the record. Only
    used to seed what OSV would have answered; the binary does its own
    comparison when it picks the fix."""
    from itertools import zip_longest

    def key(v: str):
        parts = []
        for p in v.replace("-", ".").split("."):
            num = ""
            while num != p and p[: len(num) + 1].isdigit():
                num = p[: len(num) + 1]
            parts.append((int(num) if num else -1, p[len(num):]))
        return parts

    def lt(a: str, b: str) -> bool:
        for x, y in zip_longest(key(a), key(b), fillvalue=(0, "")):
            if x != y:
                if x[0] != y[0]:
                    return x[0] < y[0]
                # a tag ("rc1") sorts before the bare release
                return (x[1] != "" and y[1] == "") or (x[1] != "" and y[1] != "" and x[1] < y[1])
        return False

    for a in rec.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") != eco or p.get("name") != name:
            continue
        for r in a.get("ranges", []):
            introduced, inside = None, False
            for e in r.get("events", []):
                if "introduced" in e:
                    introduced = e["introduced"]
                    inside = introduced == "0" or not lt(version, introduced)
                elif "fixed" in e and inside and not lt(version, e["fixed"]):
                    inside = False
            if inside:
                return True
    return False


class Advisories(unittest.TestCase):
    """A temp HOME and cache per test, the fixtures copied in as two checkouts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name, "home")
        self.home.mkdir()
        self.db = Path(self.tmp.name, "cache", "w.db")
        self.env = dict(os.environ, HOME=str(self.home), WPANTRY_DB=str(self.db), NO_COLOR="1")
        self.env.pop("XDG_CACHE_HOME", None)
        self.root = self.home / "advisories"
        for repo in ("affected", "fixed"):
            shutil.copytree(FIXTURES / repo, self.root / repo)
            (self.root / repo / ".git").mkdir()
        self.records = records()

    def run_bin(self, *argv, timeout=300):
        p = subprocess.run([str(BIN), *argv], capture_output=True, text=True, env=self.env,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def check(self, *paths):
        code, out, err = self.run_bin("--no-machine", "--offline", "--no-input", "--json",
                                      *[a for p in paths for a in ("--path", str(p))])
        self.assertIn(code, (0, 1), err)
        return code, json.loads(out)

    def seed(self):
        """What OSV answered on 2026-10-31 for each control, replayed into the
        cache: the records, one `queries` row per (ecosystem, package, version)
        and CISA's KEV entry."""
        self.run_bin("--no-machine", "--offline", "--no-input", "--json", "--path", str(self.tmp.name))  # creates the schema
        conn = sqlite3.connect(str(self.db))
        for rec in self.records.values():
            aliases = " ".join(rec.get("aliases", []))
            severity = rec.get("database_specific", {}).get("severity", "") or ""
            conn.execute("INSERT OR REPLACE INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (rec["id"], aliases, rec.get("summary", ""), rec.get("details", ""), severity,
                          rec.get("published", ""), rec.get("modified", ""),
                          f"https://osv.dev/vulnerability/{rec['id']}", json.dumps(rec)))
        now = time.time()
        controls = CONTROLS + [KEV_CONTROL[:5]]
        for eco, name, affected, fixed, _ in controls:
            for version in (affected, fixed):
                ids = sorted(i for i, r in self.records.items() if applies(r, eco, name, version))
                conn.execute("INSERT OR REPLACE INTO queries VALUES (?, ?, ?, ?, ?)",
                             (eco, name, version, now, " ".join(ids)))
        kev = json.loads((FIXTURES / "kev.json").read_text())
        for v in kev["vulnerabilities"]:
            conn.execute("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)",
                         (v["cveID"], v["dateAdded"], v["vulnerabilityName"]))
        conn.commit()
        conn.close()

    @staticmethod
    def ids_of(rec: dict) -> set:
        return {rec["id"], *rec.get("aliases", [])}

    def findings_for(self, env: dict, name: str, version: str, rec_id: str) -> list:
        ids = self.ids_of(self.records[rec_id])
        return [f for f in env["findings"]
                if f["kind"] == "project" and f["component"] == name and f["version"] == version
                and f["vuln_id"] in ids]

    # the controls -------------------------------------------------------------

    def test_seeded_answers_match_the_records_own_ranges(self):
        """The seeding reads the ranges the way the issue's table does."""
        for eco, name, affected, fixed, rec_id in CONTROLS:
            rec = self.records[rec_id]
            self.assertTrue(applies(rec, eco, name, affected), (rec_id, affected))
            self.assertFalse(applies(rec, eco, name, fixed), (rec_id, fixed))
        # zip 9.0.0 fixes one family and is still in the other's range
        self.assertTrue(applies(self.records["GHSA-m665-v7pm-7grj"], "crates.io", "zip", "9.0.0"))
        self.assertFalse(applies(self.records["GHSA-hjqx-j4rw-g7xv"], "crates.io", "zip", "9.0.0"))
        # wasmtime's branches: 48.0.7 is out, 49.0.0 is back in
        self.assertFalse(applies(self.records["GHSA-mghf-wjfp-p5xm"], "crates.io", "wasmtime", "48.0.7"))
        self.assertTrue(applies(self.records["GHSA-mghf-wjfp-p5xm"], "crates.io", "wasmtime", "49.0.0"))

    def test_affected_controls_fail_with_the_fix_osv_names(self):
        self.seed()
        code, env = self.check(self.root / "affected")
        self.assertEqual(env["checked"]["project dependencies"], 12, env["checked"])
        self.assertEqual(env["checked"]["git repos"], 1)
        for eco, name, affected, fixed, rec_id in CONTROLS:
            got = self.findings_for(env, name, affected, rec_id)
            self.assertEqual(len(got), 1, (rec_id, name, affected, [f["vuln_id"] for f in env["findings"]]))
            f = got[0]
            self.assertEqual((f["status"], f["fixed"]), ("fail", fixed), f)
            self.assertIn(fixed, f["fix_cmd"], f["fix_cmd"])  # the fix command names the safe version
            if self.records[rec_id].get("aliases"):
                self.assertTrue(f["vuln_id"].startswith("CVE-"), f)  # the CVE alias is the id shown
            else:
                self.assertEqual(f["vuln_id"], rec_id, f)  # Twisted's record has no alias
        # Branch-specific fixes: the fix for wasmtime 48.0.6 is on its own line.
        wasmtime = self.findings_for(env, "wasmtime", "48.0.6", "GHSA-mghf-wjfp-p5xm")[0]
        self.assertEqual(wasmtime["fixed"], "48.0.7")
        # A prerelease is a released fix when it is the only one.
        twisted = self.findings_for(env, "twisted", "26.4.0", "GHSA-vpp8-g58w-m8mp")[0]
        self.assertEqual(twisted["fixed"], "26.10.0rc1")
        # zip 8.6.0 is in both families, each with its own fix.
        both = sorted(f["fixed"] for f in env["findings"]
                      if f["component"] == "zip" and f["version"] == "8.6.0" and f["kind"] == "project")
        self.assertEqual(both, ["9.0.0", "9.0.5"])
        # Every cached answer was used: nothing about these dependencies is unchecked.
        self.assertEqual([f for f in env["findings"]
                          if f["kind"] == "unchecked" and f["component"].startswith("repo dependencies")], [])
        # Exit 1 for the fails above (a missing gitleaks on the runner is a `tool` fail, not ours).
        fails = [f for f in env["findings"] if f["status"] == "fail"]
        self.assertTrue(fails)
        self.assertEqual(code, 1)

    def test_fixed_controls_are_not_reported_and_zip_9_0_0_still_is(self):
        self.seed()
        code, env = self.check(self.root / "fixed")
        self.assertEqual(env["checked"]["project dependencies"], 12, env["checked"])
        for eco, name, affected, fixed, rec_id in CONTROLS:
            if (name, fixed) == ("zip", "9.0.0"):
                continue
            self.assertEqual(self.findings_for(env, name, fixed, rec_id), [], (rec_id, name, fixed))
        # zip 9.0.0 fixes GHSA-hjqx-j4rw-g7xv and is still affected by GHSA-m665-v7pm-7grj:
        # a negative control for one family is not a clean verdict on the version.
        self.assertEqual(self.findings_for(env, "zip", "9.0.0", "GHSA-hjqx-j4rw-g7xv"), [])
        still = self.findings_for(env, "zip", "9.0.0", "GHSA-m665-v7pm-7grj")
        self.assertEqual([(f["status"], f["fixed"]) for f in still], [("fail", "9.0.5")])
        project_fails = [f for f in env["findings"] if f["status"] == "fail" and f["kind"] == "project"]
        self.assertEqual(len(project_fails), 1, project_fails)
        self.assertEqual([f for f in env["findings"]
                          if f["kind"] == "unchecked" and f["component"].startswith("repo dependencies")], [])

    def test_a_record_is_found_under_its_alias_too(self):
        """A cached answer may name the CVE (another database's row) rather
        than the GHSA: the finding must still appear, under the record stored."""
        self.seed()
        conn = sqlite3.connect(str(self.db))
        # Re-store vite's record under its CVE id, with the GHSA as the alias,
        # and point the answer at that id: a CVE-form row can't evade a check.
        rec = dict(self.records["GHSA-8g5g-mxqh-grgj"])
        rec["id"], rec["aliases"] = "CVE-2026-118662", ["GHSA-8g5g-mxqh-grgj"]
        conn.execute("DELETE FROM vulns WHERE id = ?", ("GHSA-8g5g-mxqh-grgj",))
        conn.execute("INSERT OR REPLACE INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (rec["id"], " ".join(rec["aliases"]), rec.get("summary", ""), rec.get("details", ""),
                      rec.get("database_specific", {}).get("severity", ""), rec.get("published", ""),
                      rec.get("modified", ""), f"https://osv.dev/vulnerability/{rec['id']}", json.dumps(rec)))
        conn.execute("UPDATE queries SET vuln_ids = ? WHERE ecosystem = 'npm' AND package = 'vite' AND version = '6.4.4'",
                     ("CVE-2026-118662",))
        conn.commit()
        conn.close()
        _, env = self.check(self.root / "affected")
        vite = [f for f in env["findings"] if f["component"] == "vite" and f["version"] == "6.4.4"]
        self.assertEqual([(f["vuln_id"], f["fixed"], f["status"]) for f in vite], [("CVE-2026-118662", "6.4.5", "fail")])

    def test_pypi_names_are_normalized_to_the_cache_keys(self):
        """requirements.txt spells Authlib, Twisted and langgraph_sdk; the cache
        holds PEP 503 keys. The findings carry the normalized names and the
        export shows every alias."""
        self.seed()
        _, env = self.check(self.root / "affected")
        pypi = sorted({f["component"] for f in env["findings"] if f["kind"] == "project"
                       and f["location"].endswith("requirements.txt")})
        self.assertEqual(pypi, ["authlib", "langgraph-sdk", "mlflow", "twisted"])
        conn = sqlite3.connect(str(self.db))
        keys = [r[0] for r in conn.execute("SELECT package FROM queries WHERE ecosystem = 'PyPI'")]
        conn.close()
        self.assertTrue(keys)
        for k in keys:
            self.assertEqual(k, k.lower().replace("_", "-").replace(".", "-"), k)
        out = Path(self.tmp.name, "f.csv")
        code, _, _ = self.run_bin("export", "--csv", str(out))
        self.assertEqual(code, 0)
        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
        for eco, name, affected, fixed, rec_id in CONTROLS:
            # One row per (id, component, version); zip 8.6.0 has two.
            exported = [{r["id"], *r["aliases"].split()} for r in rows
                        if r["component"] == name and r["affected_version"] == affected and r["safe_version"] == fixed]
            self.assertEqual(len(exported), 1, (name, affected, fixed, exported))
            self.assertTrue(exported[0] & self.ids_of(self.records[rec_id]), (name, exported))

    def test_kev_decoration_from_the_offline_catalog(self):
        """A finding whose record carries a KEV CVE is marked `kev` from the
        cached catalog; the range is synthetic (see the fixture README)."""
        self.seed()
        eco, name, affected, fixed, rec_id, cve = KEV_CONTROL
        _, env = self.check(self.root / "affected")
        got = [f for f in env["findings"] if f["component"] == name and f["version"] == affected]
        self.assertEqual([(f["vuln_id"], f["kev"], f["fixed"], f["status"]) for f in got],
                         [(cve, True, fixed, "fail")])
        # The real controls are not in KEV.
        for _, n, a, _, r in CONTROLS:
            for f in self.findings_for(env, n, a, r):
                self.assertFalse(f["kev"], f)
        _, env = self.check(self.root / "fixed")
        self.assertEqual([f for f in env["findings"] if f["component"] == name], [])


if __name__ == "__main__":
    unittest.main()
