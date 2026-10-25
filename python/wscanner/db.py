"""The local cache: one SQLite file per machine.

It holds OSV records for what this machine has (never a mirror of OSV), the
answers to "which advisories affect package P at version V" with when we last
asked, the latest scan's findings, and the small side feeds (KEV, end-of-life
dates, the cask catalog). A full-text index over the records lets agents
search and rank them (`secure.py search`)."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .net import Offline

DAY = 86400

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY, aliases TEXT, summary TEXT, details TEXT,
  severity TEXT, published TEXT, modified TEXT, url TEXT, record TEXT);
CREATE TABLE IF NOT EXISTS queries (
  ecosystem TEXT, package TEXT, version TEXT, checked_at REAL, vuln_ids TEXT,
  PRIMARY KEY (ecosystem, package, version));
CREATE TABLE IF NOT EXISTS findings (
  kind TEXT, component TEXT, version TEXT, location TEXT, vuln_id TEXT,
  status TEXT, fixed TEXT, kev INTEGER, severity TEXT, note TEXT, fix_cmd TEXT,
  fix_auto INTEGER);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, added TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS eol (
  product TEXT, cycle TEXT, eol TEXT, latest TEXT, PRIMARY KEY (product, cycle));
CREATE TABLE IF NOT EXISTS casks (app TEXT PRIMARY KEY, token TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS runs (
  source TEXT PRIMARY KEY, fingerprint TEXT, ran_at REAL, result TEXT);
CREATE TABLE IF NOT EXISTS malicious (ecosystem TEXT, name TEXT, id TEXT);
CREATE INDEX IF NOT EXISTS malicious_name ON malicious (ecosystem, name);
"""


def path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(os.environ.get("WAFFURU_SECURITY_DB") or Path(base) / "waffuru" / "security.db")


class Cache:
    def __init__(self, file: Path | None = None):
        file = file or path()
        file.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(file))
        self.conn.executescript(SCHEMA)
        try:
            self.conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS vulns_fts USING fts5("
                "id, aliases, summary, details, packages, tokenize='porter')")
            self.fts = True
        except sqlite3.OperationalError:  # SQLite built without FTS5
            self.fts = False

    def close(self):
        self.conn.commit()
        self.conn.close()

    # meta ------------------------------------------------------------------
    def get(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key: str, value: str):
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    def fresh(self, key: str, max_age: float) -> bool:
        stamp = self.get(key)
        return stamp is not None and time.time() - float(stamp) < max_age

    def touch(self, key: str):
        self.set(key, str(time.time()))

    # OSV records -----------------------------------------------------------
    def modified(self, vuln_id: str):
        row = self.conn.execute("SELECT modified FROM vulns WHERE id = ?", (vuln_id,)).fetchone()
        return row[0] if row else None

    def put_vuln(self, rec: dict):
        vid = rec["id"]
        aliases = rec.get("aliases") or []
        packages = sorted({(a.get("package") or {}).get("name", "") for a in rec.get("affected", [])})
        self.conn.execute(
            "INSERT OR REPLACE INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (vid, " ".join(aliases), rec.get("summary", ""), rec.get("details", ""),
             severity_of(rec), rec.get("published", ""), rec.get("modified", ""),
             f"https://osv.dev/vulnerability/{vid}", json.dumps(rec)))
        if self.fts:
            self.conn.execute("DELETE FROM vulns_fts WHERE id = ?", (vid,))
            self.conn.execute(
                "INSERT INTO vulns_fts VALUES (?, ?, ?, ?, ?)",
                (vid, " ".join(aliases), rec.get("summary", ""), rec.get("details", ""), " ".join(packages)))

    def vuln(self, vuln_id: str):
        row = self.conn.execute("SELECT record FROM vulns WHERE id = ?", (vuln_id,)).fetchone()
        return json.loads(row[0]) if row else None

    # package queries -------------------------------------------------------
    def query(self, eco: str, pkg: str, ver: str):
        return self.conn.execute(
            "SELECT checked_at, vuln_ids FROM queries WHERE ecosystem=? AND package=? AND version=?",
            (eco, pkg, ver)).fetchone()

    def put_query(self, eco: str, pkg: str, ver: str, ids):
        self.conn.execute("INSERT OR REPLACE INTO queries VALUES (?, ?, ?, ?, ?)",
                          (eco, pkg, ver, time.time(), " ".join(ids)))

    # external tool runs (osv-scanner, brew vulns) --------------------------
    def run(self, source: str):
        row = self.conn.execute("SELECT fingerprint, ran_at, result FROM runs WHERE source=?",
                                (source,)).fetchone()
        return (row[0], row[1], json.loads(row[2])) if row else None

    def put_run(self, source: str, fingerprint: str, result):
        self.conn.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)",
                          (source, fingerprint, time.time(), json.dumps(result)))

    def memo(self, key: str, compute, max_age=DAY, fingerprint="", refresh=False, offline=False):
        """compute()'s result, cached under key. Reused while fresh (and the
        fingerprint of what it read still matches); reused stale when offline
        or when compute fails; otherwise net.Offline, so the caller reports
        the source unchecked rather than clean. Failures are never cached."""
        run = self.run(key)
        if run and not refresh and (offline or (run[0] == fingerprint and run[1] > time.time() - max_age)):
            return run[2]
        if offline:
            raise Offline(f"{key}: offline and not cached")
        try:
            result = compute()
        except (Offline, ValueError) as e:
            if run:
                return run[2]
            raise Offline(f"{key}: {e}") from e
        self.put_run(key, fingerprint, result)
        self.conn.commit()
        return result

    # findings --------------------------------------------------------------
    def replace_findings(self, findings):
        self.conn.execute("DELETE FROM findings")
        self.conn.executemany(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(f.kind, f.component, f.version, f.location, f.vuln_id, f.status, f.fixed,
              int(f.kev), f.severity, f.note, f.fix_cmd, int(f.fix_auto)) for f in findings])

    def kev_ids(self) -> set:
        return {r[0] for r in self.conn.execute("SELECT cve FROM kev")}


def severity_of(rec: dict) -> str:
    """A label (CRITICAL/HIGH/MODERATE/LOW) when the record carries one, else
    the CVSS score string osv-scanner computed, else empty."""
    ds = rec.get("database_specific") or {}
    label = ds.get("severity")
    if isinstance(label, str) and label:
        return label.upper()
    for a in rec.get("affected", []):
        label = (a.get("ecosystem_specific") or {}).get("severity")
        if isinstance(label, str) and label:
            return label.upper()
    return ""
