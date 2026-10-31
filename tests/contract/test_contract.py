"""The CLI contract (specs/cli-contract.md), tested from the outside: run the
binary named by WPANTRY with a temp HOME and cache, offline, and check only
its stdout, stderr, exit codes and cache file. Every implementation must pass
(specs/01-rust-port.md F2). Standard library only, Python 3.9+:

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
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("WPANTRY") or ROOT / "rust" / "target" / "release" / "wpantry")
if not BIN.is_absolute():
    BIN = (ROOT / BIN).resolve()
# The name the binary goes by, which its skill and errors carry.
NAME = BIN.name

ENVELOPE = {"schema", "impl", "version", "checked", "unfixed", "unknown_licenses", "findings"}
FINDING = {"kind": str, "component": str, "version": str, "location": str, "vuln_id": str, "status": str,
           "fixed": str, "kev": bool, "severity": str, "note": str, "fix_cmd": str, "fix_auto": bool,
           "dep_scope": str, "dep_direct": (bool, type(None)), "affected_range": str}
SCOPES = {"runtime", "dev", "optional", "unknown"}
TOOL = {"name": str, "required": bool, "found": bool, "path": str, "version": str, "purpose": str}
CACHE = {
    "meta": ["key", "value"],
    "vulns": ["id", "aliases", "summary", "details", "severity", "published", "modified", "url", "record"],
    "queries": ["ecosystem", "package", "version", "checked_at", "vuln_ids"],
    "findings": ["kind", "component", "version", "location", "vuln_id", "status", "fixed", "kev", "severity", "note",
                 "fix_cmd", "fix_auto", "dep_scope", "dep_direct", "affected_range"],
    "kev": ["cve", "added", "name"],
    "eol": ["product", "cycle", "eol", "latest"],
    "casks": ["app", "token", "version"],
    "runs": ["source", "fingerprint", "ran_at", "result"],
    "malicious": ["ecosystem", "name", "id"],
}


def git_repo(path: Path, worktree=False) -> Path:
    """A directory that looks like a checkout (a .git dir, or a worktree's .git file)."""
    path.mkdir(parents=True, exist_ok=True)
    if worktree:
        (path / ".git").write_text("gitdir: /elsewhere\n")
    else:
        (path / ".git").mkdir()
    return path


class Contract(unittest.TestCase):
    """A temp HOME and cache per test; nothing reads the real home directory
    or writes its cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name, "home")
        self.home.mkdir()
        self.db = Path(self.tmp.name, "cache", "w.db")
        self.env = dict(os.environ, HOME=str(self.home), WPANTRY_DB=str(self.db), NO_COLOR="1")
        self.env.pop("XDG_CACHE_HOME", None)

    def run_bin(self, *argv, env=None, timeout=300):
        """(exit code, stdout, stderr)."""
        p = subprocess.run([str(BIN), *argv], capture_output=True, text=True, env=env or self.env,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def project_run(self, *extra):
        return self.run_bin("--no-machine", "--path", str(self.home), "--offline", "--no-input", *extra)

    def envelope(self, out: str) -> dict:
        env = json.loads(out)
        self.assertEqual(set(env), ENVELOPE)
        self.assertEqual(env["schema"], 1)
        for f in env["findings"]:
            self.assertEqual(set(f), set(FINDING), f)
            for k, want in FINDING.items():
                self.assertIsInstance(f[k], want, (k, f))
            self.assertIn(f["status"], ("fail", "warn"))
            self.assertIn(f["dep_scope"], SCOPES, f)
        return env

    # version, tools, skill -------------------------------------------------

    def test_version(self):
        code, out, _ = self.run_bin("version", "--json")
        self.assertEqual(code, 0)
        v = json.loads(out)
        self.assertEqual(set(v), {"version", "impl", "schema"})
        self.assertEqual(v["schema"], 1)
        self.assertIn(v["impl"], ("python", "rust"))
        code, out, _ = self.run_bin("version")
        self.assertEqual(code, 0)
        self.assertIn(v["version"], out)

    def test_tools(self):
        code, out, _ = self.run_bin("tools", "--json")
        got = json.loads(out)
        self.assertEqual(set(got), {"schema", "impl", "version", "tools"})
        self.assertTrue(got["tools"])
        for t in got["tools"]:
            self.assertEqual({k: type(v) for k, v in t.items()}, TOOL)
            self.assertEqual(t["found"], bool(t["path"]))
        missing = any(t["required"] and not t["found"] for t in got["tools"])
        self.assertEqual(code, 1 if missing else 0)
        self.assertEqual(self.run_bin("tools")[0], code)

    def test_skill(self):
        code, out, _ = self.run_bin("skill")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(f"---\nname: {NAME}\n"))

    # exit codes ------------------------------------------------------------

    def test_exit_2_on_usage_errors(self):
        for argv in (["--bogus"], ["check", "--licenses", str(self.home / "nope.txt")], ["search"], ["export"],
                     ["breach", "--enable", "--disable"], ["search", "x", "--limit", "many"], ["version", "extra"]):
            code, _, err = self.run_bin(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("usage:", err, argv)
        self.assertEqual(self.run_bin("--help")[0], 0)
        self.assertEqual(self.run_bin("check", "--help")[0], 0)

    def test_exit_3_when_the_cache_cant_be_opened(self):
        env = dict(self.env, WPANTRY_DB="/dev/null/w.db")
        code, _, err = self.run_bin("search", "x", env=env)
        self.assertEqual(code, 3)
        self.assertIn(f"{NAME}:", err)
        self.assertEqual(self.run_bin("--no-machine", "--path", str(self.home), "--offline", "--json", env=env)[0], 3)

    def test_exit_0_when_only_warnings_and_unchecked(self):
        code, out, _ = self.project_run()
        self.assertEqual(code, 0, out)
        self.assertIn("not checked", out)
        self.assertIn("Incomplete", out)

    # check --json ----------------------------------------------------------

    def test_json_envelope(self):
        git_repo(self.home / "app")
        code, out, _ = self.project_run("--json")
        self.assertIn(code, (0, 1))
        env = self.envelope(out)
        version = json.loads(self.run_bin("version", "--json")[1])
        self.assertEqual((env["impl"], env["version"]), (version["impl"], version["version"]))
        self.assertEqual(env["checked"]["git repos"], 1)
        self.assertTrue(all(isinstance(n, int) for n in env["checked"].values()))
        self.assertTrue(env["findings"])  # offline: the unreachable sources are reported, never clean
        unchecked = [f for f in env["findings"] if f["kind"] == "unchecked"]
        self.assertTrue(unchecked)
        for f in unchecked:
            self.assertEqual((f["status"], f["vuln_id"]), ("warn", "UNCHECKED"))
        self.assertEqual(code, 1 if any(f["status"] == "fail" for f in env["findings"]) else 0)

    def test_no_machine_runs_only_repo_checks(self):
        (self.home / ".cursor").mkdir()
        (self.home / ".cursor/mcp.json").write_text('{"mcpServers": {"x": {"command": "npx", "args": ["x-mcp"]}}}')
        git_repo(self.home / "app")
        (self.home / "app/.mcp.json").write_text('{"mcpServers": {"y": {"command": "npx", "args": ["y-mcp"]}}}')
        _, out, _ = self.project_run("--json")
        unpinned = [f["component"] for f in self.envelope(out)["findings"] if f["vuln_id"] == "UNPINNED"]
        self.assertEqual(unpinned, ["y-mcp (project: y)"])  # the repo's server, not the harness config's

    def test_report_keeps_scan_history(self):
        self.project_run()
        self.project_run()
        code, out, err = self.run_bin("report", "--format", "json", "--since", "7")
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(set(data), {"schema", "version", "since_days", "exposures", "fixes", "scans", "events"})
        self.assertEqual(len(data["scans"]), 2, data["scans"])
        self.assertTrue(all(s["scope"].startswith("repos:") for s in data["scans"]), data["scans"])
        self.assertEqual([e["kind"] for e in data["events"]], ["scan", "scan"])
        code, out, err = self.run_bin("report", "--audit")
        self.assertEqual(code, 0, err)
        self.assertIn("## Audit log", out)
        self.assertNotIn("## Exposure log", out)
        code, out, err = self.run_bin("report", "--exposure", "--format", "csv")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("kind,component,version,location,vuln_id,"), out[:80])
        code, _, err = self.run_bin("report", "--format", "pdf")
        self.assertEqual(code, 2, err)
        conn = sqlite3.connect(str(self.db))
        for table in ("scans", "exposures", "fixes", "events"):
            self.assertTrue(conn.execute(f"PRAGMA table_info({table})").fetchall(), table)
        conn.close()
    def test_sync_offline_reports_unreachable_sources(self):
        # No network in the contract suite: every source is unreachable, none is "clean".
        code, out, err = self.run_bin("sync", "--json", env=dict(self.env, HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9"))
        self.assertEqual(code, 1, err)
        data = json.loads(out)
        self.assertEqual(set(data), {"refreshed", "failed", "packages"})
        self.assertTrue(data["failed"], data)
        self.assertEqual(data["packages"], 0)

    def test_schedule_dry_run_and_cache_prune(self):
        code, out, err = self.run_bin("schedule", "install", "--dry-run", "--every", "weekly", "--at", "07:05")
        self.assertEqual(code, 0, err)
        self.assertIn("schedule", out)
        # launchd (integers), systemd (HH:MM) or cron (M H) spell the time differently.
        self.assertTrue("07:05" in out or ("<integer>7</integer>" in out and "<integer>5</integer>" in out)
                        or out.startswith("5 7 "), out)
        code, _, err = self.run_bin("schedule", "install", "--at", "25:00")
        self.assertEqual(code, 2, err)
        code, _, err = self.run_bin("schedule", "dance")
        self.assertEqual(code, 2, err)
        code, out, err = self.run_bin("schedule", "status", env=dict(self.env, XDG_STATE_HOME=str(self.home / "state")))
        self.assertEqual(code, 0, err)
        self.assertIn("last run: never", out)
        self.project_run()
        code, out, err = self.run_bin("cache", "prune", "--older-than", "1")
        self.assertEqual(code, 0, err)
        self.assertIn("pruned", out)
        self.assertTrue(self.db.exists())

    def test_update_check_offline_reports_and_exits_0_or_10(self):
        code, out, err = self.run_bin("update", "--check", "--offline")
        # Offline with an empty cache: nothing known, so no update is claimed.
        self.assertEqual(code, 0, err)
        self.assertIn("couldn't check", out)
        code, out, err = self.run_bin("update", "--check", "--version", "99.0.0", "--offline")
        self.assertEqual(code, 10, out + err)
        self.assertIn("99.0.0", out)
        # The binary under test is a build in a checkout: reported, never replaced.
        code, out, err = self.run_bin("update", "--no-input", "--version", "99.0.0", "--offline")
        self.assertEqual(code, 10, out + err)
        self.assertIn("built from a checkout", out)
        code, out, err = self.run_bin("update", "--version", "nope", "--offline")
        self.assertEqual(code, 3, out + err)

    def test_install_scripts_follow_the_policy_file(self):
        proj = self.home / "p"
        proj.mkdir()
        (proj / "package-lock.json").write_text(
            '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/esbuild": {"version": "0.25.0", '
            '"hasInstallScript": true}, "node_modules/foo": {"version": "1.0.0", "hasInstallScript": true}}}')
        allow = Path(self.tmp.name, "allow.txt")
        allow.write_text("# ours\nfoo\n")
        _, out, _ = self.run_bin("--no-machine", "--path", str(proj), "--offline", "--json")
        self.assertEqual([f["component"] for f in self.envelope(out)["findings"] if f["kind"] == "install-script"], ["foo"])
        _, out, _ = self.run_bin("--no-machine", "--path", str(proj), "--offline", "--json", "--install-scripts",
                                 str(allow))
        got = [f for f in self.envelope(out)["findings"] if f["kind"] == "install-script"]
        self.assertEqual([f["component"] for f in got], ["esbuild"])  # bundled list allows it; this one doesn't
        self.assertIn("(--install-scripts)", got[0]["fix_cmd"])

    def test_licenses_are_opt_in(self):
        proj = self.home / "p"
        proj.mkdir()
        (proj / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "itoa"\nversion = "1.0.9"\n'
                                         'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        _, out, _ = self.run_bin("--no-machine", "--path", str(proj), "--offline", "--json")
        env = self.envelope(out)
        self.assertEqual([f for f in env["findings"] if f["kind"] == "license" or "license" in f["component"]], [])
        self.assertEqual(env["unknown_licenses"], 0)
        allow = Path(self.tmp.name, "licenses.txt")
        allow.write_text("MIT\n")
        for extra in (["--licenses"], ["--licenses", str(allow)], ["--licenses", "--json"], ["--license"],
                      ["--license", str(allow)]):
            code, _, err = self.run_bin("--no-machine", "--path", str(proj), "--offline", "--json", *extra)
            self.assertNotEqual(code, 2, (extra, err))

    # scope -----------------------------------------------------------------

    def test_default_scope_walks_home_and_prunes(self):
        h = self.home
        for wanted in ("code/app", "a/b/c/d/e/f", ".dotfiles"):
            git_repo(h / wanted)
        git_repo(h / "code" / "app" / "vendored" / "inner")       # inside a repo: the repo is the unit
        git_repo(h / "code" / "app-feature", worktree=True)       # a linked worktree of a repo
        for pruned in ("Library/x", ".Trash/x", "go/pkg/mod/x", ".cargo/registry/x", ".cargo/git/x", ".rustup/x",
                       ".npm/x", ".pnpm-store/x", ".cache/x", ".local/share/x", "code/node_modules/x", "Foo.app/x",
                       "a/b/c/d/e/f2/g"):                          # the last is past the depth limit
            git_repo(h / pruned)
        outside = git_repo(Path(self.tmp.name, "outside"))
        (h / "link").symlink_to(outside)                           # symlinks are not followed
        code, out, _ = self.run_bin("--no-machine", "--offline", "--json")
        self.assertEqual(self.envelope(out)["checked"]["git repos"], 3)

    def test_path_scopes_and_skips_missing_dirs(self):
        git_repo(self.home / "w" / "b")
        git_repo(self.home / "elsewhere")
        code, out, err = self.run_bin("--no-machine", "--offline", "--json", "--path", str(self.home / "w"),
                                      "--path", str(self.home / "missing"))
        self.assertEqual(self.envelope(out)["checked"]["git repos"], 1)
        self.assertIn("skipping --path", err)
        self.assertIn("missing", err)

    def test_explicit_worktree_counts(self):
        wt = git_repo(self.home / "wt", worktree=True)
        _, out, _ = self.run_bin("--no-machine", "--offline", "--json", "--path", str(wt))
        self.assertEqual(self.envelope(out)["checked"]["git repos"], 1)

    # the cache, search, export, breach -------------------------------------

    def test_cache_schema(self):
        self.project_run("--json")
        conn = sqlite3.connect(str(self.db))
        for table, cols in CACHE.items():
            got = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
            self.assertEqual(got, cols, table)
        idx = [r[1] for r in conn.execute("PRAGMA index_list(malicious)")]
        self.assertIn("malicious_name", idx)
        conn.close()

    def test_search_export_and_breach_read_the_cache(self):
        self.project_run()
        conn = sqlite3.connect(str(self.db))
        rec = {"id": "GHSA-b", "aliases": ["CVE-2026-1"], "summary": "vite dev server path traversal"}
        conn.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     ("GHSA-b", "CVE-2026-1", rec["summary"], "", "HIGH", "", "", "https://osv.dev/vulnerability/GHSA-b",
                      json.dumps(rec)))
        try:
            conn.execute("INSERT INTO vulns_fts VALUES (?, ?, ?, ?, ?)", ("GHSA-b", "CVE-2026-1", rec["summary"], "", "vite"))
        except sqlite3.OperationalError:
            pass  # this SQLite has no FTS5; the binary's may
        conn.execute("DELETE FROM findings")
        conn.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     ("project", "vite", "8.0.0", "/w/pnpm-lock.yaml", "CVE-2026-1", "fail", "8.0.1", 1, "HIGH",
                      "traversal", "cd /w && pnpm update vite@8.0.1", 0, "dev", 1, "<8.0.1"))
        conn.commit()
        conn.close()

        jl = Path(self.tmp.name, "f.jsonl")
        code, out, err = self.run_bin("export", "--jsonl", str(jl), "--all")
        self.assertEqual(code, 0, err)
        rows = [json.loads(line) for line in jl.read_text().splitlines()]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(set(row), set(FINDING) | {"schema", "aliases", "url", "record", "first_seen", "last_seen",
                                                   "resolved_at", "days_exposed", "fix"})
        self.assertEqual((row["schema"], row["vuln_id"], row["dep_scope"], row["dep_direct"], row["affected_range"]),
                         (1, "CVE-2026-1", "dev", True, "<8.0.1"))
        self.assertEqual((row["aliases"], row["url"]), (["GHSA-b"], "https://osv.dev/vulnerability/GHSA-b"))
        self.assertEqual(row["record"]["summary"], rec["summary"], "the full OSV record rides along")
        self.assertIsNone(row["fix"])
        self.assertIsNone(row["first_seen"], "no scan recorded this hand-written finding")
        self.assertEqual(self.run_bin("export", "--jsonl", str(jl), "--csv", str(Path(self.tmp.name, "g.csv")))[0], 0)

        code, out, _ = self.run_bin("search", "traversal", "--json")
        self.assertEqual(code, 0)
        hits = json.loads(out)
        if hits:  # FTS5 or LIKE: either finds it
            self.assertEqual(hits[0]["id"], "GHSA-b")
            self.assertEqual(set(hits[0]), {"id", "aliases", "summary", "severity", "applicable", "kev", "url", "rank"})
            self.assertTrue(hits[0]["applicable"])
        code, out, _ = self.run_bin("search", "traversal", "--applicable", "--json")
        self.assertEqual(code, 0)

        f = Path(self.tmp.name, "f.csv")
        code, out, _ = self.run_bin("export", "--csv", str(f))
        self.assertEqual(code, 0)
        rows = list(csv.reader(f.open(newline="")))
        self.assertEqual(rows[0], ["id", "aliases", "url", "component", "kind", "affected_version", "safe_version",
                                   "severity", "kev", "status", "location"])
        self.assertEqual(rows[1], ["CVE-2026-1", "CVE-2026-1", "https://osv.dev/vulnerability/GHSA-b", "vite", "project",
                                   "8.0.0", "8.0.1", "HIGH", "1", "fail", "/w/pnpm-lock.yaml"])

        self.assertIn("not decided", self.run_bin("breach")[1])
        self.assertEqual(self.run_bin("breach", "--enable")[0], 0)
        self.assertIn("yes", self.run_bin("breach")[1])
        self.assertEqual(self.run_bin("breach", "--disable")[0], 0)
        self.assertIn("no", self.run_bin("breach")[1])

    def test_findings_carry_the_dependency_relationship(self):
        """A dev dependency the root asks for: dep_scope dev, dep_direct true, and
        the advisory range the locked version fell in, from a seeded cache."""
        self.project_run()
        proj = git_repo(self.home / "app")
        (proj / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {"devDependencies": {"minimist": "1.2.5"}},
                         "node_modules/minimist": {"version": "1.2.5", "dev": True},
                         "node_modules/debug/node_modules/ms": {"version": "2.0.0"}}}))
        rec = {"id": "GHSA-m", "aliases": ["CVE-2026-7"], "summary": "minimist prototype pollution",
               "database_specific": {"severity": "MODERATE"},
               "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.6"}]}]}]}
        conn = sqlite3.connect(str(self.db))
        conn.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     ("GHSA-m", "CVE-2026-7", rec["summary"], "", "MODERATE", "", "", "", json.dumps(rec)))
        now = __import__("time").time()
        conn.execute("INSERT INTO queries VALUES (?, ?, ?, ?, ?)", ("npm", "minimist", "1.2.5", now, "GHSA-m"))
        conn.execute("INSERT INTO queries VALUES (?, ?, ?, ?, ?)", ("npm", "ms", "2.0.0", now, ""))
        conn.commit()
        conn.close()
        code, out, _ = self.run_bin("--no-machine", "--path", str(proj), "--offline", "--no-input", "--json")
        env = self.envelope(out)
        hits = [f for f in env["findings"] if f["vuln_id"] == "CVE-2026-7"]
        self.assertEqual(len(hits), 1, env["findings"])
        f = hits[0]
        self.assertEqual((f["component"], f["version"], f["fixed"], f["status"]), ("minimist", "1.2.5", "1.2.6", "fail"))
        self.assertEqual((f["dep_scope"], f["dep_direct"], f["affected_range"]), ("dev", True, ">=1.0.0, <1.2.6"))
        self.assertEqual(code, 1)
        jl = Path(self.tmp.name, "deps.jsonl")
        self.assertEqual(self.run_bin("export", "--jsonl", str(jl))[0], 0)
        rows = [json.loads(line) for line in jl.read_text().splitlines()]
        row = next(r for r in rows if r["vuln_id"] == "CVE-2026-7")
        self.assertEqual((row["dep_scope"], row["dep_direct"], row["record"]["id"]), ("dev", True, "GHSA-m"))
        self.assertIsNotNone(row["first_seen"], "the scan recorded the exposure")
        self.assertIsNone(row["resolved_at"])

    def test_json_stdout_is_pure(self):
        git_repo(self.home / "app")
        _, out, _ = self.project_run("--json")
        json.loads(out)  # nothing but the envelope on stdout

    @unittest.skipUnless(shutil.which("git"), "no git")
    def test_dryrun_changes_nothing(self):
        code, out, _ = self.project_run("--update", "--dryrun")
        self.assertIn(code, (0, 1))
        self.assertNotIn("Re-checking", out)


if __name__ == "__main__":
    unittest.main()
