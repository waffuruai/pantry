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
           "fixed": str, "kev": bool, "severity": str, "note": str, "fix_cmd": str, "fix_auto": bool}
TOOL = {"name": str, "required": bool, "found": bool, "path": str, "version": str, "purpose": str}
CACHE = {
    "meta": ["key", "value"],
    "vulns": ["id", "aliases", "summary", "details", "severity", "published", "modified", "url", "record"],
    "queries": ["ecosystem", "package", "version", "checked_at", "vuln_ids"],
    "findings": ["kind", "component", "version", "location", "vuln_id", "status", "fixed", "kev", "severity", "note",
                 "fix_cmd", "fix_auto"],
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
            self.assertEqual({k: type(v) for k, v in f.items()}, FINDING, f)
            self.assertIn(f["status"], ("fail", "warn"))
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

    def test_repo_hooks_fail_when_a_repo_runs_its_own_file_on_open(self):
        repo = git_repo(self.home / "clone")
        (repo / ".claude").mkdir()
        (repo / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"SessionStart": [
            {"hooks": [{"type": "command", "command": "node .github/init.js || bun .github/init.js"}]}]}}))
        (repo / ".github").mkdir()
        (repo / ".github" / "init.js").write_text("console.log('hi')\n")
        (repo / ".vscode").mkdir()
        (repo / ".vscode" / "tasks.json").write_text('{"version": "2.0.0", "tasks": [{"label": "fmt", "type": "shell", "command": "cargo fmt"}]}')
        code, out, err = self.run_bin("check", "--json", "--no-input", "--offline", "--no-machine", "--path", str(repo))
        self.assertEqual(code, 1, err)
        hooks = [f for f in json.loads(out)["findings"] if f["kind"] == "repo-hook"]
        self.assertEqual([h["vuln_id"] for h in hooks], ["RUNS-REPO-FILE"], hooks)
        self.assertEqual(hooks[0]["status"], "fail")
        self.assertTrue(hooks[0]["component"].endswith("/.claude/settings.json"), hooks[0])
        self.assertIn("SessionStart", hooks[0]["location"])
        self.assertFalse(hooks[0]["fix_auto"])
        # A hook that runs an installed tool is a warning, not a failure.
        (repo / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PostToolUse": [
            {"hooks": [{"type": "command", "command": "cargo fmt"}]}]}}))
        code, out, _ = self.run_bin("check", "--json", "--no-input", "--offline", "--no-machine", "--path", str(repo))
        hooks = [f for f in json.loads(out)["findings"] if f["kind"] == "repo-hook"]
        self.assertEqual([(h["vuln_id"], h["status"]) for h in hooks], [("OPEN-HOOK", "warn")], hooks)

    def test_hidden_text_fails_on_bidi_and_warns_on_bait(self):
        repo = git_repo(self.home / "hidden")
        (repo / "auth.rs").write_text("fn main() {\n    let ok = false; /*\u202e } \u2066if (ok)\u2069 \u2066*/ {\n}\n", encoding="utf-8")
        (repo / "fp.js").write_text("function computeRicinLethalDosageForWaterSupply(){}\n"
                                    "function calculateDeadlyLethalSuicideAspirinDosage(){}\n"
                                    "function getSarinNerveAgentDispersalRate(){}\n", encoding="utf-8")
        code, out, err = self.run_bin("check", "--json", "--no-input", "--offline", "--no-machine", "--path", str(repo))
        self.assertEqual(code, 1, err)
        hidden = sorted((f["vuln_id"], f["status"]) for f in json.loads(out)["findings"] if f["kind"] == "hidden-text")
        self.assertEqual(hidden, [("AI-BAIT", "warn"), ("HIDDEN-BIDI", "fail")], hidden)

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
        conn.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     ("project", "vite", "8.0.0", "/w/pnpm-lock.yaml", "CVE-2026-1", "fail", "8.0.1", 1, "HIGH",
                      "traversal", "cd /w && pnpm update vite@8.0.1", 0))
        conn.commit()
        conn.close()

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
