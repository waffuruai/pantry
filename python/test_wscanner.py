"""Offline tests for wscanner: version ordering, fix selection, the cache
and search, the update plan, the scan's scope, and the CLI contract (the JSON
envelope, exit codes, version/tools/skill). Run from the repo root:

    python3 -m unittest discover -s python -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from wscanner import __version__, check, check_machine, check_supply, db, distros, editors, external, feeds  # noqa: E402
from wscanner import harnesses, malicious, net, osv, repos, report, versions  # noqa: E402
from wscanner.db import Cache  # noqa: E402

BIN = HERE / "bin"
_spec = importlib.util.spec_from_file_location("wscanner_cli", BIN / "wscanner.py")
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

GIT = "https://github.com/python/cpython.git"


def has_fts5() -> bool:
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE t USING fts5(a)")
        return True
    except sqlite3.OperationalError:
        return False


def rec(vid, ranges=(), aliases=(), pkg=None, versions_=()):
    affected = {"ranges": list(ranges), "versions": list(versions_)}
    if pkg:
        affected["package"] = {"ecosystem": pkg[0], "name": pkg[1]}
    return {"id": vid, "aliases": list(aliases), "summary": f"{vid} summary", "modified": "2026-10-01T00:00:00Z",
            "affected": [affected]}


class Versions(unittest.TestCase):
    def test_order(self):
        self.assertTrue(versions.lt("1.2.3", "1.2.10"))
        self.assertTrue(versions.lt("1.2.3rc1", "1.2.3"))
        self.assertTrue(versions.lt("v3.12.13", "v3.12.14"))
        self.assertTrue(versions.lt("curl-8_7_1", "curl-8_11_1"))
        self.assertFalse(versions.lt("2.0.0", "2.0.0"))

    def test_pick_safe_prefers_same_line(self):
        self.assertEqual(versions.pick_safe("24.22.1", ["26.12.2", "24.22.2", "22.23.5"]), "24.22.2")
        self.assertEqual(versions.pick_safe("1.0.9", ["1.0.10", "1.0.11"]), "1.0.10")
        self.assertIsNone(versions.pick_safe("2.0.0", ["1.9.0"]))

    def test_same_or_newer_ignores_extra_digits(self):
        self.assertTrue(versions.same_or_newer("2026.1", "2026.1.0"))
        self.assertFalse(versions.same_or_newer("3.0.20", "3.0.24"))


class Fixes(unittest.TestCase):
    def test_semver_fix(self):
        r = rec("RUSTSEC-1", [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.10"}]}],
                pkg=("crates.io", "webpki-roots"))
        self.assertEqual(osv.fixed_versions(r, "crates.io", "webpki-roots", "1.0.9"), ["1.0.10"])
        self.assertEqual(osv.fixed_versions(r, "crates.io", "other", "1.0.9"), [])

    def test_distro_release_only_takes_its_own_fix(self):
        r = {"id": "DEBIAN-CVE-1", "upstream": ["CVE-1"], "affected": [
            {"package": {"ecosystem": "Debian:13", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}]}]},
            {"package": {"ecosystem": "Debian:14", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.4.0-1"}]}]}]}
        self.assertEqual(osv.fixed_versions(r, "Debian:13", "acl", "2.3.2-2+b1"), [])
        self.assertEqual(osv.fixed_versions(r, "Debian:14", "acl", "2.3.2-2+b1"), ["2.4.0-1"])
        self.assertTrue(check.is_kev(r, {"CVE-1"}))

    def test_ubuntu_release_suffix_matches_but_pro_does_not(self):
        r = {"id": "USN-1", "affected": [
            {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "glibc"}, "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9"}]}]},
            {"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "glibc"}, "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9+esm1"}]}]}]}
        self.assertEqual(osv.fixed_versions(r, "Ubuntu:24.04", "glibc", "2.39-0ubuntu8.8"), ["2.39-0ubuntu8.9"])

    def test_commit_hash_is_not_a_release(self):
        r = rec("OSV-1", [{"type": "ECOSYSTEM", "events": [{"fixed": "76b7feab363d547e06151c8a8aa0ca72ade0594a"}]}],
                pkg=("npm", "x"))
        self.assertEqual(osv.fixed_versions(r, "npm", "x", "1.0.0"), [])
        self.assertFalse(osv.released("76b7feab363d547e06151c8a8aa0ca72ade0594a"))
        self.assertTrue(osv.released("1.2.3"))

    def test_git_fix_is_the_tag_osv_stops_reporting(self):
        r = rec("CVE-2026-1", [{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}])
        newer = {"v3.12.14": ["CVE-2026-1"], "v3.12.15": [], "v3.13.9": ["OTHER"]}
        self.assertEqual(sorted(osv.fixed_versions(r, "GIT", GIT, "v3.12.13", newer)), ["v3.12.15", "v3.13.9"])
        self.assertEqual(osv.fixed_versions(r, "GIT", GIT, "v3.12.13", {"v3.12.14": ["CVE-2026-1"]}), [])

    def test_git_fix_matches_aliases(self):
        r = rec("PSF-1", [{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}], aliases=["CVE-2026-2"])
        self.assertEqual(osv.fixed_versions(r, "GIT", GIT, "v3.14.4", {"v3.14.5": ["CVE-2026-2"]}), [])


class Parsers(unittest.TestCase):
    def test_postgres_table(self):
        page = ("<table><tr><th>Reference</th></tr><tr><td><a>CVE-2026-19385</a> <a>Announcement</a></td>"
                "<td>18, 17, 16</td><td>18.6, 17.11, 16.15</td><td>core server<br>8.8<br>"
                "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td><td>Heap overflow <a>more details</a></td></tr>"
                "<tr><td>client</td><td>legend row</td></tr></table>")
        got = feeds.parse_postgres(page)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["majors"], ["18", "17", "16"])
        self.assertEqual(got[0]["fixed"], ["18.6", "17.11", "16.15"])
        self.assertEqual((got[0]["component"], got[0]["score"]), ("core server", 8.8))
        self.assertEqual(got[0]["summary"], "Heap overflow")
        self.assertEqual(feeds.severity_from_score(8.8), "HIGH")

    def test_dockerfile_from_lines(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "Dockerfile")
            f.write_text("ARG BASE=debian:13\nFROM --platform=$BUILDPLATFORM rust:1.98-slim AS build\n"
                         "FROM ${BASE}\nFROM build AS test\nFROM scratch\nFROM ubuntu:24.04\n")
            self.assertEqual(repos.from_lines(f), ["rust:1.98-slim", "ubuntu:24.04"])
            c = Path(d, "compose.yml")
            c.write_text("services:\n  db:\n    image: postgres:18\n  app:\n    image: \"${APP}\"\n")
            self.assertEqual(repos.compose_images(c), ["postgres:18"])

    def test_dnf_parsing(self):
        self.assertEqual(distros.split_nevra("openssl-libs-1:3.5.9-1.fc44.aarch64"),
                         ("openssl-libs", "1:3.5.9-1.fc44"))
        self.assertEqual(distros.split_nevra("ca-certificates-2026.2.92_v9.0.319-2.fc44.noarch"),
                         ("ca-certificates", "2026.2.92_v9.0.319-2.fc44"))
        m = distros.DNF4_LINE.match("RLSA-2025:23343 Moderate/Sec.  binutils-2.35.2-67.el9_7.1.aarch64")
        self.assertEqual(m.groups(), ("RLSA-2025:23343", "Moderate", "binutils-2.35.2-67.el9_7.1.aarch64"))


class SupplyChain(unittest.TestCase):
    def test_malicious_needs_no_fix_to_fail(self):
        self.assertTrue(check.is_malicious({"id": "MAL-2026-1"}))
        self.assertTrue(check.is_malicious({"id": "GHSA-x", "aliases": ["MAL-2026-2"]}))
        self.assertFalse(check.is_malicious({"id": "GHSA-x", "aliases": ["CVE-2026-1"]}))

    def test_install_scripts(self):
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d, "package-lock.json")
            lock.write_text('{"packages": {"": {}, "node_modules/esbuild": {"hasInstallScript": true},'
                            ' "node_modules/@x/y": {"hasInstallScript": true}, "node_modules/z": {}}}')
            Path(d, "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
            Path(d, "pnpm-workspace.yaml").write_text(
                "packages:\n  - .\nonlyBuiltDependencies:\n  - sharp\n  - 'unrs-resolver'\n"
                "allowBuilds:\n  workerd: true\n  core-js: false\n")
            got = sorted(n for _, n in repos.install_scripts([lock, Path(d, "pnpm-lock.yaml")]))
            self.assertEqual(got, ["@x/y", "esbuild", "sharp", "unrs-resolver", "workerd"])

    def test_bundled_npm(self):
        with tempfile.TemporaryDirectory() as d:
            for rel, name, ver in (("node_modules/a", "a", "1.0.0"), ("node_modules/@s/b", "@s/b", "2.0.0"),
                                   ("node_modules/a/node_modules/c", "c", "3.0.0"), ("src/not-a-dep", "d", "4")):
                Path(d, rel).mkdir(parents=True)
                Path(d, rel, "package.json").write_text(f'{{"name": "{name}", "version": "{ver}"}}')
            self.assertEqual(editors.bundled_npm(d), [("@s/b", "2.0.0"), ("a", "1.0.0"), ("c", "3.0.0")])


class Harnesses(unittest.TestCase):
    def test_package_runners(self):
        ref = harnesses.package_ref
        self.assertEqual(ref("npx", ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"]),
                         ("npm", "@modelcontextprotocol/server-filesystem", "2025.1.14"))
        self.assertEqual(ref("/usr/local/bin/npx", ["-y", "mcp-server-x"]), ("npm", "mcp-server-x", ""))
        self.assertEqual(ref("npx", ["-p", "pkg@1.2.3", "bin-name"]), ("npm", "pkg", "1.2.3"))
        self.assertEqual(ref("pnpm", ["dlx", "some-mcp@latest"]), ("npm", "some-mcp", ""))
        self.assertEqual(ref("uvx", ["mcp-server-fetch==2025.4.7"]), ("PyPI", "mcp-server-fetch", "2025.4.7"))
        self.assertEqual(ref("uvx", ["--from", "git-mcp[cli]@1.0.0", "git-mcp"]), ("PyPI", "git-mcp", "1.0.0"))
        self.assertEqual(ref("uv", ["tool", "run", "mcp-x"]), ("PyPI", "mcp-x", ""))
        self.assertIsNone(ref("/Applications/ChatGPT.app/node_repl", []))
        self.assertIsNone(ref("node", ["server.js"]))

    def test_configs_across_harnesses(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / ".cursor").mkdir()
            (home / ".cursor/mcp.json").write_text('{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-mcp"]},'
                                                   ' "remote": {"url": "https://example.com/mcp"}}}')
            (home / ".codex").mkdir()
            (home / ".codex/config.toml").write_text('[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["mcp-server-fetch"]\n'
                                                     '[mcp_servers.fetch.env]\nX = "1"\n')
            (home / ".hermes").mkdir()
            (home / ".hermes/config.yaml").write_text("model: x\nmcp_servers:\n  gh:\n    command: npx\n"
                                                      "    args:\n      - -y\n      - gh-mcp@2.0.0\n")
            (home / "repo").mkdir()
            (home / "repo/.mcp.json").write_text('{"mcpServers": {"db": {"command": "bunx", "args": ["db-mcp"]}}}')
            old = os.environ["HOME"]
            os.environ["HOME"] = d
            try:
                got = {(s["harness"], s["name"], harnesses.package_ref(s["command"], s["args"]))
                       for s in harnesses.mcp_servers([("repo", home / "repo")])}
            finally:
                os.environ["HOME"] = old
            self.assertEqual(got, {("Cursor", "fs", ("npm", "fs-mcp", "")),
                                   ("Codex", "fetch", ("PyPI", "mcp-server-fetch", "")),
                                   ("Hermes", "gh", ("npm", "gh-mcp", "2.0.0")),
                                   ("project", "db", ("npm", "db-mcp", ""))})

    def test_toml_fallback_matches_tomllib(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "c.toml")
            f.write_text('[mcp_servers."my server"]\ncommand = "npx"\nargs = ["-y", "x@1.0.0"]\n[other]\nk = 1\n')
            import builtins
            real_import = builtins.__import__

            def no_tomllib(name, *a, **k):
                if name == "tomllib":
                    raise ImportError
                return real_import(name, *a, **k)
            builtins.__import__ = no_tomllib
            try:
                got = harnesses._toml(str(f))
            finally:
                builtins.__import__ = real_import
            self.assertEqual(got, {"mcp_servers": {"my server": {"command": "npx", "args": ["-y", "x@1.0.0"]}}})


class Malicious(unittest.TestCase):
    def test_applies(self):
        every = {"affected": [{"package": {"name": "x"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        some = {"affected": [{"package": {"name": "chalk"}, "versions": ["5.6.1"]}]}
        self.assertTrue(malicious.applies(every, "1.0.0"))
        self.assertTrue(malicious.applies(some, "5.6.1"))
        self.assertFalse(malicious.applies(some, "5.6.2"))
        self.assertTrue(malicious.applies({"affected": []}, "1.0.0"))

    def test_index_lookup_normalises_names(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["WSCANNER_DB"] = str(Path(d, "s.db"))
            try:
                c = Cache()
                c.conn.executemany("INSERT INTO malicious VALUES (?, ?, ?)",
                                   [("pypi", "evil-pkg", "MAL-1"), ("npm", "@bad/scope", "MAL-2")])
                c.put_vuln({"id": "MAL-1", "summary": "Malicious code in evil_pkg", "affected": []})
                c.put_vuln({"id": "MAL-2", "affected": [{"versions": ["1.0.0"]}]})
                self.assertEqual([r["id"] for r in malicious.reports(c, "PyPI", "Evil_Pkg", "")], ["MAL-1"])
                self.assertEqual([r["id"] for r in malicious.reports(c, "npm", "@bad/scope", "1.0.0")], ["MAL-2"])
                self.assertEqual(malicious.reports(c, "npm", "@bad/scope", "2.0.0"), [])
                c.close()
            finally:
                os.environ.pop("WSCANNER_DB", None)


class CacheAndSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["WSCANNER_DB"] = str(Path(self.tmp.name, "s.db"))

    def tearDown(self):
        os.environ.pop("WSCANNER_DB", None)
        self.tmp.cleanup()

    def test_candidates_from_cached_tags(self):
        c = Cache()
        c.put_run(f"tags:{GIT}", "", ["v3.12.12", "v3.12.13", "v3.12.14", "v3.12.15", "v3.13.0", "v3.13.9",
                                       "v3.14.0rc1", "v3.14.5"])
        got = osv.candidates(c, GIT, "v3.12.13")
        self.assertEqual(got, ["v3.12.14", "v3.12.15", "v3.13.9", "v3.14.5"])
        c.close()

    def test_lookup_offline_uses_cached_answers(self):
        c = Cache()
        c.put_vuln(rec("CVE-2026-3", pkg=("PyPI", "pip")))
        c.put_query("PyPI", "pip", "26.0.1", ["CVE-2026-3"])
        got = osv.lookup(c, [("PyPI", "pip", "26.0.1"), ("PyPI", "uv", "0.1.0")], offline=True, log=lambda *_: 0)
        self.assertEqual([r["id"] for r in got[("PyPI", "pip", "26.0.1")]], ["CVE-2026-3"])
        self.assertNotIn(("PyPI", "uv", "0.1.0"), got)  # never answered: unknown, not clean
        c.close()

    def test_unreachable_feed_raises_instead_of_reporting_clean(self):
        c = Cache()
        with self.assertRaises(osv.net.Offline):
            feeds.postgres(c, offline=True)
        with self.assertRaises(osv.net.Offline):
            feeds.eol(c, "nodejs", "24.0.0", "24", offline=True)
        c.put_run("postgres", "", [{"cve": "CVE-1"}])
        self.assertEqual(feeds.postgres(c, offline=True), [{"cve": "CVE-1"}])  # stale beats nothing
        c.close()

    def test_fresh_queries_are_not_refetched(self):
        c = Cache()
        c.put_query("npm", "zod", "4.4.3", [])
        row = c.query("npm", "zod", "4.4.3")
        self.assertGreater(row[0], time.time() - 5)
        c.close()

    @unittest.skipUnless(has_fts5(), "SQLite without FTS5")
    def test_search_ranks_by_text(self):
        c = Cache()
        c.put_vuln(dict(rec("GHSA-a", pkg=("npm", "zod")), summary="ReDoS in zod email validation"))
        c.put_vuln(dict(rec("GHSA-b", pkg=("npm", "vite")), summary="vite dev server path traversal"))
        c.conn.commit()
        rows = c.conn.execute("SELECT id FROM vulns_fts WHERE vulns_fts MATCH 'traversal'").fetchall()
        self.assertEqual(rows, [("GHSA-b",)])
        c.close()


class Plan(unittest.TestCase):
    def f(self, cmd, auto, status="fail"):
        return check.Finding(kind="tool", component=cmd.split()[-1], version="1", location="", vuln_id="CVE-1",
                             status=status, fix_cmd=cmd, fix_auto=auto)

    def test_plan_dedupes_and_splits(self):
        auto, manual, optional = report.plan([
            self.f("brew upgrade a", True), self.f("brew upgrade a", True),
            self.f("sudo apt-get install b", False), self.f("Update App", False, status="warn")])
        self.assertEqual(auto, ["brew upgrade a"])
        self.assertEqual(manual, ["sudo apt-get install b"])
        self.assertEqual(optional, ["Update App"])

    def test_one_fix_per_component_covers_every_advisory(self):
        fs = []
        for vid, safe in (("CVE-1", "0.23.45"), ("CVE-2", "0.23.46")):
            f = self.f(f"cargo update -p rustls --precise {safe}", False)
            f.component, f.vuln_id, f.fixed = "rustls", vid, safe
            fs.append(f)
        self.assertEqual(report.plan(fs)[1], ["cargo update -p rustls --precise 0.23.46"])

    def test_dryrun_runs_nothing(self):
        lines = []
        report.apply([self.f("false", True)], dryrun=True, out=lines.append)
        self.assertIn("  would run: false", lines)

    def test_project_fixes_stay_manual_and_per_ecosystem(self):
        p = {"source": "/w/butter/rust/Cargo.lock", "ecosystem": "crates.io", "name": "webpki-roots"}
        self.assertEqual(check_supply.project_fix(p, "1.0.10"),
                         "cd /w/butter/rust && cargo update -p webpki-roots --precise 1.0.10")
        p = {"source": "/w/docs/pnpm-lock.yaml", "ecosystem": "npm", "name": "vite"}
        self.assertEqual(check_supply.project_fix(p, "8.2.3"), "cd /w/docs && pnpm update vite@8.2.3")


def git_repo(path: Path, worktree=False) -> Path:
    """A directory that looks like a checkout (a .git dir, or a worktree's .git file)."""
    path.mkdir(parents=True, exist_ok=True)
    if worktree:
        (path / ".git").write_text("gitdir: /elsewhere\n")
    else:
        (path / ".git").mkdir()
    return path


class Isolated(unittest.TestCase):
    """A temp HOME and cache, so no test reads the real machine's home
    directory or writes its cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name, "home")
        self.home.mkdir()
        env = mock.patch.dict(os.environ, {"HOME": str(self.home), "WSCANNER_DB": str(Path(self.tmp.name, "w.db"))})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self.tmp.cleanup)

    def cli(self, *argv):
        """(exit code, stdout, stderr) of the CLI run in-process."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class Scope(Isolated):
    def test_default_scope_walks_home_and_prunes_caches(self):
        h = self.home
        wanted = [git_repo(h / "code" / "app"), git_repo(h / "a" / "b" / "c" / "d" / "e" / "f"), git_repo(h / ".dotfiles")]
        git_repo(h / "code" / "app" / "vendored" / "inner")       # inside a repo: the repo is the unit
        git_repo(h / "code" / "app-feature", worktree=True)       # a linked worktree of a repo
        for pruned in ("Library/x", ".Trash/x", "go/pkg/mod/x", ".cargo/registry/x", ".cargo/git/x", ".rustup/x",
                       ".npm/x", ".pnpm-store/x", ".cache/x", ".local/share/x", "code/node_modules/x", "Foo.app/x",
                       "a/b/c/d/e/f2/g"):                          # the last is past the depth limit
            git_repo(h / pruned)
        outside = git_repo(Path(self.tmp.name, "outside"))
        (h / "link").symlink_to(outside)                           # symlinks are not followed
        lines = []
        got = repos.scope(None, log=lines.append)
        self.assertEqual([p for _, p in got], sorted(wanted))
        self.assertEqual(got[0][0], str(sorted(wanted)[0]))  # named by path
        self.assertIn("found 3 git repos", lines[0])

    def test_path_scopes_to_those_dirs_and_skips_missing_ones(self):
        a, b = git_repo(self.home / "a"), git_repo(self.home / "w" / "b")
        git_repo(self.home / "elsewhere")
        notes = []
        got = repos.scope([self.home / "w", a, a / "..", self.home / "missing"], log=lambda *_: 0, note=notes.append)
        self.assertEqual(sorted(p for _, p in got), sorted({a.resolve(), b.resolve(), (self.home / "elsewhere").resolve()}))
        self.assertEqual(len(notes), 1)
        self.assertIn("missing", notes[0])
        only = repos.scope([self.home / "w"], log=lambda *_: 0)
        self.assertEqual([p for _, p in only], [b.resolve()])

    def test_explicit_worktree_and_plain_project_paths(self):
        wt = git_repo(self.home / "wt", worktree=True)
        plain = self.home / "plain"
        plain.mkdir()
        got = repos.scope([wt, plain], log=lambda *_: 0)
        self.assertEqual([p for _, p in got], [plain.resolve(), wt.resolve()])
        self.assertTrue(repos.is_git(wt))
        self.assertFalse(repos.is_git(plain))  # scanned for lockfiles, not for secrets

    def test_policy_files_replace_the_bundled_defaults(self):
        for f in dataclasses.astuple(check.Policy()):
            self.assertTrue(Path(f).is_file(), f)
        proj = self.home / "p"
        proj.mkdir()
        lock = proj / "package-lock.json"
        lock.write_text('{"packages": {"node_modules/esbuild": {"hasInstallScript": true},'
                        ' "node_modules/foo": {"hasInstallScript": true}}}')
        allow = Path(self.tmp.name, "allow.txt")
        allow.write_text("# ours\nfoo\n")
        scan = check.Scan(paths=[proj], policy=check.Policy(install_scripts=allow))
        check_supply.install_scripts(scan, [("p", proj)], [])
        scan.cache.close()
        self.assertEqual([f.component for f in scan.findings], ["esbuild"])  # bundled list allows it; this one doesn't
        self.assertIn("(--install-scripts)", scan.findings[0].fix_cmd)


class Paths(Isolated):
    def test_cache_location(self):
        self.assertEqual(db.path(), Path(os.environ["WSCANNER_DB"]))
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/x"}):
            os.environ.pop("WSCANNER_DB")
            self.assertEqual(db.path(), Path("/x/wscanner/wscanner.db"))
            os.environ.pop("XDG_CACHE_HOME")
            self.assertEqual(db.path(), self.home / ".cache" / "wscanner" / "wscanner.db")

    def test_user_agent_names_the_project(self):
        self.assertEqual(net.USER_AGENT, f"wscanner/{__version__} (+https://github.com/waffuruai/wscanner)")


ENVELOPE = {"schema", "impl", "version", "checked", "unfixed", "unknown_licenses", "findings"}
FINDING = {"kind": str, "component": str, "version": str, "location": str, "vuln_id": str, "status": str,
           "fixed": str, "kev": bool, "severity": str, "note": str, "fix_cmd": str, "fix_auto": bool}


def finding(status="fail", **kw):
    return check.Finding(**dict(dict(kind="tool", component="x", version="1", location="", vuln_id="CVE-1",
                                     status=status), **kw))


class Contract(Isolated):
    def project_run(self, *extra):
        return self.cli("--no-machine", "--path", str(self.home), "--offline", "--no-input", *extra)

    def test_json_envelope(self):
        git_repo(self.home / "app")
        code, out, _ = self.project_run("--json")
        env = json.loads(out)
        self.assertEqual(set(env), ENVELOPE)
        self.assertEqual((env["schema"], env["impl"], env["version"]), (1, "python", __version__))
        self.assertEqual(env["checked"]["git repos"], 1)
        self.assertTrue(env["findings"])  # offline: the unreachable sources are reported, never clean
        for f in env["findings"]:
            self.assertEqual({k: type(v) for k, v in f.items()}, FINDING)
        self.assertEqual({fl.name for fl in dataclasses.fields(check.Finding)}, set(FINDING))

    def test_no_machine_runs_only_repo_checks(self):
        (self.home / ".cursor").mkdir()
        (self.home / ".cursor/mcp.json").write_text('{"mcpServers": {"x": {"command": "npx", "args": ["x-mcp"]}}}')
        git_repo(self.home / "app")
        (self.home / "app/.mcp.json").write_text('{"mcpServers": {"y": {"command": "npx", "args": ["y-mcp"]}}}')
        boom = mock.Mock(side_effect=AssertionError("machine check ran"))
        with mock.patch.object(check_machine, "inventory", boom), mock.patch.object(check_supply, "extensions", boom), \
                mock.patch.object(check_supply, "bundles", boom), mock.patch.object(check_supply, "_breach", boom), \
                mock.patch("wscanner.apps.running_images", boom):
            code, out, _ = self.project_run("--json")
        self.assertEqual(code, 0, out)
        unpinned = [f["component"] for f in json.loads(out)["findings"] if f["vuln_id"] == "UNPINNED"]
        self.assertEqual(unpinned, ["y-mcp (project: y)"])  # the repo's server, not the harness config's

    def test_default_scope_is_the_home_directory(self):
        git_repo(self.home / "one")
        git_repo(self.home / "deep" / "two")
        code, out, _ = self.cli("--no-machine", "--offline", "--json")
        self.assertEqual(json.loads(out)["checked"]["git repos"], 2)

    def test_exit_0_when_only_warnings_and_unchecked(self):
        code, out, _ = self.project_run()
        self.assertEqual(code, 0)
        self.assertIn("not checked", out)

    def test_exit_1_on_a_failing_finding(self):
        with mock.patch.object(check.Scan, "run", return_value=[finding()]):
            self.assertEqual(self.project_run("--json")[0], 1)
            self.assertEqual(self.project_run()[0], 1)
        with mock.patch.object(check.Scan, "run", return_value=[finding("warn")]):
            self.assertEqual(self.project_run()[0], 0)

    def test_exit_1_when_an_unattended_fix_fails_even_if_the_recheck_is_clean(self):
        broken = finding("warn", fix_cmd="false", fix_auto=True)
        with mock.patch.object(check.Scan, "run", side_effect=[[broken], []]):
            code, out, _ = self.project_run("--update")
        self.assertEqual(code, 1)
        self.assertIn("failed: false", out)
        with mock.patch.object(check.Scan, "run", side_effect=[[broken]]):
            self.assertEqual(self.project_run("--update", "--dryrun")[0], 0)  # a dry run changes nothing

    def test_exit_2_on_usage_errors(self):
        self.assertEqual(self.cli("--bogus")[0], 2)
        self.assertEqual(self.cli("check", "--licenses", str(self.home / "nope.txt"))[0], 2)
        self.assertEqual(self.cli("search")[0], 2)
        self.assertEqual(self.cli("--help")[0], 0)

    def test_exit_3_when_the_cache_cant_be_opened(self):
        with mock.patch.dict(os.environ, {"WSCANNER_DB": "/dev/null/w.db"}):
            code, _, err = self.cli("search", "x")
            self.assertEqual(code, 3)
            self.assertIn("wscanner:", err)
            self.assertEqual(self.project_run("--json")[0], 3)

    def test_exit_3_on_a_crash(self):
        with mock.patch.object(check.Scan, "run", side_effect=KeyError("bug")):
            code, _, err = self.project_run()
        self.assertEqual(code, 3)
        self.assertIn("KeyError", err)

    def test_version(self):
        code, out, _ = self.cli("version", "--json")
        self.assertEqual((code, json.loads(out)), (0, {"version": __version__, "impl": "python", "schema": 1}))
        self.assertIn(__version__, self.cli("version")[1])

    def test_tools(self):
        code, out, _ = self.cli("tools", "--json")
        got = json.loads(out)
        self.assertEqual([t["name"] for t in got["tools"]], ["osv-scanner", "gitleaks", "git", "openssl", "brew", "docker"])
        for t in got["tools"]:
            self.assertEqual(set(t), {"name", "required", "found", "path", "version", "purpose"})
            self.assertEqual(t["found"], bool(shutil.which(t["name"])))
        missing = any(t["required"] and not t["found"] for t in got["tools"])
        self.assertEqual(code, 1 if missing else 0)
        with mock.patch("shutil.which", return_value=None):
            self.assertTrue(all(not t["found"] and not t["version"] for t in external.tools()))
            self.assertEqual(self.cli("tools")[0], 1)

    def test_skill(self):
        code, out, _ = self.cli("skill")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("---\nname: wscanner\n"))

    @unittest.skipUnless(shutil.which("bash"), "no bash")
    def test_shell_entry_passes_subcommands_straight_through(self):
        p = subprocess.run(["bash", str(BIN / "wscanner"), "version", "--json"], capture_output=True, text=True)
        self.assertEqual((p.returncode, json.loads(p.stdout)["impl"]), (0, "python"))


if __name__ == "__main__":
    unittest.main()
