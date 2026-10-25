"""Offline tests for the security scanner: version ordering, fix selection,
the cache and search, and the update plan. Run with `make test`."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wscanner import check, check_supply, distros, editors, feeds, harnesses, malicious, osv, repos, report, versions  # noqa: E402
from wscanner.db import Cache  # noqa: E402

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
            os.environ["WAFFURU_SECURITY_DB"] = str(Path(d, "s.db"))
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
                os.environ.pop("WAFFURU_SECURITY_DB", None)


class CacheAndSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["WAFFURU_SECURITY_DB"] = str(Path(self.tmp.name, "s.db"))

    def tearDown(self):
        os.environ.pop("WAFFURU_SECURITY_DB", None)
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


if __name__ == "__main__":
    unittest.main()
