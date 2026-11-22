#!/usr/bin/env python3
"""Drive the production egui widgets through AccessKit against the real CLI."""

import argparse
from contextlib import closing, contextmanager
import json
import os
import plistlib
import platform
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from zipfile import ZipFile


class Driver:
    def __init__(self, app, scanner, env):
        command = [app, "--automation"]
        if scanner is not None:
            command.extend(["--scanner", scanner])
        self.process = subprocess.Popen(
            command, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )

    def request(self, op, succeeds=True, **fields):
        self.process.stdin.write(json.dumps({"op": op, **fields}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"Desktop stopped before answering {op}."
        reply = json.loads(line)
        assert reply["ok"] == succeeds, (op, fields, reply)
        return reply["result"] if succeeds else reply["error"]

    def click(self, widget):
        return self.request("click", id=widget)

    def action(self, action, **fields):
        return self.request("dispatch", command={"action": action, **fields})

    def settled(self):
        return self.request("wait")["state"]

    def state(self):
        return self.request("state")

    def widget(self, widget):
        nodes = [node for node in self.request("tree") if node["id"] == widget]
        assert len(nodes) == 1, (widget, nodes)
        return nodes[0]

    def labels(self):
        return [node["label"] or "" for node in self.request("tree")]

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=15) == 0


@contextmanager
def fixture_db(path):
    # sqlite3's context manager commits or rolls back but leaves the
    # connection open. Windows cannot remove an open database file.
    with closing(sqlite3.connect(path)) as cache, cache:
        yield cache


def insert_scan(cache, now, scope, fails=0, warns=0, unchecked=0, unfixed=0):
    return cache.execute(
        """INSERT INTO scans (started_at, finished_at, version, scope, counts, fails, warns,
                             unchecked, checked, unfixed, unknown_licenses)
           VALUES (?, ?, '0.6.0', ?, '{}', ?, ?, ?, '[["lockfiles", 1]]', ?, 0)""",
        (now - 2, now, scope, fails, warns, unchecked, unfixed),
    ).lastrowid


def add_exposure(cache, scan, now, name, status, severity, resolved, instructions):
    cache.execute(
        """INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                  status, severity, note, first_scan, first_at, last_scan,
                                  last_at, resolved_at, fix_cmd)
           VALUES (?, 'machine:~', 'osv', ?, '1.0', '/test/another-project', 'TEST-2026-OLDER',
                   ?, ?, 'Evidence from an earlier scan.', ?, ?, ?, ?, ?, ?)""",
        (name, name, status, severity, scan, now, scan, now, resolved, instructions),
    )


def seed(cache, project, applied):
    now = time.time()
    patch = shlex.join([sys.executable, "-c", f"from pathlib import Path; Path({str(applied)!r}).touch()"])
    earlier = insert_scan(cache, now - 60, "machine:~", fails=1)
    add_exposure(cache, earlier, now - 60, "older-open", "fail", "medium", None, "Update the installed tool.")
    add_exposure(cache, earlier, now - 60, "older-resolved", "warn", "low", now - 10, "")
    scan = insert_scan(cache, now, f"repos:{project}", fails=2, warns=1, unchecked=1, unfixed=1)
    rows = [
        ("osv", "auto-fixture", "1.0", str(project), "TEST-2026-AUTO", "fail", "2.0", 0, "high", "Automatic test update.", patch, 1),
        ("osv", "manual-fixture", "1.0", str(project), "TEST-2026-MANUAL", "fail", "", 0, "medium", "Manual update.", "Install the vendor update.", 0),
        ("unchecked", "Feed unavailable", "", "", "source", "warn", "", 0, "", "This feed did not answer.", "", 0),
    ]
    cache.executemany(
        """INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed,
                                kev, severity, note, fix_cmd, fix_auto) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    # What the advisory is: aliases with public-database shapes (links), a
    # summary and a weakness type, as the scanner saves them.
    cache.execute(
        """UPDATE findings SET summary = 'Out-of-bounds write in the test decoder',
                               aliases = 'GHSA-test-aaaa-bbbb CVE-2099-0001', cwe = 'CWE-787'
           WHERE vuln_id = 'TEST-2026-AUTO'""")
    cache.execute(
        """INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                  status, severity, first_scan, first_at, last_scan, last_at)
           VALUES (?, ?, 'osv', 'auto-fixture', '1.0', ?, 'TEST-2026-AUTO', 'fail', 'high', ?, ?, ?, ?)""",
        (f"osv|auto-fixture|{project}|TEST-2026-AUTO", f"repos:{project}", str(project), scan, now, scan, now),
    )
    return scan, patch


def demo_seed(cache, project, applied):
    """Synthetic data for the documentation screenshots: invented package
    names marked "demo" and DEMO-* ids, so no real advisory is misquoted."""
    now = time.time()
    patch = shlex.join([sys.executable, "-c", f"from pathlib import Path; Path({str(applied)!r}).touch()"])
    earlier = insert_scan(cache, now - 86400, "machine:~", fails=1)
    for name, status, severity, resolved in (("demo-http-client", "fail", "medium", None),
                                             ("demo-json-parser", "warn", "low", now - 3600)):
        cache.execute(
            """INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                      status, severity, note, first_scan, first_at, last_scan,
                                      last_at, resolved_at, fix_cmd)
               VALUES (?, 'machine:~', 'osv', ?, '3.1.0', ?, 'DEMO-2026-0003', ?, ?, 'Demo data.',
                       ?, ?, ?, ?, ?, 'Update the installed tool.')""",
            (name, name, str(project), status, severity, earlier, now - 86400, earlier, now - 86400, resolved),
        )
    scan = insert_scan(cache, now, f"repos:{project}", fails=2, warns=1, unchecked=1, unfixed=1)
    rows = [
        ("osv", "demo-image-tools", "1.4.2", str(project), "DEMO-2026-0001", "fail", "1.4.9", 0, "high",
         "Demo data: a crafted image can run code.", patch, 1),
        ("osv", "demo-markdown", "2.0.1", str(project), "DEMO-2026-0002", "fail", "", 0, "medium",
         "Demo data: a crafted link can slow the page.", "Install the maker's update when it is out.", 0),
        ("unchecked", "Advisory feed", "", "", "source", "warn", "", 0, "", "This source did not answer.", "", 0),
    ]
    cache.executemany(
        """INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed,
                                kev, severity, note, fix_cmd, fix_auto) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    # Demo advisory text: DEMO ids only, so no real notice is misquoted.
    cache.execute(
        """UPDATE findings SET summary = 'Demo data: heap overflow when decoding a crafted image',
                               aliases = 'DEMO-GHSA-0001 DEMO-OSV-0001', cwe = 'CWE-787',
                               affected_range = '>=1.0.0, <1.4.9', cvss = 8.8, cvss_version = '3.1',
                               epss = 0.03, dep_scope = 'runtime', dep_direct = 1
           WHERE vuln_id = 'DEMO-2026-0001'""")
    cache.execute(
        """UPDATE findings SET summary = 'Demo data: slow parsing of crafted links', cwe = 'CWE-1333'
           WHERE vuln_id = 'DEMO-2026-0002'""")
    cache.execute(
        """INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                  status, severity, first_scan, first_at, last_scan, last_at)
           VALUES (?, ?, 'osv', 'demo-image-tools', '1.4.2', ?, 'DEMO-2026-0001', 'fail', 'high', ?, ?, ?, ?)""",
        (f"osv|demo-image-tools|{project}|DEMO-2026-0001", f"repos:{project}", str(project), scan, now, scan, now),
    )
    return scan, patch


INTERACTIVE_ROLES = {"Button", "CheckBox", "ComboBox", "TextInput", "MultilineTextInput", "Link",
                     "Slider", "RadioButton", "Switch", "Tab", "ListBoxOption", "MenuItem"}


def untagged(tree):
    """Interactive widgets that lack an automation id (should be none)."""
    return [node for node in tree
            if (node.get("interactive") or node["role"] in INTERACTIVE_ROLES) and not node["id"]]


def audit(driver, where):
    tree = driver.request("tree")
    missing = untagged(tree)
    assert not missing, (where, missing)
    ids = [node["id"] for node in tree if node["id"]]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, (where, duplicates)
    for node in tree:
        if node["id"]:
            assert node["bounds"] is not None and node["role"], (where, node)
    return tree


def audit_rejects_known_bad():
    # Known-bad case: the audit must flag a button with no id.
    bad = [{"id": None, "label": "Mystery", "role": "Button", "interactive": True, "bounds": [0, 0, 1, 1]}]
    assert untagged(bad) == bad
    assert untagged([{"id": "ok", "label": "x", "role": "Button", "interactive": True}]) == []


def shown_once(driver, text):
    """A fix outcome is told once on screen: in the banner card, not again
    as the status line under it."""
    # A label's own text runs are part of it, not a second copy.
    nodes = [n for n in driver.request("tree")
             if n["label"] and n["bounds"] and n.get("role") != "TextRun" and text in n["label"]]
    assert len(nodes) == 1, (text, nodes)


def shown_once_rejects_known_bad():
    # Known-bad case: the same message as both banner and status line.
    class Twice:
        def request(self, op):
            node = {"label": "Fixed and checked.", "bounds": [0, 0, 1, 1]}
            return [dict(node, id="fix.result"), dict(node, id="status.message")]
    try:
        shown_once(Twice(), "Fixed and checked.")
    except AssertionError:
        return
    raise AssertionError("shown_once accepted a message shown twice")


def inside(bounds, region, slack=0.5):
    """True when `bounds` lies within `region` (both [x0, y0, x1, y1])."""
    return (bounds[0] >= region[0] - slack and bounds[1] >= region[1] - slack
            and bounds[2] <= region[2] + slack and bounds[3] <= region[3] + slack)


def inside_rejects_known_bad():
    # Known-bad case: a control half under the footer is not inside.
    region = [0, 100, 236, 440]
    assert inside([18, 200, 200, 230], region)
    assert not inside([18, 430, 200, 460], region)
    assert not inside([18, 600, 200, 630], region)


def sidebar_reachable(driver, where, width=820, height=480):
    """Oracle for the sidebar at the minimum window: the scroll area and the
    pinned help links fit the window, and every sidebar control either sits
    inside the scroll area or comes inside it when scrolled into view."""
    inside_rejects_known_bad()
    tree = audit(driver, where)
    regions = [node for node in tree if node["id"] == "sidebar.scroll"]
    assert len(regions) == 1 and regions[0]["role"] == "ScrollView", (where, regions)
    region = regions[0]["bounds"]
    assert inside(region, [0, 0, width, height]), (where, region)
    for link in ("help.github", "help.support"):
        bounds = next(node for node in tree if node["id"] == link)["bounds"]
        assert inside(bounds, [0, 0, width, height]) and bounds[1] >= region[3] - 0.5, (where, link, bounds)
    controls = [
        node["id"] for node in tree
        if node["id"] and node["interactive"] and not node["id"].startswith("help.")
        and node["bounds"][0] >= region[0] - 0.5 and node["bounds"][2] <= region[2] + 0.5
        and node["bounds"][1] >= region[1] - 0.5
    ]
    for expected in ("theme.toggle", "view.details", "updates.check"):
        assert expected in controls, (where, expected, controls)
    for control in controls:
        driver.request("scroll_into_view", id=control)
        bounds = driver.widget(control)["bounds"]
        assert inside(bounds, region), (where, control, bounds, region)
    return controls


def has_label(driver, text):
    return any(text in label for label in driver.labels())


def seed_fixable(cache, project, files):
    """A newer scan with one automatic fix per file; each fix creates its file."""
    now = time.time()
    scan = insert_scan(cache, now, f"repos:{project}", fails=len(files))
    cache.execute("DELETE FROM findings")
    for n, path in enumerate(files):
        patch = shlex.join([sys.executable, "-c", f"from pathlib import Path; Path({str(path)!r}).touch()"])
        name = f"batch-fixture-{n}"
        cache.execute(
            """INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed,
                                    kev, severity, note, fix_cmd, fix_auto)
               VALUES ('osv', ?, '1.0', ?, ?, 'fail', '2.0', 0, 'high', 'Batch test update.', ?, 1)""",
            (name, str(project), f"TEST-BATCH-{n}", patch),
        )
        cache.execute(
            """INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                      status, severity, first_scan, first_at, last_scan, last_at)
               VALUES (?, ?, 'osv', ?, '1.0', ?, ?, 'fail', 'high', ?, ?, ?, ?)""",
            (f"osv|{name}|{project}|TEST-BATCH-{n}", f"repos:{project}", name, str(project),
             f"TEST-BATCH-{n}", scan, now, scan, now),
        )
    return scan


def checks(driver, scanner, temp, env):
    audit_rejects_known_bad()
    shown_once_rejects_known_bad()
    # First run: the welcome card and its one big button.
    state = driver.settled()
    assert state["report"] is None and state["report_error"] is None, state
    assert driver.state()["mode"] == "first_run"
    assert has_label(driver, "Welcome to Pantry")
    assert driver.widget("scan.first")["role"] == "Button"
    assert driver.widget("scan.run")["role"] == "Button"
    if sys.platform == "darwin":
        assert driver.widget("scan.personal")["role"] == "CheckBox"
        assert driver.click("scan.personal")["state"]["include_personal_files"] is True
        assert driver.click("scan.access")["browser"].startswith("x-apple.systempreferences:")
        assert driver.click("scan.personal")["state"]["include_personal_files"] is False
    audit(driver, "first run")
    assert driver.widget("help.github")["role"] == "Link"
    assert driver.widget("help.support")["label"] == "support@waffuru.ai"
    assert driver.click("help.github")["browser"] == "https://github.com/waffuruai/pantry"
    assert driver.click("help.support")["browser"] == "mailto:support@waffuru.ai"

    # Schedule form with hour and minute dropdowns, without a real OS job.
    driver.click("schedule.edit")
    audit(driver, "schedule form")
    driver.action("set_time", at="25:90")
    assert driver.click("schedule.save")["state"]["error"]["summary"].startswith("Enter a time")
    driver.click("schedule.every")
    driver.click("schedule.every.week")
    driver.click("schedule.hour")
    driver.click("schedule.hour.07")
    driver.click("schedule.minute")
    state = driver.click("schedule.minute.05")["state"]
    assert state["period"] == "week" and state["at"] == "07:05", state
    driver.click("schedule.cancel")
    if sys.platform != "win32":
        driver.click("schedule.edit")
        driver.click("schedule.every")
        driver.click("schedule.every.week")
        driver.click("schedule.hour")
        driver.click("schedule.hour.07")
        driver.click("schedule.minute")
        driver.click("schedule.minute.05")
        driver.click("schedule.save")
        configured = driver.settled()["schedule"]
        assert configured["installed"] and configured["enabled"] and configured["every"] == "week", configured
        assert configured["at"] == "07:05" and "Mondays" in configured["interval"]
        driver.click("schedule.edit")
        driver.click("schedule.remove")
        assert driver.settled()["schedule"]["installed"] is False
    if sys.platform == "darwin":
        # A removal whose bootout fails: the plist is gone but launchd still
        # holds the job. The sidebar must not say scans are off, and Remove
        # it tries again. Known-bad: "Scheduled scans are off".
        bootout_fails = Path(shutil.which("launchctl", path=env["PATH"])).with_name(".bootout-fails")
        driver.click("schedule.edit")
        driver.click("schedule.save")
        assert driver.settled()["schedule"]["installed"]
        bootout_fails.touch()
        driver.click("schedule.edit")
        driver.click("schedule.remove")
        state = driver.settled()
        assert state["error"], "a failed removal is reported"
        assert state["schedule"]["installed"] is False and state["schedule"]["loaded"] is True, state["schedule"]
        driver.action("dismiss_error")
        assert driver.widget("schedule.state")["label"] == "A scheduled scan is still registered"
        bootout_fails.unlink()
        driver.click("schedule.remove_stray")
        state = driver.settled()
        assert state["schedule"]["loaded"] is False and state["error"] is None, (state["schedule"], state["error"])
        assert driver.widget("schedule.state")["label"] == "Scheduled scans are off"
        assert not [n for n in driver.request("tree") if n["id"] == "schedule.remove_stray"]

    # Both palettes, through the real toggle and through set_theme.
    reply = driver.click("theme.toggle")
    assert reply["palette"] == "light" and reply["state"]["settings"]["light"] is True
    audit(driver, "light palette")
    assert driver.click("theme.toggle")["palette"] == "dark"
    assert driver.action("set_theme", theme="system")["state"]["settings"]["light"] is None
    assert driver.action("set_theme", theme="light")["palette"] == "light"
    assert driver.action("set_theme", theme="dark")["palette"] == "dark"

    # Technical details on: Reload results lives there.
    assert driver.click("view.details")["state"]["details"] is True
    assert driver.widget("scan.refresh")["label"] == "Reload results"

    project = temp / "test project"
    project.mkdir()
    state = driver.action("scan", path=str(project), offline=True)
    assert state["busy"] == "Scanning…"
    state = driver.settled()
    assert state["report"]["scan"]["scope"].endswith(str(project)), state["report"]["scan"]
    assert driver.state()["mode"] == "has_report"

    db = env["WPANTRY_DB"]
    applied = temp / "patch ran"
    with fixture_db(db) as cache:
        cache.execute("DELETE FROM scans")
        cache.execute("DELETE FROM exposures")
        cache.execute("DELETE FROM findings")
        scan, patch = seed(cache, project, applied)

    # A change to the cache (like a scheduled scan) reloads by itself.
    driver.action("check_cache")
    state = driver.settled()
    assert state["report"]["scan"]["id"] == scan
    # The headline counts the latest scan only; an earlier scan of another
    # scope shows apart, under "From earlier scans".
    assert has_label(driver, "2 things need your attention"), driver.labels()
    assert driver.state()["headline_count"] == 2
    assert driver.widget("earlier.heading")["label"] == "From earlier scans"
    manual = next(item["id"] for item in state["report"]["findings"] if item["vuln_id"] == "TEST-2026-MANUAL")
    auto = next(item["id"] for item in state["report"]["findings"] if item["vuln_id"] == "TEST-2026-AUTO")
    current = driver.state()
    assert current["fixable"] == [auto], current["fixable"]
    assert driver.widget("fix.all")["label"] == "Fix the 1 that Pantry can fix"
    assert driver.widget(f"finding.{auto}.fix")["label"] == "Fix it"
    # Lower priority rows start folded away.
    assert driver.widget("findings.lower")["label"] == "Show lower priority (1)"
    driver.request("click", succeeds=False, id=f"finding.{manual}")
    driver.click("findings.lower")
    assert driver.widget(f"finding.{manual}.how")["label"] == "Show me how"
    audit(driver, "home")
    assert "Can fix (1)" in driver.labels()
    assert driver.click("findings.filter.fixable")["state"]["filter"] == "fixable"
    driver.request("click", succeeds=False, id=f"finding.{manual}")
    driver.click("findings.filter.all")
    assert not has_label(driver, "older-resolved")

    earlier = next(entry["id"] for entry in state["report"]["history"]["exposures"] if entry["component"] == "older-open")
    driver.click(f"earlier.{earlier}.how")
    assert driver.click("fix.copy")["clipboard"] == "Update the installed tool."
    driver.request("click", succeeds=False, id="fix.preview")
    driver.click("finding.back")
    driver.click("nav.results")
    assert has_label(driver, "Feed unavailable")
    assert has_label(driver, "no fix released yet")
    audit(driver, "latest scan")
    driver.click("nav.history")
    assert has_label(driver, "older-resolved")
    driver.click("nav.attention")
    driver.request("set_value", id="findings.search", value="manual-fixture")
    driver.request("click", succeeds=False, id=f"finding.{auto}")
    # Only lower-priority rows match, so they show without the toggle.
    driver.request("click", succeeds=False, id="findings.lower")
    driver.click(f"finding.{manual}")
    assert {"What Pantry found", "Installed version 1.0", "How to fix it"}.issubset(driver.labels())
    # A plain sentence leads; the scanner's note shows only with details.
    assert driver.widget("finding.sentence")["label"].startswith("manual-fixture has a security flaw with no fix yet.")
    assert "Manual update." not in driver.labels()
    # The path reads as ~/... or is elided in the middle, never a long raw path.
    found = driver.widget("finding.location")["label"]
    assert found.startswith("Found in ") and len(found) <= len("Found in ") + 56, found
    assert found.endswith(project.name), (found, project.name)
    assert driver.click("fix.copy")["clipboard"] == "Install the vendor update."
    driver.request("click", succeeds=False, id="fix.preview")
    audit(driver, "manual detail")
    # No weakness or summary: the neutral sentence, with no ids to link.
    finding = driver.state()["finding"]
    assert finding["explanation_source"] == "generic", finding
    assert finding["identifiers"] == [{"id": "TEST-2026-MANUAL", "url": None}], finding
    driver.request("key", key="Escape")
    driver.request("set_value", id="findings.search", value="")
    # A finding with a weakness type, ids and a summary: what could happen,
    # each id a link to its notice, the notice's own words, Copy ID.
    driver.action("select", id=auto)
    finding = driver.state()["finding"]
    assert finding["explanation_source"] == "cwe", finding
    assert "run their own programs" in finding["explanation"], finding
    assert finding["summary"] == "Out-of-bounds write in the test decoder", finding
    ids = [item["id"] for item in finding["identifiers"]]
    assert ids == ["CVE-2099-0001", "TEST-2026-AUTO", "GHSA-test-aaaa-bbbb"], ids
    assert finding["identifiers"][1]["url"] is None, "a test id links nowhere"
    assert driver.widget("finding.advisory.CVE-2099-0001")["role"] == "Link"
    assert driver.widget("finding.summary")["label"].startswith("From the security notice:")
    assert driver.widget("finding.attacks")["label"].startswith("It is not on the public list")
    assert driver.click("finding.advisory.CVE-2099-0001")["browser"] == "https://www.cve.org/CVERecord?id=CVE-2099-0001"
    assert driver.click("finding.advisory.GHSA-test-aaaa-bbbb")["browser"] == "https://github.com/advisories/GHSA-test-aaaa-bbbb"
    assert driver.click("finding.copy_id")["clipboard"] == "CVE-2099-0001"
    # Only an id the finding lists can be opened.
    assert driver.request("dispatch", succeeds=False, command={"action": "open_advisory", "id": "RUSTSEC-0000-0000"})
    driver.action("copy_id")
    # The home row's sentence names the consequence, not the generic hole.
    assert not driver.state()["finding"]["sentence"].endswith("has a security flaw.")
    audit(driver, "advisory detail")
    was = driver.state()["state"]["details"]
    driver.action("set_details", on=True)
    assert driver.widget("finding.tech.weakness_type")["label"] == "Weakness type: CWE-787 (Out-of-bounds write)"
    audit(driver, "advisory technical details")
    driver.action("set_details", on=was)
    driver.request("key", key="Escape")
    driver.action("select", id=manual)
    # Esc goes back.
    assert driver.request("key", key="Escape")["state"]["selected"] is None
    driver.request("set_value", id="findings.search", value="")
    # Cmd/Ctrl+F focuses search.
    assert driver.request("key", key="F", command=True)["search_focused"] is True

    # The row's own Fix it opens the finding with the confirm step.
    driver.click(f"finding.{auto}.fix")
    state = driver.settled()
    assert state["pending_fix"]["command"] == patch, state["pending_fix"]
    assert "Ready to fix" in driver.labels()
    assert not applied.exists()
    audit(driver, "confirm step")
    assert driver.click("fix.copy")["clipboard"] == patch
    driver.click("fix.cancel")
    assert driver.settled()["pending_fix"] is None
    driver.click("fix.preview")
    assert driver.settled()["pending_fix"]["scan"] == scan
    assert driver.request("key", key="Escape")["state"]["pending_fix"] is None
    # Without details, a command Pantry can't describe (this stand-in)
    # still shows, with no toggle to hide it. The npm case in the outcome
    # checks covers a described command behind its toggle.
    driver.click("view.details")
    assert not [n for n in driver.request("tree") if n["id"] == "fix.details"]
    assert driver.click("fix.copy")["clipboard"] == patch
    driver.click("view.details")

    # A scan arriving between Fix it and the confirm blocks the update.
    driver.click("fix.preview")
    assert driver.settled()["pending_fix"]["scan"] == scan
    with fixture_db(db) as cache:
        newer = insert_scan(cache, time.time(), f"repos:{project}", fails=2, warns=1, unchecked=1)
    driver.click("fix.confirm")
    state = driver.settled()
    assert state["error"]["kind"] == "stale_fix", state["error"]
    assert "newer scan" in state["error"]["details"]
    assert "newer scan" not in state["error"]["summary"]
    assert driver.click("error.details")["state"]["show_error_details"] is True
    assert any("newer scan" in label for label in driver.labels())
    audit(driver, "error banner")
    assert driver.click("error.dismiss")["state"]["error"] is None
    assert not applied.exists()

    # Fix it, confirm, then the automatic check scan of the same scope.
    driver.click("fix.preview")
    assert driver.settled()["pending_fix"]["scan"] == newer
    assert driver.click("fix.confirm")["busy"] in ("Fixing…", "Checking the fix…")
    state = driver.settled()
    assert applied.is_file()
    assert state["error"] is None, state["error"]
    assert state["report"]["scan"]["id"] > newer, "the fix was not followed by a check scan"
    result = state["fix_result"]
    # The offline check has unfinished feeds, so it can't confirm the fix.
    assert result["outcome"] == "unconfirmed", result
    assert driver.widget("fix.result")["label"] == result["message"]
    shown_once(driver, result["message"])
    assert driver.click("fix.result.dismiss")["state"]["fix_result"] is None

    driver.click("nav.history")
    assert "Fix ran, not checked yet" in driver.labels()
    fixes = driver.settled()["report"]["history"]["fixes"]
    assert fixes[-1]["command"] == patch and fixes[-1]["verified_scan"] is None
    # Supply offline answers for the three feeds the scanner reads even for
    # an empty project. The real scanner must then be able to verify the fix.
    with fixture_db(db) as cache:
        cache.execute("INSERT INTO kev (cve, added) VALUES ('CVE-2000-0000', '2000-01-01')")
        cache.execute("INSERT INTO epss VALUES ('CVE-2000-0000', 0.01, 0.01)")
        cache.execute("INSERT INTO malicious VALUES ('npm', 'pantry-test-fixture', 'MAL-TEST')")
    driver.action("scan", path=str(project), offline=True)
    state = driver.settled()
    assert state["report"]["scan"]["unchecked"] == 0, state["report"]["findings"]
    recheck = state["report"]["scan"]["id"]
    driver.click("nav.history")
    assert f"Fixed and checked · scan #{recheck}" in driver.labels(), driver.labels()
    assert driver.settled()["report"]["history"]["fixes"][-1]["verified_scan"] == recheck
    driver.click("nav.attention")
    # The latest scan is clean; the earlier finding from another scope is
    # still open, apart from the headline.
    assert has_label(driver, "Everything checked is up to date"), driver.labels()
    assert driver.widget(f"earlier.{earlier}")["label"].startswith("older-open"), driver.labels()

    # Fix all: one confirm, one at a time, per-item results, one check scan.
    made = [temp / "batch one", temp / "batch two"]
    with fixture_db(db) as cache:
        seed_fixable(cache, project, made)
    driver.action("check_cache")
    driver.settled()
    assert driver.widget("fix.all")["label"] == "Fix all 2 that Pantry can fix"
    driver.click("fix.all")
    batch = driver.settled()["batch"]
    assert batch["stage"] == "confirm" and [i["status"] for i in batch["items"]] == ["waiting", "waiting"], batch
    assert all(item["command"] for item in batch["items"])
    assert not any(path.exists() for path in made)
    audit(driver, "fix all confirm")
    assert driver.click("fix.all.cancel")["state"]["batch"] is None
    driver.click("fix.all")
    driver.settled()
    driver.click("fix.all.confirm")
    batch = driver.settled()["batch"]
    assert all(path.is_file() for path in made)
    assert batch["stage"] == "done", batch
    assert [i["status"] for i in batch["items"]] == ["fixed", "fixed"], batch
    assert driver.widget("fix.all.result")["label"] == "2 of 2 fixed and checked."
    assert driver.click("fix.all.dismiss")["state"]["batch"] is None

    # An update must use the matching package and signer's workflow at the tag.
    machine = platform.machine().lower()
    target = (
        "universal-apple-darwin" if sys.platform == "darwin" else
        ("x86_64-pc-windows-msvc" if sys.platform == "win32" else
         ("aarch64" if machine in ("aarch64", "arm64") else "x86_64") + "-unknown-linux-gnu")
    )
    asset = f"wpantry-desktop-{target}.zip"
    with fixture_db(db) as cache:
        cache.execute("INSERT OR REPLACE INTO runs VALUES (?, '', ?, ?)", (
            "github-latest:waffuruai/pantry", time.time(), json.dumps({"version": "99.1.2", "assets": [asset]})
        ))
    assert driver.state()["state"]["details"] is True
    driver.click("updates.check")
    assert driver.settled()["update"]["latest"] == "99.1.2"
    copied = driver.click("updates.copy")["clipboard"]
    assert asset in copied and "refs/tags/v99.1.2" in copied and ".github/workflows/release.yml" in copied
    assert driver.click("updates.open")["browser"].endswith(f"/v99.1.2/{asset}")

    installer_ext = {"darwin": "zip", "win32": "exe"}.get(sys.platform, "tar.gz")
    installer = f"wpantry-setup-{target}.{installer_ext}"
    with fixture_db(db) as cache:
        cache.execute("UPDATE runs SET result = ? WHERE source = 'github-latest:waffuruai/pantry'",
                      (json.dumps({"version": "99.1.2", "assets": [asset, installer]}),))
    driver.click("updates.check")
    driver.settled()
    assert driver.click("updates.open")["browser"].endswith(f"/v99.1.2/{installer}")

    # Nonmatching assets must never result in a generic download link.
    with fixture_db(db) as cache:
        cache.execute("UPDATE runs SET result = ? WHERE source = 'github-latest:waffuruai/pantry'",
                      (json.dumps({"version": "99.1.2", "assets": []}),))
    driver.click("updates.check")
    driver.settled()
    driver.request("click", succeeds=False, id="updates.open")
    audit(driver, "updates")

    # The fullest sidebar (schedule form, update notice, technical details)
    # at the 820 x 480 minimum: every control can be scrolled into view and
    # the help links stay pinned below it.
    driver.action("edit_schedule", open=True)
    driver.request("resize", width=820, height=480)
    controls = sidebar_reachable(driver, "minimum window sidebar")
    assert "scan.refresh" in controls and "schedule.save" in controls, controls
    driver.request("resize", width=1080, height=740)
    driver.action("edit_schedule", open=False)

    # Every remaining action through the typed dispatcher.
    assert driver.action("show", page="results")["state"]["page"] == "results"
    assert driver.action("search", text="zzz")["state"]["search"] == "zzz"
    assert driver.action("set_filter", filter="fixable")["state"]["filter"] == "fixable"
    driver.action("set_filter", filter="all")
    driver.action("show", page="attention")
    assert driver.action("show_lower_priority", open=True)["state"]["show_lower"] is True
    assert driver.action("set_details", on=False)["state"]["details"] is False
    assert driver.action("set_light", light=True)["palette"] == "light"
    assert driver.action("open_download")["browser"] == "https://github.com/waffuruai/pantry/releases/latest"
    assert driver.action("open_github")["browser"] == "https://github.com/waffuruai/pantry"
    assert driver.action("open_support")["browser"] == "mailto:support@waffuru.ai"
    assert driver.action("open_scan_access")["browser"].startswith("x-apple.systempreferences:")
    assert driver.action("set_personal_files", include=True)["state"]["include_personal_files"] is True
    driver.action("set_personal_files", include=False)
    driver.action("edit_schedule", open=True)
    assert driver.action("set_period", every="month")["state"]["period"] == "month"
    driver.action("edit_schedule", open=False)
    driver.request("dispatch", succeeds=False, command={"action": "cancel"})
    driver.request("dispatch", succeeds=False, command={"action": "confirm_fix"})
    driver.request("dispatch", succeeds=False, command={"action": "confirm_fix_all"})
    driver.request("dispatch", succeeds=False, command={"action": "fix_it"})
    for action in ("cancel_fix", "cancel_fix_all", "dismiss_fix_all", "dismiss_error",
                   "dismiss_fix_result", "toggle_error_details", "toggle_fix_details",
                   "close_finding", "refresh"):
        driver.action(action)
        driver.settled()
    assert driver.action("copy_watch_command")["clipboard"].endswith(" watch")

    command = [scanner, "schedule", "install", "--every", "quarter", "--at", "08:25", "--dry-run"]
    plan = subprocess.run(command, env=env, check=True, capture_output=True, text=True, encoding="utf-8").stdout
    assert ("08:25" in plan or "<integer>25</integer>" in plan or "25 8 " in plan), plan


FAKE_SCANNER = """#!/bin/sh
# Stand-in scanner: quick answers, and a scan that runs until it is killed.
case "$1" in
  report) echo "no scan yet" >&2; exit 1 ;;
  schedule) echo '{"schema":1,"installed":false,"backend":"launchd","enabled":null,"interval":null,"every":null,"at":null,"last_run":null}' ;;
  scan) echo $$ > "$PANTRY_FAKE_PID"; echo "reading the test folder" >&2; exec sleep 60 ;;
esac
"""


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def cancel_and_timeout(app, temp, env):
    """Cancel and the time limit kill the scanner (Unix: a shell stand-in)."""
    fake = temp / "fake scanner"
    fake.write_text(FAKE_SCANNER)
    fake.chmod(0o755)
    pid_file = temp / "fake pid"
    env = dict(env, PANTRY_FAKE_PID=str(pid_file))
    driver = Driver(app, fake, env)
    try:
        assert driver.settled()["report"] is None
        # Cmd/Ctrl+R starts a scan.
        reply = driver.request("key", key="R", command=True)
        assert reply["busy"] == "Scanning…", reply["busy"]
        deadline = time.time() + 10
        while not (pid_file.exists() and driver.state()["busy_note"]):
            assert time.time() < deadline, "the scan never reported a status line"
            time.sleep(0.05)
        current = driver.state()
        assert current["busy_note"] == "reading the test folder" and current["cancellable"], current
        assert driver.widget("task.note")["label"] == "reading the test folder"
        audit(driver, "running scan")
        pid = int(pid_file.read_text())
        assert pid_alive(pid)
        driver.click("task.cancel")
        state = driver.settled()
        assert state["error"]["kind"] == "cancelled", state["error"]
        assert not pid_alive(pid), "Cancel left the scanner running"
        driver.click("error.dismiss")

        # The time limit, shortened for the test.
        pid_file.unlink()
        driver.request("set_time_limit", milliseconds=700)
        driver.action("scan", offline=True)
        state = driver.settled()
        assert state["error"]["kind"] == "timed_out", state["error"]
        pid = int(pid_file.read_text())
        assert not pid_alive(pid), "the time limit left the scanner running"
        driver.request("set_time_limit", milliseconds=0)
        # The cancel op itself.
        pid_file.unlink()
        driver.action("scan", offline=True)
        deadline = time.time() + 10
        while not pid_file.exists():
            assert time.time() < deadline
            time.sleep(0.05)
        driver.request("cancel")
        assert driver.settled()["error"]["kind"] == "cancelled"
    finally:
        driver.close()


MACHINE_SCANNER = r"""
# Stand-in for a machine-scope scanner. A real machine scan also reads the
# host's own apps and tools, so offline it always has gaps this test can't
# control. This one follows the scanner's contract instead: two `excluded`
# findings for skipped personal folders, a real gap only when asked, and a
# fix verified only by a complete scan that no longer lists the finding.
import json, os, sys, time
state_path = os.environ["PANTRY_FAKE_STATE"]
args = sys.argv[1:]
try:
    with open(state_path) as f:
        st = json.load(f)
except FileNotFoundError:
    st = {"scans": [], "fixed": False, "fixes": [], "log": []}
st["log"].append(args)
home = os.environ["HOME"]
key = ["osv", "left-pad", os.path.join(home, "project"), "TEST-MACHINE-1"]
stamp = lambda: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

def finding(id, kind, component, note, status="warn", excluded=False, **more):
    item = {"id": id, "kind": kind, "component": component, "version": "", "location": "",
            "vuln_id": "", "status": status, "note": note, "fixed": "", "severity": "",
            "kev": False, "fix_cmd": "", "fix_auto": False, "excluded": excluded}
    item.update(more)
    return item

def problem():
    return finding("f1", "osv", "left-pad", "left-pad 1.0 has a known security hole.",
                   status="fail", version="1.0", location=key[2], vuln_id=key[3],
                   fixed="2.0", severity="high", fix_cmd="npm install left-pad@2.0",
                   fix_auto=True)

def scan_findings(skip):
    rows = [] if st["fixed"] else [problem()]
    if skip:
        rows.append(finding("x1", "unchecked", "Personal documents and images",
                            "Skipped by your choice (--no-personal-files). Downloads, Desktop and Documents were not read.",
                            excluded=True))
        rows.append(finding("x2", "unchecked", "Safari settings",
                            "Skipped by your choice (--no-personal-files). Safari's protected app data was not read.",
                            excluded=True))
    if os.environ.get("PANTRY_FAKE_GAP") == "1":
        rows.append(finding("g1", "unchecked", "CISA KEV (exploited-in-the-wild marks)",
                            "CISA KEV list unreachable and not cached"))
    return rows

def save():
    with open(state_path, "w") as f:
        json.dump(st, f)

cmd = args[0] if args else ""
if cmd == "report":
    save()
    if not st["scans"]:
        print("no scan yet", file=sys.stderr)
        sys.exit(1)
    last = st["scans"][-1]
    exposure = dict(problem(), resolved=stamp() if st.get("resolved") else None)
    print(json.dumps({
        "schema": 1, "scan": last["scan"], "findings": last["findings"],
        "fix_plan": [{"id": "f1", "how": "wpantry", "run": "wpantry fix f1",
                      "fix_cmd": "npm install left-pad@2.0"}] if not st["fixed"] else [],
        "checked": {}, "unfixed": 0,
        "history": {"scans": [s["scan"] for s in st["scans"]], "exposures": [exposure],
                    "fixes": st["fixes"]},
    }))
elif cmd == "scan":
    assert "--path" not in args and "--no-machine" not in args, args
    skip = "--no-personal-files" in args or os.environ.get("PANTRY_FAKE_SKIP") == "1"
    rows = scan_findings(skip)
    gaps = sum(1 for r in rows if r["kind"] == "unchecked" and not r["excluded"])
    scope = "machine:~;no-personal-files" if skip else "machine:~"
    scan = {"id": len(st["scans"]) + 1, "when": stamp(), "scope": scope,
            "fails": sum(r["status"] == "fail" for r in rows),
            "warns": sum(r["status"] == "warn" for r in rows), "unchecked": gaps}
    st["scans"].append({"scan": scan, "findings": rows})
    # A complete scan that no longer lists the finding resolves it and
    # verifies the fix; a scan with a gap resolves nothing.
    if gaps == 0 and st["fixed"]:
        st["resolved"] = True
        for fix in st["fixes"]:
            if fix["verified_scan"] is None:
                fix["verified_scan"] = scan["id"]
    save()
    print(json.dumps({"schema": 1, "findings": rows}))
    sys.exit(1 if scan["fails"] else 0)
elif cmd == "fix":
    scan = int(args[args.index("--from-scan") + 1])
    if "--dry-run" in args:
        save()
        print(json.dumps({"schema": 1, "scan": scan, "command": "npm install left-pad@2.0"}))
    else:
        st["fixed"] = True
        st["fixes"].append({"when": stamp(), "command": "npm install left-pad@2.0", "ok": True,
                            "verified_scan": None, "targets": ["|".join(key)]})
        save()
        print("Fixed left-pad.")
elif cmd == "schedule":
    save()
    print(json.dumps({"schema": 1, "installed": False, "backend": "launchd", "enabled": None,
                      "interval": None, "every": None, "at": None, "last_run": None}))
else:
    save()
    print(f"unsupported in the stand-in: {args}", file=sys.stderr)
    sys.exit(2)
"""


def machine_scope(app, temp, env, gap):
    """A machine-scope fix with skipped personal folders, in a fake HOME.

    With only skipped areas left unchecked the fix must read as fixed and
    checked. The known-bad twin adds one real gap: then it must not.
    """
    name = "machine gap" if gap else "machine"
    home = temp / f"{name} home"
    (home / "project").mkdir(parents=True)
    fake = temp / f"{name} scanner"
    fake.write_text(f"#!{sys.executable}\n" + MACHINE_SCANNER)
    fake.chmod(0o755)
    state_file = temp / f"{name} state.json"
    env = dict(env, HOME=str(home), PANTRY_FAKE_STATE=str(state_file),
               PANTRY_FAKE_GAP="1" if gap else "0",
               WPANTRY_DESKTOP_HOME=str(temp / f"{name} profile"))
    # Only macOS passes --no-personal-files; elsewhere the stand-in skips
    # the same areas on its own so the exclusion path is still exercised.
    if sys.platform != "darwin":
        env["PANTRY_FAKE_SKIP"] = "1"
    driver = Driver(app, fake, env)
    try:
        assert driver.settled()["report"] is None
        driver.action("set_personal_files", include=False)
        driver.action("scan", offline=True)
        state = driver.settled()
        report = state["report"]
        assert report["scan"]["scope"] == "machine:~;no-personal-files", report["scan"]
        assert sum(f["excluded"] for f in report["findings"]) == 2, report["findings"]
        log = json.loads(state_file.read_text())["log"]
        scans = [a for a in log if a and a[0] == "scan"]
        if sys.platform == "darwin":
            assert "--no-personal-files" in scans[-1], scans

        # Skipped areas are not problems and not unfinished checks.
        incomplete = [label for label in driver.labels() if "did not finish" in label]
        assert bool(incomplete) == gap, incomplete
        driver.action("show", page="results")
        labels = driver.labels()
        skipped = [n for n in driver.request("tree") if n["id"] == "scan.skipped"]
        assert len(skipped) == 1 and skipped[0]["label"] == "Skipped by your choice: personal folders", skipped
        # Two skipped areas, one real problem, and no warnings from the skips.
        assert ("1 problem · 1 warning" if gap else "1 problem · 0 warnings") in labels, labels
        assert not any("Safari settings" in label or "Personal documents" in label for label in labels), labels
        assert driver.widget("scan.skipped.include")["role"] == "CheckBox"
        audit(driver, f"{name} results")
        if gap:
            assert has_label(driver, "1 check did not finish in the latest scan"), labels
            assert driver.action("select", id="g1")["state"]["selected"] == "g1"
            assert has_label(driver, "CISA KEV list unreachable and not cached")
            audit(driver, f"{name} could not be checked")
            before = len(scans)
            driver.click("finding.retry")
            state = driver.settled()
            log = json.loads(state_file.read_text())["log"]
            again = [a for a in log if a and a[0] == "scan"]
            assert len(again) == before + 1 and again[-1] == scans[-1], again
            assert state["report"]["scan"]["scope"] == "machine:~;no-personal-files"
            driver.action("close_finding")
        else:
            assert not any("did not finish" in label for label in labels), labels

        # Fix it, confirm, and the automatic rescan of the same scope.
        driver.action("show", page="attention")
        assert driver.action("select", id="f1")["can_fix_selected"]
        driver.click("fix.preview")
        driver.settled()
        driver.click("fix.confirm")
        state = driver.settled()
        assert state["error"] is None, state["error"]
        rescan = [a for a in json.loads(state_file.read_text())["log"] if a and a[0] == "scan"][-1]
        assert rescan == scans[-1], (rescan, scans[-1])
        result = state["fix_result"]
        message = driver.widget("fix.result")["label"]
        fixes = state["report"]["history"]["fixes"]
        if gap:
            assert result["outcome"] == "unconfirmed", result
            assert "Fixed" not in message, message
            assert fixes[-1]["verified_scan"] is None, fixes
        else:
            assert result["outcome"] == "fixed", result
            assert message.startswith("Fixed and checked."), message
            assert fixes[-1]["verified_scan"] == state["report"]["scan"]["id"], fixes
            assert state["report"]["history"]["exposures"][0]["resolved"], state["report"]["history"]
        shown_once(driver, message)
        driver.click("fix.result.dismiss")

        # The checkbox puts personal folders back in the next scan.
        driver.action("show", page="results")
        driver.click("scan.skipped.include")
        assert driver.state()["state"]["include_personal_files"] is True
    finally:
        driver.close()


OUTCOME_SCANNER = r"""
# Stand-in for the outcome checks: two fixable findings in one folder, two
# open problems from scans of other folders (one folder still there, one
# gone), and knobs (a JSON file read on every call) that make a fix leave
# its finding behind, fail, run slowly, or break the reload after it.
import json, os, sys, time
args = sys.argv[1:]
paths = {name: os.environ["PANTRY_FAKE_" + name.upper()] for name in ("state", "knobs", "main", "other", "gone")}
try:
    with open(paths["knobs"]) as f:
        knobs = json.load(f)
except FileNotFoundError:
    knobs = {}
try:
    with open(paths["state"]) as f:
        st = json.load(f)
except FileNotFoundError:
    st = {"scans": [], "fixed": [], "fixes": [], "log": [], "other_resolved": False}
st["log"].append(args)
stamp = lambda: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

def save():
    with open(paths["state"], "w") as f:
        json.dump(st, f)

def finding(fid, component, **more):
    item = {"id": fid, "kind": "osv", "component": component, "version": "1.0",
            "location": paths["main"], "vuln_id": "TEST-2026-" + fid.upper(), "status": "fail",
            "note": component + " has a known security hole.", "fixed": "2.0", "severity": "high",
            "kev": False, "fix_cmd": "npm install " + component + "@2.0", "fix_auto": True}
    item.update(more)
    return item

def key(item):
    return "|".join([item["kind"], item["component"], item["location"], item["vuln_id"]])

def latest_rows():
    # A component name with a right-to-left override and an escape code:
    # the window must show it without them.
    # Its fix command is plain: a hidden character there is refused (the
    # dry_run_hidden knob checks that).
    rows = [finding("f1", "alpha"), finding("f2", "bravo‮gnp.exe\u001b[31m", fix_cmd="npm install bravo@2.0")]
    if knobs.get("many"):
        # Enough rows that the last ones sit below the fold of the smallest window.
        rows += [finding(f"f{n}", f"extra-{n}", severity="low", status="warn") for n in range(3, 15)]
    return [r for r in rows if r["id"] not in st["fixed"]]

def exposure(eid, component, scope, location):
    item = finding(eid, component, location=location, status="fail", severity="medium", fix_auto=False)
    item.update(resolved=None, scope=scope)
    return item

cmd = args[0] if args else ""
if cmd == "report":
    save()
    if knobs.get("report_sleep"):
        with open(paths["state"] + ".pid", "w") as f:
            f.write(str(os.getpid()))
        time.sleep(60)
    if knobs.get("report_fails") and st["fixes"]:
        print("database is locked", file=sys.stderr)
        sys.exit(3)
    if not st["scans"]:
        print("no scan yet", file=sys.stderr)
        sys.exit(1)
    last = st["scans"][-1]
    earlier = [exposure("e2", "gone-tool", "repos:" + paths["gone"], paths["gone"])]
    if not st["other_resolved"]:
        earlier.insert(0, exposure("e1", "other-tool", "repos:" + paths["other"], paths["other"]))
    plan = [{"id": r["id"], "how": "wpantry", "run": "wpantry fix " + r["id"], "fix_cmd": r["fix_cmd"]}
            for r in last["findings"] if r["kind"] != "unchecked"]
    print(json.dumps({
        "schema": 1, "scan": last["scan"], "findings": last["findings"], "fix_plan": plan,
        "checked": {}, "unfixed": 0,
        "history": {"scans": [s["scan"] for s in st["scans"]], "exposures": earlier, "fixes": st["fixes"]},
    }))
elif cmd == "scan":
    if knobs.get("scan_sleep"):
        with open(paths["state"] + ".pid", "w") as f:
            f.write(str(os.getpid()))
        save()
        time.sleep(60)
    if knobs.get("scan_garbage"):
        save()
        print("<html>proxy error</html>")
        sys.exit(0)
    where = args[args.index("--path") + 1] if "--path" in args else ""
    if knobs.get("scan_offline") and "--offline" not in args:
        save()
        print("error sending request: dns error: failed to lookup address", file=sys.stderr)
        sys.exit(2)
    if knobs.get("fresh"):
        st["fixed"] = []  # The problems are back, for the next check.
    if where == paths["other"]:
        st["other_resolved"] = True
        rows = []
    else:
        rows = latest_rows()
    if knobs.get("gap"):
        rows.append({"id": "g1", "kind": "unchecked", "component": "CISA KEV", "version": "", "location": "",
                     "vuln_id": "", "status": "warn", "note": "CISA KEV list unreachable", "fixed": "",
                     "severity": "", "kev": False, "fix_cmd": "", "fix_auto": False, "excluded": False})
    gaps = sum(1 for r in rows if r["kind"] == "unchecked")
    scan = {"id": len(st["scans"]) + 1, "when": stamp(), "scope": "repos:" + where,
            "fails": sum(r["status"] == "fail" for r in rows), "warns": 0, "unchecked": gaps}
    st["scans"].append({"scan": scan, "findings": rows})
    save()
    print(json.dumps({"schema": 1, "findings": rows}))
    sys.exit(1 if scan["fails"] else 0)
elif cmd == "fix":
    fid = args[1]
    scan = int(args[args.index("--from-scan") + 1])
    row = next(r for r in st["scans"][-1]["findings"] if r["id"] == fid)
    if "--dry-run" in args:
        save()
        command = row["fix_cmd"]
        # A right-to-left override makes the command read differently from
        # how it runs; an answer for another scan is not this fix.
        if fid in knobs.get("dry_run_hidden", []):
            command += " \u202eexe.gnp"
        # Extra words after a well-formed command: run as more arguments.
        command += knobs.get("dry_run_suffix", {}).get(fid, "")
        answer = scan + 1 if fid in knobs.get("dry_run_other_scan", []) else scan
        print(json.dumps({"schema": 1, "scan": answer, "command": command}))
        sys.exit(0)
    if fid in knobs.get("fix_sleep", []):
        with open(paths["state"] + ".pid", "w") as f:
            f.write(str(os.getpid()))
        save()
        time.sleep(60)
    if fid in knobs.get("fix_fail", []):
        save()
        print("npm ERR! code E404 for " + row["component"], file=sys.stderr)
        sys.exit(1)
    # A sticky fix runs and exits 0, but the problem stays.
    if not knobs.get("sticky"):
        st["fixed"].append(fid)
    st["fixes"].append({"when": stamp(), "command": row["fix_cmd"], "ok": True,
                        "verified_scan": None, "targets": [key(row)]})
    save()
    print("Ran " + row["fix_cmd"])
elif cmd == "schedule":
    save()
    print(json.dumps({"schema": 1, "installed": False, "backend": "launchd", "enabled": None,
                      "interval": None, "every": None, "at": None, "last_run": None}))
elif cmd == "update":
    save()
    print(json.dumps({"current": os.environ["PANTRY_FAKE_VERSION"], "latest": os.environ["PANTRY_FAKE_VERSION"],
                      "available": False, "assets": [], "checked_at": "2026-05-05 20:11 UTC",
                      "stale": bool(knobs.get("update_stale"))}))
    sys.exit(0)
else:
    save()
    print(f"unsupported in the stand-in: {args}", file=sys.stderr)
    sys.exit(2)
"""


def desktop_version():
    text = (Path(__file__).resolve().parent.parent / "Cargo.toml").read_text()
    return next(line.split('"')[1] for line in text.splitlines() if line.startswith("version"))


def outcomes(app, temp, env):
    """What a fix and Fix all report when the stand-in scanner misbehaves.

    Oracle for each check: the stand-in's own state. A finding it still
    lists after the fix is "still open"; a fix that failed keeps what the
    scanner said; a reload that failed after a fix can't confirm anything;
    a cancelled job leaves the results usable; earlier scopes never count
    in the headline.
    """
    base = temp / "outcomes"
    main, other, gone = base / "main", base / "other", base / "gone"
    main.mkdir(parents=True)
    other.mkdir()
    fake = base / "scanner"
    fake.write_text(f"#!{sys.executable}\n" + OUTCOME_SCANNER)
    fake.chmod(0o755)
    knobs_file, state_file = base / "knobs.json", base / "state.json"
    profile = base / "profile"
    env = dict(env, PANTRY_FAKE_STATE=str(state_file), PANTRY_FAKE_KNOBS=str(knobs_file),
               PANTRY_FAKE_MAIN=str(main), PANTRY_FAKE_OTHER=str(other), PANTRY_FAKE_GONE=str(gone),
               PANTRY_FAKE_VERSION=desktop_version(), WPANTRY_DESKTOP_HOME=str(profile))

    def knobs(**values):
        knobs_file.write_text(json.dumps(values))

    def log():
        return json.loads(state_file.read_text())["log"]

    def wait_pid():
        pid_file = Path(str(state_file) + ".pid")
        deadline = time.time() + 10
        while not pid_file.exists():
            assert time.time() < deadline, "the stand-in never started"
            time.sleep(0.05)
        pid = int(pid_file.read_text())
        pid_file.unlink()
        return pid

    knobs()
    driver = Driver(app, fake, env)
    try:
        driver.settled()
        driver.action("scan", path=str(main), offline=True)
        state = driver.settled()

        # scanner text is shown without control or bidi characters.
        names = [f["component"] for f in state["report"]["findings"]]
        assert names == ["alpha", "bravognp.exe[31m"], names
        assert not any("‮" in label or "\x1b" in label for label in driver.labels())

        # the headline counts only the latest scan.
        assert driver.state()["headline_count"] == 2
        assert has_label(driver, "2 things need your attention"), driver.labels()
        earlier = {e["id"]: e for e in driver.state()["earlier"]}
        assert set(earlier) == {"e1", "e2"} and earlier["e2"]["missing_folders"] == [str(gone)], earlier
        # A folder that is gone says so and offers only Dismiss.
        assert driver.widget("earlier.e2.missing")["label"].startswith("That folder is no longer there.")
        assert not [n for n in driver.request("tree") if n["id"] == "earlier.e2.rescan"]
        assert "no longer there" in driver.request("dispatch", succeeds=False,
                                                   command={"action": "rescan_earlier", "id": "e2"})
        audit(driver, "from earlier scans")
        # Dismiss hides it, is saved, and Latest scan shows it again.
        driver.click("earlier.e2.dismiss")
        assert not [n for n in driver.request("tree") if n["id"] == "earlier.e2"]
        settings = json.loads((profile / "state" / "settings.json").read_text())
        assert settings["dismissed"] == ["e2"], settings
        assert any(e["id"] == "e2" for e in driver.state()["state"]["report"]["history"]["exposures"])
        driver.click("nav.results")
        assert driver.widget("earlier.dismissed")["label"] == "Dismissed from earlier scans (1)"
        driver.click("earlier.e2.restore")
        driver.click("nav.attention")
        assert driver.widget("earlier.e2")["label"].startswith("gone-tool")
        # Scan that folder again: a scan of exactly that path.
        driver.click("earlier.e1.rescan")
        state = driver.settled()
        assert log()[-2] == ["scan", "--json", "--no-input", "--no-machine", "--path", str(other), "--offline"], log()[-2]
        assert not any(e["id"] == "e1" for e in driver.state()["earlier"])
        driver.action("scan", path=str(main), offline=True)
        driver.settled()

        # Busy guard: one job at a time, and a row's Fix it is disabled
        # (not just unclickable) while a scan runs.
        knobs(scan_sleep=True)
        driver.action("scan", path=str(main), offline=True)
        pid = wait_pid()
        refused = driver.request("dispatch", succeeds=False,
                                 command={"action": "scan", "path": str(main), "offline": True})
        assert refused == "Wait for Pantry to finish the current task.", refused
        assert driver.widget("finding.f1.fix")["enabled"] is False
        # Cancel keeps the results usable.
        driver.click("task.cancel")
        state = driver.settled()
        assert not pid_alive(pid)
        assert state["error"]["kind"] == "cancelled" and state["report_error"] is None, state
        assert state["report"] is not None
        driver.click("error.dismiss")
        assert driver.state()["banner"] is None
        # A reload that is itself cancelled keeps the results it had.
        knobs(report_sleep=True)
        driver.action("refresh")
        wait_pid()
        driver.action("cancel")
        state = driver.settled()
        assert state["report_error"] is None and state["report"] is not None, state["report_error"]
        knobs()
        driver.action("select", id="f1")
        driver.click("fix.preview")
        assert driver.settled()["pending_fix"]["id"] == "f1"

        # a newer scan clears a pending fix and a Fix all confirm.
        driver.action("scan", path=str(main), offline=True)
        assert driver.settled()["pending_fix"] is None
        driver.click("fix.all")
        assert driver.settled()["batch"]["stage"] == "confirm"
        driver.action("scan", path=str(main), offline=True)
        assert driver.settled()["batch"] is None
        # Esc closes the Fix all confirm.
        driver.click("fix.all")
        driver.settled()
        assert driver.request("key", key="Escape")["state"]["batch"] is None
        # The exact commands are one click away in the confirm.
        driver.click("fix.all")
        driver.settled()
        driver.click("fix.all.commands")
        assert driver.widget("fix.all.item.f1.command")["label"] == "npm install alpha@2.0"
        driver.click("fix.all.cancel")
        driver.action("toggle_fix_details")

        # Still open: the fix exits 0 but the scanner still lists it.
        knobs(sticky=True)
        driver.action("select", id="f1")
        driver.click("fix.preview")
        driver.settled()
        driver.click("fix.confirm")
        state = driver.settled()
        assert state["fix_result"]["outcome"] == "still_open", state["fix_result"]
        assert driver.widget("fix.result")["label"].startswith("Still open."), driver.widget("fix.result")
        shown_once(driver, state["fix_result"]["message"])
        driver.click("fix.result.dismiss")
        driver.action("close_finding")
        driver.click("fix.all")
        driver.settled()
        driver.click("fix.all.confirm")
        batch = driver.settled()["batch"]
        assert [i["status"] for i in batch["items"]] == ["still_open", "still_open"], batch
        assert batch["message"] == "0 of 2 fixed and checked.", batch
        assert driver.widget("fix.all.item.f1")["label"] == "Still open"
        driver.click("fix.all.dismiss")

        # A real gap: nothing may read as Fixed.
        knobs(gap=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.click("fix.all")
        driver.settled()
        driver.click("fix.all.confirm")
        batch = driver.settled()["batch"]
        assert all(i["status"] == "unconfirmed" for i in batch["items"]), batch
        assert not any(driver.widget(f"fix.all.item.{i['id']}")["label"] == "Fixed" for i in batch["items"])
        driver.click("fix.all.dismiss")

        # a failed item keeps what the scanner said.
        knobs(sticky=True, fix_fail=["f2"], fresh=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.click("fix.all")
        driver.settled()
        driver.click("fix.all.confirm")
        batch = driver.settled()["batch"]
        failed = next(i for i in batch["items"] if i["id"] == "f2")
        assert failed["status"] == "failed" and "E404" in failed["details"], failed
        driver.click("fix.all.item.f2.details")
        assert "npm ERR! code E404" in driver.widget("fix.all.item.f2.raw")["label"]
        driver.click("fix.all.dismiss")

        # the reload after a fix fails: never "Still open".
        knobs(sticky=True, report_fails=True)
        driver.action("select", id="f1")
        driver.click("fix.preview")
        driver.settled()
        driver.click("fix.confirm")
        state = driver.settled()
        assert state["fix_result"]["outcome"] == "unconfirmed", state["fix_result"]
        assert state["fix_result"]["message"] == "Could not confirm. Scan again.", state["fix_result"]
        driver.click("fix.result.dismiss")
        driver.action("close_finding")
        driver.action("dismiss_error")
        assert driver.state()["state"]["report_error"] is None
        driver.click("fix.all")
        driver.settled()
        driver.click("fix.all.confirm")
        batch = driver.settled()["batch"]
        assert [i["message"] for i in batch["items"]] == ["Could not confirm. Scan again."] * 2, batch
        assert not any(i["status"] == "still_open" for i in batch["items"]), batch
        driver.click("fix.all.dismiss")
        driver.action("dismiss_error")

        # a cancelled fix may have partly run, and offers Scan now.
        knobs(fix_sleep=["f1"], fresh=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.action("select", id="f1")
        driver.click("fix.preview")
        driver.settled()
        driver.click("fix.confirm")
        pid = wait_pid()
        driver.click("task.cancel")
        state = driver.settled()
        assert not pid_alive(pid)
        assert state["error"]["kind"] == "fix_stopped", state["error"]
        # The results are read again after the cancelled fix.
        assert log()[-1] == ["report", "all", "--json"], log()[-1]
        assert "may have partly run" in state["error"]["summary"], state["error"]
        shown_once(driver, state["error"]["summary"])
        assert state["report_error"] is None
        knobs()
        before = len([a for a in log() if a[0] == "scan"])
        driver.click("error.scan")
        driver.settled()
        assert len([a for a in log() if a[0] == "scan"]) == before + 1

        # garbage from the scanner is "unexpected", never "Reinstall".
        knobs(scan_garbage=True)
        driver.action("scan", path=str(main), offline=True)
        banner = driver.settled() and driver.state()["banner"]
        assert banner["summary"].startswith("Pantry's scanner returned something unexpected."), banner
        assert "proxy error" in banner["details"], banner
        assert not [n for n in driver.request("tree") if n["id"] == "error.download"]
        driver.click("error.dismiss")

        # an old update answer says when Pantry last checked.
        knobs(update_stale=True)
        driver.click("updates.check")
        driver.settled()
        assert driver.widget("updates.stale")["label"].startswith("Could not check for updates. Last checked ")
        assert not has_label(driver, "You're up to date.")
        knobs()
        driver.click("updates.check")
        driver.settled()
        assert has_label(driver, "You're up to date.")
        assert not [n for n in driver.request("tree") if n["id"] == "updates.stale"]

        unverified = "Pantry could not verify the command for this fix."
        # A fix preview with a hidden character is refused as it was sent,
        # not cleaned and shown: one fix, and the same item in Fix all.
        knobs(dry_run_hidden=["f2"], fresh=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.action("select", id="f2")
        driver.click("fix.preview")
        state = driver.settled()
        assert state["pending_fix"] is None, state["pending_fix"]
        assert driver.state()["banner"]["summary"] == unverified, driver.state()["banner"]
        driver.action("dismiss_error")
        driver.action("close_finding")
        driver.click("fix.all")
        batch = driver.settled()["batch"]
        items = {i["id"]: i for i in batch["items"]}
        assert items["f2"]["status"] == "not_ready" and items["f2"]["message"] == unverified, items
        assert items["f2"]["command"] == "", items["f2"]
        assert items["f1"]["status"] == "waiting", items
        assert not any("\u202e" in label for label in driver.labels())
        driver.click("fix.all.cancel")
        # An answer for a different scan is refused the same way.
        knobs(dry_run_other_scan=["f1"])
        driver.click("fix.all")
        items = {i["id"]: i for i in driver.settled()["batch"]["items"]}
        assert items["f1"]["status"] == "not_ready" and items["f1"]["message"] == unverified, items
        driver.click("fix.all.cancel")
        # A preview with words beyond the known npm shape does not get the
        # specific "install the fixed version" sentence, and the whole
        # command shows without a click.
        extra = "npm install alpha@2.0; touch marker"
        knobs(dry_run_suffix={"f1": "; touch marker"})
        driver.action("select", id="f1")
        driver.click("fix.preview")
        assert driver.settled()["pending_fix"]["command"] == extra
        labels = driver.labels()
        assert any(l.startswith("Pantry will run one command. Then") for l in labels), labels
        assert not any("install the fixed version" in l for l in labels), labels
        assert extra in labels, labels
        assert not [n for n in driver.request("tree") if n["id"] == "fix.details"]
        driver.action("cancel_fix")
        # The plain command keeps the specific sentence behind Show the command.
        knobs()
        driver.click("fix.preview")
        driver.settled()
        labels = driver.labels()
        assert any(l.startswith("Pantry will update alpha from version 1.0 to 2.0.") for l in labels), labels
        assert "npm install alpha@2.0" not in labels and driver.widget("fix.details")
        driver.action("cancel_fix")
        driver.action("close_finding")

        # Cancel during Fix all: the running item is Stopped, the later one
        # Skipped, no check scan runs, and Scan now is offered in the card.
        knobs(fix_sleep=["f1"], fresh=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.click("fix.all")
        driver.settled()
        scans_before = len([a for a in log() if a[0] == "scan"])
        f2_runs = lambda: len([a for a in log() if a[:2] == ["fix", "f2"] and "--yes" in a])
        f2_before = f2_runs()
        driver.click("fix.all.confirm")
        pid = wait_pid()
        driver.click("task.cancel")
        batch = driver.settled()["batch"]
        assert not pid_alive(pid)
        assert [i["status"] for i in batch["items"]] == ["stopped", "skipped"], batch
        assert len([a for a in log() if a[0] == "scan"]) == scans_before, log()[-3:]
        assert f2_runs() == f2_before, "the later fix ran"
        assert driver.widget("fix.all.scan")["enabled"] is True
        # The summary line shows once, in the card, not again as the status.
        assert driver.widget("fix.all.result")["label"] == batch["message"]
        assert not [n for n in driver.request("tree") if n["id"] == "status.message"], "shown twice"
        driver.click("fix.all.scan")
        driver.settled()
        assert len([a for a in log() if a[0] == "scan"]) == scans_before + 1
        driver.click("fix.all.dismiss")
        knobs()

        # Offline: "Scan with saved data" repeats the scan that failed.
        knobs(scan_offline=True)
        driver.action("scan", path=str(main))
        driver.settled()
        assert driver.state()["banner"]["kind"] == "offline", driver.state()["banner"]
        driver.click("error.offline")
        driver.settled()
        assert log()[-2] == ["scan", "--json", "--no-input", "--no-machine", "--path", str(main), "--offline"], log()[-2]
        knobs()

        # A background reload keeps a banner being read.
        knobs(scan_garbage=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        banner = driver.state()["banner"]
        assert banner is not None
        cache = Path(env["WPANTRY_DB"])
        reports = len([a for a in log() if a[0] == "report"])
        cache.write_text(str(time.time()))
        driver.action("check_cache")
        driver.settled()
        assert len([a for a in log() if a[0] == "report"]) == reports + 1, log()[-2:]
        assert driver.state()["banner"] == banner, driver.state()["banner"]
        driver.action("dismiss_error")
        knobs()

        # Fix it is refused while the results could not be read.
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        knobs(report_fails=True, sticky=True)
        driver.action("select", id="f1")
        driver.click("fix.preview")
        driver.settled()
        driver.click("fix.confirm")
        assert driver.settled()["report_error"] is not None
        driver.action("select", id="f1")
        refused = driver.request("dispatch", succeeds=False, command={"action": "fix_it"})
        assert refused == "Reload results before running a fix.", refused
        knobs()
        driver.action("refresh")
        assert driver.settled()["report_error"] is None

        # Not checked against the attack list: the line says so, and a
        # finding with no notice summary has no quoted summary.
        knobs(gap=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.action("select", id="f1")
        assert driver.widget("finding.attacks")["label"] == "Pantry could not check whether attackers are using this."
        assert driver.state()["finding"]["attacks"] == "Pantry could not check whether attackers are using this."
        assert not [n for n in driver.request("tree") if n["id"] == "finding.summary"]
        driver.action("close_finding")
        knobs()

        # settings.json is right straight after Show again, and an unknown
        # id is refused without touching it.
        settings_file = profile / "state" / "settings.json"
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.click("earlier.e2.dismiss")
        assert driver.widget("status.message")["label"] == "Dismissed. Show it again from Latest scan."
        driver.click("nav.results")
        assert not [n for n in driver.request("tree") if n["id"] == "status.message"], "the status outlived navigation"
        driver.click("earlier.e2.restore")
        assert json.loads(settings_file.read_text())["dismissed"] == [], settings_file.read_text()
        before = settings_file.read_text()
        refused = driver.request("dispatch", succeeds=False, command={"action": "dismiss_earlier", "id": "nope"})
        assert refused == "This problem is no longer in the results.", refused
        assert settings_file.read_text() == before

        # At the smallest window, every Latest scan row is in the
        # accessibility tree, even one far below the fold, and can be
        # scrolled to. Known-bad: a list that lays out only visible rows
        # leaves the last row out of the tree.
        knobs(many=True)
        driver.action("scan", path=str(main), offline=True)
        driver.settled()
        driver.action("show", page="results")
        driver.request("resize", width=820, height=480)
        last = driver.widget("finding.f14")
        assert last["bounds"] and last["bounds"][1] >= 480, ("not below the fold", last)
        driver.request("scroll_into_view", id="finding.f14")
        last = driver.widget("finding.f14")
        assert last["bounds"] and inside(last["bounds"], [0, 0, 820, 480]), last
        driver.request("resize", width=1080, height=740)
        knobs()
    finally:
        driver.close()

    # Closing the driver's stdin while a scan runs stops that scan too.
    knobs(scan_sleep=True)
    driver = Driver(app, fake, env)
    driver.settled()
    driver.action("scan", path=str(main), offline=True)
    pid = wait_pid()
    driver.process.stdin.close()
    driver.process.wait(timeout=15)
    deadline = time.time() + 10
    while pid_alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not pid_alive(pid), f"scanner {pid} outlived the app"
    knobs()


def scanner_missing(app, temp, env):
    """Without a scanner, one plain message and a Download button."""
    alone = temp / "app alone"
    alone.mkdir()
    copy = alone / Path(app).name
    copy.write_bytes(Path(app).read_bytes())
    copy.chmod(0o755)
    env = dict(env, PATH=os.pathsep.join(p for p in ("/usr/bin", "/bin") if Path(p).is_dir()))
    driver = Driver(copy, None, env)
    try:
        state = driver.settled()
        assert state["scanner_found"] is False
        banner = driver.state()["banner"]
        assert banner["kind"] == "scanner_missing", banner
        assert "os error" not in banner["summary"]
        assert driver.widget("error.message")["label"] == banner["summary"]
        assert driver.widget("scan.run")["enabled"] is False
        assert driver.click("error.download")["browser"].endswith("/releases/latest")
        audit(driver, "scanner missing")
    finally:
        driver.close()


def settings_persist(app, scanner, temp, env):
    """Theme, details, page and window size survive a restart; a damaged
    settings file falls back to defaults."""
    profile = temp / "settings profile"
    env = dict(env, WPANTRY_DESKTOP_HOME=str(profile))
    settings = profile / "state" / "settings.json"
    driver = Driver(app, scanner, env)
    try:
        driver.settled()
        driver.click("theme.toggle")
        driver.click("view.details")
        driver.click("nav.history")
        driver.request("resize", width=820, height=480)
        # The minimum window keeps every control inside the frame.
        for node in audit(driver, "minimum window"):
            if node["id"] in ("scan.run", "nav.history", "theme.toggle"):
                x0, y0, x1, y1 = node["bounds"]
                assert x1 <= 820 and y0 >= 0, node
    finally:
        driver.close()
    saved = json.loads(settings.read_text())
    assert saved["light"] is True and saved["details"] is True and saved["page"] == "history", saved
    assert saved["window"] == [820, 480], saved
    driver = Driver(app, scanner, env)
    try:
        state = driver.settled()
        assert state["light"] is True and state["details"] is True and state["page"] == "history", state
    finally:
        driver.close()
    settings.write_text("{ this is not json")
    driver = Driver(app, scanner, env)
    try:
        state = driver.settled()
        assert state["light"] is False and state["details"] is False and state["page"] == "attention"
    finally:
        driver.close()


def demo_row_fits(driver):
    """At the 820 x 480 minimum, the demo High row's sentence wraps onto a
    second line, so the consequence starts in the row, and the row's
    accessible label and hover carry the whole sentence. Known-bad: the
    one-line row showed only "A specially made file or message…".
    The whole sentence (about 200 characters) does not fit in two lines of
    about 60 characters, so the second line still ends cut short."""
    report = driver.state()["state"]["report"]
    high = next(f["id"] for f in report["findings"] if f["vuln_id"] == "DEMO-2026-0001")
    driver.action("show", page="attention")
    driver.request("resize", width=820, height=480)
    state = driver.state()
    row = state["rows"].get(high)
    assert row and row["lines"] == 2, (row, state["rows"])
    label = driver.widget(f"finding.{high}")["label"]
    assert "run their own programs on this computer." in label, label
    driver.request("resize", width=1080, height=740)


def demo_rows(app, scanner, temp, env):
    """The home rows with the documentation's demo data, at the smallest
    window. Known-bad: a one-line row cut the High row's consequence short."""
    base = temp / "demo rows"
    project = base / "Projects" / "recipe-site"
    project.mkdir(parents=True)
    env = dict(env, WPANTRY_DESKTOP_HOME=str(base / "profile"), WPANTRY_DB=str(base / "pantry.db"))
    driver = Driver(app, scanner, env)
    try:
        driver.settled()
        driver.action("scan", path=str(project), offline=True)
        driver.settled()
        with fixture_db(env["WPANTRY_DB"]) as cache:
            for table in ("scans", "exposures", "findings"):
                cache.execute(f"DELETE FROM {table}")
            demo_seed(cache, project, base / "demo patch")
        driver.action("check_cache")
        driver.settled()
        demo_row_fits(driver)
    finally:
        driver.close()


def screens(app, scanner, temp, env, out):
    """Render each main screen to PNG in both palettes, headless (no window)."""
    out.mkdir(parents=True, exist_ok=True)
    project = temp / "Projects" / "recipe-site"
    project.mkdir(parents=True)
    driver = Driver(app, scanner, env)
    try:
        for theme in ("dark", "light"):
            def shot(name):
                driver.request("screenshot", path=str(out / f"{name}-{theme}.png"))
            driver.action("set_theme", theme=theme)
            if theme == "dark":
                driver.settled()
            with fixture_db(env["WPANTRY_DB"]) as cache:
                for table in ("scans", "exposures", "findings"):
                    try:
                        cache.execute(f"DELETE FROM {table}")
                    except sqlite3.OperationalError:
                        pass
            driver.action("refresh")
            driver.settled()
            shot("01-first-run")
            driver.action("scan", path=str(project), offline=True)
            driver.settled()
            with fixture_db(env["WPANTRY_DB"]) as cache:
                for table in ("scans", "exposures", "findings"):
                    cache.execute(f"DELETE FROM {table}")
                demo_seed(cache, project, temp / "screens patch")
            driver.action("check_cache")
            state = driver.settled()
            driver.action("show", page="attention")
            shot("02-home")
            driver.action("show_lower_priority", open=True)
            shot("03-home-all")
            auto = next(f["id"] for f in state["report"]["findings"] if f["vuln_id"] == "DEMO-2026-0001")
            manual = next(f["id"] for f in state["report"]["findings"] if f["vuln_id"] == "DEMO-2026-0002")
            driver.action("fix_all")
            driver.settled()
            shot("04-fix-all-confirm")
            driver.action("cancel_fix_all")
            driver.action("select", id=manual)
            shot("05-show-me-how")
            driver.action("select", id=auto)
            shot("11-what-is-this")
            driver.action("set_details", on=True)
            shot("12-technical-details")
            driver.action("set_details", on=False)
            driver.action("fix_it")
            driver.settled()
            shot("06-fix-confirm")
            driver.action("cancel_fix")
            driver.action("close_finding")
            driver.action("show", page="results")
            shot("07-latest-scan")
            driver.action("show", page="history")
            shot("08-history")
            driver.action("show", page="attention")
            driver.action("set_details", on=True)
            shot("09-home-details")
            driver.action("set_details", on=False)
            driver.request("resize", width=820, height=480)
            shot("10-minimum-window")
            demo_row_fits(driver)
            driver.request("resize", width=1080, height=740)
    finally:
        driver.close()
    print(f"Saved screens to {out}")


def bundle_plist(app, **expected):
    # The Dock name comes from these keys; LSUIElement keeps Setup out of the Dock.
    with (app / "Contents/Info.plist").open("rb") as stream:
        plist = plistlib.load(stream)
    for key, value in expected.items():
        assert plist.get(key) == value, (app.name, key, plist.get(key))


def extract_setup(setup, package):
    """Unpack a Setup download the way a user would and return its launcher."""
    package.mkdir()
    if setup.suffix == ".exe":
        return setup.resolve()
    if setup.suffix == ".zip":
        with ZipFile(setup) as archive:
            archive.extractall(package)
            for item in archive.infolist():
                (package / item.filename).chmod((item.external_attr >> 16) & 0o777)
        bundle_plist(package / "Pantry Setup.app", LSUIElement=True)
        return package / "Pantry Setup.app/Contents/MacOS/Pantry Setup"
    with tarfile.open(setup) as archive:
        names = sorted(archive.getnames())
        assert names == ["Pantry Setup", "README.txt", "pantry-setup.desktop"], names
        for item in archive.getmembers():
            assert item.mtime == 0 and item.uid == 0 and item.gid == 0, item.name
        archive.extractall(package, filter="data")
    launcher = package / "Pantry Setup"
    # The double-click launcher must resolve to Setup beside it.
    entry = package / "pantry-setup.desktop"
    assert os.access(entry, os.X_OK) and os.access(launcher, os.X_OK)
    argv = desktop_exec(entry, {"%k": str(entry)})
    assert argv[:2] == ["sh", "-c"], argv
    script = argv[2].replace("exec ", "test -x ", 1)
    assert subprocess.run([*argv[:2], script, *argv[3:]], timeout=10).returncode == 0, argv
    return launcher


def desktop_exec(entry, codes):
    """Split a Desktop Entry Exec value per the spec: string escapes first,
    then the quoting rules, then field codes as whole arguments."""
    line = next(l for l in entry.read_text().splitlines() if l.startswith("Exec="))[5:]
    value, i = "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            value += {"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(line[i + 1], "\\" + line[i + 1])
            i += 2
        else:
            value += line[i]
            i += 1
    args, current, quoted, started, i = [], "", False, False, 0
    while i < len(value):
        c = value[i]
        if quoted and c == "\\" and i + 1 < len(value) and value[i + 1] in '"`$\\':
            current += value[i + 1]
            i += 2
            continue
        if c == '"':
            quoted, started = not quoted, True
        elif c == " " and not quoted:
            if started:
                args.append(codes.get(current, current))
            current, started = "", False
        else:
            current += c
            started = True
        i += 1
    assert not quoted, value
    if started:
        args.append(codes.get(current, current))
    return args


# A stand-in launchctl that remembers whether the job is loaded, in a file
# beside it: bootstrap loads it, bootout unloads it, and print fails once it
# is gone, as the real one does. It never reaches the real user's jobs.
LAUNCHCTL = """#!/bin/sh
state="$(dirname "$0")/.launchd-job"
case "$1" in
  bootstrap) echo loaded > "$state" ;;
  bootout) [ -e "$(dirname "$0")/.bootout-fails" ] && { echo "Boot-out failed: 5: Input/output error" >&2; exit 5; }
           echo gone > "$state" ;;
  print) grep -qx loaded "$state" 2>/dev/null || exit 113 ;;
esac
exit 0
"""


def fake_tools(folder, names, log):
    """Stand-ins that record their arguments. Dialog tools and schedulers
    must never reach the real desktop or the real user's jobs."""
    folder.mkdir()
    for name in names:
        tool = folder / name
        record = f'printf "%s\\n" "{name} $*" >> {shlex.quote(str(log))}\n'
        if name == "launchctl":
            tool.write_text(LAUNCHCTL.replace("#!/bin/sh\n", "#!/bin/sh\n" + record, 1))
        else:
            tool.write_text(f"#!/bin/sh\n{record}exit 0\n")
        tool.chmod(0o755)


@contextmanager
def held(path):
    import fcntl
    with path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def setup_lifecycle(launcher, temp, env):
    """Shortcuts, the running-app guards and --uninstall, in a profile of
    their own so the main install stays for the UI checks."""
    profile = temp / "lifecycle profile"
    env = dict(env, WPANTRY_DESKTOP_HOME=str(profile))
    log = temp / "lifecycle tools.log"
    if sys.platform != "win32":
        fake_tools(temp / "lifecycle bin", ["osascript", "open", "zenity", "kdialog", "notify-send",
                                            "launchctl", "systemctl", "crontab"], log)
        env["PATH"] = str(temp / "lifecycle bin") + os.pathsep + env["PATH"]
    run = lambda *extra: subprocess.run([launcher, *extra], env=env, capture_output=True, text=True, timeout=60)
    assert run("--install-only").returncode == 0
    destination, state = profile / "installed", profile / "state"
    marker = destination / ".waffuru-pantry-desktop"
    bundled = marker.read_text()
    shortcuts = profile / "shortcuts"
    if sys.platform == "win32":
        assert (shortcuts / "Pantry.lnk").is_file()
        return  # Locks and schtasks below are POSIX-only stand-ins.
    if sys.platform.startswith("linux"):
        entry = shortcuts / "applications/ai.waffuru.pantry.desktop"
        assert desktop_exec(entry, {}) == [str(destination / "wpantry-desktop")]
        assert "StartupWMClass=ai.waffuru.pantry.desktop" in entry.read_text()
        icon = shortcuts / "icons/hicolor/256x256/apps/ai.waffuru.pantry.png"
        assert icon.read_bytes().startswith(b"\x89PNG")

    # Pantry open and the install older: refuse in plain words, change nothing.
    marker.write_text("0.0.1")
    with held(state / "window.lock"):
        result = run("--install-only")
        assert result.returncode != 0 and "Pantry is open. Quit Pantry" in result.stderr, result
        result = run()  # a double-click also shows the dialog
        assert result.returncode != 0 and "Pantry is open" in log.read_text()
        assert marker.read_text() == "0.0.1"
        # Up to date: a plain relaunch only brings the window forward.
        marker.write_text(bundled)
        activation = state / "activate"
        before = activation.stat().st_size if activation.exists() else 0
        log.unlink()
        assert run().returncode == 0
        assert activation.stat().st_size == before + 1 and not log.exists()
        assert "Pantry is open" in run("--uninstall").stderr
    # A second Setup while one runs exits quietly and installs nothing.
    marker.write_text("0.0.1")
    with held(state / "setup.lock"):
        assert run("--install-only").returncode == 0 and marker.read_text() == "0.0.1"
    # A staging folder from a killed run is cleaned on the next install.
    stale = profile / ".pantry-setup-999999"
    (stale / "Pantry").mkdir(parents=True)
    assert run("--install-only").returncode == 0 and marker.read_text() == bundled
    assert not stale.exists()

    # Uninstall removes the app and its menu entry, asks the installed
    # scanner to drop the schedule, and keeps the state folder.
    (state / "keep").write_text("user data")
    result = run("--uninstall")
    assert result.returncode == 0, result
    assert not destination.exists() and (state / "keep").read_text() == "user data"
    assert not (shortcuts / "applications/ai.waffuru.pantry.desktop").exists()
    calls = log.read_text()
    assert any(tool in calls for tool in ("launchctl bootout", "systemctl", "crontab")), calls


def setup_install(setup, temp, env):
    launcher = extract_setup(setup, temp / "Pantry setup package")
    setup_lifecycle(launcher, temp, env)
    profile = temp / "desktop profile"
    env["WPANTRY_DESKTOP_HOME"] = str(profile)
    destination = profile / "installed"
    destination.mkdir(parents=True)
    sentinel = destination / "owned by user"
    sentinel.touch()
    args = [launcher, "--install-only"]
    refused = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
    assert refused.returncode != 0 and "Move or delete that folder" in refused.stderr, refused
    assert sentinel.is_file()
    sentinel.unlink()
    destination.rmdir()
    for _ in range(2):
        subprocess.run(args, env=env, check=True, capture_output=True, timeout=30)
    marker = destination / ".waffuru-pantry-desktop"
    installed = marker.read_text()
    marker.write_text("999.0.0")
    subprocess.run(args, env=env, check=True, capture_output=True, timeout=30)
    assert marker.read_text() == "999.0.0"
    marker.write_text(installed)
    if sys.platform == "darwin":
        bundle_plist(destination / "Pantry.app", CFBundleName="Pantry", CFBundleDisplayName="Pantry")
        return (destination / "Pantry.app/Contents/MacOS/Pantry",
                destination / "Pantry.app/Contents/MacOS/wpantry")
    ext = ".exe" if sys.platform == "win32" else ""
    return destination / f"wpantry-desktop{ext}", destination / f"wpantry{ext}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", nargs="?", type=Path)
    parser.add_argument("scanner", nargs="?", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--screens", type=Path, help="only render PNGs of each screen into this folder")
    args = parser.parse_args()
    if not (args.bundle or args.setup or (args.app and args.scanner)):
        parser.error("Provide an app and scanner, --bundle ZIP, or --setup INSTALLER.")
    with tempfile.TemporaryDirectory(prefix="pantry-desktop-tests-") as root:
        temp = Path(root)
        if args.bundle:
            package = temp / "Pantry package"
            with ZipFile(args.bundle) as archive:
                archive.extractall(package)
                for item in archive.infolist():
                    (package / item.filename).chmod((item.external_attr >> 16) & 0o777)
            ext = ".exe" if sys.platform == "win32" else ""
            if sys.platform == "darwin":
                app = package / "Pantry.app/Contents/MacOS/Pantry"
                bundle_plist(package / "Pantry.app", CFBundleName="Pantry", CFBundleDisplayName="Pantry")
                scanner = app.with_name("wpantry")
            else:
                app, scanner = package / f"wpantry-desktop{ext}", package / f"wpantry{ext}"
        elif not args.setup:
            app, scanner = args.app.resolve(), args.scanner.resolve()
        env = dict(os.environ, HOME=root, USERPROFILE=root, WPANTRY_DB=str(temp / "pantry.db"),
                   XDG_STATE_HOME=str(temp / "state"), XDG_CONFIG_HOME=str(temp / "config"),
                   WPANTRY_NO_UPDATE_CHECK="1", NO_COLOR="1")
        if args.setup:
            app, scanner = setup_install(args.setup, temp, env)
        if sys.platform != "win32":
            # Only the scheduler is faked. The real scanner still writes and
            # reads its launch-agent or timer files in the fixture directory.
            tools = temp / "bin"
            tools.mkdir()
            for name in ("launchctl", "systemctl"):
                tool = tools / name
                tool.write_text(LAUNCHCTL if name == "launchctl" else "#!/bin/sh\nexit 0\n")
                tool.chmod(0o755)
            env["PATH"] = str(tools) + os.pathsep + env["PATH"]
            env["XDG_RUNTIME_DIR"] = str(temp / "runtime")
        if args.screens:
            screens(app, scanner, temp, env, args.screens.resolve())
            sys.exit(0)
        driver = Driver(app, None if args.bundle or args.setup else scanner, env)
        try:
            checks(driver, scanner, temp, env)
        finally:
            driver.close()
        explicit = None if args.bundle or args.setup else scanner
        settings_persist(app, explicit, temp, env)
        demo_rows(app, explicit, temp, env)
        if not (args.bundle or args.setup):
            scanner_missing(app, temp, env)
        if sys.platform != "win32":
            cancel_and_timeout(app, temp, env)
            outcomes(app, temp, env)
            machine_scope(app, temp, env, gap=False)
            machine_scope(app, temp, env, gap=True)
    print("Pantry desktop end-to-end checks passed.")
