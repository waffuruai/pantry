"""vet_actions.py against made-up workflows and records, with the GitHub API faked:

    python3 -m unittest discover -s scripts
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import vet_actions as vet

SHA_A = "a" * 40
SHA_B = "b" * 40
TAG_OBJ = "c" * 40
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
API = vet.API


def entry(action: str, sha: str, version: str, **extra: str) -> str:
    lines = [
        "[[audit]]",
        f'action = "{action}"',
        f'sha = "{sha}"',
        f'version = "{version}"',
        'who = "Waffuru AI, Inc. <security@waffuru.ai>"',
        "date = 2026-10-31",
        'notes = "read the compare"',
    ]
    lines += [f'{k} = "{v}"' for k, v in extra.items()]
    return "\n".join(lines) + "\n"


class Fake:
    """api.github.com as a dict of URL -> document; anything else is a 404."""

    def __init__(self, docs: dict[str, dict]):
        self.docs = docs
        self.asked: list[str] = []

    def __call__(self, url: str) -> dict | None:
        self.asked.append(url)
        return self.docs.get(url)


def lightweight(action: str, version: str, sha: str, published: datetime) -> dict[str, dict]:
    return {
        f"{API}/repos/{action}/git/ref/tags/{version}": {"object": {"type": "commit", "sha": sha}},
        f"{API}/repos/{action}/releases/tags/{version}": {"published_at": published.isoformat().replace("+00:00", "Z")},
    }


class Workflows(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.workflows = self.root / "workflows"
        self.workflows.mkdir()

    def tearDown(self) -> None:
        self.dir.cleanup()

    def workflow(self, name: str, text: str) -> None:
        (self.workflows / name).write_text(text)

    def record(self, text: str) -> dict:
        p = self.root / "actions-audits.toml"
        p.write_text(text)
        entries, problems = vet.record_in(p)
        self.assertEqual(problems, [])
        return entries

    def test_uses_are_read_with_their_version_comments(self) -> None:
        self.workflow(
            "ci.yml",
            f"steps:\n  - uses: actions/checkout@{SHA_A} # v7.0.1\n"
            f"  - name: x\n    uses: 'jdx/mise-action@{SHA_B}'   # v5.2.3\n"
            "  - uses: ./local/action\n  - uses: docker://alpine:3\n"
            f"  - uses: owner/repo/.github/workflows/reuse.yml@{SHA_A} # v1\n"
            "  - uses: actions/setup-node@v4\n",
        )
        got = vet.uses_in(self.workflows)
        self.assertEqual(
            [(u.action, u.ref, u.version, u.line) for u in got],
            [
                ("actions/checkout", SHA_A, "v7.0.1", 2),
                ("jdx/mise-action", SHA_B, "v5.2.3", 4),
                ("owner/repo", SHA_A, "v1", 7),
                ("actions/setup-node", "v4", None, 8),
            ],
        )

    def test_pins_record_and_leftovers(self) -> None:
        self.workflow(
            "ci.yml",
            f"- uses: actions/checkout@{SHA_A} # v7.0.1\n"
            f"- uses: jdx/mise-action@{SHA_B} # v5.2.4\n"
            "- uses: actions/setup-node@v4 # v4\n"
            f"- uses: docker/build-push-action@{SHA_A}\n"
            f"- uses: sigstore/cosign-installer@{SHA_B} # v4.1.2\n",
        )
        entries = self.record(
            entry("actions/checkout", SHA_A, "v7.0.1")
            + entry("jdx/mise-action", SHA_B, "v5.2.3")
            + entry("actions/upload-artifact", SHA_A, "v7.0.2")
        )
        problems = vet.check(vet.uses_in(self.workflows), entries, fetch=None)
        self.assertEqual(len(problems), 5, problems)
        self.assertIn("ci.yml:2: jdx/mise-action@" + SHA_B + " is v5.2.4 in the workflow and v5.2.3", problems[0])
        self.assertIn("ci.yml:3: actions/setup-node@v4 is not pinned", problems[1])
        self.assertIn("ci.yml:4: docker/build-push-action@" + SHA_A + " has no version comment", problems[2])
        self.assertIn("ci.yml:5: sigstore/cosign-installer@" + SHA_B + " (v4.1.2) is not in", problems[3])
        self.assertIn("nothing uses actions/upload-artifact@" + SHA_A, problems[4])

    def test_a_clean_offline_check_has_no_problems(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        entries = self.record(entry("actions/checkout", SHA_A, "v7.0.1"))
        self.assertEqual(vet.check(vet.uses_in(self.workflows), entries, fetch=None), [])

    def test_a_record_entry_needs_every_field(self) -> None:
        p = self.root / "actions-audits.toml"
        p.write_text('[[audit]]\naction = "actions/checkout"\nsha = "' + SHA_A + '"\n')
        entries, problems = vet.record_in(p)
        self.assertEqual(entries, {})
        self.assertEqual(len(problems), 1)
        self.assertIn("lacks version, who, date, notes", problems[0])
        p.write_text(entry("actions/checkout", SHA_A, "v7.0.1") * 2)
        _, problems = vet.record_in(p)
        self.assertIn("recorded twice", problems[0])

    def test_tags_must_resolve_to_the_pinned_commit(self) -> None:
        self.workflow(
            "ci.yml",
            f"- uses: actions/checkout@{SHA_A} # v7.0.1\n- uses: jdx/mise-action@{SHA_B} # v5.2.3\n",
        )
        entries = self.record(
            entry("actions/checkout", SHA_A, "v7.0.1") + entry("jdx/mise-action", SHA_B, "v5.2.3")
        )
        old = NOW - timedelta(days=30)
        fake = Fake({**lightweight("actions/checkout", "v7.0.1", SHA_A, old), **lightweight("jdx/mise-action", "v5.2.3", SHA_A, old)})
        problems = vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW)
        self.assertEqual(problems, [f"jdx/mise-action: tag v5.2.3 is commit {SHA_A}, not the pinned {SHA_B}"])
        fake = Fake(lightweight("actions/checkout", "v7.0.1", SHA_A, old))
        problems = vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW)
        self.assertEqual(problems, ["jdx/mise-action: tag v5.2.3 does not exist"])

    def test_an_annotated_tag_is_dereferenced_and_dated(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        entries = self.record(entry("actions/checkout", SHA_A, "v7.0.1"))
        fake = Fake(
            {
                f"{API}/repos/actions/checkout/git/ref/tags/v7.0.1": {"object": {"type": "tag", "sha": TAG_OBJ}},
                f"{API}/repos/actions/checkout/git/tags/{TAG_OBJ}": {
                    "object": {"type": "commit", "sha": SHA_A},
                    "tagger": {"date": "2026-10-01T00:00:00Z"},
                },
            }
        )
        self.assertEqual(vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW), [])
        self.assertNotIn(f"{API}/repos/actions/checkout/commits/{SHA_A}", fake.asked, "the tag carries the date")

    def test_a_release_younger_than_72_hours_is_refused_unless_exempt(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        young = NOW - timedelta(hours=10)
        fake = Fake(lightweight("actions/checkout", "v7.0.1", SHA_A, young))
        entries = self.record(entry("actions/checkout", SHA_A, "v7.0.1"))
        problems = vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW)
        self.assertEqual(len(problems), 1)
        self.assertIn("published 10 hours ago", problems[0])
        entries = self.record(entry("actions/checkout", SHA_A, "v7.0.1", age_exempt="fixes GHSA-xxxx in the checkout step"))
        self.assertEqual(vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW), [])

    def test_the_date_falls_back_to_the_commit(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        entries = self.record(entry("actions/checkout", SHA_A, "v7.0.1"))
        fake = Fake(
            {
                f"{API}/repos/actions/checkout/git/ref/tags/v7.0.1": {"object": {"type": "commit", "sha": SHA_A}},
                f"{API}/repos/actions/checkout/commits/{SHA_A}": {"commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}},
            }
        )
        self.assertEqual(vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW), [])
        fake = Fake({f"{API}/repos/actions/checkout/git/ref/tags/v7.0.1": {"object": {"type": "commit", "sha": SHA_A}}})
        problems = vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW)
        self.assertEqual(problems, ["actions/checkout: no date found for v7.0.1; cannot apply the 3 days, 0:00:00 age rule"])

    def test_network_checks_wait_for_a_clean_record(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        entries = self.record("")
        fake = Fake({})
        problems = vet.check(vet.uses_in(self.workflows), entries, fake, now=NOW)
        self.assertEqual(len(problems), 1)
        self.assertEqual(fake.asked, [], "nothing is asked of GitHub until the record is right")

    def test_main_reports_and_exits(self) -> None:
        self.workflow("ci.yml", f"- uses: actions/checkout@{SHA_A} # v7.0.1\n")
        record = self.root / "actions-audits.toml"
        record.write_text(entry("actions/checkout", SHA_A, "v7.0.1"))
        args = ["--offline", "--workflows", str(self.workflows), "--record", str(record)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(vet.main(args), 0)
            record.write_text("")
            self.assertEqual(vet.main(args), 1)
        self.assertIn("1 actions in 1 uses: pins and record checked", out.getvalue())
        self.assertIn("is not in actions-audits.toml", err.getvalue())


if __name__ == "__main__":
    unittest.main()
