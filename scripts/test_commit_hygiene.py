"""commit_hygiene.py against made-up commits and PR text, with the GitHub API faked:

    python3 -m unittest discover -s scripts

Fixtures that carry an attribution are assembled at run time, so this file
itself never trips a commit-msg hook or a scan for those lines.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path
from unittest import mock

import commit_hygiene as ch

CO = "Co-" + "Authored-By"
CO_GH = "Co-" + "authored-by"
SOB = "Signed-" + "off-by"
VENDOR = "noreply@" + "anthropic.com"
AI_NAME = "Clau" + "de Opus 5.5"
ROBOT = chr(0x1F916)
TOOL = "Clau" + "de Code"

HUMAN = ("Joshua Pinter", "joshuapinter@gmail.com")
WEB_FLOW = ("GitHub", "noreply@github.com")
DEPENDABOT = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")

# The squash commit of #387, verbatim but for the trailer, assembled here.
PR_387 = (
    "fix: pass over a logged-out gh when verifying an update\n"
    "\n"
    "wpantry update used gh whenever it was on PATH, and gh attestation verify\n"
    "needs a login, so a logged-out gh failed the update even when cosign was\n"
    "installed. gh exits 4 when a command needs a login it doesn't have (gh help\n"
    "exit-codes), having checked nothing. selfinstall now passes that gh over\n"
    "for the next verifier, as install.sh passes over a gh that isn't logged in,\n"
    "and names it when no verifier is left. A gh that ran and failed is still an\n"
    "error, never skipped for cosign.\n"
    "\n"
    f"{CO}: {AI_NAME} <{VENDOR}>\n"
)


def commit(message: str, author=HUMAN, committer=WEB_FLOW, sha="d80a9e8af0c4", **kw) -> ch.Commit:
    return ch.Commit(sha, message, author[0], author[1], kw.pop("author_login", ""),
                     committer[0], committer[1], kw.pop("committer_login", ""), **kw)


def kinds(findings):
    return [f.what for f in findings]


class MessageRules(unittest.TestCase):
    def test_pr_387_verbatim_fails_on_its_trailer(self):
        got = ch.commit_findings(commit(PR_387))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].lineno, 11)
        self.assertIn("AI vendor address", got[0].what)
        self.assertIn("d80a9e8", got[0].render())

    def test_ai_coauthor_trailer_by_name_and_noreply(self):
        for value in (f"{TOOL} <{VENDOR}>", "Copilot <175728472+Copilot@users.noreply.github.com>",
                      "Cursor Agent <cursoragent@cursor.com>", "aider (gpt-4o) <noreply@aider.chat>",
                      "Devin AI <158243242+devin-ai-integration[bot]@users.noreply.github.com>",
                      "Codex <codex@openai.com>", "Gemini <gemini@example.com>"):
            with self.subTest(value=value):
                self.assertTrue(ch.message_findings(f"fix: x\n\nbody\n\n{CO_GH}: {value}\n", "c"))

    def test_signoff_and_other_credit_keys_naming_a_tool(self):
        for line in (f"{SOB}: {TOOL} <{VENDOR}>", "Assisted-by: GPT-5", "Generated-by: Windsurf",
                     "Made-with: Cursor", "Helped-by: Grok"):
            with self.subTest(line=line):
                self.assertTrue(ch.message_findings(f"fix: x\n\n{line}\nmore body\n", "c"))

    def test_trailer_mid_message_is_caught(self):
        text = f"fix: x\n\n{CO}: {AI_NAME} <{VENDOR}>\n\nA closing paragraph.\n"
        self.assertEqual(len(ch.message_findings(text, "c")), 1)

    def test_tool_keyed_trailer_in_closing_paragraph(self):
        text = "fix: x\n\nbody\n\n" + "Clau" + "de-Session: https://example.invalid/session_1\n"
        self.assertEqual(kinds(ch.message_findings(text, "c")), [("Clau" + "de-Session") + " trailer names an AI tool"])

    def test_closing_trailer_block_value_naming_a_tool(self):
        text = "fix: x\n\nbody\n\nModel: " + "clau" + "de-opus-5-5\n"
        self.assertEqual(len(ch.message_findings(text, "c")), 1)

    def test_robot_footer_and_generated_with_phrase(self):
        self.assertEqual(kinds(ch.message_findings(f"body\n\n{ROBOT} Generated with [{TOOL}](https://x)\n", "c")),
                         ["AI footer (robot emoji)"])
        self.assertEqual(kinds(ch.message_findings(f"This change was generated with {TOOL}.\n", "c")),
                         ["AI attribution phrase"])

    def test_human_coauthors_and_signoffs_pass(self):
        text = (f"feat: y\n\nbody\n\n{CO_GH}: Eric Kryski <599019+ekryski@users.noreply.github.com>\n"
                f"{CO_GH}: Tom Turney <tturney1@gmail.com>\n{SOB}: Joshua Pinter <joshuapinter@gmail.com>\n")
        self.assertEqual(ch.message_findings(text, "c"), [])

    def test_a_person_named_like_a_tool_passes_with_a_personal_address(self):
        self.assertEqual(ch.message_findings(f"x\n\nbody\n\n{CO_GH}: " + "Clau" + "de <claude@monet.example>\n", "c"), [])
        self.assertTrue(ch.message_findings(f"x\n\nbody\n\n{CO_GH}: " + "Clau" + "de <noreply@example.com>\n", "c"))

    def test_bare_mentions_and_ordinary_trailers_pass(self):
        for text in ("docs: point AGENTS.md and .cursor/rules at CONTRIBUTING\n",
                     "feat: compare with the llama.cpp CVE list\n\nWe asked Gemini for nothing; prose is fine.\n",
                     "fix: build with -O3\n\nbody\n\nRefs: #12\nTests: 7/7\n",
                     "feat: one line conventional subject\n"):
            with self.subTest(text=text):
                self.assertEqual(ch.message_findings(text, "c"), [])


class Identities(unittest.TestCase):
    def test_ai_author_fails_even_with_a_clean_message(self):
        got = ch.commit_findings(commit("fix: clean message\n", author=(AI_NAME, VENDOR), committer=(AI_NAME, VENDOR)))
        self.assertEqual(kinds(got), ["author is not a person", "committer is not a person"])
        self.assertIn("co-author of the squash commit", got[0].line)

    def test_bot_accounts_fail(self):
        for ident in (("copilot-swe-agent[bot]", "198982749+Copilot@users.noreply.github.com"),
                      ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com")):
            with self.subTest(ident=ident):
                self.assertTrue(ch.commit_findings(commit("chore: x\n", author=ident)))
        self.assertTrue(ch.commit_findings(commit("chore: x\n", author=("Some App", "app@example.com"), author_type="Bot")))

    def test_allowlist_web_flow_and_dependabot(self):
        msg = (f"chore(deps): bump serde\n\nBumps serde.\n\n---\nupdated-dependencies:\n- dependency-name: serde\n\n"
               f"{SOB}: dependabot[bot] <support@github.com>\n")
        self.assertEqual(ch.commit_findings(commit(msg, author=DEPENDABOT, author_login="dependabot[bot]",
                                                   committer=WEB_FLOW, committer_login="web-flow")), [])
        squash = f"chore(deps): bump serde (#5)\n\nbody\n\n{CO_GH}: {DEPENDABOT[0]} <{DEPENDABOT[1]}>\n"
        self.assertEqual(ch.commit_findings(commit(squash, author=HUMAN)), [])

    def test_human_author_on_users_noreply_passes(self):
        self.assertEqual(ch.commit_findings(commit("x\n", author=("Eric Kryski", "599019+ekryski@users.noreply.github.com"))), [])


class PullRequestText(unittest.TestCase):
    def test_pr_body_footer_and_trailer(self):
        body = ("## Summary\n\nFixes a thing.\n\n## AI assistance disclosure\n\n"
                "- [x] Research\n- [ ] No AI used\n\n" + f"{ROBOT} Generated with [{TOOL}](https://x)\n")
        got = ch.pr_findings("fix: a thing", body)
        self.assertEqual([(f.where, f.lineno) for f in got], [("PR body", 10)])
        body2 = f"Summary.\n\n{CO_GH}: {AI_NAME} <{VENDOR}>\n"
        self.assertEqual([f.where for f in ch.pr_findings("fix: a thing", body2)], ["PR body"])

    def test_pr_title(self):
        self.assertEqual([f.where for f in ch.pr_findings(f"feat: x, generated with {TOOL}", "")], ["PR title"])

    def test_template_disclosure_passes(self):
        with open(Path(__file__).resolve().parent.parent / ".github/PULL_REQUEST_TEMPLATE.md", encoding="utf-8") as fh:
            template = fh.read().replace("- [ ]", "- [x]")
        self.assertEqual(ch.pr_findings("feat: x", template), [])


def api_commit(message, author=HUMAN, committer=WEB_FLOW, sha="a" * 40, login="joshuapinter"):
    return {"sha": sha, "commit": {"message": message, "author": {"name": author[0], "email": author[1]},
                                   "committer": {"name": committer[0], "email": committer[1]}},
            "author": {"login": login, "type": "User"}, "committer": {"login": "web-flow", "type": "User"}}


class Events(unittest.TestCase):
    def fake(self, responses):
        def run(cmd):
            path = next(a for a in cmd if a.startswith("repos/"))
            for prefix, value in responses.items():
                if path.startswith(prefix):
                    return value if isinstance(value, str) else json.dumps(value)
            raise AssertionError(path)
        return mock.patch.object(ch, "_run", side_effect=run)

    def test_pull_request_checks_commits_identity_and_body(self):
        event = {"pull_request": {"number": 387, "title": "fix: pass over a logged-out gh", "body": f"ok\n\n{ROBOT} x\n"}}
        pages = [[api_commit("fix: clean\n"), api_commit("fix: two\n", author=(AI_NAME, VENDOR), sha="b" * 40, login="")]]
        with self.fake({"repos/o/r/pulls/387/commits": pages, "repos/o/r/compare/main...": "ahead\n"}):
            got = ch.from_event(event, "pull_request", "o/r")
        self.assertEqual([f.where.split(" (")[0] for f in got], ["commit bbbbbbb", "PR body"])

    def test_commits_already_on_main_are_skipped(self):
        event = {"pull_request": {"number": 1, "title": "chore: merge main", "body": ""}}
        with self.fake({"repos/o/r/pulls/1/commits": [[api_commit(PR_387)]], "repos/o/r/compare/main...": "behind\n"}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ch.from_event(event, "pull_request", "o/r"), [])

    def test_push_reports_new_commits(self):
        event = {"before": "1" * 40, "after": "2" * 40}
        with self.fake({"repos/o/r/compare/": [{"commits": [api_commit(PR_387)]}]}):
            got = ch.from_event(event, "push", "o/r")
        self.assertEqual(len(got), 1)

    def test_report_prints_where_and_how_to_fix(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = ch.report(ch.commit_findings(commit(PR_387)) + ch.pr_findings("x", f"{ROBOT} y"), annotate=True)
        text = out.getvalue()
        self.assertEqual(rc, 1)
        for needle in ("commit d80a9e8", "line 11", "git rebase -i", "--reset-author", "edit the pull request",
                       "::error title=Commit hygiene::"):
            self.assertIn(needle, text)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ch.report([]), 0)


class Workflow(unittest.TestCase):
    """The job runs the base's checker, never the pull request's."""

    def test_checks_out_the_base_and_asserts_it(self):
        wf = (Path(__file__).resolve().parent.parent / ".github/workflows/commit-hygiene.yml").read_text(encoding="utf-8")
        self.assertIn("CHECKER_SHA: ${{ github.event.pull_request.base.sha || github.sha }}", wf)
        self.assertIn("ref: ${{ env.CHECKER_SHA }}", wf)
        self.assertIn('[ "$(git rev-parse HEAD)" = "$CHECKER_SHA" ]', wf)
        self.assertIn('python3 "$CHECKER"', wf)
        self.assertNotIn("pull_request_target", wf.split("\non:")[1])
        self.assertIn("edited", wf)


if __name__ == "__main__":
    unittest.main()
