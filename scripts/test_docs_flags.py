"""docs_flags.py against a stand-in scanner whose help is fixed text:

    python3 -m unittest discover -s scripts
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import docs_flags

HELP = {
    "": "Usage: wpantry [options] [command]\n\nOptions:\n  -h, --help  print this help\n\n"
        "Commands:\n  scan [options]  Scan\n  schedule <command>  Schedule\n",
    "scan": "Usage: wpantry scan [options]\n\nOptions:\n  --json  JSON\n  --no-personal-files  skip\n",
    "schedule": "Usage: wpantry schedule <command>\n\nCommands:\n  status [options]  Status\n  run  Run\n",
    "schedule status": "Usage: wpantry schedule status [options]\n\nOptions:\n  --json  JSON\n",
    "schedule run": "Usage: wpantry schedule run\n",
}


def fake_scanner(folder: Path) -> str:
    """A POSIX shell scanner that prints HELP for `<path> --help`."""
    cases = "\n".join(
        f"  '{key}') cat <<'TEXT'\n{text}TEXT\n  ;;" for key, text in HELP.items()
    )
    script = folder / "wpantry"
    script.write_text(
        "#!/bin/sh\npath=\"\"\nfor a in \"$@\"; do [ \"$a\" = --help ] && break; "
        "path=\"${path:+$path }$a\"; done\ncase \"$path\" in\n" + cases + "\n  *) exit 2 ;;\nesac\n"
    )
    script.chmod(0o755)
    return str(script)


@unittest.skipIf(sys.platform == "win32", "the stand-in scanner is a shell script")
class DocsFlags(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.scanner = fake_scanner(self.folder)

    def tearDown(self):
        self.temp.cleanup()

    def doc(self, text: str) -> Path:
        path = self.folder / "doc.md"
        path.write_text(text)
        return path

    def test_real_commands_and_flags_pass(self):
        doc = self.doc(
            "Run `wpantry scan --json` or `wpantry schedule status --json`.\n\n"
            "```bash\nwpantry schedule run\nwpantry scan ~/code --no-personal-files\n```\n"
            "With `wpantry scan`, `--no-personal-files` skips folders.\n"
            "Pantry Setup takes `--install-only`; `cargo install --locked` is cargo's.\n"
        )
        self.assertEqual(docs_flags.check(self.scanner, [doc]), [])

    def test_known_bad_flags_and_commands_fail(self):
        # Known bad: a flag scan never had, a flag from another subcommand,
        # a command that does not exist, and a bare flag nobody has.
        doc = self.doc(
            "`wpantry scan --fix`\n"
            "`wpantry schedule run --json`\n"
            "`wpantry frobnicate`\n"
            "With `wpantry scan`, `--made-up` does things.\n"
        )
        problems = docs_flags.check(self.scanner, [doc])
        self.assertEqual(len(problems), 4, problems)
        self.assertIn("`wpantry scan` has no --fix", problems[0])
        self.assertIn("`wpantry schedule run` has no --json", problems[1])
        self.assertIn("`wpantry frobnicate` is not a command", problems[2])
        self.assertIn("--made-up is not", problems[3])

    def test_arguments_are_not_taken_for_commands(self):
        mentions = docs_flags.mentions("`wpantry scan ~/code --json`", "x.md", {"scan", "schedule"})
        self.assertEqual(mentions[0].path, ("scan",))
        self.assertEqual(mentions[0].flags, ("--json",))


if __name__ == "__main__":
    unittest.main()
