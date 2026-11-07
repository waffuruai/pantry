"""secret_rules.py against a fake pantry-rules checkout:

    python3 -m unittest discover -s scripts
"""

from __future__ import annotations

import pathlib
import tempfile
import tomllib
import unittest

import secret_rules


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        src = self.root / secret_rules.SOURCE
        src.mkdir(parents=True)
        (src / "Any.Secret.B.yar").write_text("rule B { condition: true }\n")
        (src / "Any.Secret.A.yar").write_text("rule A { condition: true }\n")
        (src / "Any.Secret.A.test.toml").write_text('[[case]]\nname = "a"\ntext = "x"\nrules = ["A"]\n')
        (src / "Any.Secret.B.test.toml").write_text('[[case]]\nname = "b"\ntext = "y"\nrules = []\n')

    def tearDown(self):
        self.dir.cleanup()

    def test_rules_are_concatenated_in_file_name_order_under_the_commit(self):
        text, _ = secret_rules.bundle(self.root, "abc123")
        self.assertTrue(text.startswith("// pantry-rules abc123, rules/any/secret: 2 files."))
        self.assertLess(text.index("rule A"), text.index("rule B"))
        self.assertIn("// ---- Any.Secret.A.yar\n", text)

    def test_cases_merge_into_one_toml_document(self):
        _, tests = secret_rules.bundle(self.root, "abc123")
        cases = tomllib.loads(tests)["case"]
        self.assertEqual([c["name"] for c in cases], ["a", "b"])

    def test_a_checkout_without_rules_is_an_error(self):
        with self.assertRaises(SystemExit):
            secret_rules.bundle(pathlib.Path(self.dir.name) / "missing", "x")


if __name__ == "__main__":
    unittest.main()
