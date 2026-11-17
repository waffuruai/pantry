"""secret_words.py on a small stand-in for web2:

    python3 -m unittest discover -s scripts
"""

from __future__ import annotations

import gzip
import pathlib
import tempfile
import unittest
from unittest import mock

import secret_words


class WordsTests(unittest.TestCase):
    def test_keeps_lowercase_ascii_words_of_five_to_ten_letters(self):
        text = "apple\nAustin\nfig\nbanana\nextraordinarily\nnaïve\ncherry\nbanana\n"
        self.assertEqual(secret_words.words(text), ["apple", "banana", "cherry"])

    def test_writes_a_reproducible_gzip(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d) / "web2"
            src.write_text("zebra\napple\n")
            out = pathlib.Path(d) / "words.txt.gz"
            with mock.patch.object(secret_words, "OUT", out), mock.patch.object(secret_words, "ROOT", pathlib.Path(d)):
                secret_words.main([str(src)])
                first = out.read_bytes()
                secret_words.main([str(src)])
            self.assertEqual(first, out.read_bytes())
            self.assertEqual(gzip.decompress(first), b"apple\nzebra\n")


if __name__ == "__main__":
    unittest.main()
