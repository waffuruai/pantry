"""Build the word list the secret scan's readable-text check uses.

rust/crates/wpantry/assets/secrets/words.txt.gz is compiled into wpantry: lowercase words of 5 to
12 letters, one per line, from web2 (Webster's Second International, 1934, public domain), the
list BSD and macOS ship as /usr/share/dict/words, less its proper nouns. A secret holding one of
them, cased as a word, reads as text, not a key (see checks/secrets/readable.rs). Standard
library only:

    python3 scripts/secret_words.py [WEB2]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "rust/crates/wpantry/assets/secrets/words.txt.gz"
WEB2 = pathlib.Path("/usr/share/dict/web2")
# web2 as macOS and FreeBSD ship it; another copy may differ, and the list with it.
WEB2_SHA256 = "be41ad97963bf8dabedd5871d5d691596175269d540956b0f9965a885c2bbab9"
MIN, MAX = 5, 12


def words(text: str) -> list[str]:
    """web2's lowercase, ASCII-letter words of MIN to MAX letters: capitalized ones are names."""
    out = set()
    for w in text.split():
        if w.isascii() and w.isalpha() and w[0].islower() and MIN <= len(w) <= MAX:
            out.add(w.lower())
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("web2", nargs="?", type=pathlib.Path, default=WEB2)
    args = ap.parse_args(argv)
    raw = args.web2.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != WEB2_SHA256:
        print(f"warning: {args.web2} is sha256 {digest}, not the pinned {WEB2_SHA256}", file=sys.stderr)
    data = ("\n".join(words(raw.decode("ascii", "replace"))) + "\n").encode()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))
    print(f"wrote {OUT.relative_to(ROOT)}: {data.count(b'\n')} words")
    return 0


if __name__ == "__main__":
    sys.exit(main())
