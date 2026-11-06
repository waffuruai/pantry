"""Regenerate the popular package names the typosquat check compares dependencies against.

rust/crates/wpantry/assets/defaults/popular.toml is compiled into wpantry, so the check works
offline and never asks a registry. A dependency one keystroke from a name in it, and not itself
in it, warns as SUSPECT-TYPOSQUAT; the list has to be large enough that an established package
is in it, or established packages get called typos of each other (query-string of querystring).
Every name comes from a public download ranking, so the file is reproducible:

    npm        npm-high-impact, a pinned release (lib/top.js: the packages npm calls high-impact,
               a million weekly downloads or 500 dependents, most downloaded first)
    PyPI       hugovk/top-pypi-packages, the 15,000 most downloaded over the last 30 days
    crates.io  the crates.io API sorted by downloads over the last 90 days (one request a second,
               as its crawler policy asks)
    RubyGems   packages.ecosyste.ms, rubygems.org sorted by total downloads

A few wallet and chain libraries (EXTRA) are listed whatever their rank. Standard library only:

    python3 scripts/popular.py [--npm N] [--pypi N] [--crates N] [--gems N] [--out FILE]
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import time
import urllib.request
from datetime import date
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rust" / "crates" / "wpantry" / "assets" / "defaults" / "popular.toml"
# The release of npm-high-impact to read; bump it to refresh the npm names.
NPM_HIGH_IMPACT = "1.13.0"
NPM_TARBALL = f"https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-{NPM_HIGH_IMPACT}.tgz"
PYPI_JSON = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
CRATES_API = "https://crates.io/api/v1/crates?sort=recent-downloads&per_page=100&page={page}"
GEMS_API = (
    "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/package_names"
    "?sort=downloads&order=desc&per_page=1000&page={page}"
)
USER_AGENT = "wpantry-popular (https://github.com/waffuruai/pantry)"
# crates.io's crawler policy: at most one request a second.
CRATES_PAUSE = 1.0
# How many names each ecosystem gets by default: enough that a developer machine's lockfiles
# are made of listed names, small enough to compile in (about 20 bytes a name).
COUNTS = {"npm": 10000, "PyPI": 8000, "crates.io": 5000, "RubyGems": 2000}
# Ecosystems as OSV names them, in the order the file lists them.
ECOSYSTEMS = ("npm", "PyPI", "crates.io", "RubyGems")
# Names below the rankings' cut that squats target anyway: the wallet and chain libraries, where a
# typo'd install drains an account. Every hand-added name can call a neighbour a typo, so keep it short.
EXTRA = {
    "npm": (
        "web3", "viem", "wagmi", "hardhat", "truffle", "bitcoinjs-lib",
        "@openzeppelin/contracts", "@rainbow-me/rainbowkit", "@web3-react/core",
    ),
}
# A registry name: lowercase letters, digits, `-`, `_` and `.`, with an optional npm scope.
NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
# One `'name',` line of npm-high-impact's lib/top.js: the file is read as data, never run.
JS_NAME = re.compile(r"^\s*'([^']+)',?\s*$", re.M)

Fetch = Callable[[str], bytes]


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def clean(names: list[str], count: int) -> list[str]:
    """The first `count` distinct registry names, lowercased, in ranking order."""
    out: list[str] = []
    seen: set[str] = set()
    for n in names:
        n = n.strip().lower()
        if n in seen or not NAME.match(n):
            continue
        seen.add(n)
        out.append(n)
        if len(out) == count:
            break
    return out


def npm(get: Fetch, count: int) -> tuple[list[str], str]:
    """npm-high-impact's `top` list, most downloaded first, and where it came from."""
    with tarfile.open(fileobj=io.BytesIO(get(NPM_TARBALL)), mode="r:gz") as tar:
        member = tar.extractfile("package/lib/top.js")
        if member is None:
            raise SystemExit("npm-high-impact tarball has no package/lib/top.js")
        names = JS_NAME.findall(member.read().decode())
    return clean(names, count), f"npm-high-impact {NPM_HIGH_IMPACT} (lib/top.js: most downloaded, then most depended on)"


def pypi(get: Fetch, count: int) -> tuple[list[str], str]:
    """hugovk's top PyPI packages by downloads over 30 days."""
    data = json.loads(get(PYPI_JSON))
    rows = sorted(data["rows"], key=lambda r: -int(r["download_count"]))
    updated = str(data.get("last_update", ""))[:10]
    return clean([r["project"] for r in rows], count), f"hugovk/top-pypi-packages, 30 days to {updated}"


def crates(get: Fetch, count: int, pause: float = CRATES_PAUSE) -> tuple[list[str], str]:
    """crates.io by downloads over the last 90 days, 100 a page."""
    names: list[str] = []
    page = 1
    while len(names) < count:
        if page > 1:
            time.sleep(pause)
        got = [c["name"] for c in json.loads(get(CRATES_API.format(page=page)))["crates"]]
        if not got:
            break
        names.extend(got)
        page += 1
    return clean(names, count), f"crates.io API sorted by downloads over 90 days, {date.today().isoformat()}"


def gems(get: Fetch, count: int) -> tuple[list[str], str]:
    """rubygems.org by total downloads, through packages.ecosyste.ms, 1000 a page."""
    names: list[str] = []
    page = 1
    while len(names) < count:
        got = json.loads(get(GEMS_API.format(page=page)))
        if not got:
            break
        names.extend(got)
        page += 1
    return clean(names, count), f"packages.ecosyste.ms, rubygems.org sorted by downloads, {date.today().isoformat()}"


SOURCES = {"npm": npm, "PyPI": pypi, "crates.io": crates, "RubyGems": gems}


def render(lists: dict[str, tuple[list[str], str]], today: str) -> str:
    """The file (TOML): a header naming each source, then `[popular]` with each ecosystem's names sorted."""
    head = [
        "# Popular package names for the typosquat check (SUSPECT-TYPOSQUAT), sorted,",
        "# by ecosystem as OSV names it. A dependency one keystroke from one of these,",
        "# and not itself listed, warns; a listed name is never a squat, and a name the",
        "# registry treats as the same (separators dropped or swapped) is the listed,",
        "# older package. npm scopes come from the scoped names (`@babel` from",
        "# `@babel/core`).",
        "#",
        f"# Generated by scripts/popular.py on {today}; regenerate rather than edit.",
    ]
    for eco in ECOSYSTEMS:
        names, source = lists[eco]
        extra = len(set(EXTRA.get(eco, ())) - set(names))
        head.append(f"# {eco:<10} {len(names):>6} names  {source}" + (f", plus {extra} wallet libraries" if extra else ""))
    body = ["", "[popular]"]
    for eco in ECOSYSTEMS:
        key = eco if re.fullmatch(r"[A-Za-z0-9_-]+", eco) else json.dumps(eco)
        body.append(f"{key} = [")
        body.extend(f"  {json.dumps(n, ensure_ascii=False)}," for n in sorted(set(lists[eco][0]) | set(EXTRA.get(eco, ()))))
        body.append("]")
    return "\n".join(head + body) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for eco, flag in (("npm", "--npm"), ("PyPI", "--pypi"), ("crates.io", "--crates"), ("RubyGems", "--gems")):
        ap.add_argument(flag, type=int, default=COUNTS[eco], metavar="N", help=f"{eco} names to keep (default {COUNTS[eco]})")
    ap.add_argument("--out", type=Path, default=OUT, help=f"where to write (default {OUT.relative_to(ROOT)})")
    args = ap.parse_args(argv)
    counts = {"npm": args.npm, "PyPI": args.pypi, "crates.io": args.crates, "RubyGems": args.gems}
    lists: dict[str, tuple[list[str], str]] = {}
    for eco in ECOSYSTEMS:
        print(f"{eco}: fetching {counts[eco]} names", file=sys.stderr)
        lists[eco] = SOURCES[eco](fetch, counts[eco])
        if len(lists[eco][0]) < counts[eco]:
            print(f"{eco}: only {len(lists[eco][0])} names available", file=sys.stderr)
    args.out.write_text(render(lists, date.today().isoformat()))
    total = sum(len(v[0]) for v in lists.values())
    print(f"wrote {total} names to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
