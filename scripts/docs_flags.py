#!/usr/bin/env python3
"""Check that every `wpantry` command and flag the user docs mention exists.

    python3 scripts/docs_flags.py rust/target/debug/wpantry

Reads docs/public/*.md and desktop/README.md. For each `wpantry ...`
command in inline code or a code block, the subcommand path (such as
`schedule status`) must be a real command, and each `--flag` after it must
appear in that command's `--help`, or in the help of a command above it
(`wpantry --help` lists the global options). A flag in inline code on its
own, such as `--no-personal-files`, on a line that also names a `wpantry`
command in code, must appear in some wpantry help text, or belong to Pantry
Setup or the desktop app. Commands of other programs (cargo, rustup,
wpantry-setup, ...) and bare flags on lines about them are skipped.

Exit 0 when everything matches; otherwise each unknown command or flag is
printed with its file and line, and the exit code is 1.

The oracle is the scanner's own help output, so a renamed or removed flag
fails here as soon as the docs still name it. The unit tests in
scripts/test_docs_flags.py include a known-bad case.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted((ROOT / "docs/public").glob("*.md")) + [ROOT / "desktop/README.md"]

# Flags of the other Pantry programs that docs mention on their own:
# Pantry Setup (desktop/src/bin/wpantry-setup.rs) and the desktop app
# (desktop/src/main.rs, `wpantry-desktop --help`).
OTHER_PROGRAM_FLAGS = {
    "--install-only", "--uninstall",  # Pantry Setup
    "--automation", "--scanner", "--scheduled-run",  # wpantry-desktop
    "--open", "--no-install",  # desktop/release/install-local.sh
    "--dir",  # rust/release/install.sh (its --version is also wpantry's)
}

CODE_SPAN = re.compile(r"`([^`\n]+)`")
FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
COMMAND = re.compile(r"(?<![\w./-])wpantry(?:\.exe)?(?![\w-])((?:\s+[^\s|;&]+)*)")
WORD = re.compile(r"[a-z][a-z-]*$")
# What may come before `wpantry` for it to be a command, not a word in a
# sentence: nothing, a prompt, a shell separator, `sudo`, or VAR=value pairs.
LEAD = re.compile(r"(?:.*(?:&&|\|\||[|;(]))?\s*(?:\$\s*)?(?:sudo\s+)?(?:[A-Z_][A-Z0-9_]*=\S*\s+)*")


@dataclass(frozen=True)
class Mention:
    file: str
    line: int
    path: tuple[str, ...]  # subcommand path, () for wpantry itself
    flags: tuple[str, ...]
    standalone: bool = False  # a bare `--flag` in inline code
    unknown: str = ""  # a first word that looks like a command but is not one


def snippets(text: str):
    """Yield (line number, code) for inline code spans and code block lines."""
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            yield number, line, True
        else:
            for span in CODE_SPAN.findall(line):
                yield number, span, False


def mentions(text: str, name: str, commands: set[str]) -> list[Mention]:
    """Commands and bare flags in one Markdown file.

    `commands` is the set of top-level subcommands, used to tell a
    subcommand from an argument (`wpantry scan ~/code` has none)."""
    found = []
    lines_with_commands = {
        number for number, code, _ in snippets(text)
        if any(LEAD.fullmatch(code[: m.start()]) for m in COMMAND.finditer(code))
    }
    for number, code, block in snippets(text):
        matched = False
        for match in COMMAND.finditer(code):
            if not LEAD.fullmatch(code[: match.start()]):
                continue
            matched = True
            words = match.group(1).split()
            path: list[str] = []
            unknown = ""
            if words and WORD.match(words[0]) and words[0] not in commands:
                unknown = words[0]
            for word in words:
                if word.startswith("-"):
                    break
                if not path and word in commands:
                    path.append(word)
                elif path and WORD.match(word) and len(path) == 1:
                    # A second word is a nested command only if help knows it;
                    # check_mention resolves that against the real CLI.
                    path.append(word)
                else:
                    break
            flags = tuple(FLAG.findall(match.group(1)))
            found.append(Mention(name, number, tuple(path), flags, unknown=unknown))
        if not matched and not block and number in lines_with_commands:
            flags = FLAG.findall(code)
            # Only inline code that is just a flag (and maybe its value).
            if flags and code.strip().startswith("--") and len(code.split()) <= 2:
                found.append(Mention(name, number, (), (flags[0],), standalone=True))
    return found


class Cli:
    """Help text from the real scanner, cached per subcommand path."""

    def __init__(self, scanner: str):
        self.scanner = scanner
        self.cache: dict[tuple[str, ...], str | None] = {}

    def help(self, path: tuple[str, ...]) -> str | None:
        if path not in self.cache:
            run = subprocess.run(
                [self.scanner, *path, "--help"], capture_output=True, text=True, encoding="utf-8",
                env=dict(os.environ, WPANTRY_NO_UPDATE_CHECK="1", NO_COLOR="1"),
            )
            self.cache[path] = run.stdout if run.returncode == 0 else None
        return self.cache[path]

    def commands(self) -> set[str]:
        text = self.help(()) or ""
        section = text.split("Commands:", 1)[-1]
        return {m.group(1) for m in re.finditer(r"^  ([a-z][a-z-]*)\b", section, re.M)}

    def all_flags(self) -> set[str]:
        flags = set(FLAG.findall(self.help(()) or ""))
        for command in self.commands():
            text = self.help((command,)) or ""
            flags |= set(FLAG.findall(text))
            nested = text.split("Commands:", 1)[1] if "Commands:" in text else ""
            for sub in re.findall(r"^  ([a-z][a-z-]*)\b", nested, re.M):
                flags |= set(FLAG.findall(self.help((command, sub)) or ""))
        return flags


def check_mention(mention: Mention, cli: Cli, every_flag: set[str]) -> list[str]:
    where = f"{mention.file}:{mention.line}"
    if mention.standalone:
        flag = mention.flags[0]
        if flag in every_flag or flag in OTHER_PROGRAM_FLAGS:
            return []
        return [f"{where}: {flag} is not a wpantry, Pantry Setup or Pantry Desktop flag"]
    if mention.unknown:
        return [f"{where}: `wpantry {mention.unknown}` is not a command"]
    path = mention.path
    # Drop a trailing word that is an argument, not a nested command.
    if len(path) == 2 and cli.help(path) is None:
        path = path[:1]
    if path and cli.help(path) is None:
        return [f"{where}: `wpantry {' '.join(path)}` is not a command"]
    known = set()
    for depth in range(len(path) + 1):
        known |= set(FLAG.findall(cli.help(path[:depth]) or ""))
    command = " ".join(("wpantry", *path))
    return [f"{where}: `{command}` has no {flag}" for flag in mention.flags if flag not in known]


def check(scanner: str, docs: list[Path] = DOCS) -> list[str]:
    cli = Cli(scanner)
    commands = cli.commands()
    if not commands:
        return [f"{scanner} --help listed no commands"]
    every_flag = cli.all_flags()
    problems = []
    for doc in docs:
        name = str(doc.relative_to(ROOT)) if doc.is_relative_to(ROOT) else str(doc)
        for mention in mentions(doc.read_text(encoding="utf-8"), name, commands):
            problems.extend(check_mention(mention, cli, every_flag))
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    problems = check(argv[1])
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} doc mention(s) do not match `wpantry --help`.", file=sys.stderr)
        return 1
    print(f"Every wpantry command and flag in {len(DOCS)} docs matches the CLI help.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
