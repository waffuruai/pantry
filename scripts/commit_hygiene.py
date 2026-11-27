"""Commit hygiene: no AI or bot attribution in what a pull request would merge.

A commit is authored by the person accountable for it (each repository's
CONTRIBUTING.md, "Commit authorship"). This fails when a pull request, a push
to dev or main, or a local commit (--message-file, the commit-msg hook)
brings in any of:

  (I) a commit whose author or committer is an AI tool or a bot rather than a
      person: GitHub lists that author as a co-author of the squash commit even
      when the message is clean;
  (K) an attribution trailer anywhere in a message (`Co-authored-by:`,
      `Signed-off-by:`, `Assisted-by:`, any `<word>-by:` or `<word>-with:`)
      whose value names an AI tool or a bot identity;
  (T) a trailer-shaped line (`Key: value`) in the closing paragraph whose
      value does;
  (P) the robot-emoji footer, or an attribution verb (generated, co-authored,
      created, ...) joined by `by`/`with`/`using` to an AI tool name on the
      same line;

in a commit message, or in the pull request's title or body, which GitHub
writes into the squash commit.

What passes: trailers naming people (two people co-authoring), bare mentions
(`AGENTS.md`, `.claude/`, a model named in prose) and the PR template's
AI-assistance disclosure boxes. GitHub's web-flow committer and Dependabot are
allowed by name (ALLOWED_IDENTITIES).

Canonical copy: waffuruai/pantry scripts/commit_hygiene.py. butter, ops and
iron carry this file byte-identical (ops' commit-msg hook runs it too); change
it in pantry first, then copy it to the others unchanged. It grew from butter's
and ops' earlier copies (AI_TERMS, ATTRIB_PHRASE_RE, the trailer-block walk,
already_released()) and differs from them on purpose: it qualifies trailers by
who they name, so human co-authors pass; it checks author and committer
identities; and it only reads (no PR edit, no comment), so it runs on fork PRs
with a read-only token.

    python3 scripts/commit_hygiene.py                    # in CI: PR or push, from the event
    python3 scripts/commit_hygiene.py --range origin/dev..HEAD   # locally, before pushing
    python3 scripts/commit_hygiene.py --message-file .git/COMMIT_EDITMSG  # a commit-msg hook
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

# AI tools, vendors and models. Butter's list, extended. Used to qualify a
# trailer value or an attribution phrase; a bare mention is never flagged.
AI_TERMS = [
    r"claude", r"anthropic", r"\bcodex\b", r"openai", r"chatgpt",
    r"\bgpt[- ]?\d", r"antigravity", r"gemini", r"\bbard\b",
    r"copilot", r"\bcursor\b", r"sourcegraph", r"\bcody\b",
    r"\bdevin\b", r"\baider\b", r"windsurf", r"codeium", r"tabnine",
    r"\bllama\b", r"\bmistral\b", r"\bgrok\b", r"\bxai\b", r"perplexity",
    r"replit", r"ghostwriter", r"\bpieces\b", r"\bjules\b", r"\bkiro\b",
    r"amazon q\b", r"codewhisperer", r"\bcline\b", r"\broo ?code\b", r"opencode",
    r"openhands", r"\bgoose\b", r"\bqodo\b",
    r"\bamp ?code\b", r"\bzed agent\b", r"\bqwen\b", r"deepseek",
    r"lovable", r"\bbolt\.new\b",
]
AI_RE = re.compile("|".join(AI_TERMS), re.IGNORECASE)
# Open model families: names of software people build with ("built with
# llama.cpp"), so they qualify an identity or a trailer but not a prose phrase.
MODEL_TERMS = {r"\bllama\b", r"\bmistral\b", r"\bqwen\b", r"deepseek"}
TOOL_RE = re.compile("|".join(t for t in AI_TERMS if t not in MODEL_TERMS), re.IGNORECASE)

# Names that are also people's names. On their own they mark an identity as AI
# only with a noreply, vendor or empty email; with a tool word after them they
# always do ("Claude Opus 5.5", "Devin AI").
AMBIGUOUS_RE = re.compile(r"^\s*(claude|devin|cody|bard|jules|aider|goose|kiro|cline)\s*$", re.IGNORECASE)

# Mail domains of AI vendors and agent services: an address here is never a person's commit.
AI_DOMAINS = (
    "anthropic.com", "claude.ai", "claude.com", "openai.com", "chatgpt.com",
    "cursor.com", "cursor.sh", "anysphere.co", "cognition.ai", "cognition-labs.com", "devin.ai",
    "aider.chat", "codeium.com", "windsurf.com", "tabnine.com", "sourcegraph.com",
    "x.ai", "mistral.ai", "perplexity.ai", "replit.com", "all-hands.dev",
    "cline.bot", "kiro.dev", "qodo.ai", "sweep.dev", "ampcode.com", "lovable.dev",
)

# Non-human identities allowed as author, committer or trailer: GitHub's web-flow
# committer (the web UI and merges), and Dependabot (.github/dependabot.yml), whose
# bump commits carry its own sign-off. Matched on the email, lowercased.
ALLOWED_IDENTITIES = {
    "noreply@github.com": "GitHub web-flow",
    "49699333+dependabot[bot]@users.noreply.github.com": "Dependabot",
    "support@github.com": "Dependabot sign-off",
}
ALLOWED_LOGINS = {"web-flow", "dependabot[bot]"}

# A trailer key that credits someone: the list git and the tools use, and any
# `<word>-by` / `<word>-with` key.
ATTRIB_KEY_RE = re.compile(
    r"^\s*(?P<key>co-?authored-by|signed-off-by|reviewed-by|tested-by|acked-by"
    r"|assisted-by|generated-by|created-by|authored-by|helped-by|suggested-by"
    r"|reported-by|written-by|[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-(?:by|with))\s*:\s*(?P<value>.*)$",
    re.IGNORECASE,
)
TRAILER_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9-]*):\s+(?P<value>.*)$")
# Conventional-commit subjects (a merge or squash body lists them) are `Key: value`-shaped, not trailers.
CONVENTIONAL_KEYS = {"feat", "fix", "chore", "docs", "refactor", "perf", "test", "tests", "ci", "build",
                     "style", "revert", "release", "deps", "security"}
IDENTITY_RE = re.compile(r"^\s*(?P<name>.*?)\s*<(?P<email>[^>]*)>\s*$")

ATTRIB_PHRASE_RE = re.compile(
    r"(?i)\b(co-?authored|generated|created|authored|written|produced"
    r"|powered|assisted|made|built|crafted)\b.{0,30}?\b(by|with|using)\b"
)
ROBOT = "\U0001f916"

FIX_COMMITS = (
    "Commits: rewrite them under your own name and drop the lines, then force-push the branch:\n"
    "  git rebase -i <base>   # mark each listed commit `reword` and delete the line;\n"
    "                          # a commit authored by a bot or tool also needs\n"
    "  git commit --amend --reset-author --no-edit   # at that commit, as your own account\n"
    "  git push --force-with-lease\n"
    "  Then turn off the tool's attribution so it does not come back (CONTRIBUTING.md, Commit authorship)."
)
FIX_NEW = ("This commit: delete the line from the message and commit again, as your own git identity\n"
           "  (not the tool's); turn off the tool's attribution so it does not come back.")
FIX_PR = "PR title or body: edit the pull request and delete the line; this check re-runs on the edit."


@dataclass
class Finding:
    where: str  # "commit abc1234" or "PR body"
    what: str
    line: str
    lineno: int | None = None

    def render(self) -> str:
        at = f" line {self.lineno}" if self.lineno else ""
        return f"{self.where}{at}: {self.what}: {self.line}"


@dataclass
class Commit:
    sha: str
    message: str
    author_name: str = ""
    author_email: str = ""
    author_login: str = ""
    committer_name: str = ""
    committer_email: str = ""
    committer_login: str = ""
    author_type: str = ""
    committer_type: str = ""
    extra: dict = field(default_factory=dict)


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def ai_identity(name: str = "", email: str = "", login: str = "", account_type: str = "") -> str | None:
    """Why this identity is an AI tool or a bot rather than a person, or None."""
    email_l = email.strip().lower()
    login_l = login.strip().lower()
    if email_l in ALLOWED_IDENTITIES or (login_l and login_l in ALLOWED_LOGINS):
        return None
    if account_type.lower() == "bot":
        return f"GitHub bot account {login or name}"
    for part in (name, email_l, login_l):
        if "[bot]" in part.lower():
            return f"bot identity {part.strip()}"
    domain = _domain(email_l)
    if any(domain == d or domain.endswith("." + d) for d in AI_DOMAINS):
        return f"AI vendor address {email.strip()}"
    if login_l and AI_RE.search(login_l) and not AMBIGUOUS_RE.match(login_l):
        return f"AI tool account {login}"
    who = name.strip()
    if who and AI_RE.search(who):
        if not AMBIGUOUS_RE.match(who):
            return f"AI tool name {who}"
        if not email_l or "noreply" in email_l or "no-reply" in email_l:
            return f"AI tool name {who} with no personal address"
    return None


def _value_identity(value: str) -> str | None:
    m = IDENTITY_RE.match(value)
    if m:
        return ai_identity(m.group("name"), m.group("email"))
    if "@" in value and " " not in value.strip():
        return ai_identity(email=value)
    # A name, not a sentence: "Claude Opus 5.5" is credit, "add DeepSeek V4 support" is not.
    if len(value.split()) > 4:
        return None
    return ai_identity(name=value)


def message_findings(text: str, where: str) -> list[Finding]:
    """Attribution in a commit message or PR text (rules K, T and P)."""
    out: list[Finding] = []
    lines = text.splitlines()
    flagged: set[int] = set()

    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s:
            continue
        m = ATTRIB_KEY_RE.match(ln)
        if m:
            why = _value_identity(m.group("value"))
            if why:
                out.append(Finding(where, f"{m.group('key')} trailer names {why}", s, i + 1))
                flagged.add(i)
            continue
        m = TRAILER_RE.match(ln)
        if m and m.group("key").lower() not in CONVENTIONAL_KEYS and AI_RE.search(m.group("key")):
            out.append(Finding(where, f"{m.group('key')} trailer names an AI tool", s, i + 1))
            flagged.add(i)
            continue
        if ROBOT in ln:
            out.append(Finding(where, "AI footer (robot emoji)", s, i + 1))
            flagged.add(i)
        elif ATTRIB_PHRASE_RE.search(ln) and TOOL_RE.search(ln):
            out.append(Finding(where, "AI attribution phrase", s, i + 1))
            flagged.add(i)

    # (T) the closing paragraph of `Key: value` lines, preceded by a blank line.
    end = len(lines)
    while end and not lines[end - 1].strip():
        end -= 1
    i = end - 1
    while i >= 0 and lines[i].strip() and TRAILER_RE.match(lines[i]):
        i -= 1
    if i >= 0 and not lines[i].strip():
        for j in range(i + 1, end):
            if j in flagged:
                continue
            m = TRAILER_RE.match(lines[j])
            if m.group("key").lower() in CONVENTIONAL_KEYS:
                continue
            why = _value_identity(m.group("value"))
            if why:
                out.append(Finding(where, f"{m.group('key')} trailer names {why}", lines[j].strip(), j + 1))
    out.sort(key=lambda f: f.lineno or 0)
    return out


def commit_findings(c: Commit) -> list[Finding]:
    where = f"commit {c.sha[:7]} ({c.message.splitlines()[0] if c.message else ''})"
    out = []
    why = ai_identity(c.author_name, c.author_email, c.author_login, c.author_type)
    if why:
        out.append(Finding(where, "author is not a person",
                           f"{why} (GitHub would add it as a co-author of the squash commit)"))
    why = ai_identity(c.committer_name, c.committer_email, c.committer_login, c.committer_type)
    if why:
        out.append(Finding(where, "committer is not a person", why))
    return out + message_findings(c.message, where)


def pr_findings(title: str, body: str) -> list[Finding]:
    return message_findings(title, "PR title") + message_findings(body or "", "PR body")


def report(findings: list[Finding], summary_path: str | None = None, annotate: bool = False) -> int:
    if not findings:
        print("Commit hygiene: no AI or bot attribution found.")
        return 0
    lines = ["Commit hygiene: AI or bot attribution in what this would merge.", ""]
    lines += [f"- {f.render()}" for f in findings]
    lines.append("")
    if any(f.where.startswith("commit") for f in findings):
        lines.append(FIX_COMMITS)
    if any(f.where == "this commit" for f in findings):
        lines.append(FIX_NEW)
    if any(f.where.startswith("PR") for f in findings):
        lines.append(FIX_PR)
    lines.append("Disclose AI use where the PR template asks for it instead; see CONTRIBUTING.md, Commit authorship.")
    text = "\n".join(lines)
    print(text)
    if annotate:
        for f in findings:
            print(f"::error title=Commit hygiene::{f.render()}")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("## Commit hygiene\n\n```\n" + text + "\n```\n")
    return 1


# ---- I/O: GitHub and git ----------------------------------------------------


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def _api_commit(c: dict) -> Commit:
    commit = c.get("commit", {})
    a, m = commit.get("author") or {}, commit.get("committer") or {}
    ga, gm = c.get("author") or {}, c.get("committer") or {}
    return Commit(
        sha=c["sha"], message=commit.get("message", ""),
        author_name=a.get("name", ""), author_email=a.get("email", ""),
        author_login=ga.get("login", ""), author_type=ga.get("type", ""),
        committer_name=m.get("name", ""), committer_email=m.get("email", ""),
        committer_login=gm.get("login", ""), committer_type=gm.get("type", ""),
    )


def already_released(repo: str, sha: str) -> bool:
    """True if `sha` is already on main (butter's rule): a PR merging main back
    into dev carries main's history, which was reviewed when it landed and
    cannot be rewritten, so it is not this PR's to fix."""
    try:
        status = _run(["gh", "api", f"repos/{repo}/compare/main...{sha}", "--jq", ".status"]).strip()
    except subprocess.CalledProcessError:
        return False
    return status in ("behind", "identical")


def _paged(path: str) -> list[dict]:
    out = _run(["gh", "api", "--paginate", "--slurp", path])
    pages = json.loads(out)
    return [item for page in pages for item in (page if isinstance(page, list) else page.get("commits", []))]


def from_event(event: dict, event_name: str, repo: str) -> list[Finding]:
    findings: list[Finding] = []
    if event_name.startswith("pull_request"):
        pr = event["pull_request"]
        for c in map(_api_commit, _paged(f"repos/{repo}/pulls/{pr['number']}/commits?per_page=100")):
            got = commit_findings(c)
            if got and already_released(repo, c.sha):
                print(f"{c.sha[:7]} is already on main; skipping it")
                continue
            findings += got
        findings += pr_findings(pr.get("title") or "", pr.get("body") or "")
    elif event_name == "push":
        before, after = event.get("before", ""), event["after"]
        if before and set(before) != {"0"}:
            path = f"repos/{repo}/compare/{before}...{after}?per_page=100"
        else:
            path = f"repos/{repo}/commits?sha={after}&per_page=1"
        raw = _paged(path) if "compare" in path else json.loads(_run(["gh", "api", path]))
        for c in map(_api_commit, raw):
            findings += commit_findings(c)
    else:
        raise SystemExit(f"commit_hygiene: unsupported event {event_name}")
    return findings


def from_range(rev_range: str) -> list[Finding]:
    fmt = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"
    out = _run(["git", "log", f"--format={fmt}", rev_range])
    findings = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, an, ae, cn, ce, body = rec.split("\x1f", 5)
        findings += commit_findings(Commit(sha, body, an, ae, "", cn, ce))
    return findings


def _ident(var: str) -> tuple[str, str]:
    """(name, email) git will record for GIT_AUTHOR_IDENT or GIT_COMMITTER_IDENT."""
    try:
        m = IDENTITY_RE.match(_run(["git", "var", var]).rsplit(">", 1)[0] + ">")
    except (subprocess.CalledProcessError, OSError):
        return "", ""
    return (m.group("name"), m.group("email")) if m else ("", "")


def from_message_file(path: str) -> list[Finding]:
    """A commit about to be made: its message (git's `#` comment lines dropped)
    and the author and committer identities git will record."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = "".join(ln for ln in fh if not ln.startswith("#"))
    an, ae = _ident("GIT_AUTHOR_IDENT")
    cn, ce = _ident("GIT_COMMITTER_IDENT")
    c = Commit("(new commit)", text, an, ae, "", cn, ce)
    findings = commit_findings(c)
    for f in findings:
        f.where = "this commit"
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--range", help="check local commits, e.g. origin/dev..HEAD, instead of the CI event")
    ap.add_argument("--message-file", help="check a commit message file and git's author and committer (a commit-msg hook)")
    args = ap.parse_args(argv)
    if args.message_file:
        return report(from_message_file(args.message_file))
    if args.range:
        return report(from_range(args.range))
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    findings = from_event(event, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REPOSITORY"])
    return report(findings, os.environ.get("GITHUB_STEP_SUMMARY"), annotate=True)


if __name__ == "__main__":
    sys.exit(main())
