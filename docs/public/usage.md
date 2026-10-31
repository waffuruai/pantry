# Using wpantry

wpantry finds the vulnerabilities that actually apply to your computer and your git repos. It inventories what is installed and what your repos lock, asks [OSV.dev](https://osv.dev), CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list and [endoflife.date](https://endoflife.date) only about those exact versions, and fails only when something here has a known vulnerability with a released fix, is past end of life, is a known malicious package, or is a committed secret. A source it can't reach is reported "not checked", never clean.

Install it first: [install.md](install.md).

## Quick start

```bash
wpantry                                       # this computer: machine + every git repo under ~
wpantry --path ~/code/myproject --no-machine  # one project, no machine inventory
wpantry --update --dryrun                     # what it would fix, changing nothing
wpantry --update                              # apply the fixes that can run unattended, then re-check
wpantry check --json --no-input               # findings as JSON, for tools and agents
```

The first run downloads advisories for what it finds and takes a while; answers are cached for a day, so the next run the same day takes seconds.

## What it checks

| Area | What |
|---|---|
| Your repos' dependencies | The lockfiles in every git repo it finds (Cargo, npm, pnpm, yarn, bun, deno, Swift, Go, uv, poetry, pip, Bundler, Composer and more) |
| Committed secrets | Each repo's whole git history once, then only the commits its branches gained since, with [gitleaks](https://github.com/gitleaks/gitleaks); secrets are never printed or stored, only the rule, file, line and commit. A repo's own `.gitleaks.toml` is reported, not obeyed; its `.gitleaksignore` is |
| Malicious packages | Every package name against the OpenSSF malicious-packages index |
| AI harnesses | The MCP servers your repos and coding agents start (an unpinned `npx some-server` warns: it runs whatever is latest), their plugins and skills |
| Install scripts | Dependencies that run code when installed, outside an allowlist |
| The OS | Debian, Ubuntu, Alpine, SUSE packages (from the package database), dnf distros, Arch; macOS Software Update |
| Installed software | Runtimes and compilers (every version a version manager keeps), package managers, CLI tools, datastores, Docker, global packages, Homebrew formulae, apps, browsers, editor extensions |
| End of life | Runtimes and datastores past their end-of-life date fail |
| Certificate authorities | System and tool trust stores against known-distrusted CAs |

`--no-machine` limits a run to the first five rows, for the repos in scope. The Rust binary does not cover every row yet; what it doesn't check shows up as "not checked" ([rust/README.md](../../rust/README.md)).

## Scope

By default wpantry checks the machine and every git repo under your home directory. The walk is bounded: depth 6, symlinks not followed, and it skips `Library`, caches, toolchains, `node_modules`, build output and app bundles. It prints how many repos it found.

- `--path DIR` (repeatable) limits the repo checks to the repos at or under DIR. A DIR with no git repo is scanned as one project, without the git-history checks. A missing DIR is skipped with a note.
- `--no-machine` skips the machine inventory: repo checks only.

## Reading the report

While it scans, a progress line shows what it is doing (the directory it is walking, the lockfile it is reading, the advisories it is downloading) and the elapsed time. It is only drawn when the output is a terminal.

Then the findings, grouped by kind, one line per component with why it is listed and how to fix it:

```
==> Security scan (~/.cache/wpantry/wpantry.db)
  checked 12 git repos, 486 OS packages, 1820 project dependencies, 3 MCP servers

project
  ✗ smallvec 1.6.0 (~/code/app/Cargo.lock) - (CVE-2021-25900 KEV CRITICAL) Buffer overflow in SmallVec::insert_many. Fix: cd ~/code/app && cargo update -p smallvec --precise 1.6.1

secret
  ✗ app/.env (line 3, commit 1a2b3c4d5e6f) - (aws-access-token) AWS Access Key. Fix: If it's real: rotate it, then purge it from history. …

mcp
  ⚠ some-server (project: db) unpinned (~/code/app/.mcp.json) - (UNPINNED) `npx some-server` runs the latest release on every launch. Fix: Pin some-server to a reviewed version in ~/code/app/.mcp.json

not checked
  ⚠ CISA KEV (exploited-in-the-wild marks) - CISA KEV list unreachable and not cached

✗ 2 thing(s) to update (2 advisories), 1 warning(s). See the plan: wpantry --update --dryrun
```

- `✗` fails: a released fix exists, it's end of life, it's malicious, or it's a committed secret from a provider-specific rule.
- `⚠` warns: no fix yet, an outdated app, an unpinned MCP server, an install script, a generic secret rule to review.
- `KEV` marks a vulnerability CISA has seen exploited in the wild. Fix those first.
- **not checked** lists sources that couldn't be reached and had nothing cached. Those areas are unknown, not clean; re-run when you're online.

The (Python) implementation prints the same findings as one block per component.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and "not checked" sources still exit 0 (the report says "Incomplete") |
| 1 | Something fails, or an unattended fix failed under `--update` |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |

## Fixing

`wpantry --update --dryrun` prints the plan: one fix per component (the one that clears all its advisories), split into what can run unattended and what needs you. `wpantry --update` runs the unattended ones (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, removing malicious extensions), then re-checks. On a terminal it lists them first and asks `Run these N updates now? [Y/n]`; answer `n` and nothing changes. With `--no-input`, or no terminal, it runs them without asking. Everything that needs sudo, a vendor, or a change in a repo is printed as a step. A fix in a repo's lockfile is a code change: make it on a branch with that repo's tests.

## JSON

`wpantry check --json` prints one object and never prompts:

```json
{
 "schema": 1, "impl": "rust", "version": "0.2.0",
 "checked": {"git repos": 12, "project dependencies": 1820},
 "unfixed": 3, "unknown_licenses": 0,
 "findings": [{"kind": "project", "component": "smallvec", "version": "1.6.0", "location": "/home/me/code/app/Cargo.lock",
               "vuln_id": "CVE-2021-25900", "status": "fail", "fixed": "1.6.1", "kev": true, "severity": "CRITICAL",
               "note": "…", "fix_cmd": "…", "fix_auto": false}]
}
```

Check `schema` before reading it. The fields, the finding kinds and markers (`UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, …) are defined in the [CLI contract](../../specs/cli-contract.md).

## Options

| Option | Effect |
|---|---|
| `--refresh` | Ignore cached answers and ask every source again |
| `--offline` | Use only the cache; anything never cached is "not checked" |
| `--jobs N` | How many git histories gitleaks scans at once (default: half the cores, at most 4). Each scan gets a share of the cores, so a first run over many repos no longer takes the whole machine |
| `--no-input` | Never prompt: the breach-check question is skipped, and `--update` runs without asking |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled allowlist. Off by default; `--license` works too |
| `--gitleaks-config FILE` | Your gitleaks config instead of the bundled one (a repo's own `.gitleaks.toml` still wins) |
| `--install-scripts FILE` | Your allowlist of packages whose install scripts are accepted |

Policy files are one entry per line, `#` for comments. Reviewed false positives from gitleaks go in the repo's `.gitleaksignore` (the report prints the fingerprint to add).

## The cache, search and export

Answers live in one SQLite file: `~/.cache/wpantry/wpantry.db`, or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`. It holds the advisories for what is here, which versions were checked and when, the latest findings and the side feeds; never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (SQLite FTS5 syntax: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
wpantry export --csv findings.csv             # id, aliases, url, component, kind, affected and safe version, …
```

## Advisories with no fix yet

Some advisories have no fix you can install: the vendor has not shipped the kernel or package yet. For a few of those there is something a host can do meanwhile, and that is a script in [`mitigations/`](../../mitigations/), one per advisory. The first is [`mitigations/cve-2026-98432.sh`](../../mitigations/cve-2026-98432.sh), for the Linux kernel's IPv4 TCP use-after-free (CVSS 9.8): an nftables rule dropping inbound TCP with IP options before conntrack, reloaded at boot, and MPTCP off.

Every script works the same way. `--status` says whether the host is exposed (exit 0 fixed or mitigated, 1 exposed, 2 when it needs root it does not have) and changes nothing, `--dry-run` prints what it would write, a plain run shows the same plan and asks before writing (`--yes` skips the question, for provisioning and CI), and `--remove` takes the stopgap away once the real fix is installed. A scan never runs one; it prints the script as the step. They are a reduction of exposure, not the patch: update when the fix ships, then `--remove`.

## What leaves your machine

- To OSV.dev: the (ecosystem, name, version) of what is installed or locked. No file contents, paths or secrets.
- Feeds are downloaded: CISA KEV, endoflife.date, the Homebrew cask catalog, browser release feeds, the OpenSSF malicious-packages index (a git clone), and with `--licenses`, deps.dev.
- The breach check sends your email address to Have I Been Pwned (`HIBP_API_KEY`) or XposedOrNot, and only after you say yes (`wpantry breach --enable`; `--disable` turns it off).

Every request names wpantry in its User-Agent and times out after 30 seconds.

## Environment

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | The cache file |
| `GITHUB_TOKEN` | Lifts GitHub's anonymous rate limit for latest-release lookups |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned |
| `NO_COLOR` | Any non-empty value turns colour off. Without it, wpantry colours its report, prompts and errors on a terminal only (never in pipes, files or `--json`) |
| `HTTPS_PROXY` | Requests go through the proxy |

## For agents

`wpantry skill` prints an agent skill (`SKILL.md`) that teaches a coding agent to run wpantry, triage its JSON and plan fixes safely. `wpantry tools --json` lists the external tools and whether they're installed.

## Troubleshooting

- **Everything is "not checked"**: you're offline, or a proxy blocks `api.osv.dev`. Re-run online, or `--offline` to use what's cached.
- **`gitleaks` MISSING**: install it (`brew install gitleaks`, or see its README); the secret scan can't run without it.
- **It's slow on the first run**: the first run downloads advisories and clones the malicious-package index; later runs reuse them for a day. `--path` and `--no-machine` narrow a run.
- **A finding is wrong**: open an issue with a minimal reproducer (never paste a real report; see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Security reports go through [SECURITY.md](../../SECURITY.md).
