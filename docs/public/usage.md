# Using wpantry

wpantry finds the vulnerabilities that actually apply to your computer and your git repos: it inventories what is installed and what your repos lock, and asks [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [endoflife.date](https://endoflife.date) only about those exact versions. Every check and every source is listed in [checks-and-sources.md](checks-and-sources.md); this page is how to run it and read what it says. Install it first: [install.md](install.md).

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

Dependencies, committed secrets, malicious packages, AI harnesses, install scripts, the OS, installed software, end of life, certificate authorities and the machine's own settings: the full table, with what each source is asked and what is sent, is [checks-and-sources.md](checks-and-sources.md). `--no-machine` limits a run to the repo checks. What a run could not check shows up as "not checked", never as clean.

## Scope

By default wpantry checks the machine and every git repo under your home directory. The walk is bounded: depth 6, symlinks not followed, and it skips `Library`, caches, toolchains, `node_modules`, build output and app bundles. It prints how many repos it found.

- `--path DIR` (repeatable) limits the repo checks to the repos at or under DIR. A DIR with no git repo is scanned as one project, without the git-history checks. A missing DIR is skipped with a note.
- `--no-machine` skips the machine inventory: repo checks only.

## Cloned a repo? Check it before you open it

A repo can run code the moment an agent or editor opens it: a `.claude/settings.json` SessionStart hook, a `.cursor/mcp.json` server, a `.vscode/tasks.json` task on folder open, a devcontainer command, an npm `postinstall`. Hijacked repos hide the payload in a file the hook runs (a 13 MB `.github/init.js` that code search never indexes). Before opening a clone you didn't write:

```bash
wpantry check --path ~/Downloads/some-repo --no-machine
```

Alongside the hooks, the same pass reads every source, config and prose file for text that would fool you or a tool: bidirectional overrides and Unicode tag characters fail (`HIDDEN-BIDI`, `HIDDEN-TAGS`); runs of zero-width characters, identifiers that mix Latin with Cyrillic or Greek, and identifiers named after weapons and lethal doses warn (`HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`). The last is a trick aimed at AI-assisted review: a model that refuses to read "computeRicinLethalDosage" never sees the fingerprinting it does. Pantry reads the code regardless and tells you the names were chosen to make a reviewer look away.

A hook that runs a file kept in the repo, a file that looks like a dropper, or a known indicator fails (`repo-hook` findings `RUNS-REPO-FILE`, `LOADER`, `IOC`); a hook that runs a command at all warns (`OPEN-HOOK`, `INSTALL-HOOK`), as do the commit and branch markers of a known campaign (`MARKER`). Nothing is run or fixed for you: read the file the finding names, then remove the hook or decide to trust it. `--repo-hooks FILE` replaces the bundled indicator list.

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

## Reports: what you were exposed to, and what was done

Every scan is kept: when it ran, what it covered, and each finding from the scan that first saw it to the scan that no longer did. `--update` records the fixes it ran and the scan that verified them.

```bash
wpantry report                              # exposure, remediation and audit logs, last 90 days, Markdown
wpantry report --exposure --since 365 --format csv -o exposures.csv
wpantry report --remediation --format json
```

[reports.md](reports.md) says what each log holds and how it maps onto SOC 2 evidence.
## Keeping the cache fresh, and scanning on a schedule

```bash
wpantry sync                          # refresh the feeds and every answer the cache holds
wpantry schedule install              # daily at 09:30: sync, then check (never --update)
wpantry schedule install --every weekly --at 07:00
wpantry schedule status               # scheduled? when did it last run, what did it find
wpantry schedule uninstall
wpantry cache prune                   # drop what no scan has used in 90 days, compact the file
```

`sync` re-asks every source about what the cache already knows (feeds, end-of-life dates, every package version scanned before) without inventorying anything, so a `check --offline` afterwards answers from fresh data. `schedule` runs it for you through launchd (macOS), a systemd user timer (Linux) or cron, at low priority, and writes the check's JSON to `~/.local/state/wpantry/last.json` (`$XDG_STATE_HOME`) with one line per run in `schedule.log`. A scheduled run never changes anything: run `wpantry --update` yourself when the morning report says so.
## Keeping wpantry current

```bash
wpantry update --check     # exit 10 when a newer release exists, 0 when you have the latest
wpantry update             # asks, then installs the verified release (--yes to skip the question)
```

An update is verified before anything is replaced (see [install.md](install.md#upgrade-and-uninstall)); a mise, cargo or Homebrew install is updated through that tool. `check` mentions a newer release on stderr once a day; `WPANTRY_NO_UPDATE_CHECK=1` silences it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and "not checked" sources still exit 0 (the report says "Incomplete") |
| 1 | Something fails, or an unattended fix failed under `--update` |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |
| 10 | `wpantry watch` only: a fix has landed for something that had none |

## Fixing

`wpantry --update --dryrun` prints the plan: one fix per component (the one that clears all its advisories), split into what can run unattended and what needs you. `wpantry --update` runs the unattended ones (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, removing malicious extensions), then re-checks. On a terminal it lists them first and asks `Run these N updates now? [Y/n]`; answer `n` and nothing changes. With `--no-input`, or no terminal, it runs them without asking. Everything that needs sudo, a vendor, or a change in a repo is printed as a step. A fix in a repo's lockfile is a code change: make it on a branch with that repo's tests.

## Exposed with no fix yet

Most advisories are `✗` because a fixed version exists. When none does, the scan still tells you about the ones that matter (Critical, High, or exploited in the wild): a `⚠` line with `(no fix released for … yet)` and, as its step, what to do meanwhile. The steps come from a bundled list ([`mitigations.txt`](../../rust/crates/wpantry/assets/defaults/mitigations.txt), one line per advisory); an advisory with no entry says to keep checking and reduce exposure. The Moderate and Low ones are only counted (`unfixed` in the JSON). Nothing here fails the run.

```
os
  ⚠ linux-image-generic 6.8.0-45.45 (/var/lib/dpkg/status) - (CVE-2026-98432 CRITICAL) TCP use-after-free (no fix released for Ubuntu:24.04:LTS yet). Fix: Until the kernel update lands: drop inbound IPv4 TCP packets that carry IP options (…) and turn off MPTCP (…)
```

The daily scan asks OSV about a package version once a day. For these you want to know within the hour, so `wpantry watch` asks again about exactly them, bypassing that cache, and exits 10 when a fix has landed:

```bash
wpantry watch                 # each watched advisory: "no fix yet" + the mitigation, or "FIX AVAILABLE: <component> <version>"
wpantry watch --json          # {"schema": 1, …, "watched": [{"id", "severity", "summary", "ecosystem", "package", "version", "fixed", "mitigation"}]}
```

Run it hourly from cron or a timer and alert on exit 10 (`0 * * * * wpantry watch --json > ~/.cache/wpantry/watch.json || notify …`), then run `wpantry --update --dryrun` for the step. On Linux the posture checks also cover the kernel: `POSTURE-KERNEL-TCP-IP-OPTIONS` fails while the running kernel is in CVE-2026-98432's range and no rule drops inbound TCP with IP options, and `POSTURE-MPTCP` warns while MPTCP is on (see [posture.md](posture.md)).

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
| `--repo-hooks FILE` | Your list of hijacked-repo indicators (file names, package names, hosts, hashes) |
| `--no-posture` | Skip the machine's security settings |
| `--posture-policy FILE` | Posture checks to skip, one id per line (a server that means to run ssh: `REMOTE-LOGIN`) |

Policy files are one entry per line, `#` for comments. Reviewed false positives from gitleaks go in the repo's `.gitleaksignore` (the report prints the fingerprint to add).

## The cache, search and export

Answers live in one SQLite file: `~/.cache/wpantry/wpantry.db`, or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`. It holds the advisories for what is here, which versions were checked and when, the latest findings and the side feeds; never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (SQLite FTS5 syntax: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
wpantry export --csv findings.csv             # id, aliases, url, component, kind, affected and safe version, …
wpantry export --jsonl findings.jsonl --all   # one JSON object per finding, joined with its OSV record, lifecycle and fix outcome
wpantry watch                                 # re-ask about the unfixed Critical/High advisories; exit 10 when a fix landed
```

Each finding also says how the vulnerable dependency is depended on, where the lockfile records it: `dep_scope` (`runtime`, `dev`, `optional` or `unknown`), `dep_direct` (the project's own dependency, or pulled in by another; `null` when the lockfile doesn't say) and `affected_range` (the advisory's range the locked version fell in, such as `>=7.2.0, <9.0.0`). A dev-only dependency is rarely exposed where the code runs, so these three fields decide most of an advisory's applicability. npm, pnpm, Cargo, Composer, Pipfile, go.mod, Gemfile, uv and poetry lockfiles say some of this; `requirements-dev.txt` and its kin are read as dev. The JSON Lines export adds the full OSV `record`, when the exposure was first and last seen and resolved, and what the fix `--update` ran did; with `--all` the exposures a later scan resolved are rows too. It is what [wsentinel](https://github.com/waffuruai/wsentinel) builds its triage training data from.

## Advisories with no fix yet

Some advisories have no fix you can install: the vendor has not shipped the kernel or package yet. For a few of those there is something a host can do meanwhile, and that is a script in [`mitigations/`](../../mitigations/), one per advisory. The first is [`mitigations/cve-2026-98432.sh`](../../mitigations/cve-2026-98432.sh), for the Linux kernel's IPv4 TCP use-after-free (CVSS 9.8): an nftables rule dropping inbound TCP with IP options before conntrack, reloaded at boot, and MPTCP off.

Every script works the same way. `--status` says whether the host is exposed (exit 0 fixed or mitigated, 1 exposed, 2 when it needs root it does not have) and changes nothing, `--dry-run` prints what it would write, a plain run shows the same plan and asks before writing (`--yes` skips the question, for provisioning and CI), and `--remove` takes the stopgap away once the real fix is installed. A scan never runs one; it prints the script as the step. They are a reduction of exposure, not the patch: update when the fix ships, then `--remove`.

## What leaves your machine

Package names and versions go to OSV.dev; the feeds are downloaded; the breach check sends your email address only after you say yes. The complete list, source by source, is in [checks-and-sources.md](checks-and-sources.md#sources). Every request names wpantry in its User-Agent and times out after 30 seconds.

## Environment

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | The cache file |
| `GITHUB_TOKEN` | Lifts GitHub's anonymous rate limit for latest-release lookups |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned |
| `WPANTRY_TIMINGS` | Any value: each scan step on stderr with the seconds since the scan began, to see where a slow run spends its time |
| `NO_COLOR` | Any non-empty value turns colour off. Without it, wpantry colours its report, prompts and errors on a terminal only (never in pipes, files or `--json`) |
| `HTTPS_PROXY` | Requests go through the proxy |

## For agents

`wpantry skill` prints an agent skill (`SKILL.md`) that teaches a coding agent to run wpantry, triage its JSON and plan fixes safely. `wpantry tools --json` lists the external tools and whether they're installed.

## Troubleshooting

- **Everything is "not checked"**: you're offline, or a proxy blocks `api.osv.dev`. Re-run online, or `--offline` to use what's cached.
- **`gitleaks` MISSING**: install it (`brew install gitleaks`, or see its README); the secret scan can't run without it.
- **It's slow on the first run**: the first run downloads advisories and clones the malicious-package index; later runs reuse them for a day. `--path` and `--no-machine` narrow a run.
- **A finding is wrong**: open an issue with a minimal reproducer (never paste a real report; see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Security reports go through [SECURITY.md](../../SECURITY.md).
