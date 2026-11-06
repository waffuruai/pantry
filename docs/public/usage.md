# Using wpantry

wpantry finds the vulnerabilities that actually apply to your computer and your git repos: it inventories what is installed and what your repos lock, and asks [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [endoflife.date](https://endoflife.date) only about those exact versions. Every check and every source is listed in [checks-and-sources.md](checks-and-sources.md); this page is how to run it and read what it says. Install it first: [install.md](install.md).

## Quick start

```bash
wpantry scan                                       # this computer: machine + every git repo under ~
wpantry scan --path ~/code/myproject --no-machine  # one project, no machine inventory
wpantry fix --dryrun                               # what it would fix, changing nothing
wpantry fix                                        # apply the fixes that can run unattended and the stopgaps wpantry has, then re-check
wpantry mitigate list                              # the stopgaps wpantry can install and whether each applies here
wpantry scan --json --no-input                     # findings as JSON, for tools and agents
wpantry help                                       # every command; wpantry help fix for one
```

`wpantry` on its own prints the commands. `wpantry check` is the same as `wpantry scan`. The first run downloads advisories for what it finds and takes a while; answers are cached for a day, so the next run the same day takes seconds.

## What it checks

Dependencies, committed secrets, malicious packages, AI harnesses, install scripts, the OS, installed software, end of life, certificate authorities and the machine's own settings: the full table, with what each source is asked and what is sent, is [checks-and-sources.md](checks-and-sources.md). `--no-machine` limits a run to the repo checks. What a run could not check shows up as "not checked", never as clean.

## Scope

By default wpantry checks the machine and every git repo under your home directory. The walk is bounded: depth 6, symlinks not followed, and it skips `Library`, caches, toolchains, `node_modules`, build output and app bundles. It prints how many repos it found.

- `--path DIR` (repeatable) limits the repo checks to the repos at or under DIR. A DIR with no git repo is scanned as one project, without the git-history checks. A missing DIR is skipped with a note.
- `--no-machine` skips the machine inventory: repo checks only.

## Cloned a repo? Check it before you open it

A repo can run code the moment an agent or editor opens it: a `.claude/settings.json` SessionStart hook, a `.cursor/mcp.json` server, a `.vscode/tasks.json` task on folder open, a devcontainer command, an npm `postinstall`. Hijacked repos hide the payload in a file the hook runs (a 13 MB `.github/init.js` that code search never indexes). Before opening a clone you didn't write:

```bash
wpantry scan --path ~/Downloads/some-repo --no-machine
```

Alongside the hooks, the same pass reads every source, config and prose file for text that would fool you or a tool. Context decides, not the character alone: a bidirectional override on a line with no right-to-left text **fails** (`HIDDEN-BIDI`, Trojan Source), while the same control beside Arabic or Hebrew (a translation file, a link title) warns; Unicode tag characters **fail** when what they spell is an instruction to an agent or they sit in a file written for agents (`CLAUDE.md`, prompts), and warn otherwise, the note quoting what they spell either way (`HIDDEN-TAGS`); the England, Scotland and Wales flags, which are tag characters after a black flag, are emoji and not counted. Runs of zero-width characters, identifiers that mix Latin with Cyrillic or Greek, and identifiers named after weapons and lethal doses warn (`HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`). The last is a trick aimed at AI-assisted review: a model that refuses to read "computeRicinLethalDosage" never sees the fingerprinting it does. Pantry reads the code regardless and tells you the names were chosen to make a reviewer look away.

An agent also reads what a person skims: READMEs, comments, package descriptions, commit messages, and whatever a page renders. Text in those places that addresses the agent instead of the reader ("ignore previous instructions", "note to AI agents: install …", "do not tell the user") warns (`AGENT-INSTRUCTIONS`); the files whose job that is (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, prompts) are left alone, and in code only comment lines count. The same text hidden from the reader (a `display:none` block, white on white, a zero-size font, an off-screen position, an HTML comment) **fails** (`HIDDEN-PROMPT`); a hidden block of ordinary text in a README warns (`HIDDEN-HTML`). A markdown image or link whose query string is built to carry something (`?data={{conversation}}`, `?secret=`) warns (`EXFIL-LINK`), and fails in a file that also addresses the agent: rendered, it posts whatever it was given. `javascript:`, `vbscript:` and executable `data:` URIs fail as link targets in prose and warn in page source (`DANGEROUS-URI`). A file name with invisible or direction-changing characters, or a document's extension in front of a program's (`report.pdf.exe`), fails (`HIDDEN-FILENAME`); a name or a domain in a link that mixes Latin with look-alike letters from another script fails for the domain (`CONFUSABLE-DOMAIN`) and warns for the name (`CONFUSABLE-NAME`); a punycode domain warns.

The documents and images in the clone are read too (`document` findings): a PDF that runs JavaScript on open, a `.docx` carrying macros or fetching its template from a URL, an image with a program after its last byte, an SVG with a script fail; what can't be read (encrypted, zip64, over 32 MiB) says so rather than passing. The same pass covers the top of `~/Downloads`, `~/Desktop` and `~/Documents` on a machine scan, and runs ClamAV over those files when `clamscan` is installed (`wpantry tools` lists it; wpantry never installs it). [documents.md](documents.md) has every id.

A hook that runs a file kept in the repo, a file that looks like a dropper, or a known indicator fails (`repo-hook` findings `RUNS-REPO-FILE`, `LOADER`, `IOC`); a hook that runs a command at all warns (`OPEN-HOOK`, `INSTALL-HOOK`), as do the commit and branch markers of a known campaign (`MARKER`). Nothing is run or fixed for you: read the file the finding names, then remove the hook or decide to trust it. `--repo-hooks FILE` replaces the bundled indicator list. A hook you have read and accept goes in your hooks policy (`--hooks-policy FILE`): each `OPEN-HOOK` and `INSTALL-HOOK` finding ends with the exact line to paste (`hook assets/package.json "npm postinstall script" node bin/postinstall`), and `repo ~/Development/mine` accepts every such hook under a path. Accepted hooks are counted in the report (`repo hooks accepted by policy`) rather than listed, and a hook whose command changes is listed again. Nothing that fails can be accepted.

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

✗ 2 thing(s) to update (2 advisories), 1 warning(s). See the plan: wpantry fix --dryrun
```

- `✗` fails: a released fix exists, it's end of life, it's malicious, or it's a committed secret from a provider-specific rule.
- `⚠` warns: no fix yet, an outdated app, an unpinned MCP server, an install script, a generic secret rule to review.
- `KEV` marks a vulnerability CISA has seen exploited in the wild. Fix those first.
- **not checked** lists sources that couldn't be reached and had nothing cached. Those areas are unknown, not clean; re-run when you're online.

## Reports: what the latest scan found, and what was done

`wpantry report` shows the latest scan from the cache; it never scans. `scan` and `fix` show the same when they finish, and take the same options. `export` is another name for it.

```bash
wpantry report                              # the terminal report: areas, a table each, the update plan
wpantry report --md -o report.md            # the same as Markdown, in a file
wpantry report --html -o report.html        # one offline page (open it in a browser)
wpantry report --json                       # the schema-1 envelope scan --json prints
wpantry report --csv -o findings.csv        # one row per finding
wpantry report --jsonl -o findings.jsonl    # one object per finding, joined with its OSV record and lifecycle
wpantry report --md --history               # and the exposure, remediation and audit logs, last 14 days
wpantry report --csv --since 365 -o exposures.csv   # the exposure log of the last year
wpantry scan --html -o report.html          # scan, then write the page
```

Every scan is kept: when it ran, what it covered, and each finding from the scan that first saw it to the scan that no longer did. `wpantry fix` records the fixes it ran and the scan that verified them; `--history` adds those logs to any format.

[reports.md](reports.md) says what each log holds and how it maps onto SOC 2 evidence.
## Keeping the cache fresh, and scanning on a schedule

```bash
wpantry sync                          # refresh the feeds and every answer the cache holds
wpantry schedule install              # daily at 09:30: sync, then scan (never fix)
wpantry schedule install --every weekly --at 07:00
wpantry schedule status               # scheduled? when did it last run, what did it find
wpantry schedule uninstall
wpantry cache prune                   # drop what no scan has used in 90 days, compact the file
```

`sync` re-asks every source about what the cache already knows (feeds, end-of-life dates, every package version scanned before) without inventorying anything, so a `scan --offline` afterwards answers from fresh data. `schedule` runs it for you through launchd (macOS), a systemd user timer (Linux) or cron, at low priority, and writes the scan's JSON to `~/.local/state/wpantry/last.json` (`$XDG_STATE_HOME`) with one line per run in `schedule.log`. A scheduled run never changes anything: run `wpantry fix` yourself when the morning report says so.

## Keeping wpantry current

```bash
wpantry update --check     # exit 10 when a newer release exists, 0 when you have the latest
wpantry update             # asks, then installs the verified release (--yes to skip the question)
```

An update is verified before anything is replaced (see [install.md](install.md#upgrade-and-uninstall)); a mise, cargo or Homebrew install is updated through that tool. `scan` mentions a newer release on stderr once a day; `WPANTRY_NO_UPDATE_CHECK=1` silences it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and "not checked" sources still exit 0 (the report says "Incomplete") |
| 1 | Something fails, or an unattended fix failed under `fix` |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |
| 10 | `wpantry watch` only: a fix has landed for something that had none |

## Fixing

`wpantry fix --dryrun` prints the plan: one fix per component (the one that clears all its advisories), split into what can run unattended and what needs you. `wpantry fix` runs the unattended ones (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, removing malicious extensions), then re-checks. On a terminal it lists them first and asks `Run these N updates now? [Y/n]`; answer `n` and nothing changes. With `--no-input`, or no terminal, it runs them without asking. Everything that needs sudo, a vendor, or a change in a repo is printed as a step. A fix in a repo's lockfile is a code change: make it on a branch with that repo's tests.

For a browser report, run `wpantry report --html -o report.html` (or `wpantry scan --html -o report.html` to scan first). The page is the visual summary of that run, in Waffuru's design language, dark or light, and answers four questions in order: **1 Scanned**, the inventory counts by area, every source that could not be checked listed as a gap (never as clean), and the scope and policy of the scan; **2 At risk**, one row per component grouped by area, with areas and rows in the order the fixes should go (a repo that runs code on open, malicious packages, committed secrets, known exploited, end of life, then severity), KEV and severity badges, and the advisories, affected range, dependency scope and fix behind each row; **3 Patching**, the commands `wpantry fix` runs unattended, what the local history says has been patched (fixes verified by a complete re-check, exposures resolved) and the advisories with no released fix and their mitigation; **4 By hand**, numbered steps with the exact command or setting and what each clears. When the cache has history, **5 History** carries the exposure and remediation logs of `wpantry report`.

The plan is wpantry's own (`wpantry fix --dryrun` prints the same one): one fix per component, `mise` never upgraded for you, many secret hits in one file one decision. **Hand this to an AI agent** under By hand copies a prompt with every finding, the plan and the coverage context of the scan for the agent of your choice; preview it and remove local paths you do not want to share. Copying sends nothing and runs nothing.

A scan with no findings or recorded coverage gaps gets a quiet **All clear. Nicely done.** finish with the Waffuru mark. It applies only to the checked scope: empty imports, zero inventory, offline scans, unknown licenses, unfixed advisories and failed updates do not trigger it.

The viewer imports `scan --json` reports and `export --csv` findings (Load report, or drop the file on the page). An imported scan has no recorded scope, plan or history; its steps are grouped from the findings' suggested actions and say so. History reports and lifecycle JSONL exports use different formats and are not scan imports. Older JSON reports remain readable, with missing dependency and scope information shown as unknown.

**Print** (or your browser's Print command) produces a light paper layout of the same page with every row open, whatever the screen filters, and without controls or the agent prompt. Choose Save as PDF in the print dialog to keep a copy. The file makes no request when opened: the fonts, the mark, the styles and the script are embedded.

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

Run it hourly from cron or a timer and alert on exit 10 (`0 * * * * wpantry watch --json > ~/.cache/wpantry/watch.json || notify …`), then run `wpantry fix --dryrun` for the step. On Linux the posture checks also cover the kernel: `POSTURE-KERNEL-TCP-IP-OPTIONS` fails while the running kernel is in CVE-2026-98432's range and no rule drops inbound TCP with IP options, and `POSTURE-MPTCP` warns while MPTCP is on or a program still holds an MPTCP listening socket (the sysctl only stops new ones; the evidence names the services to restart) (see [posture.md](posture.md)). The repo side is covered too: a Go module on `go 1.24` or newer that listens for TCP without `GODEBUG=multipathtcp=0` or `SetMultipathTCP(false)` (Go turns Multipath TCP on by default there, which is the path the bug is reached through), or any source that asks for MPTCP by name, is a `project` warning naming the file and the opt-out ([checks-and-sources.md](checks-and-sources.md#what-it-checks)); it is never auto-fixed.

## JSON

`wpantry scan --json` prints one object and never prompts:

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

## The cache, search and export

Answers live in one SQLite file: `~/.cache/wpantry/wpantry.db`, or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`. It holds the advisories for what is here, which versions were checked and when, the latest findings and the side feeds; never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (SQLite FTS5 syntax: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
wpantry report --csv -o findings.csv          # id, aliases, url, component, kind, affected and safe version, …
wpantry report --jsonl --history -o f.jsonl   # one JSON object per finding, joined with its OSV record, lifecycle and fix outcome
wpantry watch                                 # re-ask about the unfixed Critical/High advisories; exit 10 when a fix landed
```

Each finding also says how the vulnerable dependency is depended on, where the lockfile records it: `dep_scope` (`runtime`, `dev`, `optional` or `unknown`), `dep_direct` (the project's own dependency, or pulled in by another; `null` when the lockfile doesn't say) and `affected_range` (the advisory's range the locked version fell in, such as `>=7.2.0, <9.0.0`). A dev-only dependency is rarely exposed where the code runs, so these three fields decide most of an advisory's applicability. npm, pnpm, Cargo, Composer, Pipfile, go.mod, Gemfile, uv and poetry lockfiles say some of this; `requirements-dev.txt` and its kin are read as dev. The JSON Lines export adds the full OSV `record`, when the exposure was first and last seen and resolved, and what the fix `wpantry fix` ran did; with `--history` the exposures a later scan resolved are rows too. It is what [wsentinel](https://github.com/waffuruai/wsentinel) builds its triage training data from.

## Advisories with no fix yet

Some advisories have no fix you can install: the vendor has not shipped the kernel or package yet. `wpantry mitigate <ID>` does what this host can about one advisory, by id or alias:

```
wpantry mitigate CVE-2026-98432 --dry-run   # the state of the host and what would be written; nothing changes
wpantry mitigate CVE-2026-98432             # the plan, a question, then the stopgap (as root: sudo asks on the terminal)
wpantry mitigate CVE-2026-98432 --yes       # the same without the question (provisioning)
wpantry mitigate CVE-2026-98432 --undo      # take the stopgap away once the kernel update is in (--remove is the same)
wpantry mitigate GHSA-xxxx-yyyy-zzzz        # an advisory with a released fix: runs its unattended fix, prints the rest
wpantry mitigate list                       # the stopgaps wpantry can install, whether each applies here, and the advisories with an unattended fix
wpantry mitigate all --dry-run              # everything at once: the same as wpantry fix --dryrun
```

It runs the fixes the last scan found for the id that may run unattended (a version bump, the way `wpantry fix` does), runs wpantry's own stopgap for it where one exists, and prints the steps that need you; exit 1 when a step is left, a fix failed, or nothing is known for the id here (not in the last scan, no stopgap). The first stopgap is for the Linux kernel's IPv4 TCP use-after-free, [CVE-2026-98432](https://osv.dev/vulnerability/CVE-2026-98432) (CVSS 9.8): an nftables rule dropping inbound TCP with IP options before conntrack, a systemd unit that reloads it at boot, MPTCP off through `sysctl.d`, and the services still holding an MPTCP listening socket named for a restart (`sudo systemctl restart …`, printed, never run: `net.mptcp.enabled=0` only stops new sockets, a program that already listens keeps its until restarted). The listeners are read from `ss -tlnpi` as root (every TCP listener whose upper-layer protocol is MPTCP is marked `tcp-ulp-mptcp`, which needs no `mptcp_diag` module), else from `ss -M` where the kernel has that module, else reported as unseen. A scan never runs any of it; it prints the command as the step. `wpantry fix` (and `mitigate all`, the same thing) runs the stopgaps too, after the unattended fixes, asking on a terminal and skipping them without one unless `--yes`.

A stopgap survives a reboot: the systemd unit reloads the rule before the network comes up (`Before=network-pre.target`), and `/etc/sysctl.d/90-no-mptcp.conf` is applied by `systemd-sysctl` at boot. It is a reduction of exposure, not the patch, and it is meant to come off again. When the kernel update lands, three things tell you: `wpantry watch` exits 10 with `FIX AVAILABLE`, `POSTURE-KERNEL-TCP-IP-OPTIONS` passes with "the stopgap is still in place", and `wpantry mitigate list` says the fix is in. Then `wpantry mitigate CVE-2026-98432 --undo` puts the host back as it was: the unit disabled and removed, the nft table deleted, the rule file and the sysctl file removed, `net.mptcp.enabled` back to 1. Nothing else was changed, so nothing else needs undoing.

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

## Command reference

Every command and its options, as `wpantry help` and `wpantry <command> --help` print them. `wpantry` with no arguments prints the same top-level help as `wpantry help` and `wpantry -h`, and exits 0; `wpantry help <command>` is `wpantry <command> --help`. An option can be shortened to any prefix that names only one (`--no-m` for `--no-machine`) and takes its value as the next word or after `=`. A usage error prints the usage line and the error to stderr and exits 2.

```
usage: wpantry [-h] {scan,check,fix,search,export,breach,watch,version,tools,skill,sync,schedule,cache,update,report,harden,mitigate,rules,sources,help} ...
```

| Command | What it does |
|---|---|
| `scan` | Scan this computer and report what applies to it; change nothing |
| `check` | The same as `scan`, with the same options, output and exit codes |
| `fix` | Scan, run the unattended fixes and the stopgaps, then re-check (`--dryrun` prints the plan) |
| `search` | Search cached advisories (for agents) |
| `export` | The same as `report` |
| `breach` | Show or set consent for the email breach check |
| `watch` | Re-check the unfixed Critical/High advisories; exit 10 when a fix has landed |
| `version` | Print the version, implementation and JSON schema |
| `tools` | List the external tools this implementation uses |
| `skill` | Print the agent skill (`SKILL.md`) |
| `sync` | Refresh the cache for offline scans |
| `schedule` | Run sync and scan on a schedule |
| `cache` | Maintain the cache (prune) |
| `update` | Check for a newer release and install it verified |
| `report` | The exposure, remediation and audit logs |
| `harden` | Apply a fix wpantry can make itself (`extension-cooldown`, `ca-trust`) |
| `mitigate` | `list`, `all`, or one advisory: its unattended fixes, its stopgap, the steps left for you |
| `help` | This help, or with a command that command's (`wpantry help fix`) |

### scan, check

```
usage: wpantry scan [-h] [--path DIR] [--no-machine] [--refresh] [--offline] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--history] [--since DAYS] [--no-input] [--jobs N]
                    [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]
                    [--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-malware] [--deep]
```

`check` is the same command under its older name: `wpantry check --help` prints the same options. Exit 0 when nothing fails, 1 when something does, 2 on a usage error, 3 on an internal error.

| Option | Effect |
|---|---|
| `--path DIR` | Check only the repos at or under DIR (repeatable; default: every git repo under `~`). See [Scope](#scope) |
| `--no-machine` | Skip the machine inventory: repo checks only |
| `--refresh` | Ignore cached answers and ask every source again |
| `--offline` | Use only the cache; anything never cached is "not checked" |
| `--txt`, `--json`, `--jsonl`, `--csv`, `--md`, `--html`, `-o FILE`, `--history`, `--since DAYS` | How the report is shown when the scan is done, as [`report`](#report) shows it. `--json` (schema 1, see [JSON](#json)) never prompts. `-o FILE` is checked before the scan starts |
| `--no-input` | Never prompt: the breach-check question is skipped, and `fix` runs without asking |
| `--jobs N` | How many git histories gitleaks scans at once (default: half the cores, at most 4). Each scan gets a share of the cores, so a first run over many repos no longer takes the whole machine |
| `--gitleaks-config FILE` | Your gitleaks config instead of the bundled `gitleaks.toml` (a repo's own `.gitleaks.toml` is reported, never obeyed) |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled `licenses.txt`. Off by default; `--license` works too |
| `--install-scripts FILE` | Your allowlist of npm packages whose install scripts are accepted, each at a version range (`esbuild@^0.28`); a locked version outside its entry still warns |
| `--repo-hooks FILE` | Your list of hijacked-repo indicators (file names, package names, hosts, hashes) instead of the bundled `repo-hooks.txt` |
| `--hooks-policy FILE` | Repo hooks you have read and accept, each on its exact command (`hook <file> "<when>" <command>`, the line each warning prints) or every warning under a path (`repo <path>`); counted, not listed, until a command changes. Hooks that fail are never accepted |
| `--suspect-policy FILE` | Suspicious-code ids and `path:` entries that should warn instead of fail (a legitimate hex table, an installer that uses sudo); nothing is silenced |
| `--no-posture` | Skip the machine's security settings (FileVault, firewall, sharing, …) |
| `--posture-policy FILE` | Posture checks to skip, one id per line (a server that means to run ssh: `REMOTE-LOGIN`) |
| `--no-malware` | Skip the malware scan (YARA rules over Downloads, Desktop, temp, login items and repo programs) |
| `--deep` | The malware scan reads everything under `~` with every system's rules (slower) |

Policy files are one entry per line, `#` for comments. An install-scripts entry is `name@1.2.3` (that version), `name@^1.2` or `name@~1.2` (npm's caret and tilde ranges, so `^0.28` is `>=0.28.0 <0.29.0`), or a bare `name` for every version, which is allowed and discouraged: the allowlist is the only thing that decides whether an install script runs unremarked, so each entry should name the versions someone has read. The bundled list ([`install-scripts.txt`](../../rust/crates/wpantry/assets/defaults/install-scripts.txt)) explains itself, as does the hooks policy's ([`hooks.txt`](../../rust/crates/wpantry/assets/defaults/hooks.txt)). Reviewed false positives from gitleaks go in the repo's `.gitleaksignore` (the report prints the fingerprint to add).

### fix

```
usage: wpantry fix [-h] [--dryrun] [--yes] [--path DIR] [--no-machine] [--refresh] [--offline] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--history] [--since DAYS] [--no-input] [--jobs N]
                   [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]
                   [--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-malware] [--deep]
```

Scan, then run the fixes that can run unattended and the stopgaps wpantry has for what it found, then re-check. It takes every option `scan` does, plus:

| Option | Effect |
|---|---|
| `--dryrun` | Print the fix plan; change nothing |
| `--yes` | Run the fixes and write the stopgaps without asking |

Exit 0 when nothing fails after the re-check, 1 when something still fails or a fix failed, 2 on a usage error, 3 on an internal error. With `--json` it reports only, as `scan --json` does. [Fixing](#fixing) says what runs and when it asks.

### search

```
usage: wpantry search [-h] [--applicable] [--limit LIMIT] [--json] query
```

Search cached advisories, ranked (SQLite FTS5 syntax: `"exact phrase"`, `tls AND cert`, `rust*`).

| Option | Effect |
|---|---|
| `query` | What to search for |
| `--applicable` | Only advisories that apply here |
| `--limit LIMIT` | At most this many (default 20) |
| `--json` | Print the results as JSON |

### export

The same as [`report`](#report).

### breach

```
usage: wpantry breach [-h] [--enable | --disable]
```

Show or set consent for the email breach check. Without an option it shows the consent.

| Option | Effect |
|---|---|
| `--enable` | Consent: the breach check runs on a machine scan |
| `--disable` | Withdraw it |

### watch

```
usage: wpantry watch [-h] [--offline] [--json]
```

Ask OSV again about the advisories the last scan found with no released fix (Critical, High, exploited in the wild): exit 10 when a fix has landed. See [Exposed with no fix yet](#exposed-with-no-fix-yet).

| Option | Effect |
|---|---|
| `--offline` | Use only the local cache |
| `--json` | Print the watched advisories as JSON |

### version, tools, skill

```
usage: wpantry version [-h] [--json]
usage: wpantry tools [-h] [--json]
usage: wpantry skill [-h]
```

`version` prints the version, implementation and JSON schema; `tools` lists the external tools this implementation uses, found or missing (exit 1 when a required one is missing); `skill` prints the agent skill. `--json` prints `version` and `tools` as JSON.

### sync

```
usage: wpantry sync [-h] [--refresh] [--json]
```

Refresh the cache: the feeds, end-of-life dates and OSV answers for what was scanned before, so `scan --offline` has fresh answers. Exit 1 when a source was unreachable.

| Option | Effect |
|---|---|
| `--refresh` | Ask every source again, even when its answer is fresh |
| `--json` | Print what was refreshed as JSON |

### schedule

```
usage: wpantry schedule [-h] [--every WHEN] [--at HH:MM] [--dry-run] {install,status,uninstall,run}
```

Run sync and scan on a schedule (launchd, a systemd user timer, or cron); a scheduled run never fixes anything (that is `wpantry fix`). `install` sets it up, `status` says whether it is installed and what the last run found, `uninstall` takes it away, `run` is what the scheduler runs.

| Option | Effect |
|---|---|
| `--every WHEN` | `hourly`, `daily` (default) or `weekly` |
| `--at HH:MM` | The time of day (default 09:30; weekly: Mondays) |
| `--dry-run` | Print the job definition without installing it |

### cache

```
usage: wpantry cache [-h] [--older-than DAYS] {prune}
```

Maintain the cache. `prune` drops what no scan has used in a while, then compacts the file.

| Option | Effect |
|---|---|
| `--older-than DAYS` | What counts as unused (default 90) |

### update

```
usage: wpantry update [-h] [--check] [--yes] [--no-input] [--offline] [--version VER]
```

Check for a newer wpantry release and, after a yes, install it verified. See [Keeping wpantry current](#keeping-wpantry-current).

| Option | Effect |
|---|---|
| `--check` | Only say whether a newer release exists (exit 10 when one does) |
| `--yes` | Install without asking |
| `--no-input` | Never ask: report only |
| `--offline` | Use only the cached answer |
| `--version VER` | This release instead of the latest |

### report

```
usage: wpantry report [-h] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--history] [--since DAYS]
```

The latest scan's report, from the cache; it never scans. `scan` and `fix` show the same when they finish, with the same options. Exit 1 when the latest scan has a failing finding (or there is none yet), 0 otherwise. See [reports.md](reports.md).

| Option | Effect |
|---|---|
| (none) | The terminal report: the findings grouped into areas in the order to fix them, each area a table (component, version, advisory, severity, fix) with where and why under each row; what couldn't be checked; the update plan, alike commands batched and `sudo` ones apart. Coloured on a terminal and fitted to its width |
| `--txt` | The same as plain text, 120 columns |
| `--json` | The schema-1 envelope `scan --json` prints |
| `--jsonl` | One JSON object per finding: the finding, aliases, url, record, first_seen, last_seen, resolved_at, days_exposed, fix |
| `--csv` | One row per finding: id, aliases, url, component, kind, affected and safe version, severity, kev, status, location |
| `--md` | Markdown: the areas as tables, the gaps, the plan |
| `--html` | One offline page; with 14 days of history (`--since DAYS` for more) |
| `-o`, `--out FILE` | Write there instead of stdout (the terminal report becomes `--txt`) |
| `--history` | Add the exposure, remediation and audit logs (`--json`: under `history`; `--csv`: the exposure log instead of the findings; `--jsonl`: the resolved exposures too) |
| `--since DAYS` | How far back the history goes (default 14); implies `--history` |

### harden

```
usage: wpantry harden [-h] [--hours N] [--bundle FILE] {extension-cooldown,ca-trust}
```

Apply one of the fixes wpantry can make itself. `extension-cooldown` sets `extensions.installCooldownHours` in every VS Code-family editor's `settings.json`; `ca-trust` distrusts the leaked eMudhra roots in the system trust store (sudo asks to install the result).

| Option | Effect |
|---|---|
| `--hours N` | `extension-cooldown`: the cooldown (default 72) |
| `--bundle FILE` | `ca-trust`: rewrite this PEM bundle instead of the system store |

### mitigate

```
usage: wpantry mitigate [-h] [--dry-run] [--yes] [--no-input] [--undo] [--offline] [--no-machine] [--path DIR]
                        {list,all,ID}
```

Do what this host can about advisories: `list` (the stopgaps wpantry has and whether each applies here, and the advisories in the last scan with an unattended fix), `all` (everything: the same as `wpantry fix`), or one advisory `ID` (`CVE-…`, `GHSA-…`; an alias works). See [Advisories with no fix yet](#advisories-with-no-fix-yet). Exit 0 when everything that applies here was done (or, with `--dry-run`, printed), 1 when a step is left for you, a fix failed, or nothing is known for the id here, 2 on a usage error.

| Option | Effect |
|---|---|
| `--dry-run` | Print what would run or be written; change nothing |
| `--yes` | Run and write without asking |
| `--no-input` | Never ask: the unattended fixes run, the stopgaps are skipped unless `--yes` |
| `--undo` | `ID` only: take wpantry's stopgap away again once the real fix is installed (`--remove` is the same) |
| `--offline`, `--no-machine`, `--path DIR` | `all` only: as for `scan` |

## Troubleshooting

- **Everything is "not checked"**: you're offline, or a proxy blocks `api.osv.dev`. Re-run online, or `--offline` to use what's cached.
- **`gitleaks` MISSING**: install it (`brew install gitleaks`, or see its README); the secret scan can't run without it.
- **It's slow on the first run**: the first run downloads advisories and clones the malicious-package index; later runs reuse them for a day. `--path` and `--no-machine` narrow a run.
- **A finding is wrong**: open an issue with a minimal reproducer (never paste a real report; see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Security reports go through [SECURITY.md](../../SECURITY.md).
