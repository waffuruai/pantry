# Using wpantry

wpantry finds the vulnerabilities that actually apply to your computer and your git repos: it inventories what is installed and what your repos lock, and asks [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [endoflife.date](https://endoflife.date) only about those exact versions. Every check and every source is listed in [checks-and-sources.md](checks-and-sources.md); this page is how to run it and read what it says. Install it first: [install.md](install.md).

## Quick start

```bash
wpantry scan                                       # this computer: machine + every git repo under ~
wpantry scan --path ~/code/myproject --no-machine  # one project, no machine inventory
wpantry report                                     # the latest scan again, without scanning
wpantry report --html                              # one offline page: pantry_report_<when>.html in this directory
wpantry fix --dry-run                              # what it would fix, changing nothing
wpantry fix                                        # apply the fixes that can run unattended and the stopgaps wpantry has, then re-check
wpantry fix list                                   # what can be fixed: the plan, and wpantry's own fixes and whether each applies
wpantry scan --json --no-input | jq .              # findings as JSON, for tools and agents
wpantry schedule install --every week              # sync and scan every Monday at 09:30
wpantry help                                       # every command; wpantry help fix for one
```

`wpantry` on its own prints the commands; `wpantry --version` the version. Each command has one name, and a mistyped command or option is an error that names the closest one (`Did you mean --dry-run?`). The first run downloads advisories for what it finds and takes a while. After that, nothing expires: each run reads only what OSV changed since the last one, however long ago that was, and asks OSV only about versions it hasn't asked about before, so a later run takes seconds.

## What it checks

Dependencies, committed secrets, malicious packages, AI harnesses, install scripts, the OS, installed software, end of life, certificate authorities and the machine's own settings: the full table, with what each source is asked and what is sent, is [checks-and-sources.md](checks-and-sources.md). `--no-machine` limits a run to the repo checks. What a run could not check shows up as "not checked", never as clean.

## Scope

By default wpantry checks the machine and every git repo under your home directory. The walk is bounded: depth 6, symlinks not followed, and it skips `Library`, caches, toolchains, `node_modules`, build output and app bundles. It prints how many repos it found.

- `--path DIR` (repeat it for more) limits the repo checks to the repos at or under DIR. A DIR with no git repo is scanned as one project, without the git-history checks. A missing DIR is skipped with a note.
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

Then the findings, in areas in the order the fixes should go, a table each: one row per component with its advisory, its severity on CVSS's scale, the CVSS score and the EPSS likelihood (columns a table has no value for are left out), and the fix; under each row, where it is and why it is listed. Then what couldn't be checked, the update plan, and one line:

```
==> Security scan #12  2026-11-05 14:30 UTC · ~/.cache/wpantry/wpantry.db
  checked 12 git repos, 486 OS packages, 1820 project dependencies, 3 MCP servers

Project dependencies  1 fail
    COMPONENT  VERSION  ADVISORY        SEVERITY  CVSS  EPSS  FIX
  ✗ smallvec   1.6.0    CVE-2021-25900  CRITICAL  9.8   2.1%  cd ~/code/app && cargo update -p smallvec --precise 1.6.1
    ~/code/app/Cargo.lock · known exploited · Buffer overflow in SmallVec::insert_many

Secrets  1 fail
    COMPONENT    ADVISORY          SEVERITY  FIX
  ✗ app/.env     aws-access-token  HIGH      If it's real: rotate it, then purge it from history
    line 3, commit 1a2b3c4d5e6f · AWS Access Key

MCP servers  1 warn
    COMPONENT                    ADVISORY  SEVERITY  FIX
  ⚠ some-server (project: db)    UNPINNED  LOW       Pin some-server to a reviewed version in ~/code/app/.mcp.json
    ~/code/app/.mcp.json · `npx some-server` runs the latest release on every launch

Not checked
  ⚠ CISA KEV (exploited-in-the-wild marks): CISA KEV list unreachable and not cached

Update plan  wpantry fix runs the automatic ones
  needs you  cd ~/code/app && cargo update -p smallvec --precise 1.6.1  clears 1 finding

✗ 2 thing(s) to update (2 advisories), 1 warning(s). See the plan: wpantry fix --dry-run
```

- `✗` fails: a released fix exists, it's end of life, it's malicious, or it's a committed secret from a provider-specific rule.
- `⚠` warns: no fix yet, an outdated app, an unpinned MCP server, an install script, a generic secret rule to review.
- `known exploited` (KEV) marks a vulnerability CISA has seen exploited in the wild. Fix those first.
- **Severity** is on CVSS's scale: CRITICAL (9.0–10.0), HIGH (7.0–8.9), MEDIUM (4.0–6.9), LOW (0.1–3.9). An advisory's comes from its record's label (GitHub's MODERATE is MEDIUM), else from its CVSS 3.x or 4.0 score, or that of the records it is an alias of, or (when none has one) its CVE's at OSV or CVE.org; wpantry's own checks rate theirs by what they mean for the machine. **CVSS** is the advisory's base score. **EPSS** is [FIRST's](https://www.first.org/epss/) estimate of the chance it is exploited in the next 30 days: likelihood, shown beside the severity and never folded into it; within a severity, the likelier one is listed first.
- **not checked** lists sources that couldn't be reached and had nothing cached. Those areas are unknown, not clean; re-run when you're online.

## Reports: what the latest scan found, and what was done

`wpantry report` shows the latest scan from the cache; it never scans. `scan` and `fix` show the same when they finish, and take the same options. On a terminal a format other than the tables is written to `pantry_report_<when>.<ext>` in the current directory (the time in UTC, `pantry_report_20261105T143000Z.md`); through a pipe or into a file it goes to stdout; `-o FILE` names the file and `-o -` forces stdout.

```bash
wpantry report                              # the terminal report: areas, a table each, the update plan
wpantry report --md                        # the same as Markdown, in pantry_report_<when>.md here
wpantry report --html                      # one offline page in pantry_report_<when>.html (open it in a browser)
wpantry report --json                       # the schema-1 envelope scan --json prints
wpantry report --csv -o findings.csv        # one row per finding
wpantry report --jsonl -o findings.jsonl    # one object per finding, joined with its OSV record and lifecycle
wpantry report summary                      # one page for a CSO or an auditor: where things stand, times to fix, who fixed what
wpantry report summary --md -o summary.md
wpantry report history --md                 # the exposure, remediation and audit logs, last 14 days
wpantry report exposure --csv --since 365 -o exposure.csv     # what was exposed, and for how long, over a year
wpantry report remediation --csv -o fixes.csv                 # each fix: when, who, the result, the scan that verified it
wpantry report audit --json                 # every scan and event
wpantry report all --md                     # the findings, then every log
wpantry scan --html                        # scan, then write the page
```

Every scan is kept: when it ran, what it covered, and each finding from the scan that first saw it to the scan that no longer did. `wpantry fix` records the fixes it ran, who ran them and the scan that verified them. The word after `report` picks what it covers, the flags how it looks.

[reports.md](reports.md) says what each log holds and how it maps onto SOC 2 evidence.
## Keeping the cache fresh, and scanning on a schedule

```bash
wpantry sync                          # refresh the feeds and every answer the cache holds
wpantry schedule install              # every day at 09:30: sync, then scan (never fix)
wpantry schedule install --every week --at 07:00   # Mondays at 07:00; also hour, month (the 1st), quarter (1 Jan, Apr, Jul, Oct), year (1 Jan)
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

`wpantry fix --dry-run` prints the plan: one fix per component (the one that clears all its advisories), split into what can run unattended and what needs you. `wpantry fix` runs the unattended ones (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, removing malicious extensions), then re-checks. On a terminal it lists them first and asks `Run these N updates now? [Y/n]`; answer `n` and nothing changes. With `--no-input`, or no terminal, it runs them without asking. Everything that needs sudo, a vendor, or a change in a repo is printed as a step. A fix in a repo's lockfile is a code change: make it on a branch with that repo's tests.

For a browser report, run `wpantry report --html` (or `wpantry scan --html` to scan first): it writes `pantry_report_<when>.html` in the current directory, or the file `-o FILE` names. The page is the visual summary of that run, in Waffuru's design language, dark or light, and answers four questions in order: **1 Scanned**, the inventory counts by area, every source that could not be checked listed as a gap (never as clean), and the scope and policy of the scan; **2 At risk**, one row per component grouped by area, with areas and rows in the order the fixes should go (a repo that runs code on open, malicious packages, committed secrets, known exploited, end of life, then severity), KEV and severity badges, and the advisories, affected range, dependency scope and fix behind each row; **3 Patching**, the commands `wpantry fix` runs unattended, what the local history says has been patched (fixes verified by a complete re-check, exposures resolved) and the advisories with no released fix and their mitigation; **4 By hand**, numbered steps with the exact command or setting and what each clears. When the cache has history, **5 History** carries the exposure and remediation logs of `wpantry report`.

The plan is wpantry's own (`wpantry fix --dry-run` prints the same one): one fix per component, `mise` never upgraded for you, many secret hits in one file one decision. **Hand this to an AI agent** under By hand copies a prompt with every finding, the plan and the coverage context of the scan for the agent of your choice; preview it and remove local paths you do not want to share. Copying sends nothing and runs nothing.

A scan with no findings or recorded coverage gaps gets a quiet **All clear. Nicely done.** finish with the Waffuru mark. It applies only to the checked scope: empty imports, zero inventory, offline scans, unknown licenses, unfixed advisories and failed updates do not trigger it.

The viewer imports `scan --json` reports and `report --csv` findings (Load report, or drop the file on the page). An imported scan has no recorded scope, plan or history; its steps are grouped from the findings' suggested actions and say so. History reports and lifecycle JSONL exports use different formats and are not scan imports. Older JSON reports remain readable, with missing dependency and scope information shown as unknown.

**Print** (or your browser's Print command) produces a light paper layout of the same page with every row open, whatever the screen filters, and without controls or the agent prompt. Choose Save as PDF in the print dialog to keep a copy. The file makes no request when opened: the fonts, the mark, the styles and the script are embedded.

## Exposed with no fix yet

Most advisories are `✗` because a fixed version exists. When none does, the scan still tells you about the ones that matter (Critical, High, or exploited in the wild): a `⚠` line with `(no fix released for … yet)` and, as its step, what to do meanwhile. The steps come from a bundled list ([`mitigations.txt`](../../rust/crates/wpantry/assets/defaults/mitigations.txt), one line per advisory); an advisory with no entry says to keep checking and reduce exposure. The Moderate and Low ones are only counted (`unfixed` in the JSON). Nothing here fails the run.

```
os
  ⚠ linux-image-generic 6.8.0-45.45 (/var/lib/dpkg/status) - (CVE-2026-98432 CRITICAL) TCP use-after-free (no fix released for Ubuntu:24.04:LTS yet). Fix: Until the kernel update lands: drop inbound IPv4 TCP packets that carry IP options (…) and turn off MPTCP (…)
```

A scan picks up a fix when OSV's change list shows it. For these you want to know within the hour, so `wpantry watch` asks again about exactly them, bypassing that cache, and exits 10 when a fix has landed:

```bash
wpantry watch                 # each watched advisory: "no fix yet" + the mitigation, or "FIX AVAILABLE: <component> <version>"
wpantry watch --json          # {"schema": 1, …, "watched": [{"id", "severity", "summary", "ecosystem", "package", "version", "fixed", "mitigation"}]}
```

Run it hourly from cron or a timer and alert on exit 10 (`0 * * * * wpantry watch --json > ~/.cache/wpantry/watch.json || notify …`), then run `wpantry fix --dry-run` for the step. On Linux the posture checks also cover the kernel: `POSTURE-KERNEL-TCP-IP-OPTIONS` fails while the running kernel is in CVE-2026-98432's range and no rule drops inbound TCP with IP options, and `POSTURE-MPTCP` warns while MPTCP is on or a program still holds an MPTCP listening socket (the sysctl only stops new ones; the evidence names the services to restart) (see [posture.md](posture.md)). The repo side is covered too: a Go module on `go 1.24` or newer that listens for TCP without `GODEBUG=multipathtcp=0` or `SetMultipathTCP(false)` (Go turns Multipath TCP on by default there, which is the path the bug is reached through), or any source that asks for MPTCP by name, is a `project` warning naming the file and the opt-out ([checks-and-sources.md](checks-and-sources.md#what-it-checks)); it is never auto-fixed.

## JSON

`wpantry scan --json` prints one object and never prompts:

```json
{
 "schema": 1, "impl": "rust", "version": "0.2.0",
 "checked": {"git repos": 12, "project dependencies": 1820},
 "unfixed": 3, "unknown_licenses": 0,
 "findings": [{"kind": "project", "component": "smallvec", "version": "1.6.0", "location": "/home/me/code/app/Cargo.lock",
               "vuln_id": "CVE-2021-25900", "status": "fail", "fixed": "1.6.1", "kev": true, "severity": "CRITICAL",
               "cvss": 9.8, "cvss_version": "3.1", "epss": 0.0213, "epss_percentile": 0.84,
               "note": "…", "fix_cmd": "…", "fix_auto": false}]
}
```

Check `schema` before reading it. The fields, the finding kinds and markers (`UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, …) are defined in the [CLI contract](../../specs/cli-contract.md).

## The cache and search

Answers live in one SQLite file: `~/.cache/wpantry/wpantry.db`, or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`. It holds the advisories for what is here, which versions were checked and when, the latest findings, every scan's history, and the side feeds (CISA KEV, EPSS, …); never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (SQLite FTS5 syntax: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
wpantry report --csv -o findings.csv          # id, aliases, url, component, kind, affected and safe version, …
wpantry report exposure --jsonl -o f.jsonl   # one JSON object per finding, joined with its OSV record, lifecycle and fix outcome
wpantry watch                                 # re-ask about the unfixed Critical/High advisories; exit 10 when a fix landed
```

Each finding also says how the vulnerable dependency is depended on, where the lockfile records it: `dep_scope` (`runtime`, `dev`, `optional` or `unknown`), `dep_direct` (the project's own dependency, or pulled in by another; `null` when the lockfile doesn't say) and `affected_range` (the advisory's range the locked version fell in, such as `>=7.2.0, <9.0.0`). A dev-only dependency is rarely exposed where the code runs, so these three fields decide most of an advisory's applicability. npm, pnpm, Cargo, Composer, Pipfile, go.mod, Gemfile, uv and poetry lockfiles say some of this; `requirements-dev.txt` and its kin are read as dev. The JSON Lines export adds the full OSV `record`, when the exposure was first and last seen and resolved, and what the fix `wpantry fix` ran did; with `report exposure` the exposures a later scan resolved are rows too. It is what [wsentinel](https://github.com/waffuruai/wsentinel) builds its triage training data from.

## Fixing one thing, and fixes with no update yet

`wpantry fix` does everything; `wpantry fix list` shows what that is, and `wpantry fix ID` does one thing: an advisory (by id or alias), or one of the fixes wpantry makes itself, by name.

```
wpantry fix list                            # the update plan in batches, and wpantry's own fixes and whether each applies here
wpantry fix --dry-run                       # every command and change, nothing run
wpantry fix GHSA-xxxx-yyyy-zzzz             # an advisory with a released fix: runs its unattended fix, prints the rest
wpantry fix ca-trust                        # distrust the leaked eMudhra roots in the system trust store (sudo asks)
wpantry fix extension-cooldown --hours 72   # editors wait before installing a newly published extension version
wpantry fix CVE-2026-98432 --dry-run        # an advisory with no fix to install yet: the state of the host and what the stopgap would write
wpantry fix CVE-2026-98432                  # the plan, a question, then the stopgap (as root: sudo asks on the terminal)
wpantry fix CVE-2026-98432 --yes            # the same without the question (provisioning)
wpantry fix CVE-2026-98432 --undo           # take the stopgap away once the kernel update is in
```

`fix ID` runs the fixes the last scan found for the id that may run unattended (a version bump, the way `wpantry fix` does), runs wpantry's own fix for it where one exists, and prints the steps that need you; exit 1 when a step is left, a fix failed, nothing is known for the id here, or a question went unanswered (no terminal and no `--yes`). Every fix it runs goes into the remediation log with who ran it (`wpantry report remediation`). `wpantry fix` runs wpantry's own fixes too: `ca-trust` and `extension-cooldown` when the scan found what they fix, the CVE-2026-98432 stopgap on a Linux host it is for.

A stopgap survives a reboot: the systemd unit reloads the rule before the network comes up (`Before=network-pre.target`), and `/etc/sysctl.d/90-no-mptcp.conf` is applied by `systemd-sysctl` at boot. It is a reduction of exposure, not the patch, and is taken away with `--undo` once the kernel update is in.

## What leaves your machine

Package names and versions go to OSV.dev; the id of a CVE that applies and has no CVSS score goes to OSV.dev, then CVE.org; the feeds are downloaded; the breach check sends your email address only after you say yes. The complete list, source by source, is in [checks-and-sources.md](checks-and-sources.md#sources). Every request names wpantry in its User-Agent and times out after 30 seconds.

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

Every command and its options, exactly as `wpantry <command> --help` prints them (`wpantry help <command>` is the same). Each command and option has one name; options are spelled out in full, and take their value as the next word or after `=` (`-o -` too). A usage error prints the usage line and the error, with the closest name when one is close, to stderr and exits 2. The command line is declared with [wcli](../../rust/crates/wcli/README.md), which generates this help.

```
Usage: wpantry [options] [command]

The vulnerabilities, malware and risky settings that apply to this computer and its repos. See
README.md.

Options:
  -V, --version  print the version
  -h, --help     print this help

Commands:
  scan [options]             Scan this computer and its repos, then show the report
  fix [options] [target]     Scan, run the unattended fixes and stopgaps, then re-check (list, or
                             one id)
  report [options] [part]    The latest scan's report, a log, or the summary, in any format
  search [options] <query>   Search the cached advisories (for agents)
  watch [options]            Re-check the advisories with no fix yet; exit 10 when one lands
  sync [options]             Refresh the cache for offline scans
  schedule <command>         Run sync and scan on a schedule
  rules [options] [command]  The malware scan's YARA rules; gen writes one from samples
  sources [options]          Every outside source, when it was last fetched and what went wrong
  breach [options]           Show or set consent for the email breach check
  cache <command>            Maintain the cache
  update [options]           Install a newer release, verified
  version [options]          Print the version, implementation and JSON schema
  tools [options]            List the external tools wpantry uses
  skill                      Print the agent skill (SKILL.md)
  help [command]             Print a command's help

Exit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error.
```

### scan

```
Usage: wpantry scan [options]

Scan this computer and its repos, then show the report. Changes nothing.

Options:
  --path <dir>              check only the repos at or under this directory; repeat it for more
                            (default: every git repo under ~)
  --no-machine              skip the machine inventory: repo checks only
  --refresh                 ignore cached answers and ask every source again
  --offline                 use only the local cache
  --txt                     the report as plain text, without colour
  --json                    the findings as JSON (schema 1)
  --jsonl                   one JSON object per finding, joined with its OSV record, lifecycle and
                            fix
  --csv                     one table: the findings, or the log asked for
  --md                      Markdown
  --html                    one offline HTML page
  -o, --out <file>          write the report there; - for stdout. Without it, a format goes to
                            pantry_report_<when>.<ext> here when stdout is a terminal, and to stdout
                            when it is a pipe or a file
  --since <days>            how far back the logs go (default: 14)
  --no-input                never prompt
  --jobs <n>                gitleaks scans at once (default: half the cores, at most 4)
  --gitleaks-config <file>  gitleaks policy (default: the bundled gitleaks.toml)
  --licenses [file]         also check dependency licenses, against the file or the bundled
                            licenses.txt
  --install-scripts <file>  install-script policy (default: the bundled install-scripts.txt)
  --repo-hooks <file>       indicators of hijacked repos (default: the bundled repo-hooks.txt)
  --hooks-policy <file>     repo hooks you've read and accept, one per line
  --suspect-policy <file>   suspicious-code ids and paths that warn instead of fail
  --no-posture              skip the machine's security settings (FileVault, firewall, sharing, …)
  --posture-policy <file>   posture checks to skip, one id per line
  --no-malware              skip the malware scan (YARA rules over Downloads, Desktop, temp, login
                            items and repo programs)
  --deep                    the malware scan reads everything under ~ with every system's rules
                            (slower)
  --no-online-hash          never look up a flagged file's SHA-256 at YARAify, CIRCL or
                            MalwareBazaar (asked once otherwise)
  --sources <file>          your sources file for this run (default: ~/.config/wpantry/sources.toml
                            when it exists)
  -h, --help                print this help

Exit codes: 0 nothing fails, 1 something fails, 2 usage error, 3 internal error.
```

### fix

```
Usage: wpantry fix [options] [target]

Scan, run the fixes that can run unattended and the stopgaps wpantry has for what it found, then
re-check.

Arguments:
  target  all: a scan, the unattended fixes, every stopgap that applies, a re-check. list: what can
          be fixed, from the latest scan; nothing runs. An advisory id (CVE-…, GHSA-…; an alias
          works): its unattended fixes, wpantry's stopgap for it, the steps that need you. Or one of
          wpantry's own fixes: ca-trust (distrust the leaked eMudhra roots), extension-cooldown
          (editors wait before installing a new extension version), cve-2026-98432 (default: all)

Options:
  --dry-run                 print what would run or be written; change nothing
  --yes                     run the fixes and write the stopgaps without asking
  --undo                    with an id: take wpantry's stopgap away once the real fix is installed
  --bundle <file>           ca-trust: rewrite this PEM bundle instead of the system trust store
  --hours <n>               extension-cooldown: the cooldown (default: 72)
  --path <dir>              check only the repos at or under this directory; repeat it for more
                            (default: every git repo under ~)
  --no-machine              skip the machine inventory: repo checks only
  --refresh                 ignore cached answers and ask every source again
  --offline                 use only the local cache
  --txt                     the report as plain text, without colour
  --json                    the findings as JSON (schema 1)
  --jsonl                   one JSON object per finding, joined with its OSV record, lifecycle and
                            fix
  --csv                     one table: the findings, or the log asked for
  --md                      Markdown
  --html                    one offline HTML page
  -o, --out <file>          write the report there; - for stdout. Without it, a format goes to
                            pantry_report_<when>.<ext> here when stdout is a terminal, and to stdout
                            when it is a pipe or a file
  --since <days>            how far back the logs go (default: 14)
  --no-input                never prompt
  --jobs <n>                gitleaks scans at once (default: half the cores, at most 4)
  --gitleaks-config <file>  gitleaks policy (default: the bundled gitleaks.toml)
  --licenses [file]         also check dependency licenses, against the file or the bundled
                            licenses.txt
  --install-scripts <file>  install-script policy (default: the bundled install-scripts.txt)
  --repo-hooks <file>       indicators of hijacked repos (default: the bundled repo-hooks.txt)
  --hooks-policy <file>     repo hooks you've read and accept, one per line
  --suspect-policy <file>   suspicious-code ids and paths that warn instead of fail
  --no-posture              skip the machine's security settings (FileVault, firewall, sharing, …)
  --posture-policy <file>   posture checks to skip, one id per line
  --no-malware              skip the malware scan (YARA rules over Downloads, Desktop, temp, login
                            items and repo programs)
  --deep                    the malware scan reads everything under ~ with every system's rules
                            (slower)
  --no-online-hash          never look up a flagged file's SHA-256 at YARAify, CIRCL or
                            MalwareBazaar (asked once otherwise)
  --sources <file>          your sources file for this run (default: ~/.config/wpantry/sources.toml
                            when it exists)
  -h, --help                print this help

Exit codes: 0 nothing fails after the re-check, 1 something still fails or a fix failed, 2 usage
error, 3 internal error.
```

### report

```
Usage: wpantry report [options] [part]

The latest scan's report, from the cache; it never scans (scan and fix show it when they finish).

Arguments:
  part  what the report covers (choices: findings, history, exposure, remediation, audit, summary,
        all; default: findings)

Options:
  --txt             the report as plain text, without colour
  --json            the findings as JSON (schema 1)
  --jsonl           one JSON object per finding, joined with its OSV record, lifecycle and fix
  --csv             one table: the findings, or the log asked for
  --md              Markdown
  --html            one offline HTML page
  -o, --out <file>  write the report there; - for stdout. Without it, a format goes to
                    pantry_report_<when>.<ext> here when stdout is a terminal, and to stdout when it
                    is a pipe or a file
  --since <days>    how far back the logs go (default: 14)
  -h, --help        print this help

Parts:
findings     the latest scan's findings
history      the exposure, remediation and audit logs
exposure     what applied, from first seen to resolved
remediation  the fixes run: when, who, the result, the scan that verified them
audit        every scan and event
summary      one page for a CSO, an auditor or an insurer
all          the findings, then every log

Exit codes: 0 nothing fails, 1 something fails in the latest scan or there is none, 2 usage error, 3
internal error.
```

### search

```
Usage: wpantry search [options] <query>

Search the cached advisories (for agents).

Arguments:
  query  an id, package or word

Options:
  --applicable  only advisories that apply here
  --limit <n>   the most to list (default: 20)
  --json        the hits as JSON
  -h, --help    print this help
```

### watch

```
Usage: wpantry watch [options]

Ask OSV again about the advisories the last scan found with no released fix (Critical, High,
exploited in the wild); exit 10 when a fix has landed.

Options:
  --offline   use only the local cache
  --json      the watched advisories as JSON
  -h, --help  print this help
```

### sync

```
Usage: wpantry sync [options]

Refresh the cache: the feeds, end-of-life dates and OSV answers for what was scanned before, so scan
--offline has fresh answers.

Options:
  --refresh   ask every source again, even when its answer is fresh
  --json      what was refreshed, as JSON
  -h, --help  print this help
```

### schedule

```
Usage: wpantry schedule [options] <command>

Run sync and scan on a schedule (launchd, a systemd user timer, or cron); never fixes.

Options:
  -h, --help  print this help

Commands:
  install [options]  Install the job
  status             Whether the job is installed, and how its last run went
  uninstall          Remove the job
  run                What the job runs: sync, then scan --json --no-input
  help [command]     Print a command's help
```

### schedule install

```
Usage: wpantry schedule install [options]

Install the job.

Options:
  --every <period>  how often, each from the period's start: a week on Monday, a month on the 1st, a
                    quarter on 1 January, April, July and October, a year on 1 January (choices:
                    hour, day, week, month, quarter, year; default: day)
  --at <time>       the time of day, HH:MM (default: 09:30)
  --dry-run         print the job definition without installing it
  -h, --help        print this help
```

### rules

```
Usage: wpantry rules [options] [command]

The YARA rules the malware scan uses: ours, built in, and YARA Forge's, fetched into the cache
directory.

Options:
  --update    fetch YARA Forge's latest package now
  --json      the sources and counts as JSON
  -h, --help  print this help

Commands:
  gen [options] <sample...>  Write a YARA rule matching what the samples share and this machine's
                             programs don't (unreviewed: category suspicious, score 60)
  goodware                   Rebuild the goodware database from this machine's system programs (gen
                             builds it the first time)
  help [command]             Print a command's help
```

### rules gen

```
Usage: wpantry rules gen [options] <sample...>

Write a YARA rule matching what the samples share and this machine's programs don't (unreviewed:
category suspicious, score 60).

Arguments:
  sample  the sample files

Options:
  --category <cat>  the category you propose (default: malware)
  --family <name>   the family's name (default: the first sample's file name)
  --name <rule>     the rule's name (default Gen_<category>_<family>)
  -o, --out <file>  write the rule there, and its test file beside it (default: stdout)
  -h, --help        print this help
```

### sources

```
Usage: wpantry sources [options]

Every outside source wpantry reads: its kind, tier, host and licence, when it was last fetched,
whether that is fresh, and what last went wrong.

Options:
  --json            the sources as JSON
  --sources <file>  your sources file (default: ~/.config/wpantry/sources.toml when it exists)
  -h, --help        print this help
```

### breach

```
Usage: wpantry breach [options]

Show or set consent for the email breach check.

Options:
  --enable    allow it
  --disable   stop it
  -h, --help  print this help
```

### cache prune

```
Usage: wpantry cache prune [options]

Drop what no scan has used in a while, then compact the file.

Options:
  --older-than <days>  what counts as unused (default: 90)
  -h, --help           print this help
```

### update

```
Usage: wpantry update [options]

Check for a newer wpantry release and, after a yes, install it verified.

Options:
  --check          only say whether a newer release exists (exit 10 when one does)
  --yes            install without asking
  --no-input       never ask: report only
  --offline        use only the cached answer
  --version <ver>  this release instead of the latest
  -h, --help       print this help
```

### version

```
Usage: wpantry version [options]

Print the version, implementation and JSON schema.

Options:
  --json      as JSON
  -h, --help  print this help
```

### tools

```
Usage: wpantry tools [options]

List the external tools wpantry uses.

Options:
  --json      as JSON
  -h, --help  print this help
```

### skill

```
Usage: wpantry skill [options]

Print the agent skill (SKILL.md).

Options:
  -h, --help  print this help
```

## Troubleshooting

- **Everything is "not checked"**: you're offline, or a proxy blocks `api.osv.dev`. Re-run online, or `--offline` to use what's cached.
- **`gitleaks` MISSING**: install it (`brew install gitleaks`, or see its README); the secret scan can't run without it.
- **It's slow on the first run**: the first run downloads advisories and clones the malicious-package index; later runs read only what changed. `--path` and `--no-machine` narrow a run.
- **A finding is wrong**: open an issue with a minimal reproducer (never paste a real report; see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Security reports go through [SECURITY.md](../../SECURITY.md).
