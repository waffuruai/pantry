# Using Pantry

Pantry finds the vulnerabilities that apply to your computer and your git repos. It inventories what is installed and what your repos lock, and asks [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [endoflife.date](https://endoflife.date) about those exact versions only. Install it first: [install](install.md). Every check and source: [checks and sources](checks-and-sources.md).

## Quick start

```bash
wpantry scan                                       # this computer: the machine and every git repo under ~
wpantry scan --path ~/code/myproject --no-machine  # one project, no machine inventory
wpantry report                                     # the latest scan again, without scanning
wpantry report --html                              # one offline page: pantry_report_<when>.html here
wpantry fix --dry-run                              # what it would fix; changes nothing
wpantry fix                                        # apply the unattended fixes and stopgaps, then re-check
wpantry fix list                                   # what can be fixed
wpantry scan --json --no-input | jq .              # findings as JSON, for tools and agents
wpantry schedule install --every week              # sync and scan every Monday at 09:30
wpantry help                                       # every command (wpantry help fix for one)
```

- `wpantry` alone prints the commands; `wpantry --version` prints the version.
- A mistyped command or option is an error that names the closest one (`Did you mean --dry-run?`).
- The first run downloads advisories and takes a while. After that nothing expires: each run reads only what OSV changed since the last one, and asks OSV only about new versions, so later runs take seconds.

## Scope

By default Pantry checks the machine and every git repo under your home directory. The walk goes 6 levels deep, doesn't follow symlinks, and skips `Library`, caches, toolchains, `node_modules`, build output and app bundles.

- `--path DIR` checks only the repos at or under DIR (repeat it for more). A DIR with no git repo is scanned as one project, without the git-history checks.
- `--no-machine` skips the machine: repo checks only.

What a run couldn't check is reported "not checked", never clean.

## Check a clone before you open it

A repo can run code the moment an agent or editor opens it: a Claude Code hook, an MCP server, a VS Code folder-open task, a devcontainer command, an npm `postinstall`. Before opening a clone you didn't write:

```bash
wpantry scan --path ~/Downloads/some-repo --no-machine
```

| Finding | Fails | Warns |
|---|---|---|
| Repo hooks (`repo-hook`) | A hook that runs a file kept in the repo, looks like a dropper, or matches a known indicator (`RUNS-REPO-FILE`, `LOADER`, `IOC`) | A hook that runs any command (`OPEN-HOOK`, `INSTALL-HOOK`); a known campaign's commit or branch markers (`MARKER`) |
| Hidden text ([suspect code](suspect-code.md)) | Trojan Source bidi overrides, hidden instructions to an agent, dangerous link targets, disguised file names | Zero-width runs, mixed-script names, text that addresses an agent |
| Documents ([documents](documents.md)) | A PDF that runs JavaScript, an Office file with macros or a remote template, an image or SVG carrying code | What can't be read says so, never passes |

Nothing is run or fixed for you: read the file the finding names, then remove the hook or trust it.

To accept a hook you've read, add it to your hooks policy (`--hooks-policy FILE`, TOML). Each `OPEN-HOOK` and `INSTALL-HOOK` finding ends with the entry to paste:

```toml
hooks = [
  { file = "assets/package.json", when = "npm postinstall script", command = "node bin/postinstall" },
]
repos = ["~/Development/mine"]   # every hook that warns under this path
```

Accepted hooks are counted, not listed. A hook whose command changes is listed again. A hook that fails can't be accepted.

## Reading the report

While it scans, a progress line shows what it's doing (only on a terminal). Then the findings, grouped into areas in the order to fix them:

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

- **`✗` fails**: a released fix exists, end of life, malicious, or a committed secret from a provider-specific rule.
- **`⚠` warns**: no fix yet, an outdated app, an unpinned MCP server, an install script, a generic secret to review.
- **known exploited** (CISA KEV): seen exploited in the wild. Fix these first.
- **Severity** uses CVSS's scale: CRITICAL 9.0–10.0, HIGH 7.0–8.9, MEDIUM 4.0–6.9, LOW 0.1–3.9. It comes from the advisory's label (GitHub's MODERATE is MEDIUM), else its CVSS 3.x or 4.0 score. Pantry's own checks are rated by what they mean for the machine.
- **CVSS**: the advisory's base score. When its records have none, its CVE's score from OSV or CVE.org.
- **EPSS**: [FIRST's](https://www.first.org/epss/) estimate of the chance it's exploited in the next 30 days. Shown beside the severity, never folded in; within a severity, the likelier comes first.
- **Not checked**: sources that couldn't be reached and had nothing cached. Unknown, not clean.

## Reports

`wpantry report` shows the latest scan from the cache; it never scans. `scan` and `fix` end with the same report and take the same options.

```bash
wpantry report                              # the terminal report
wpantry report --html                       # one offline page
wpantry report --md                         # Markdown
wpantry report --json                       # the schema-1 envelope (as scan --json)
wpantry report --csv -o findings.csv        # one row per finding
wpantry report --jsonl                      # one object per finding, with its OSV record and lifecycle
wpantry report summary                      # one page for a CSO or an auditor
wpantry report history --md                 # exposure, remediation and audit logs, last 14 days
wpantry report exposure --csv --since 365   # what was exposed, and for how long, over a year
wpantry report remediation --csv            # each fix: when, who, the result, the scan that verified it
wpantry report audit --json                 # every scan and event
wpantry report all --md                     # the findings, then every log
```

- **Where it goes:** on a terminal, a format other than the terminal tables is written to `pantry_report_<when>.<ext>` here (UTC, e.g. `pantry_report_20261105T143000Z.html`). Through a pipe or into a file it goes to stdout. `-o FILE` names the file; `-o -` forces stdout.
- **What's kept:** every scan, and every finding from the scan that first saw it to the one that no longer did. `wpantry fix` records each fix, who ran it, and the scan that verified it.

[Reports](reports.md) covers each log, the HTML page and the SOC 2 and ISO 27001 mapping.

## Scheduled scans and the cache

```bash
wpantry sync                                       # refresh the cache without scanning
wpantry schedule install                           # every day at 09:30: sync, then scan (never fix)
wpantry schedule install --every week --at 07:00   # also hour, month, quarter, year: each at the period's start
wpantry schedule status                            # installed? last run, and what it found
wpantry schedule uninstall
wpantry cache prune                                # drop what no scan used in 90 days, compact the file
```

- `sync` refreshes the feeds, end-of-life dates and OSV's answers for every version scanned before, so a later `scan --offline` is current.
- `schedule` uses launchd (macOS), a systemd user timer (Linux) or cron, at low priority. Each run writes `~/.local/state/wpantry/last.json` and a line in `schedule.log`.
- A scheduled run never changes anything. Run `wpantry fix` yourself.
- The cache is one SQLite file: `~/.cache/wpantry/wpantry.db` (or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`). It holds advisories for what's here, which versions were checked, every scan's findings, and the feeds; never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (FTS5: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
```

## Fixing

```bash
wpantry fix --dry-run    # the plan: one fix per component, unattended or needs you
wpantry fix              # run the unattended fixes, then re-check
```

- **Unattended:** Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, removing malicious extensions. On a terminal it asks `Run these N updates now? [Y/n]` first; with `--no-input`, or no terminal, it runs them.
- **Needs you:** anything needing sudo, a vendor, or a repo change, printed as a step for you or your agent to run. A lockfile fix is a code change: make it on a branch, with that repo's tests.
- `mise` is never upgraded for you.

### One thing at a time

```bash
wpantry fix list                            # the plan in batches, and Pantry's own fixes and whether each applies
wpantry fix GHSA-xxxx-yyyy-zzzz             # one advisory: its unattended fix, then the steps that need you
wpantry fix ca-trust                        # distrust the leaked eMudhra roots in the system trust store
wpantry fix extension-cooldown --hours 72   # editors wait before installing a new extension version
wpantry fix CVE-2026-98432 --dry-run        # no fix to install yet: the host's state and what the stopgap writes
wpantry fix CVE-2026-98432                  # asks, then installs the stopgap (sudo asks on the terminal)
wpantry fix CVE-2026-98432 --undo           # remove the stopgap once the kernel update is in
```

- `fix ID` exits 1 when a step is left, a fix failed, nothing is known for the id, or a question went unanswered (no terminal and no `--yes`).
- Every fix goes into the remediation log with who ran it (`wpantry report remediation`).
- `wpantry fix` also runs `ca-trust` and `extension-cooldown` when the scan found what they fix, and the CVE-2026-98432 stopgap on a Linux host that needs it.
- A stopgap survives a reboot. It reduces exposure; it isn't the patch.

### No fix released yet

When an advisory that matters (Critical, High, or known exploited) has no fixed version, the scan warns with a stopgap from [`mitigations.toml`](../../rust/crates/wpantry/assets/defaults/mitigations.toml), or says to keep checking. Medium and Low ones are only counted (`unfixed` in the JSON). None of these fail the run.

`wpantry watch` re-asks OSV about exactly those advisories and exits 10 when a fix lands. Run it hourly and alert on exit 10, for example from cron:

```
0 * * * * wpantry watch --json > ~/.cache/wpantry/watch.json || notify …
```

For CVE-2026-98432 the [posture checks](posture.md) also cover the Linux kernel (`POSTURE-KERNEL-TCP-IP-OPTIONS`, `POSTURE-MPTCP`), and a Go 1.24+ module that listens for TCP with Multipath TCP on is a `project` warning.

## Keeping Pantry current

```bash
wpantry update --check    # exit 10 when a newer release exists
wpantry update            # asks, then installs it, verified
```

See [upgrade](install.md#upgrade).

## JSON

`wpantry scan --json` prints one object and never prompts:

```json
{
 "schema": 1, "impl": "rust", "version": "0.3.0",
 "checked": {"git repos": 12, "project dependencies": 1820},
 "unfixed": 3, "unknown_licenses": 0,
 "findings": [{"kind": "project", "component": "smallvec", "version": "1.6.0", "location": "/home/me/code/app/Cargo.lock",
               "vuln_id": "CVE-2021-25900", "status": "fail", "fixed": "1.6.1", "kev": true, "severity": "CRITICAL",
               "cvss": 9.8, "cvss_version": "3.1", "epss": 0.0213, "epss_percentile": 0.84,
               "note": "…", "fix_cmd": "…", "fix_auto": false}]
}
```

- Check `schema` before reading it. Every field, kind and marker is defined in the [CLI contract](../../specs/cli-contract.md).
- A dependency finding also says how it's depended on: `dep_scope` (`runtime`, `dev`, `optional`, `unknown`), `dep_direct` (the project's own, or pulled in; `null` when unknown) and `affected_range`. A dev-only dependency is rarely exposed where the code runs.
- `wpantry report --jsonl` adds each finding's full OSV record, when it was first and last seen and resolved, and what `wpantry fix` did about it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and "not checked" still exit 0 (the report says "Incomplete") |
| 1 | Something fails, or an unattended fix failed |
| 2 | Usage error: unknown option, missing argument, missing or invalid policy file |
| 3 | Internal error: the cache can't be opened or written, or a crash |
| 10 | `watch`: a fix has landed. `update --check`: a newer release exists |

## What leaves your machine

- Package names and versions go to OSV.dev.
- The id of a CVE that applies and has no CVSS score goes to OSV.dev, then CVE.org.
- Feeds are downloaded whole.
- The breach check sends your email address only after you say yes.

Source by source: [what is sent](checks-and-sources.md#sources). Every request names `wpantry` in its User-Agent and times out after 30 seconds.

## Environment

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | The cache file |
| `GITHUB_TOKEN` | Lifts GitHub's anonymous rate limit for latest-release lookups |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned |
| `WPANTRY_TIMINGS` | Print each scan step's elapsed time on stderr |
| `NO_COLOR` | Turn colour off. Colour is only ever used on a terminal |
| `HTTPS_PROXY` | Send requests through the proxy |

## For agents

`wpantry skill` prints the agent skill (`SKILL.md`): how to run Pantry, triage its JSON and plan fixes safely. `wpantry tools --json` lists the external tools and whether they're installed.

## Command reference

Every command, exactly as `wpantry <command> --help` prints it. Options are spelled out in full and take their value as the next word or after `=`. A usage error exits 2. The help is generated by [wcli](../../rust/crates/wcli/README.md).

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
