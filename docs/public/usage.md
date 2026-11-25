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

- `--path DIR` checks only the repos and files at or under DIR (repeat it for more). A DIR with no git repo is scanned as one project, without the git-history checks. Nothing else of yours is read: not Downloads, Desktop, Documents or the temp directories. The machine inventory still runs, unless `--no-machine`.
- `--deep` reads everything in scope, and is slower: every file of the computer this user can read, `~` first (or each `--path`), for malware with every system's rules and for secrets, plus history files up to 256 MB with no time limit. Hours on a first run; after that only what changed is read.
  - **What it reads:** on macOS the data volume's folders and each local volume under `/Volumes`, never the read-only system volume; on Linux `/`, less `/proc`, `/sys`, `/dev`, `/run` and network or pseudo mounts. Network shares are never read.
  - **Secrets in files:** an uncommitted `.env`, `~/.aws/credentials`, a key under `/opt`. A secret already found in history isn't reported twice.
  - **Not checked:** folders this user can't read, by place (on macOS, give your terminal Full Disk Access), and files over 10 MB for secrets. When a repo's history couldn't all be read, its "not checked" row gives the command to copy: `wpantry scan --path <repo> --no-machine --deep`.
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

To accept a hook you've read, add it to your hooks policy, `~/.config/wpantry/hooks.toml` (see [policy files](#policy-files)). Each `OPEN-HOOK` and `INSTALL-HOOK` finding ends with the entry to paste:

```toml
hooks = [
  { file = "assets/package.json", when = "npm postinstall script", command = "node bin/postinstall" },
]
repos = ["~/Development/mine"]   # every hook that warns under this path
```

Accepted hooks are counted, not listed. A hook whose command changes is listed again. A hook that fails can't be accepted.

## Policy files

Policy files tune what a scan accepts or checks. Each is a TOML file in `~/.config/wpantry/` (or `$XDG_CONFIG_HOME/wpantry/`), named as below. Pantry loads it on every scan, scheduled ones included, in place of its bundled default. An option names another file for one run.

| File | Option | What it does | Keys | Bundled default |
|---|---|---|---|---|
| `suspect.toml` | `--suspect-policy` | Suspicious code you've reviewed warns instead of failing ([suspect code](suspect-code.md#the-policy-file)) | `ids`, `paths` | empty |
| `hooks.toml` | `--hooks-policy` | Repo hooks you've read stop being reported (see above) | `hooks`, `repos` | empty |
| `posture.toml` | `--posture-policy` | Machine settings checks to skip ([machine settings](posture.md)) | `skip` | empty |
| `install-scripts.toml` | `--install-scripts` | npm packages whose install scripts are allowed | `allow` | [`install-scripts.toml`](../../rust/crates/wpantry/assets/defaults/install-scripts.toml) |
| `licenses.toml` | `--licenses FILE` | Dependency licenses allowed without review (checked only with `--licenses`) | `allow` | [`licenses.toml`](../../rust/crates/wpantry/assets/defaults/licenses.toml) |
| `repo-hooks.toml` | `--repo-hooks` | Indicators of hijacked repos | `files`, `packages`, `hosts`, `sha256` | [`repo-hooks.toml`](../../rust/crates/wpantry/assets/defaults/repo-hooks.toml) |

To start one, copy the bundled default linked above (its comments explain each key) into `~/.config/wpantry/` and edit it. The next scan uses it:

```bash
mkdir -p ~/.config/wpantry
$EDITOR ~/.config/wpantry/install-scripts.toml
wpantry scan
```

- A policy never silences a failure it isn't for. A hook that runs a file kept in the repo fails whatever the hooks policy says.
- A file that isn't TOML is a usage error (exit 2), whether Pantry found it or an option named it.
- `ignore` in the same folder, and a repo's `.pantryignore`, leave paths out of the findings, for every check or one ([ignore.md](ignore.md)). They are gitignore patterns, not TOML.
- `wpantry ignore add F-… [--scope user|repo] [--reason TEXT]` writes the rule for a finding into one of those files for you, `ignore list` shows them and `ignore remove` takes a rule out again ([ignore.md](ignore.md#ignoring-a-finding-from-the-command-line)). It never prompts, so a program driving wpantry can use it: `wpantry ignore add F-3fa9c01b2e --scope repo --reason "test key, revoked" --json`.
- `secrets.yar` in the same folder adds secret rules of your own (`--secret-rules`): YARA, in pantry-rules' form (a `$secret` regex, an `id` and `category = "secret"` meta). They must compile beside the bundled ones.

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
  ✗ app/.env     aws-access-token  HIGH      If it's real: rotate it first, then take it out of …
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
wpantry schedule status --json                     # the same as JSON, for scripts
wpantry schedule uninstall
wpantry cache prune                                # drop what no scan used in 90 days, compact the file
```

- `sync` refreshes what the cache already knows, so a later `scan --offline` is current. It inventories nothing:
  - the feeds: CISA KEV, EPSS, the malicious-package index, Homebrew casks, Chrome, Firefox, VS Code's extension lists, the latest Pantry;
  - once a malware scan fetched them: YARA Forge's rules, signature-base's and Feodo Tracker's lists;
  - Elastic's rules, once turned on ([malware.md](malware.md#adding-elastics-rules)), replacing a copy you added by hand; and the rules and lists of your sources file you said yes to; a rules file put in the rules directory by hand is named, since nothing can update it;
  - once PostgreSQL was found: its security page;
  - for what scans asked about: end-of-life dates, OSV, CIRCL's CVE records, the latest Open VSX and Marketplace versions of the extensions last checked, upstream repos' release tags, and CVE scores (OSV, CVE.org).
- `sync` keeps your `sources.toml` tiers: a source turned off isn't fetched. It never asks a source that needs your yes (breaches, hash lookups).
- `schedule` uses launchd (macOS), a systemd user timer (Linux) or cron, at low priority, and on Windows a Task Scheduler job for your account only, with least privilege, that runs while you are signed in. Each run writes `~/.local/state/wpantry/last.json` and a line in `schedule.log`.
- On Windows, when a windowless launcher, `wpantry-desktop.exe`, sits beside the scanner, the task starts `wpantry-desktop.exe --scheduled-run`, which runs `wpantry.exe schedule run` without a console window. Otherwise the task runs `wpantry.exe schedule run`.
- On macOS and Linux the same rule holds with a launcher named `wpantry-desktop`: when an executable by that name sits beside the scanner, the launchd job, systemd timer or cron line runs `wpantry-desktop --scheduled-run` instead of `wpantry schedule run`, and that launcher does the scheduled work. Run `wpantry schedule install` again after the launcher appears or goes, and the job is rewritten to match.
- On macOS a scheduled run scans with `--no-personal-files`: it leaves Downloads, Desktop and Documents out, because opening them can wait on a permission prompt nobody is there to answer. The report lists them under "Skipped by your choice", not as unfinished checks. Linux and Windows scan those folders.
- There is one scheduled scan per account. Every copy of wpantry, and any program that drives it, sees and changes that one job.
- `schedule status --json` prints one object: `schema`, `backend` (`launchd`, `systemd`, `cron` or `windows`), `installed`, `enabled` (null when nothing is installed or the scheduler could not be asked), `interval` (in words), `every`, `at`, `last_run` (UTC, null before the first readable run) and `program` (the path of the program the scheduled job runs, read from the job itself, so it can be another copy of wpantry or the launcher; null when nothing is scheduled or it cannot be read).
- A scheduled run never changes anything. Run `wpantry fix` yourself.
- The cache is one SQLite file: `~/.cache/wpantry/wpantry.db` (or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`). It holds advisories for what's here, which versions were checked, every scan's findings, and the feeds; never a mirror of OSV.

```bash
wpantry search "tarfile traversal"            # rank cached advisories (FTS5: "exact phrase", tls AND cert, rust*)
wpantry search openssl --applicable --json    # only those that apply here
```

## macOS privacy prompts

macOS asks before a program opens some folders, and a scan started by a GUI program or a scheduled job has nobody to answer. With `--no-personal-files` (what a scheduled run uses) a scan never lists or opens:

- `~/Documents`, `~/Desktop` and `~/Downloads`, in any pass: finding repos, the files pass, the malware scan, the programs that start at login, the PATH;
- iCloud Drive and other cloud drives (`~/Library/Mobile Documents`, `~/Library/CloudStorage`), `~/Pictures`, `~/Music` and `~/Movies`;
- other apps' data: `~/Library/Mail`, `Messages`, `Safari`, `Calendars`, `Application Support/AddressBook`, `Containers` and `Group Containers`.

They are left out by path, before anything touches them, and the report says so as "Skipped by your choice" (`Repositories in personal folders`, `Personal documents and images`). A repo kept in one of them is not scanned. To include them, run the scan without `--no-personal-files` at a terminal that can answer the prompt, or name the folder: `wpantry scan --path ~/Documents/project` scans it even with the flag. A folder the system refuses to list (a denied prompt, no Full Disk Access) is reported as not checked and the scan goes on. On Linux and Windows the flag leaves out the same three folders under your home folder.

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
wpantry fix list                            # the plan in batches, the findings in fix order with their ids, and Pantry's own fixes
wpantry fix next                            # the next finding to fix, and how (--json for agents)
wpantry fix F-3fa9c01b2e --dry-run          # one finding, by its id: what its fix would run
wpantry fix secret F-0c41d9a7b2             # a committed secret: check it, then take it out of git history, step by step
wpantry fix GHSA-xxxx-yyyy-zzzz             # one advisory: its unattended fix, then the steps that need you
wpantry fix ca-trust                        # distrust the leaked eMudhra roots in the system trust store
wpantry fix extension-cooldown --hours 72   # editors wait before installing a new extension version
wpantry fix CVE-2026-98432 --dry-run        # no fix to install yet: the host's state and what the stopgap writes
wpantry fix CVE-2026-98432                  # asks, then installs the stopgap (sudo asks on the terminal)
wpantry fix CVE-2026-98432 --undo           # remove the stopgap once the kernel update is in
```

- `fix next` gives the findings one at a time, in fix order. It skips what a fix was tried for since the scan, so an agent can loop on `wpantry fix next --json` until `"item": null`, then scan again. Each item says `how`: `wpantry` (run `fix <id>`), `you` (a command to run), or `terminal` (a secret for `fix secret`).
- `fix secret ID` needs a terminal and git-filter-repo 2.47+. It shows the line, asks whether it's real, and adds the file to `.pantryignore` if it isn't. If it is and has been rotated, it takes the secret with echo off, rewrites history in a fresh mirror clone, checks it's gone, and asks before the force-push. The secret is never printed by Pantry, passed as an argument, or kept.
- `fix F-… --from-scan SCAN` fixes one finding only if SCAN is still the latest scan and the finding has an unattended fix; otherwise it stops before running anything. A program that shows a scan and asks before fixing uses it, so the fix the user confirmed is the fix that runs. Without a terminal to ask on (or with `--no-input`) it runs only with `--yes`; otherwise it is a usage error (exit 2). `--dry-run --json` prints `{schema, scan, command}`, the one command it would run.
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
wpantry update --check           # exit 10 when a newer release exists
wpantry update --check --json    # current, latest, available and the release's file names
wpantry update                   # asks, then installs it, verified
```

See [upgrade](install.md#upgrade).

## JSON

`wpantry scan --json` prints one object and never prompts:

```json
{
 "schema": 1, "impl": "rust", "version": "0.4.0",
 "checked": {"git repos": 12, "project dependencies": 1820},
 "unfixed": 3, "unknown_licenses": 0,
 "findings": [{"kind": "project", "component": "smallvec", "version": "1.6.0", "location": "/home/me/code/app/Cargo.lock",
               "vuln_id": "CVE-2021-25900", "status": "fail", "fixed": "1.6.1", "kev": true, "severity": "CRITICAL",
               "cvss": 9.8, "cvss_version": "3.1", "epss": 0.0213, "epss_percentile": 0.84,
               "epss_date": "2026-11-05T12:03:04Z", "epss_model": "v2026.06.15",
               "note": "…", "fix_cmd": "…", "fix_auto": false}]
}
```

- Check `schema` before reading it. Every field, kind and marker is defined in the [CLI contract](../../specs/cli-contract.md).
- A dependency finding also says how it's depended on: `dep_scope` (`runtime`, `dev`, `optional`, `unknown`), `dep_direct` (the project's own, or pulled in; `null` when unknown) and `affected_range`. A dev-only dependency is rarely exposed where the code runs.
- `wpantry report --jsonl` adds each finding's full OSV record, when it was first and last seen and resolved, and what `wpantry fix` did about it.

### Following a scan while it runs

A program that runs `wpantry scan` as a child process (a script, a CI wrapper, an editor, a dashboard) can follow it with `--events`: one JSON object per line on stderr, while stdout gets the report as usual. A scan of a whole home folder can take minutes; the events say which step it is in, what it is reading and what it has found so far.

```bash
wpantry scan --json --events 2>events.jsonl >report.json
```

```
{"v": 1, "event": "start", "version": "0.8.0", "steps": [{"id": "sources", "title": "Getting advisory data"}, …], "paths": ["/home/me/code"]}
{"v": 1, "event": "step", "id": "dependencies", "title": "Checking dependencies", "state": "begin", "index": 3, "of": 11}
{"v": 1, "event": "at", "step": "dependencies", "path": "/home/me/code/app/Cargo.lock", "kind": "file"}
{"v": 1, "event": "finding", "step": "dependencies", "id": "F-3fa9c01b2e", "kind": "project", "severity": "CRITICAL", "status": "fail", "title": "…", "component": "smallvec", "location": "/home/me/code/app/Cargo.lock", "vuln_id": "CVE-2021-25900", "fix_cmd": "…", "fix_auto": false, "fix_provisional": true}
{"v": 1, "event": "step", "id": "dependencies", "state": "end", "index": 3, "of": 11, "findings": 1, "unchecked": 0, "ms": 812}
{"v": 1, "event": "done", "exit": 1, "findings": 1, "unchecked": 0, "ms": 9120, "scan": 42, "dropped": 0}
```

- `--events` never prompts (as `--no-input`) and draws no progress line. Check that `wpantry scan --help` lists it before passing it.
- Ignore events and fields you don't know: new ones are added without changing `v`.
- Inside a step, a line comes at least about once a second: when nothing else is sent, a `tally` with the same counts says the scan is still working (on a long read, or while it looks over a big tree before reading it).
- A `finding` event is provisional: the report on stdout is the final word (an ignore file can still leave a finding out, and severities are filled in near the end).
- A reader that falls behind never slows the scan: at most 4096 `finding` and `note` lines (4 MiB) wait for it, and the ones past that are left out of the stream and counted in a `dropped` event (`count`) once it catches up, and in `done.dropped`. The report has every finding.
- A finding with a fix carries it: `fix_cmd` (the command or manual steps), `fix_auto` (whether `wpantry fix` runs it unattended) and `fix_provisional`. A provisional command can still change: at the end the plan takes one command per component, at the highest fixed version of all its findings, so act on those after `done` from `wpantry fix list --json` (its `scan` is `done.scan`). Manual steps that are not provisional can be shown at once.
- Events carry what the report shows, never a file's contents or a secret.
- If your program stops reading, the scan carries on and exits as it would have.

Every event, field and step: [`scan --events` in the CLI contract](../../specs/cli-contract.md#scan---events).

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
- The vendor and product names of the runtimes and datastores Pantry looks up CVE records for (Oracle's Java SE and MySQL Server) go to CIRCL's Vulnerability-Lookup. Versions aren't sent: the records are compared here.
- Feeds are downloaded whole.
- With `WORDFENCE_API_KEY` set, the key goes to Wordfence to download its whole WordPress feed; nothing about your sites is sent.
- The `breach` command sends your git and GitHub email addresses to see if they've been exposed in a hack. It only does this with your explicit approval.

Source by source: [what is sent](checks-and-sources.md#sources). Every request names `wpantry` in its User-Agent and times out after 30 seconds.

## Environment Variables

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | The cache file |
| `GITHUB_TOKEN` | Lifts GitHub's anonymous rate limit for latest-release lookups |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned |
| `WORDFENCE_API_KEY` | Check WordPress core, plugins and themes against Wordfence Intelligence. The key is free from a [wordfence.com](https://www.wordfence.com) account and is yours alone: Wordfence's terms forbid sharing it. Without it, each WordPress site is reported "not checked" |
| `WPANTRY_TIMINGS` | Print each scan step's elapsed time on stderr |
| `WPANTRY_ALLOW_SLEEP` | `1`: let the Mac idle-sleep during a scan, as `--allow-sleep` does |
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
  scan [options]               Scan this computer and its repos, then show the report
  fix [options] [target] [id]  Scan, run the unattended fixes and stopgaps, then re-check (list, or
                               one id)
  report [options] [part]      The latest scan's report, a log, or the summary, in any format
  search [options] <query>     Search the cached advisories (for agents)
  watch [options]              Re-check the advisories with no fix yet; exit 10 when one lands
  sync [options]               Refresh the cache for offline scans
  schedule <command>           Run sync and scan on a schedule
  rules [options] [command]    The malware scan's YARA rules; gen writes one from samples
  sources [options]            Every outside source, when it was last fetched and what went wrong
  ignore <command>             Dismiss a finding: write, list and remove ignore rules
  breach [options]             Show or set consent for the email breach check
  cache <command>              Maintain the cache
  update [options]             Install a newer release, verified
  version [options]            Print the version, implementation and JSON schema
  tools [options]              List the external tools wpantry uses
  skill                        Print the agent skill (SKILL.md)
  licenses                     Print the third-party licences built into wpantry
  help [command]               Print a command's help

Exit codes: 0 clean, 1 something fails, 2 usage error, 3 internal error.
```

### scan

```
Usage: wpantry scan [options]

Scan this computer and its repos, then show the report. Changes nothing.

Options:
  --path <dir>              check only the repos and files at or under this directory, not
                            Downloads, Desktop, Documents or temp; repeat it for more (default:
                            every git repo under ~)
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
  --jobs <n>                repos scanned for secrets at once (default: half the cores, at most 4)
  --secret-rules <file>     secret rules of your own, YARA, added to the bundled ones (default:
                            secrets.yar in ~/.config/wpantry)
  --licenses [file]         also check dependency licenses, against the file (default: licenses.toml
                            in ~/.config/wpantry, else the bundled one)
  --install-scripts <file>  install-script policy, TOML (default: install-scripts.toml in
                            ~/.config/wpantry, else the bundled one)
  --repo-hooks <file>       indicators of hijacked repos, TOML (default: repo-hooks.toml in
                            ~/.config/wpantry, else the bundled one)
  --hooks-policy <file>     repo hooks you've read and accept, TOML (default: hooks.toml in
                            ~/.config/wpantry)
  --suspect-policy <file>   suspicious-code ids and paths that warn instead of fail, TOML (default:
                            suspect.toml in ~/.config/wpantry)
  --no-posture              skip the machine's security settings (FileVault, firewall, sharing, …)
  --posture-policy <file>   posture checks to skip, TOML (default: posture.toml in
                            ~/.config/wpantry)
  --no-malware              skip the malware scan (YARA rules over Downloads, Desktop, temp, login
                            items and repo programs)
  --deep                    read everything in scope (slower): every file of the computer this user
                            can read, ~ first (or each --path), for malware with every system's
                            rules and for secrets; git history's files up to 256 MB with no time
                            limit
  --no-personal-files       never open Downloads, Desktop or Documents in any pass, finding repos
                            included (on macOS also the other folders it asks permission for),
                            reported as not checked (for unattended runs)
  --no-online-hash          never look up a flagged file's SHA-256 at YARAify, CIRCL or
                            MalwareBazaar (asked once otherwise)
  --sources <file>          your sources file for this run (default: ~/.config/wpantry/sources.toml
                            when it exists)
  --allow-sleep             let the Mac idle-sleep during the scan (kept awake otherwise; or
                            WPANTRY_ALLOW_SLEEP=1)
  --events                  write the scan's progress to stderr as JSON Lines (steps, the path being
                            read, findings), for programs that run wpantry; implies --no-input
  -h, --help                print this help

Exit codes: 0 nothing fails, 1 something fails, 2 usage error, 3 internal error.
```

### fix

```
Usage: wpantry fix [options] [target] [id]

Scan, run the fixes that can run unattended and the stopgaps wpantry has for what it found, then
re-check.

Arguments:
  target  all: a scan, the unattended fixes, every stopgap that applies, a re-check. list: what can
          be fixed, from the latest scan, in fix order with each finding's id; nothing runs. next:
          the first of those no fix has been tried for since the scan (for agents, with --json). A
          finding id (F-…, from list or the JSON report): its fix. secret ID: take that committed
          secret out of git history, a step at a time, at a terminal. An advisory id (CVE-…, GHSA-…;
          an alias works): its unattended fixes, wpantry's stopgap for it, the steps that need you.
          Or one of wpantry's own fixes: ca-trust (distrust the leaked eMudhra roots),
          extension-cooldown (editors wait before installing a new extension version),
          cve-2026-98432 (default: all)
  id      with secret: the finding id (F-…) of a committed secret

Options:
  --dry-run                 print what would run or be written; change nothing
  --yes                     run the fixes and write the stopgaps without asking
  --from-scan <id>          with a finding id: require this latest scan and an automatic fix
  --undo                    with an id: take wpantry's stopgap away once the real fix is installed
  --bundle <file>           ca-trust: rewrite this PEM bundle instead of the system trust store
  --hours <n>               extension-cooldown: the cooldown (default: 72)
  --path <dir>              check only the repos and files at or under this directory, not
                            Downloads, Desktop, Documents or temp; repeat it for more (default:
                            every git repo under ~)
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
  --jobs <n>                repos scanned for secrets at once (default: half the cores, at most 4)
  --secret-rules <file>     secret rules of your own, YARA, added to the bundled ones (default:
                            secrets.yar in ~/.config/wpantry)
  --licenses [file]         also check dependency licenses, against the file (default: licenses.toml
                            in ~/.config/wpantry, else the bundled one)
  --install-scripts <file>  install-script policy, TOML (default: install-scripts.toml in
                            ~/.config/wpantry, else the bundled one)
  --repo-hooks <file>       indicators of hijacked repos, TOML (default: repo-hooks.toml in
                            ~/.config/wpantry, else the bundled one)
  --hooks-policy <file>     repo hooks you've read and accept, TOML (default: hooks.toml in
                            ~/.config/wpantry)
  --suspect-policy <file>   suspicious-code ids and paths that warn instead of fail, TOML (default:
                            suspect.toml in ~/.config/wpantry)
  --no-posture              skip the machine's security settings (FileVault, firewall, sharing, …)
  --posture-policy <file>   posture checks to skip, TOML (default: posture.toml in
                            ~/.config/wpantry)
  --no-malware              skip the malware scan (YARA rules over Downloads, Desktop, temp, login
                            items and repo programs)
  --deep                    read everything in scope (slower): every file of the computer this user
                            can read, ~ first (or each --path), for malware with every system's
                            rules and for secrets; git history's files up to 256 MB with no time
                            limit
  --no-personal-files       never open Downloads, Desktop or Documents in any pass, finding repos
                            included (on macOS also the other folders it asks permission for),
                            reported as not checked (for unattended runs)
  --no-online-hash          never look up a flagged file's SHA-256 at YARAify, CIRCL or
                            MalwareBazaar (asked once otherwise)
  --sources <file>          your sources file for this run (default: ~/.config/wpantry/sources.toml
                            when it exists)
  --allow-sleep             let the Mac idle-sleep during the scan (kept awake otherwise; or
                            WPANTRY_ALLOW_SLEEP=1)
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

Refresh the cache: the feeds, and every source a scan used for what it found (end-of-life dates,
OSV, CVE records, extension versions, release tags, CVE scores, the malware rules), so scan
--offline has fresh answers.

Options:
  --refresh   ask every source again, even when its answer is fresh
  --json      what was refreshed, as JSON
  -h, --help  print this help
```

### schedule

```
Usage: wpantry schedule [options] <command>

Run sync and scan on a schedule (launchd, a systemd user timer, cron, or Windows Task Scheduler);
never fixes.

Options:
  -h, --help  print this help

Commands:
  install [options]  Install the job
  status [options]   Whether the job is installed, and how its last run went
  uninstall          Remove the job
  run                What the job runs: sync, then scan --json --no-input (with --no-personal-files
                     on macOS)
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

### schedule status

```
Usage: wpantry schedule status [options]

Whether the job is installed, and how its last run went.

Options:
  --json      the schedule and last run as JSON
  -h, --help  print this help
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

### ignore

```
Usage: wpantry ignore [options] <command>

Leave a finding out of future scans: write the rule for it into your ignore file or a repo's
.pantryignore, list the rules in them, or take one out. It never prompts.

Options:
  -h, --help  print this help

Commands:
  add [options] <finding>  Leave one finding out of future scans
  list [options]           The rules in your ignore file and a repo's
  remove [options] <id>    Take a rule out, so the finding is reported again
  help [command]           Print a command's help
```

One short example, with the ids `wpantry fix list` shows:

```bash
wpantry ignore add F-3fa9c01b2e --scope repo --reason "test key, revoked in 2025"
wpantry ignore list --path ~/code/app
wpantry ignore remove F-3fa9c01b2e        # the next scan reports it again
```

### ignore add

```
Usage: wpantry ignore add [options] <finding>

Write the narrowest rule that leaves one finding out of the next scan: its path, under the section
for its check and its rule or advisory. The finding is read from the latest scan, so add a finding
that scan listed (wpantry fix list shows the ids). Adding it again changes nothing.

Arguments:
  finding  a finding id from the latest scan (F-…)

Options:
  --scope <scope>  user: your ignore file (the default; creates it, private, when missing). repo:
                   the finding's repo's .pantryignore (a finding inside a repo, and not one that
                   protects you from the repo) (choices: user, repo; default: user)
  --reason <text>  why, kept in a comment under the rule and in the audit log (one line)
  --all-places     one rule for each place the same rule or advisory was found for the same package,
                   not only this one
  --no-input       never prompt (this command never does)
  --json           the result as JSON
  -h, --help       print this help

Exit codes: 0 done or already done, 1 refused (nothing changed) or not found, 2 usage error, 3
internal error.
```

### ignore list

```
Usage: wpantry ignore list [options]

Every rule in your ignore file and, with --path, in a repo's .pantryignore: its id, section and
pattern, and for a rule `ignore add` wrote the finding it came from, when and why. A rule the log
says was added and the file no longer holds is shown as removed by hand.

Options:
  --path <dir>  also list this repo's .pantryignore (the repo at or above DIR)
  --json        as JSON
  -h, --help    print this help
```

### ignore remove

```
Usage: wpantry ignore remove [options] <id>

Take a rule out: R-… (any rule `list` shows, hand-written ones too) or F-… (every rule `ignore add`
wrote for that finding). Only those lines go; the next scan reports the finding again.

Arguments:
  id  a rule id (R-…) or a finding id (F-…)

Options:
  --path <dir>  also look in this repo's .pantryignore (needed for a hand-written rule of a repo's)
  --no-input    never prompt (this command never does)
  --json        the result as JSON
  -h, --help    print this help

Exit codes: 0 done or already gone, 1 nothing matches, 2 usage error, 3 internal error.
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
  --json           with --check: current and latest versions as JSON
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

### licenses

```
Usage: wpantry licenses [options]

Print the licences and notices of the third-party code, data and fonts built into wpantry: every
crate with its licence text, then the rest. Each release ships the same text as
THIRD-PARTY-NOTICES.txt.

Options:
  -h, --help  print this help
```

## Troubleshooting

- **Everything is "not checked"**: you're offline, or a proxy blocks `api.osv.dev`. Re-run online, or `--offline` to use what's cached.
- **It's slow on the first run**: the first run downloads advisories, clones the malicious-package index and reads every repo's git history for secrets; later runs read only what changed. On macOS a scan keeps the Mac from idle sleep (`caffeinate`) until it ends (`--allow-sleep` or `WPANTRY_ALLOW_SLEEP=1` turns that off); closing the lid still sleeps it. `--path` and `--no-machine` narrow a run.
- **A finding is wrong**: open an issue with a minimal reproducer (never paste a real report; see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Security reports go through [SECURITY.md](../../SECURITY.md).
