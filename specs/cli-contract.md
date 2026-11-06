# wpantry CLI contract

Status: frozen at schema 1, 2026-10-25. Owner: Eric.

The command line, its exit codes, its JSON and its cache file are wpantry's only stable surface. Callers (ops, Syrup, wsentinel, agents) depend on this page and nothing else. The product is Pantry, and its command is `wpantry` (how it is built: [docs/architecture.md](../docs/architecture.md)). It MUST pass the contract tests, which run the binary and check its output rather than its internals.

## Change rule

- Additive changes only: a new subcommand, flag, JSON key, finding `kind`, `vuln_id` value or cache column is fine without a bump.
- Removing or renaming a JSON key, changing a key's type, or changing what an exit code means bumps `schema`. The cache schema follows the same rule.
- `version --json` and every JSON envelope carry `schema`, so a caller can refuse an output it doesn't understand.

## Synopsis

```
wpantry [-h]
wpantry scan [--path DIR]... [--no-machine] [--refresh] [--offline] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--since DAYS] [--no-input] [--jobs N]
             [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]
             [--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-malware] [--deep]
             [--no-online-hash] [--sources FILE]
wpantry check ...                (the same as scan)
wpantry fix [list|all|ID] [--dryrun] [--yes] [--undo] [--bundle FILE] [--hours N] [the scan's options]
wpantry search QUERY [--applicable] [--limit N] [--json]
wpantry report [findings|history|exposure|remediation|audit|summary|all] [--txt|--json|--jsonl|--csv|--md|--html] [-o FILE] [--since DAYS]
wpantry export ...               (the same as report)
wpantry breach [--enable | --disable]
wpantry watch [--offline] [--json]
wpantry version [--json]
wpantry tools [--json]
wpantry skill
wpantry sync [--refresh] [--json]
wpantry schedule {install,status,uninstall,run} [--every WHEN] [--at HH:MM] [--dry-run]
wpantry cache prune [--older-than DAYS]
wpantry update [--check] [--yes] [--no-input] [--offline] [--version VER]
wpantry mitigate ...             (the same as fix)
wpantry rules [--update] [--json]
wpantry help [COMMAND]
```

`wpantry` with no arguments, `wpantry -h` and `wpantry help` print the top-level help (`usage: wpantry [-h] {scan,check,fix,...}`, every command, the exit codes) and exit 0; nothing is scanned. `wpantry help COMMAND` is `wpantry COMMAND --help`. An unknown first word is a usage error (2). `check` is `scan` under its older name: the same options, output and exit codes. Changed 2026-11-02: until then `check` was the default subcommand and the fixes were its `--fix` flag.

Deprecated, kept for scripts written before 2026-11-02 and left out of `--help`: `scan --fix` and `check --fix` (`--update` is the same flag) behave exactly as `fix`, taking `--dryrun` and `--yes` as `fix` does, and `scan --dryrun` as `fix --dryrun`; options given with no subcommand (`wpantry --fix`, `wpantry --json`) are `scan`'s. New callers use `scan` and `fix`.

Removed 2026-11-05: wpantry scans files and never touches the clipboard. The `clipboard` command (the self-test and `--watch`, the resident guard), `scan --no-clipboard`, `schedule install --clipboard-guard` and `WPANTRY_CLIPBOARD_FAKE` are gone, and no finding is `CLIPPER-ACTIVE`; `CLIPPER-PERSISTENCE` and `CLIPPER-EXTENSION` are unchanged. Watching the clipboard live belongs to a resident watchdog. No compatibility was kept: nothing depends on wpantry yet.

| Subcommand / flag | Meaning |
|---|---|
| `scan` | Scan, report, and exit by the result; change nothing. The rows below, down to `search`, are its options and `fix`'s |
| `check` | The same as `scan` |
| `fix` | `scan`, then the unattended fixes, then every stopgap wpantry has that is for this host (asked on a terminal, skipped without one unless `--yes`; see `mitigate`), then a re-check whose result is the exit. On a terminal (stdin) without `--no-input`, list the fixes and ask `Run these N updates now? [Y/n]` first; declining changes nothing (exit as the scan). Added 2026-11-02, replacing `check --fix` |
| `--path DIR` | Repeatable. The repo checks cover only the git repos at or under each DIR; a DIR holding no repo is scanned as one project without the git-history checks. A missing DIR is skipped with a one-line note on stderr. Without it the scope is every git repo under `$HOME` |
| `--no-machine` | Skip the machine inventory (tools, runtimes, packages, apps, browsers, OS, Homebrew, editors, harness configs, running containers, CA trust, breach). Repo checks only |
| `--yes` | `fix` only: run the unattended fixes and write the stopgaps without asking. Added 2026-11-02 |
| `--dryrun` | `fix` only: print the update plan; change nothing |
| `--refresh` | Ignore cached answers |
| `--offline` | Cache only; anything never cached is `unchecked` |
| `--txt`, `--json`, `--jsonl`, `--csv`, `--md`, `--html`, `-o FILE`, `--since DAYS` | The report options, the same as `report`'s (below): when the scan is done it shows its findings exactly as `wpantry report` with the same options would. At most one format; `-o FILE` writes it there (a terminal report becomes `--txt`) and is checked before the scan: a directory or a missing parent fails with 3 before anything is scanned. Changed 2026-11-05: `--html FILE` was an extra file beside the terminal report; it is now `--html -o FILE` |
| `--json` | Print the envelope below instead of the terminal report; never prompts, and nothing else goes to stdout (the same for `--jsonl`, `--csv`, `--md` and `--html` without `-o`) |
| `--no-input` | Never prompt: the breach-consent question is skipped, and `fix` runs without asking. Prompts are only asked when stdin is a terminal: `? Question [y/N]` on stderr, Enter takes the default, anything but y/yes/n/no asks again |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled allowlist; `--license` is the same option. Off by default (it's noisy): without it there are no `license` findings and `unknown_licenses` is 0. A missing FILE is a usage error |
| `--gitleaks-config`, `--install-scripts`, `--repo-hooks`, `--suspect-policy`, `--hooks-policy` | Policy files; default to the bundled ones. A missing file is a usage error. A repo's own `.gitleaks.toml` is reported (`REPO-POLICY`, warn), never obeyed |
| `--hooks-policy FILE` | Repo hooks someone has read and accepts: `hook <file> "<when>" <command>` (one hook, matched on its exact command, so a hook that changes what it runs is reported again) or `repo <path>` (every hook that warns in the repos at or under that path). Only `OPEN-HOOK` and `INSTALL-HOOK` findings can be accepted; `RUNS-REPO-FILE`, `LOADER`, `IOC` and `MARKER` never are, and a line naming one is refused in the finding's `fix_cmd`. Accepted hooks are not findings and are counted (`checked["repo hooks accepted by policy"]`); every `OPEN-HOOK` and `INSTALL-HOOK` `fix_cmd` ends with the line that accepts it. The file is part of the scan's scope |
| `--jobs N` | gitleaks scans at once (default: half the cores, at most 4); each gets a share of the cores |
| `--no-posture`, `--posture-policy FILE` | The machine's own security settings (kind `posture`) run with the machine inventory; `--no-posture` skips them, the policy file lists check ids to skip (one per line, `POSTURE-` prefix optional). The ids are `POSTURE-<NAME>` as [posture.md](../docs/public/posture.md) lists them; `POSTURE-DNS-ENCRYPTED` (Medium: `warn`, never `fail`) was added 2026-11-01 |
| `--no-posture`, `--posture-policy FILE` | The machine's own security settings (kind `posture`) run with the machine inventory; `--no-posture` skips them, the policy file lists check ids to skip (one per line, `POSTURE-` prefix optional) |
| `--no-malware` | Skip the malware scan (kind `malware`): YARA rules over the top two levels of Downloads, Desktop and the temp directories, the programs launch items start, and the executables in the repos. Added 2026-11-04 |
| `--deep` | The malware scan reads everything under `$HOME` (twelve levels, the repo walk's pruned directories skipped) with every system's rules, not only this system's and any system's. Added 2026-11-04 |
| `--no-online-hash` | Never look up a flagged file's SHA-256 online. Otherwise, after one yes (asked once on a terminal, kept in the cache as `online_hash_consent`), the SHA-256 of each file the malware scan flagged (at most 50 a scan), and nothing else about it, goes to YARAify and CIRCL hashlookup, and to MalwareBazaar when `ABUSECH_AUTH_KEY` is set. A malware verdict makes the finding `fail`, Critical, and its note names the source and family; a known-good answer is noted on a heuristic `warn`. A source that can't be reached is `unchecked`. Added 2026-11-04 |
| `--sources FILE` | The user's sources file for this run, in place of `~/.config/wpantry/sources.toml` (`$XDG_CONFIG_HOME/wpantry/sources.toml`), which is read when it exists (`specs/design/sources-file.md`). It may set a bundled source's `tier` (`default`, `deep`, `off`: an `off` source isn't asked, and what needs it is `unchecked`), and add sources of its own: YARA rules, hash, host and file-name lists, an OSV-compatible API (asked beside OSV.dev), or a hash lookup that sends only a SHA-256. A source of the user's whose host wpantry doesn't already ask, or that sends anything, is used only after a yes, asked once on a terminal and kept by its id and URL; without one it is `unchecked`. Each used is counted as `user source <id>`. A file that can't be used leaves the bundled sources in effect and is `unchecked`. Added 2026-11-05 |
| `rules` | The YARA rule sources the malware scan uses (ours, built in; YARA Forge's `full` package, fetched into `rules/` beside the cache at most daily; any `.yar` you put there), how many compile and how many are for this system; `--update` fetches YARA Forge now (exit 1 when it can't); `--json` as `{directory, sources: [{source, rules}], rules, this_system, rejected, update_failed}`. Added 2026-11-04 |
| `search` | Rank cached advisories (SQLite FTS5 syntax); `--applicable` keeps those in the latest findings |
| `export` | The same as `report`. Changed 2026-11-05: `export --csv FILE`, `--jsonl FILE` and `--all` are `export --csv -o FILE`, `--jsonl -o FILE` and `export exposure --jsonl` |
| `report --jsonl` | Latest findings as JSON Lines, one object per finding: every [finding](#finding) key, plus `aliases` (the record's other ids), `url`, `record` (the full OSV JSON, or `null`), `first_seen`, `last_seen`, `resolved_at` (`YYYY-MM-DD HH:MM UTC` strings, `null` when unknown or open), `days_exposed` and `fix` (`null`, or `{attempted_at, mode, ok, verified, succeeded}` for the latest `fix` run of its `fix_cmd`). `report exposure --jsonl` (or `history`, `all`) adds the exposures a later scan of the same scope resolved and the latest scan no longer lists. `--csv` and `--jsonl` may be given together; one is required |
| `breach` | Show or set consent for the opt-in email breach check |
| `watch` | Ask OSV again (bypassing the daily cache) about every advisory the latest findings carry with `status == "warn"` and `fixed == ""`: the Critical, High and exploited-in-the-wild advisories no fix was released for. Prints each with `no fix yet` and its mitigation, or `FIX AVAILABLE: <component> <version>`; exits 10 when at least one has a fix now. `--offline` reads the cache only. `--json` prints `{"schema", "impl", "version", "watched": [{id, severity, summary, ecosystem, package, version, fixed (string or null), mitigation (string or null)}]}`. For an hourly cron: a non-zero exit is the signal |
| `version` | `{"version": "0.1.0", "impl": "rust", "schema": 1}` with `--json` |
| `tools` | The external tools this implementation runs, found or missing |
| `sources` | Every outside source (`assets/defaults/sources.toml`): kind, tier, host, licence, whether it is redistributed, when it was last fetched, whether that is fresh, and its last error; `--json` as `{sources: [{id, kind, format, tier, host, transport, user, license, redistribute, refresh_seconds, sends, last_attempt, last_success, fresh, error}]}` (times as epoch seconds, null when never); `--sources FILE` reads that user's sources file instead of `~/.config/wpantry/sources.toml`. Exit 0; 2 when the user's file can't be used. Added 2026-11-05 |
| `skill` | Print the bundled agent skill (`SKILL.md`) to stdout |
| `report` | `report [WHAT] [FORMAT] [-o FILE] [--since DAYS]`, from the cache; it never scans (`scan` and `fix` show `findings` when they finish, with the same format options). WHAT: `findings` (the default: the latest scan), `history` (the exposure, remediation and audit logs, without the findings), `exposure`, `remediation`, `audit` (one log), `summary` (one page for a CSO, an auditor or an insurer) or `all` (the findings, then every log). The logs cover the last 14 days unless `--since DAYS`. FORMAT: the terminal report by default (the findings grouped into areas, one per kind, in the order fixes go in, a table of rows each, what couldn't be checked, and the update plan in batches of alike commands, `sudo` ones apart; coloured on a terminal and fitted to its width), or one of `--txt` (the same plain, 120 columns), `--json`, `--jsonl`, `--csv`, `--md`, `--html`. `--json`: for `findings` the envelope below (byte for byte what `scan --json` printed); for `all` the envelope plus `history: {since_days, exposures, fixes, scans, events}`; for a log `{schema, version, since_days}` plus `exposures`, `fixes` (each with `user` and `host`: who ran it) or `scans` and `events`; for `summary` `{schema, version, summary: {since_days, by_severity: [{severity, target_days, open_fail, open_warn, overdue, resolved, resolved_late, median_days_to_resolve}], known_exploited_open, oldest_open_critical_or_high, median_days_to_resolve, p90_days_to_resolve, scans, hosts, users, days_without_a_scan, not_checked, fixes, controls}}`. `--csv` is one table: the findings (`findings`, `all`: `id, aliases, url, component, kind, affected_version, safe_version, severity, kev, status, location`), the exposure log (`history`, `exposure`: `first_seen, resolved` (its date, or `open`), `severity, component, version, vuln_id, kev, status, fixed, days_exposed, last_seen, kind, location`; Markdown and the terminal use the same order), the fix log (`when, user, host, command, mode, ok, verified_scan`), the scan log (`scan, finished, host, user, version, scope, fails, warns, unchecked`) or the summary's figures (`metric, value`). `--jsonl`: one object per row of the same (the findings with `all`, `history` and `exposure` adding the resolved exposures). `--md`: the same sections as Markdown. `--html`: the scan's offline page (below) whatever WHAT says. The summary's remediation targets are our security policy's (Critical 14 days, High 30, Medium 90, Low 180); a file of your own will set them (#171). Exit 1 when the latest scan has a failing finding, or there is none yet ("no scan yet" on stderr); 0 otherwise. Changed 2026-11-05: `report` was the three logs only (`--exposure`, `--remediation`, `--audit`, `--format md|json|csv`) |
| `sync` | `sync [--refresh] [--json]`: refresh what the cache already knows, without an inventory: the feeds (CISA KEV, the malicious-package index, the cask catalog and browser releases, VS Code's lists, the latest wpantry), end-of-life dates for every product on record, and OSV's answers for every package version asked about before. Exit 0, or 1 when a source was unreachable. `--json`: `{"refreshed": [...], "failed": [{"source", "why"}], "packages": n}` |
| `schedule` | `schedule install [--every hourly|daily|weekly] [--at HH:MM] [--dry-run]`, `status`, `uninstall`, `run`: a scheduled `sync` then `scan --json --no-input` (never `fix`) through launchd (`~/Library/LaunchAgents/ai.waffuru.wpantry.plist`), a systemd user timer (`~/.config/systemd/user/wpantry.{service,timer}`) or cron. `run` writes `$XDG_STATE_HOME/wpantry/last.json` (default `~/.local/state/wpantry/`) and appends one line to `schedule.log`; one run at a time (`schedule.lock`). Default daily at 09:30. Added 2026-11-01 |
| `cache` | `cache prune [--older-than DAYS]` (default 90): drop package versions not asked about since then, the advisories only they referred to, and cached runs that old, then `VACUUM` |
| `update` | `update [--check] [--yes] [--no-input] [--offline] [--version VER]`: is there a newer release; after a yes (or `--yes`), install it. The download is checked against the release `SHA256SUMS` and then verified by the first installed verifier (packslip with the release signer pinned, `gh attestation verify` against `release.yml` at the tag, cosign against the same identity); with none, nothing is installed. An install mise, cargo or Homebrew made is updated through that tool; a source build is only reported. `scan` prints one stderr line when a newer release is cached (`WPANTRY_NO_UPDATE_CHECK=1` turns it off) |
| `fix list`, `fix ID` | `fix list`: what can be fixed, from the latest scan (no scan runs): the update plan in batches of alike commands (`[sudo]` marks those run as root) with the findings each clears, then each of wpantry's own fixes (`ca-trust` for `DISTRUSTED-CA`, `extension-cooldown` for `POSTURE-EXTENSION-COOLDOWN`, `cve-2026-98432`) and whether it applies here. `fix ID`: one advisory (by id or alias, any case) or one of wpantry's own fixes by name. It runs the fixes the latest findings carry for it with `fix_auto` true (as `fix` does; asked on a terminal, run as is without one), runs wpantry's own fix for it where one exists (asked first unless `--yes`, skipped without a terminal unless `--yes`), and prints the remaining `fix_cmd`s under `Needs you`. `ca-trust` distrusts the leaked eMudhra roots in the system trust store, or in `--bundle FILE`, until the OS's ca-certificates update ships; `extension-cooldown` sets `extensions.installCooldownHours` (`--hours N`, default 72) in every VS Code-family editor's `settings.json`, keeping comments and formatting; CVE-2026-98432 on Linux: an nftables rule dropping inbound TCP with IP options, a boot-time unit, `net.mptcp.enabled=0`, and the services still holding an MPTCP listener printed as `systemctl restart` lines, never run, written as root. `--dry-run` prints the state and the plan and changes nothing; `--undo` (`--remove` is the same) takes a stopgap away. Every fix run is recorded with who ran it (`report remediation`). Exit 0 when everything that applies here was done or printed, 1 when a step is left for you, a fix failed, a question went unanswered, or nothing is known for the id here, 2 usage. A scan never runs it. `mitigate` is the same command. Changed 2026-11-05: `harden extension-cooldown` and `harden ca-trust` are `fix extension-cooldown` and `fix ca-trust`, `mitigate list` is `fix list`, `mitigate all` is `fix` |

### Scope walk

The default scope walks `$HOME` to depth 6 without following symlinks and only looks at directory entries. A directory with a `.git` directory is a repo and is not descended into. A `.git` file (linked worktree, submodule) ends the descent and counts only when it is the `--path` itself. Pruned by name: `.git`, `node_modules`, `target`, `.build`, `vendor`, `.cache`, `dist`, `build`, `.venv`, `venv`, `__pycache__`, `.next`, `Library`, `.Trash`, `.rustup`, `.npm`, `.pnpm-store`, any `*.app`; by path: `go/pkg`, `.cargo/registry`, `.cargo/git`, `.local/share`. The count lands in `checked["git repos"]`.

## Environment

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | Cache file. Default `$XDG_CACHE_HOME/wpantry/wpantry.db`, else `~/.cache/wpantry/wpantry.db`. The malicious-packages clone sits beside it. |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned instead of XposedOrNot |
| `GITHUB_TOKEN` | Sent to the GitHub API (latest-release lookups, such as mise's) to lift the anonymous rate limit |
| `WPANTRY_NO_UPDATE_CHECK` | Set to anything: `scan` never mentions a newer wpantry release |
| `WPANTRY_TIMINGS` | Set to anything: every scan step is printed to stderr with the seconds since the scan began (for finding slow steps; not under `--json`) |
| `NO_COLOR` | Honoured: set to anything non-empty, no ANSI colour. Without it, wpantry colours its report, `tools`, prompts and errors only on a terminal, and never when `TERM=dumb`. `--json` output, pipes and files are never coloured. Child tools always run with `NO_COLOR=1` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and `unchecked` sources still exit 0; the report says "incomplete" |
| 1 | At least one finding has `status == "fail"`, or an unattended fix failed under `fix`. `tools` exits 1 when a required tool is missing |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |
| 10 | `update`: a newer release exists and was not installed (`--check`, `--no-input`, no terminal, a "no", or a source build); `watch`: a fix has landed for an advisory that had none |
| 130 | Interrupted (Ctrl-C) |

## `report --html`

The page shows the report the cache keeps for the latest scan: `scan --html -o FILE` and `report --html -o FILE` write the same page. It embeds the schema-1 envelope `scan --json` prints, the scan's scope (kept with the scan in the cache), the update plan and 14 days of history (`--since DAYS` for more). Its phase is `after updates` when the scan verified fixes `fix` ran, `scan` otherwise.

With `-o FILE`, the parent must exist. Output is staged beside the destination (before scanning, for `scan` and `fix`), written with mode 0600 on Unix and renamed over the destination only after successful generation. A destination symlink is replaced rather than followed. File errors return 3; a scan error leaves a previous report intact. Without `-o` the page goes to stdout. Nothing opens a browser, fetches anything, or leaves the machine.

## `scan --json`

```json
{
  "schema": 1,
  "impl": "rust",
  "version": "0.1.0",
  "checked": {"git repos": 12, "tools, runtimes and packages": 140},
  "unfixed": 3,
  "unknown_licenses": 0,
  "findings": [Finding, ...]
}
```

| Key | Type | Meaning |
|---|---|---|
| `schema` | int | Contract version, 1 |
| `impl` | string | `rust` |
| `version` | string | The implementation's version |
| `checked` | object string → int | What was checked and how many (labels are display text; callers SHOULD NOT parse them) |
| `unfixed` | int | Applicable advisories with no released fix. Those rated Critical or High (by the advisory's label, else its CVSS 3.x vector) or listed in CISA KEV also appear in `findings` as `warn` with `fixed` empty and the mitigation (bundled `mitigations.txt`, else a line saying to keep checking) as `fix_cmd`; the rest are only counted. A program exposed to such an advisory by what it does (a Go 1.24+ module listening with Multipath TCP on, `CVE-2026-98432`) counts here too, as a `project` warning with `fixed` empty and the opt-out as `fix_cmd`, `fix_auto` false. Added 2026-11-01 |
| `unknown_licenses` | int | Repo dependencies with no identifiable license; 0 unless `--licenses` |
| `findings` | array of Finding | Everything that applies, failing or warning |

The optional HTML presentation bundle preserves the scan envelope unchanged. It additionally records `scan_id` (the local history entry), generation phase and scope: machine, offline, licenses, posture, paths, posture exclusions, suspicious-code warning exemptions, and policy file choices. These presentation fields do not alter schema 1 on stdout. The HTML viewer accepts current and older schema-1 scan JSON plus findings CSV; history reports and lifecycle JSONL are separate formats.

### Finding

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `runtime`, `compiler`, `manager`, `pkgmgr`, `tool`, `datastore`, `harness`, `package`, `app`, `browser`, `extension`, `brew`, `os`, `project`, `image`, `bundled`, `mcp`, `repo-hook`, `hidden-text`, `secret`, `license`, `install-script`, `config`, `account`, `posture`, `unchecked`, `suspect-code`, `document`, `clipper`, `persistence`, `malware` (open set) |
| `component` | string | What it is about (`openssl`, `vite`, `~/code/app/.env`) |
| `version` | string | Installed or locked version; `""` when none |
| `location` | string | Path, lockfile, image or source; `""` when none |
| `vuln_id` | string | Advisory id (CVE preferred), a gitleaks rule id, or a marker: `UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, `DEPRECATED`, `UNPINNED`, `BROWSER`, `OS-UPDATE`, `LICENSE`, `INSTALL-SCRIPT`, `NPM-SCRIPTS`, `BREACH`, `REPO-POLICY`, `hidden-text`, `HIDDEN-BIDI`, `HIDDEN-TAGS`, `HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`, `HIDDEN-PROMPT`, `HIDDEN-FILENAME`, `CONFUSABLE-DOMAIN`, `AGENT-INSTRUCTIONS`, `HIDDEN-HTML`, `EXFIL-LINK`, `CONFUSABLE-NAME`, `DANGEROUS-URI`, `suspect-code`, `SUSPECT-EXEC-DECODED`, `SUSPECT-ENCODED-PAYLOAD`, `SUSPECT-STRING-DECODER`, `SUSPECT-ESCAPED-SOURCE`, `SUSPECT-PRIV-ESCALATION`, `SUSPECT-CREDENTIAL-ACCESS`, `SUSPECT-WALLET-SIGNING`, `SUSPECT-THIRD-PARTY-SCRIPT`, `SUSPECT-RAW-IP`, `SUSPECT-TYPOSQUAT`, `SUSPECT-BINARY-BLOB`, `SUSPECT-PROFILING-PROMPT`, `SUSPECT-CARDHOLDER-DATA`, `SUSPECT-WEAK-PASSWORD`, `SUSPECT-KEYLOGGER`, `SUSPECT-CLIPBOARD-SWAP`, `CLIPPER-PERSISTENCE`, `CLIPPER-EXTENSION`, `PERSISTENCE-NEW`, `PERSISTENCE-INJECTION`, `PERSISTENCE-SIGNATURE`, `PERSISTENCE-HIDDEN`, `--suspect-policy`, `document`, `DISGUISED-PROGRAM`, `DOC-POLYGLOT`, `DOC-LAUNCH`, `DOC-JS-ON-OPEN`, `DOC-OBFUSCATED`, `DOC-XL4-MACRO`, `DOC-REMOTE-TEMPLATE`, `DOC-REMOTE-OBJECT`, `DOC-DDE`, `DOC-RTF-OBJECT`, `IMG-PAYLOAD`, `IMG-SVG-SCRIPT`, `MALWARE`, `DOC-MACRO`, `IMG-WRONG-TYPE`, `DOC-JAVASCRIPT`, `DOC-EMBEDDED`, `DOC-FORM`, `DOC-TRAILER`, `DOC-OLE-OBJECT`, `DOC-ACTIVEX`, `DOC-REMOTE-CONTENT`, `DOC-UNREADABLE`, `IMG-TRAILER`, `IMG-SVG-EXTERNAL` |
| `status` | string | `fail` or `warn` |
| `fixed` | string | The safe version; `""` when none |
| `kev` | bool | In CISA KEV (also true for malicious packages) |
| `severity` | string | Usually `CRITICAL`, `HIGH`, `MODERATE`, `LOW` or `MALICIOUS`; a source's own label (dnf: `IMPORTANT`) or `""` otherwise |
| `note` | string | One line for a human |
| `fix_cmd` | string | Command or step that fixes it; `""` when none |
| `fix_auto` | bool | `fix` may run `fix_cmd` unattended |
| `dep_scope` | string | How a locked dependency is depended on: `runtime`, `dev`, `optional`, or `unknown` (the lockfile doesn't say, or the finding isn't about a locked dependency). Added 2026-10-31 |
| `dep_direct` | bool or null | The project's own dependency (`true`) or one another pulled in (`false`); `null` when the lockfile doesn't say. Added 2026-10-31 |
| `affected_range` | string | The advisory's range the installed or locked version fell in, as `>=A, <B` (`<=B` for a last-affected bound, `=V` for a listed version); `""` when the finding has none (markers, GIT ranges). Added 2026-10-31 |

The three dependency keys were added under the additive rule: older callers ignore them, and `schema` stays 1.

A source that couldn't be reached is a finding with `kind == "unchecked"`, `status == "warn"`: never silence, never "clean".

## `tools --json`

`{"schema": 1, "impl": ..., "version": ..., "tools": [{"name", "required", "found", "path", "version", "purpose"}]}`. Today: `gitleaks`, `git`, `openssl` required; `brew`, `docker`, `rpm` optional. The list may shrink.

## Cache (SQLite)

One file per machine. Both implementations MUST read and write the same schema, so switching implementation keeps the cache. `vulns_fts` exists only where SQLite has FTS5.

| Table | Columns |
|---|---|
| `meta` | `key` TEXT PK, `value` TEXT (`breach_consent`, `malicious_at`, `<feed>_at`, `<feed>_etag`, `eol_at:<product>`, `vuln_etag:<id>`, `persistence_at:<source>`) |
| `vulns` | `id` TEXT PK, `aliases` TEXT (space-separated), `summary`, `details`, `severity`, `published`, `modified`, `url`, `record` TEXT (full OSV JSON) |
| `queries` | `ecosystem`, `package`, `version` TEXT (PK together), `checked_at` REAL (Unix time), `vuln_ids` TEXT (space-separated) |
| `findings` | `kind`, `component`, `version`, `location`, `vuln_id`, `status`, `fixed` TEXT, `kev` INTEGER, `severity`, `note`, `fix_cmd` TEXT, `fix_auto` INTEGER, `dep_scope` TEXT, `dep_direct` INTEGER (NULL when unknown), `affected_range` TEXT. The last three were added 2026-10-31; a cache from before gains them on open |
| `kev` | `cve` TEXT PK, `added`, `name` |
| `eol` | `product`, `cycle` TEXT (PK together), `eol`, `latest` |
| `casks` | `app` TEXT PK, `token`, `version` |
| `runs` | `source` TEXT PK (`gitleaks:<repo>`, `brew-vulns`, `tags:<repo>`, `image-packages:<id>`, the feeds' keys such as `arch-tracker` and `firefox`, …; rows an earlier implementation wrote are left alone), `fingerprint` TEXT, `ran_at` REAL, `result` TEXT (JSON) |
| `malicious` | `ecosystem`, `name`, `id` TEXT; index `malicious_name (ecosystem, name)` |
| `persistence` | `key` TEXT PK (a SHA-256 of the source, the location and what tells the item apart: a startup file's line is kept only as this hash), `source` TEXT (`launchd`, `app-login`, `cron`, `at`, `periodic`, `emond`, `authorization`, `kext`, `system-extension`, `quicklook`, `spotlight`, `shell`, `launchd-env`, `systemd`, `autostart`, `preload`), `location` TEXT, `program` TEXT, `first_at` REAL, `last_at` REAL: the persistence baseline, one row per item the last machine scan that read its source found; `meta` `persistence_at:<source>` says when that was. Added 2026-11-04 |
| `scans` | `id` INTEGER PK, `started_at` REAL, `finished_at` REAL, `host`, `user`, `version`, `scope` TEXT, `counts` TEXT (JSON), `fails` INTEGER, `warns` INTEGER, `unchecked` INTEGER (sources that couldn't be asked; a scan with any resolves no exposure and verifies no fix): one row per scan |
| `exposures` | `key` TEXT PK (`kind|component|location|vuln_id`), `scope`, `kind`, `component`, `version`, `location`, `vuln_id`, `status`, `severity` TEXT, `kev` INTEGER, `fixed`, `note` TEXT, `first_scan` INTEGER, `first_at` REAL, `last_scan` INTEGER, `last_at` REAL, `resolved_scan` INTEGER, `resolved_at` REAL, `dep_scope` TEXT, `dep_direct` INTEGER, `affected_range` TEXT, `fix_cmd` TEXT: a finding across scans; resolved by a scan of the same scope that no longer lists it |
| `fixes` | `id` INTEGER PK, `scan_id` INTEGER, `at` REAL, `command` TEXT, `mode` TEXT, `ok` INTEGER, `verified_scan` INTEGER (the complete scan after a fix that exited 0 in which none of its `targets` were listed; NULL otherwise), `targets` TEXT (JSON array of `exposures.key`): the unattended fixes `--fix` ran |
| `events` | `id` INTEGER PK, `at` REAL, `kind` TEXT (`scan`, `fix`, `clipper`, …), `detail` TEXT (JSON) |
| `hash_verdict` | `sha256`, `source` TEXT (PK together), `verdict` TEXT (`malware`, `good`, `unknown`), `family` TEXT, `checked_at` REAL: online answers about flagged files, reused for a day. Added 2026-11-04 |
| `malware_files` | `path` TEXT PK, `dev`, `ino`, `size` INTEGER, `mtime` REAL, `rules` TEXT (the rule set's digest), `hits` TEXT (JSON: `[namespace, rule, category, description]` per hit), `scanned_at` REAL: the malware scan's result per file, reused while the file's identity and the rule set are unchanged. Added 2026-11-04 |
| `vulns_fts` | FTS5 over `id`, `aliases`, `summary`, `details`, `packages`, `tokenize='porter'` |

`runs.result` JSON is internal to each source and not part of the contract.
