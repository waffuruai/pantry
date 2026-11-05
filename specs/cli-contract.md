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
wpantry scan [--path DIR]... [--no-machine] [--refresh] [--offline] [--json] [--html FILE] [--no-input] [--jobs N]
             [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE] [--no-posture] [--posture-policy FILE]
             [--repo-hooks FILE] [--suspect-policy FILE] [--hooks-policy FILE] [--no-clipboard] [--no-malware] [--deep]
             [--no-online-hash]
wpantry check ...                (the same as scan)
wpantry fix [--dryrun] [--yes] [the scan's options]
wpantry search QUERY [--applicable] [--limit N] [--json]
wpantry export [--csv FILE] [--jsonl FILE] [--all]
wpantry breach [--enable | --disable]
wpantry watch [--offline] [--json]
wpantry version [--json]
wpantry tools [--json]
wpantry skill
wpantry sync [--refresh] [--json]
wpantry schedule {install,status,uninstall,run} [--every WHEN] [--at HH:MM] [--dry-run] [--clipboard-guard]
wpantry cache prune [--older-than DAYS]
wpantry update [--check] [--yes] [--no-input] [--offline] [--version VER]
wpantry report [--exposure] [--remediation] [--audit] [--since DAYS] [--format FORMAT] [-o FILE]
wpantry harden {extension-cooldown,ca-trust} [--hours N] [--bundle FILE]
wpantry clipboard [--watch] [--once] [--window SECONDS] [--json]
wpantry mitigate {list,all,ID} [--dry-run] [--yes] [--no-input] [--undo] [--offline] [--no-machine] [--path DIR]
wpantry rules [--update] [--json]
wpantry help [COMMAND]
```

`wpantry` with no arguments, `wpantry -h` and `wpantry help` print the top-level help (`usage: wpantry [-h] {scan,check,fix,...}`, every command, the exit codes) and exit 0; nothing is scanned. `wpantry help COMMAND` is `wpantry COMMAND --help`. An unknown first word is a usage error (2). `check` is `scan` under its older name: the same options, output and exit codes. Changed 2026-11-02: until then `check` was the default subcommand and the fixes were its `--fix` flag.

Deprecated, kept for scripts written before 2026-11-02 and left out of `--help`: `scan --fix` and `check --fix` (`--update` is the same flag) behave exactly as `fix`, taking `--dryrun` and `--yes` as `fix` does, and `scan --dryrun` as `fix --dryrun`; options given with no subcommand (`wpantry --fix`, `wpantry --json`) are `scan`'s. New callers use `scan` and `fix`.

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
| `--html FILE` | Also write an offline, self-contained HTML report; optional, no browser auto-launch, success notice on stderr |
| `--json` | Print the envelope below instead of the report; never prompts |
| `--no-input` | Never prompt: the breach-consent question is skipped, and `fix` runs without asking. Prompts are only asked when stdin is a terminal: `? Question [y/N]` on stderr, Enter takes the default, anything but y/yes/n/no asks again |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled allowlist; `--license` is the same option. Off by default (it's noisy): without it there are no `license` findings and `unknown_licenses` is 0. A missing FILE is a usage error |
| `--gitleaks-config`, `--install-scripts`, `--repo-hooks`, `--suspect-policy`, `--hooks-policy` | Policy files; default to the bundled ones. A missing file is a usage error. A repo's own `.gitleaks.toml` is reported (`REPO-POLICY`, warn), never obeyed |
| `--hooks-policy FILE` | Repo hooks someone has read and accepts: `hook <file> "<when>" <command>` (one hook, matched on its exact command, so a hook that changes what it runs is reported again) or `repo <path>` (every hook that warns in the repos at or under that path). Only `OPEN-HOOK` and `INSTALL-HOOK` findings can be accepted; `RUNS-REPO-FILE`, `LOADER`, `IOC` and `MARKER` never are, and a line naming one is refused in the finding's `fix_cmd`. Accepted hooks are not findings and are counted (`checked["repo hooks accepted by policy"]`); every `OPEN-HOOK` and `INSTALL-HOOK` `fix_cmd` ends with the line that accepts it. The file is part of the scan's scope |
| `--jobs N` | gitleaks scans at once (default: half the cores, at most 4); each gets a share of the cores |
| `--no-posture`, `--posture-policy FILE` | The machine's own security settings (kind `posture`) run with the machine inventory; `--no-posture` skips them, the policy file lists check ids to skip (one per line, `POSTURE-` prefix optional). The ids are `POSTURE-<NAME>` as [posture.md](../docs/public/posture.md) lists them; `POSTURE-DNS-ENCRYPTED` (Medium: `warn`, never `fail`) was added 2026-11-01 |
| `--no-posture`, `--posture-policy FILE` | The machine's own security settings (kind `posture`) run with the machine inventory; `--no-posture` skips them, the policy file lists check ids to skip (one per line, `POSTURE-` prefix optional) |
| `--no-clipboard` | Skip the clipboard self-test of the machine inventory (kind `clipper`, `CLIPPER-ACTIVE`): it writes a canary address to the clipboard and restores the clipboard after. The persistence check (`CLIPPER-PERSISTENCE`) runs regardless. Added 2026-11-01 |
| `--no-malware` | Skip the malware scan (kind `malware`): YARA rules over the top two levels of Downloads, Desktop and the temp directories, the programs launch items start, and the executables in the repos. Added 2026-11-04 |
| `--deep` | The malware scan reads everything under `$HOME` (twelve levels, the repo walk's pruned directories skipped) with every system's rules, not only this system's and any system's. Added 2026-11-04 |
| `--no-online-hash` | Never look up a flagged file's SHA-256 online. Otherwise, after one yes (asked once on a terminal, kept in the cache as `online_hash_consent`), the SHA-256 of each file the malware scan flagged (at most 50 a scan), and nothing else about it, goes to YARAify and CIRCL hashlookup, and to MalwareBazaar when `ABUSECH_AUTH_KEY` is set. A malware verdict makes the finding `fail`, Critical, and its note names the source and family; a known-good answer is noted on a heuristic `warn`. A source that can't be reached is `unchecked`. Added 2026-11-04 |
| `rules` | The YARA rule sources the malware scan uses (ours, built in; YARA Forge's `full` package, fetched into `rules/` beside the cache at most daily; any `.yar` you put there), how many compile and how many are for this system; `--update` fetches YARA Forge now (exit 1 when it can't); `--json` as `{directory, sources: [{source, rules}], rules, this_system, rejected, update_failed}`. Added 2026-11-04 |
| `search` | Rank cached advisories (SQLite FTS5 syntax); `--applicable` keeps those in the latest findings |
| `export --csv` | Latest findings as CSV: `id, aliases, url, component, kind, affected_version, safe_version, severity, kev, status, location` |
| `export --jsonl` | Latest findings as JSON Lines, one object per finding: every [finding](#finding) key, plus `aliases` (the record's other ids), `url`, `record` (the full OSV JSON, or `null`), `first_seen`, `last_seen`, `resolved_at` (`YYYY-MM-DD HH:MM UTC` strings, `null` when unknown or open), `days_exposed` and `fix` (`null`, or `{attempted_at, mode, ok, verified, succeeded}` for the latest `fix` run of its `fix_cmd`). `--all` adds the exposures a later scan of the same scope resolved and the latest scan no longer lists. `--csv` and `--jsonl` may be given together; one is required |
| `breach` | Show or set consent for the opt-in email breach check |
| `watch` | Ask OSV again (bypassing the daily cache) about every advisory the latest findings carry with `status == "warn"` and `fixed == ""`: the Critical, High and exploited-in-the-wild advisories no fix was released for. Prints each with `no fix yet` and its mitigation, or `FIX AVAILABLE: <component> <version>`; exits 10 when at least one has a fix now. `--offline` reads the cache only. `--json` prints `{"schema", "impl", "version", "watched": [{id, severity, summary, ecosystem, package, version, fixed (string or null), mitigation (string or null)}]}`. For an hourly cron: a non-zero exit is the signal |
| `version` | `{"version": "0.1.0", "impl": "rust", "schema": 1}` with `--json` |
| `tools` | The external tools this implementation runs, found or missing |
| `sources` | Every outside source (`assets/defaults/sources.toml`): kind, tier, host, licence, whether it is redistributed, when it was last fetched, whether that is fresh, and its last error; `--json` as `{sources: [{id, kind, format, tier, host, transport, license, redistribute, refresh_seconds, sends, last_attempt, last_success, fresh, error}]}` (times as epoch seconds, null when never). Exit 0. Added 2026-11-05 |
| `skill` | Print the bundled agent skill (`SKILL.md`) to stdout |
| `report` | `report [--exposure] [--remediation] [--audit] [--since DAYS] [--format md\|json\|csv] [-o FILE]`: the logs kept across scans (default: all three, 90 days, Markdown to stdout). Exposure log: each finding from the scan that first saw it to the scan of the same scope that no longer did, with days exposed; remediation log: every unattended fix `fix` ran, its result, the exposures it addressed and the complete scan that verified them gone; audit log: every scan (when, host, user, version, scope, counts) and event. `--format csv` is the exposure log. JSON: `{"schema", "version", "since_days", "exposures", "fixes", "scans", "events"}` |
| `sync` | `sync [--refresh] [--json]`: refresh what the cache already knows, without an inventory: the feeds (CISA KEV, the malicious-package index, the cask catalog and browser releases, VS Code's lists, the latest wpantry), end-of-life dates for every product on record, and OSV's answers for every package version asked about before. Exit 0, or 1 when a source was unreachable. `--json`: `{"refreshed": [...], "failed": [{"source", "why"}], "packages": n}` |
| `schedule` | `schedule install [--every hourly|daily|weekly] [--at HH:MM] [--dry-run]`, `status`, `uninstall`, `run`: a scheduled `sync` then `scan --json --no-input` (never `fix`) through launchd (`~/Library/LaunchAgents/ai.waffuru.wpantry.plist`), a systemd user timer (`~/.config/systemd/user/wpantry.{service,timer}`) or cron. `run` writes `$XDG_STATE_HOME/wpantry/last.json` (default `~/.local/state/wpantry/`) and appends one line to `schedule.log`; one run at a time (`schedule.lock`). Default daily at 09:30. `install --clipboard-guard` and `uninstall --clipboard-guard` act on the resident clipboard guard instead (`clipboard --watch` as `~/Library/LaunchAgents/ai.waffuru.wpantry.clipboard.plist`, started at login and restarted on failure, or `~/.config/systemd/user/wpantry-clipboard.service` wanted by `graphical-session.target`; cron is refused with a message), its output in `clipboard.log`; off unless installed. `status` reports both jobs; a plain `uninstall` leaves the guard and says so. Added 2026-11-01 |
| `cache` | `cache prune [--older-than DAYS]` (default 90): drop package versions not asked about since then, the advisories only they referred to, and cached runs that old, then `VACUUM` |
| `update` | `update [--check] [--yes] [--no-input] [--offline] [--version VER]`: is there a newer release; after a yes (or `--yes`), install it. The download is checked against the release `SHA256SUMS` and then verified by the first installed verifier (packslip with the release signer pinned, `gh attestation verify` against `release.yml` at the tag, cosign against the same identity); with none, nothing is installed. An install mise, cargo or Homebrew made is updated through that tool; a source build is only reported. `scan` prints one stderr line when a newer release is cached (`WPANTRY_NO_UPDATE_CHECK=1` turns it off) |
| `harden` | `harden extension-cooldown [--hours N]` (default 72): set `extensions.installCooldownHours` in every installed VS Code-family editor's `settings.json`, keeping comments and formatting; the fix `POSTURE-EXTENSION-COOLDOWN` names, and the one posture fix that edits a file. Exit 0 |
| `mitigate` | `mitigate {list,all,ID} [--dry-run] [--yes] [--no-input] [--undo]`. `list`: the stopgaps wpantry can install, each with whether it applies here (needed, already in place, the fix is in, not this OS), then the advisories in the latest findings with `fix_auto` true. `all`: `fix` (it takes `--offline`, `--no-machine` and `--path DIR` as `scan` does). `ID`: what this host can do about one advisory (by id or alias, any case). Runs the fixes the latest findings carry for it with `fix_auto` true (as `fix` does; asked on a terminal, run as is without one), runs wpantry's own stopgap for it where one exists (CVE-2026-98432 on Linux: an nftables rule dropping inbound TCP with IP options, a boot-time unit, `net.mptcp.enabled=0`, and the services still holding an MPTCP listener printed as `systemctl restart` lines, never run; written as root, asked first unless `--yes`, skipped without a terminal unless `--yes`), and prints the remaining `fix_cmd`s under `Needs you`. `--dry-run` prints the state and the plan and changes nothing; `--undo` (`--remove` is the same) takes the stopgap away: the unit is disabled and removed, the nft table deleted, the rule and sysctl files removed and `net.mptcp.enabled` set back to 1. A stopgap persists across reboots (the unit reloads the rule before the network comes up; `sysctl.d` reapplies the sysctl) until undone. Exit 0 when everything that applies here was done or printed, 1 when a step is left for you, a fix failed, or nothing is known for the id here (not in the latest findings and no stopgap), 2 usage. A scan never runs it. Added 2026-11-02 |
| `clipboard` | Without `--watch`: the clipboard self-test of the machine scan, now. Prints one line, or with `--json` `{"schema", "impl", "version", "self_test": "clean"|"swapped"|"skipped", "canaries": n (clean), "swaps": [{chain, canary, got, read}] (swapped), "why": string (skipped)}`; exit 1 when a canary came back changed, else 0 (a test that couldn't run says so and exits 0, as an `unchecked` source does). With `--watch`: the resident guard. It reads the clipboard about four times a second and never writes it; when text holding exactly one wallet address becomes a different valid address of the same chain within `--window SECONDS` (default 2, 0.1 to 3600) with nothing but addresses on the clipboard in between, that is an alert: one line on stdout naming both addresses and the chain (and that a double copy by hand looks the same), a desktop notification (Notification Center through `osascript`, or `notify-send`) and a `clipper` row in the cache's `events` table. `--json` prints one object per alert instead of the line (below). It runs until interrupted, or exits 0 after the first alert with `--once`. Exit 3 when there is no clipboard to read (no `pbpaste`, `wl-paste`, `xclip` or `xsel`, or no display session). `--once` and `--window` without `--watch` are usage errors. Added 2026-11-01 |

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
| `WPANTRY_CLIPBOARD_FAKE` | A test hook for `clipboard --watch`, which the contract suite uses: the path of a file whose lines are the clipboard's successive contents, one per read (a blank line is an empty clipboard), the clock advancing a quarter second per read. The guard reads the file instead of the clipboard, sends no desktop notification, and exits 0 when the lines run out. Not for use outside tests |
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

## `scan --html FILE`

HTML is an optional sidecar to the scan. Terminal output and scan exit codes stay the same; `--json --html FILE` prints the unchanged schema-1 envelope on stdout and embeds that same envelope in the HTML. As before, `--json` selects reporting only even under `fix`. Without JSON, `fix` exports the final recheck, including an indication of failed update commands; `--dryrun` exports the initial scan. A report retains unchecked sources, unfixed-advisory and unknown-license counts, and scope (paths, machine inventory, offline mode and license checking).

`FILE` is required; empty values and `-` are usage errors (2). The parent must exist. Output is staged beside the destination before scanning, written with mode 0600 on Unix and renamed over the destination only after successful generation. A destination symlink is replaced rather than followed. File errors return 3; a scan error leaves a previous report intact. Export never opens a browser, fetches extra advisories, or applies updates. The viewer uses embedded assets, escapes report text, and only copies proposed commands on request. The HTML layout and bundle metadata are presentation details, not a new version of the JSON contract.

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
| `vuln_id` | string | Advisory id (CVE preferred), a gitleaks rule id, or a marker: `UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, `DEPRECATED`, `UNPINNED`, `BROWSER`, `OS-UPDATE`, `LICENSE`, `INSTALL-SCRIPT`, `NPM-SCRIPTS`, `BREACH`, `REPO-POLICY`, `hidden-text`, `HIDDEN-BIDI`, `HIDDEN-TAGS`, `HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`, `HIDDEN-PROMPT`, `HIDDEN-FILENAME`, `CONFUSABLE-DOMAIN`, `AGENT-INSTRUCTIONS`, `HIDDEN-HTML`, `EXFIL-LINK`, `CONFUSABLE-NAME`, `DANGEROUS-URI`, `suspect-code`, `SUSPECT-EXEC-DECODED`, `SUSPECT-ENCODED-PAYLOAD`, `SUSPECT-STRING-DECODER`, `SUSPECT-ESCAPED-SOURCE`, `SUSPECT-PRIV-ESCALATION`, `SUSPECT-CREDENTIAL-ACCESS`, `SUSPECT-WALLET-SIGNING`, `SUSPECT-THIRD-PARTY-SCRIPT`, `SUSPECT-RAW-IP`, `SUSPECT-TYPOSQUAT`, `SUSPECT-BINARY-BLOB`, `SUSPECT-PROFILING-PROMPT`, `SUSPECT-CARDHOLDER-DATA`, `SUSPECT-WEAK-PASSWORD`, `SUSPECT-KEYLOGGER`, `SUSPECT-CLIPBOARD-SWAP`, `CLIPPER-ACTIVE`, `CLIPPER-PERSISTENCE`, `CLIPPER-EXTENSION`, `PERSISTENCE-NEW`, `PERSISTENCE-INJECTION`, `PERSISTENCE-SIGNATURE`, `PERSISTENCE-HIDDEN`, `--suspect-policy`, `document`, `DISGUISED-PROGRAM`, `DOC-POLYGLOT`, `DOC-LAUNCH`, `DOC-JS-ON-OPEN`, `DOC-OBFUSCATED`, `DOC-XL4-MACRO`, `DOC-REMOTE-TEMPLATE`, `DOC-REMOTE-OBJECT`, `DOC-DDE`, `DOC-RTF-OBJECT`, `IMG-PAYLOAD`, `IMG-SVG-SCRIPT`, `MALWARE`, `DOC-MACRO`, `IMG-WRONG-TYPE`, `DOC-JAVASCRIPT`, `DOC-EMBEDDED`, `DOC-FORM`, `DOC-TRAILER`, `DOC-OLE-OBJECT`, `DOC-ACTIVEX`, `DOC-REMOTE-CONTENT`, `DOC-UNREADABLE`, `IMG-TRAILER`, `IMG-SVG-EXTERNAL` |
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

## `clipboard --watch --json`

One object per alert, one per line, as they happen:

```json
{"schema": 1, "impl": "rust", "version": "0.2.0", "event": "clipper", "at": 1793591878.9,
 "chain": "EVM (Ethereum, BSC, Tempo)", "from": "0x5290…9EE7", "to": "0xD62E…90E6", "seconds": 0.5,
 "note": "clipboard swap: the EVM (Ethereum, BSC, Tempo) address … If you copied two addresses yourself, ignore this"}
```

| Key | Type | Meaning |
|---|---|---|
| `event` | string | `clipper` |
| `at` | float | Unix time of the alert |
| `chain` | string | The chain's name, as `Chain::name` spells it |
| `from`, `to` | string | The address copied, and what it became |
| `seconds` | float | How long after `from` appeared `to` did, to two decimals |
| `note` | string | The one line a person reads |

The cache's `events` row for the alert has `kind == "clipper"` and the same object as `detail` minus `schema`, `impl`, `version` and `at` (the row has its own `at`).

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
