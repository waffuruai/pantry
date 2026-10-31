# wpantry CLI contract

Status: frozen at schema 1, 2026-10-25. Owner: Eric.

The command line, its exit codes, its JSON and its cache file are wpantry's only stable surface. Callers (ops, Syrup, wsentinel, agents) depend on this page and nothing else. The product is Pantry, and its command is `wpantry` (how it is built: [docs/architecture.md](../docs/architecture.md)). It MUST pass the contract tests, which run the binary and check its output rather than its internals.

## Change rule

- Additive changes only: a new subcommand, flag, JSON key, finding `kind`, `vuln_id` value or cache column is fine without a bump.
- Removing or renaming a JSON key, changing a key's type, or changing what an exit code means bumps `schema`. The cache schema follows the same rule.
- `version --json` and every JSON envelope carry `schema`, so a caller can refuse an output it doesn't understand.

## Synopsis

```
wpantry [check] [--path DIR]... [--no-machine] [--update] [--dryrun] [--refresh] [--offline]
                 [--json] [--no-input] [--jobs N] [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE]
                 [--no-posture] [--posture-policy FILE] [--repo-hooks FILE] [--suspect-policy FILE]
wpantry search QUERY [--applicable] [--limit N] [--json]
wpantry export [--csv FILE] [--jsonl FILE] [--all]
wpantry breach [--enable | --disable]
wpantry watch [--offline] [--json]
wpantry version [--json]
wpantry tools [--json]
wpantry skill
```

`check` is the default subcommand.

| Subcommand / flag | Meaning |
|---|---|
| `check` | Scan, report, and exit by the result |
| `--path DIR` | Repeatable. The repo checks cover only the git repos at or under each DIR; a DIR holding no repo is scanned as one project without the git-history checks. A missing DIR is skipped with a one-line note on stderr. Without it the scope is every git repo under `$HOME` |
| `--no-machine` | Skip the machine inventory (tools, runtimes, packages, apps, browsers, OS, Homebrew, editors, harness configs, running containers, CA trust, breach). Repo checks only |
| `--update` | Run the unattended fixes, then re-check. On a terminal (stdin) without `--no-input`, list them and ask `Run these N updates now? [Y/n]` first; declining changes nothing (exit as the scan) |
| `--dryrun` | Print the update plan; change nothing |
| `--refresh` | Ignore cached answers |
| `--offline` | Cache only; anything never cached is `unchecked` |
| `--json` | Print the envelope below instead of the report; never prompts |
| `--no-input` | Never prompt: the breach-consent question is skipped, and `--update` runs without asking. Prompts are only asked when stdin is a terminal: `? Question [y/N]` on stderr, Enter takes the default, anything but y/yes/n/no asks again |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled allowlist; `--license` is the same option. Off by default (it's noisy): without it there are no `license` findings and `unknown_licenses` is 0. A missing FILE is a usage error |
| `--gitleaks-config`, `--install-scripts`, `--repo-hooks`, `--suspect-policy` | Policy files; default to the bundled ones. A missing file is a usage error. A repo's own `.gitleaks.toml` is reported (`REPO-POLICY`, warn), never obeyed |
| `--jobs N` | gitleaks scans at once (default: half the cores, at most 4); each gets a share of the cores |
| `--no-posture`, `--posture-policy FILE` | The machine's own security settings (kind `posture`) run with the machine inventory; `--no-posture` skips them, the policy file lists check ids to skip (one per line, `POSTURE-` prefix optional) |
| `search` | Rank cached advisories (SQLite FTS5 syntax); `--applicable` keeps those in the latest findings |
| `export --csv` | Latest findings as CSV: `id, aliases, url, component, kind, affected_version, safe_version, severity, kev, status, location` |
| `export --jsonl` | Latest findings as JSON Lines, one object per finding: every [finding](#finding) key, plus `aliases` (the record's other ids), `url`, `record` (the full OSV JSON, or `null`), `first_seen`, `last_seen`, `resolved_at` (`YYYY-MM-DD HH:MM UTC` strings, `null` when unknown or open), `days_exposed` and `fix` (`null`, or `{attempted_at, mode, ok, verified, succeeded}` for the latest `--update` run of its `fix_cmd`). `--all` adds the exposures a later scan of the same scope resolved and the latest scan no longer lists. `--csv` and `--jsonl` may be given together; one is required |
| `breach` | Show or set consent for the opt-in email breach check |
| `watch` | Ask OSV again (bypassing the daily cache) about every advisory the latest findings carry with `status == "warn"` and `fixed == ""`: the Critical, High and exploited-in-the-wild advisories no fix was released for. Prints each with `no fix yet` and its mitigation, or `FIX AVAILABLE: <component> <version>`; exits 10 when at least one has a fix now. `--offline` reads the cache only. `--json` prints `{"schema", "impl", "version", "watched": [{id, severity, summary, ecosystem, package, version, fixed (string or null), mitigation (string or null)}]}`. For an hourly cron: a non-zero exit is the signal |
| `version` | `{"version": "0.1.0", "impl": "rust", "schema": 1}` with `--json` |
| `tools` | The external tools this implementation runs, found or missing |
| `skill` | Print the bundled agent skill (`SKILL.md`) to stdout |
| `report` | `report [--exposure] [--remediation] [--audit] [--since DAYS] [--format md\|json\|csv] [-o FILE]`: the logs kept across scans (default: all three, 90 days, Markdown to stdout). Exposure log: each finding from the scan that first saw it to the scan of the same scope that no longer did, with days exposed; remediation log: every unattended fix `--update` ran, its result, the exposures it addressed and the complete scan that verified them gone; audit log: every scan (when, host, user, version, scope, counts) and event. `--format csv` is the exposure log. JSON: `{"schema", "version", "since_days", "exposures", "fixes", "scans", "events"}` |
| `sync` | `sync [--refresh] [--json]`: refresh what the cache already knows, without an inventory: the feeds (CISA KEV, the malicious-package index, the cask catalog and browser releases, VS Code's lists, the latest wpantry), end-of-life dates for every product on record, and OSV's answers for every package version asked about before. Exit 0, or 1 when a source was unreachable. `--json`: `{"refreshed": [...], "failed": [{"source", "why"}], "packages": n}` |
| `schedule` | `schedule install [--every hourly|daily|weekly] [--at HH:MM] [--dry-run]`, `status`, `uninstall`, `run`: a scheduled `sync` then `check --json --no-input` (never `--update`) through launchd (`~/Library/LaunchAgents/ai.waffuru.wpantry.plist`), a systemd user timer (`~/.config/systemd/user/wpantry.{service,timer}`) or cron. `run` writes `$XDG_STATE_HOME/wpantry/last.json` (default `~/.local/state/wpantry/`) and appends one line to `schedule.log`; one run at a time (`schedule.lock`). Default daily at 09:30 |
| `cache` | `cache prune [--older-than DAYS]` (default 90): drop package versions not asked about since then, the advisories only they referred to, and cached runs that old, then `VACUUM` |
| `update` | `update [--check] [--yes] [--no-input] [--offline] [--version VER]`: is there a newer release; after a yes (or `--yes`), install it. The download is checked against the release `SHA256SUMS` and then verified by the first installed verifier (packslip with the release signer pinned, `gh attestation verify` against `release.yml` at the tag, cosign against the same identity); with none, nothing is installed. An install mise, cargo or Homebrew made is updated through that tool; a source build is only reported. `check` prints one stderr line when a newer release is cached (`WPANTRY_NO_UPDATE_CHECK=1` turns it off) |
| `harden` | `harden extension-cooldown [--hours N]` (default 72): set `extensions.installCooldownHours` in every installed VS Code-family editor's `settings.json`, keeping comments and formatting; the fix `POSTURE-EXTENSION-COOLDOWN` names, and the one posture fix that edits a file. Exit 0 |

### Scope walk

The default scope walks `$HOME` to depth 6 without following symlinks and only looks at directory entries. A directory with a `.git` directory is a repo and is not descended into. A `.git` file (linked worktree, submodule) ends the descent and counts only when it is the `--path` itself. Pruned by name: `.git`, `node_modules`, `target`, `.build`, `vendor`, `.cache`, `dist`, `build`, `.venv`, `venv`, `__pycache__`, `.next`, `Library`, `.Trash`, `.rustup`, `.npm`, `.pnpm-store`, any `*.app`; by path: `go/pkg`, `.cargo/registry`, `.cargo/git`, `.local/share`. The count lands in `checked["git repos"]`.

## Environment

| Variable | Effect |
|---|---|
| `WPANTRY_DB` | Cache file. Default `$XDG_CACHE_HOME/wpantry/wpantry.db`, else `~/.cache/wpantry/wpantry.db`. The malicious-packages clone sits beside it. |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned instead of XposedOrNot |
| `GITHUB_TOKEN` | Sent to the GitHub API (latest-release lookups, such as mise's) to lift the anonymous rate limit |
| `WPANTRY_NO_UPDATE_CHECK` | Set to anything: `check` never mentions a newer wpantry release |
| `WPANTRY_TIMINGS` | Set to anything: every scan step is printed to stderr with the seconds since the scan began (for finding slow steps; not under `--json`) |
| `NO_COLOR` | Honoured: set to anything non-empty, no ANSI colour. Without it, wpantry colours its report, `tools`, prompts and errors only on a terminal, and never when `TERM=dumb`. `--json` output, pipes and files are never coloured. Child tools always run with `NO_COLOR=1` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and `unchecked` sources still exit 0; the report says "incomplete" |
| 1 | At least one finding has `status == "fail"`, or an unattended fix failed under `--update`. `tools` exits 1 when a required tool is missing |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |
| 10 | `update`: a newer release exists and was not installed (`--check`, `--no-input`, no terminal, a "no", or a source build); `watch`: a fix has landed for an advisory that had none |
| 130 | Interrupted (Ctrl-C) |

## `check --json`

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
| `unfixed` | int | Applicable advisories with no released fix. Those rated Critical or High (by the advisory's label, else its CVSS 3.x vector) or listed in CISA KEV also appear in `findings` as `warn` with `fixed` empty and the mitigation (bundled `mitigations.txt`, else a line saying to keep checking) as `fix_cmd`; the rest are only counted |
| `unknown_licenses` | int | Repo dependencies with no identifiable license; 0 unless `--licenses` |
| `findings` | array of Finding | Everything that applies, failing or warning |

### Finding

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `runtime`, `compiler`, `manager`, `pkgmgr`, `tool`, `datastore`, `harness`, `package`, `app`, `browser`, `extension`, `brew`, `os`, `project`, `image`, `bundled`, `mcp`, `repo-hook`, `hidden-text`, `secret`, `license`, `install-script`, `config`, `account`, `posture`, `unchecked`, `suspect-code` (open set) |
| `component` | string | What it is about (`openssl`, `vite`, `~/code/app/.env`) |
| `version` | string | Installed or locked version; `""` when none |
| `location` | string | Path, lockfile, image or source; `""` when none |
| `vuln_id` | string | Advisory id (CVE preferred), a gitleaks rule id, or a marker: `UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, `DEPRECATED`, `UNPINNED`, `BROWSER`, `OS-UPDATE`, `LICENSE`, `INSTALL-SCRIPT`, `NPM-SCRIPTS`, `BREACH`, `REPO-POLICY`, `hidden-text`, `HIDDEN-BIDI`, `HIDDEN-TAGS`, `HIDDEN-ZERO-WIDTH`, `HIDDEN-HOMOGLYPH`, `AI-BAIT`, `HIDDEN-PROMPT`, `HIDDEN-FILENAME`, `CONFUSABLE-DOMAIN`, `AGENT-INSTRUCTIONS`, `HIDDEN-HTML`, `EXFIL-LINK`, `CONFUSABLE-NAME`, `DANGEROUS-URI`, `suspect-code`, `SUSPECT-EXEC-DECODED`, `SUSPECT-ENCODED-PAYLOAD`, `SUSPECT-STRING-DECODER`, `SUSPECT-ESCAPED-SOURCE`, `SUSPECT-PRIV-ESCALATION`, `SUSPECT-CREDENTIAL-ACCESS`, `SUSPECT-WALLET-SIGNING`, `SUSPECT-THIRD-PARTY-SCRIPT`, `SUSPECT-RAW-IP`, `SUSPECT-TYPOSQUAT`, `SUSPECT-BINARY-BLOB`, `--suspect-policy` |
| `status` | string | `fail` or `warn` |
| `fixed` | string | The safe version; `""` when none |
| `kev` | bool | In CISA KEV (also true for malicious packages) |
| `severity` | string | Usually `CRITICAL`, `HIGH`, `MODERATE`, `LOW` or `MALICIOUS`; a source's own label (dnf: `IMPORTANT`) or `""` otherwise |
| `note` | string | One line for a human |
| `fix_cmd` | string | Command or step that fixes it; `""` when none |
| `fix_auto` | bool | `--update` may run `fix_cmd` unattended |
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
| `meta` | `key` TEXT PK, `value` TEXT (`breach_consent`, `malicious_at`, `<feed>_at`, `<feed>_etag`, `eol_at:<product>`, `vuln_etag:<id>`) |
| `vulns` | `id` TEXT PK, `aliases` TEXT (space-separated), `summary`, `details`, `severity`, `published`, `modified`, `url`, `record` TEXT (full OSV JSON) |
| `queries` | `ecosystem`, `package`, `version` TEXT (PK together), `checked_at` REAL (Unix time), `vuln_ids` TEXT (space-separated) |
| `findings` | `kind`, `component`, `version`, `location`, `vuln_id`, `status`, `fixed` TEXT, `kev` INTEGER, `severity`, `note`, `fix_cmd` TEXT, `fix_auto` INTEGER, `dep_scope` TEXT, `dep_direct` INTEGER (NULL when unknown), `affected_range` TEXT. The last three were added 2026-10-31; a cache from before gains them on open |
| `kev` | `cve` TEXT PK, `added`, `name` |
| `eol` | `product`, `cycle` TEXT (PK together), `eol`, `latest` |
| `casks` | `app` TEXT PK, `token`, `version` |
| `runs` | `source` TEXT PK (`gitleaks:<repo>`, `brew-vulns`, `tags:<repo>`, `image-packages:<id>`, the feeds' keys such as `arch-tracker` and `firefox`, …; rows an earlier implementation wrote are left alone), `fingerprint` TEXT, `ran_at` REAL, `result` TEXT (JSON) |
| `malicious` | `ecosystem`, `name`, `id` TEXT; index `malicious_name (ecosystem, name)` |
| `scans` | `id` INTEGER PK, `started_at` REAL, `finished_at` REAL, `host`, `user`, `version`, `scope` TEXT, `counts` TEXT (JSON), `fails` INTEGER, `warns` INTEGER, `unchecked` INTEGER (sources that couldn't be asked; a scan with any resolves no exposure and verifies no fix): one row per scan |
| `exposures` | `key` TEXT PK (`kind|component|location|vuln_id`), `scope`, `kind`, `component`, `version`, `location`, `vuln_id`, `status`, `severity` TEXT, `kev` INTEGER, `fixed`, `note` TEXT, `first_scan` INTEGER, `first_at` REAL, `last_scan` INTEGER, `last_at` REAL, `resolved_scan` INTEGER, `resolved_at` REAL, `dep_scope` TEXT, `dep_direct` INTEGER, `affected_range` TEXT, `fix_cmd` TEXT: a finding across scans; resolved by a scan of the same scope that no longer lists it |
| `fixes` | `id` INTEGER PK, `scan_id` INTEGER, `at` REAL, `command` TEXT, `mode` TEXT, `ok` INTEGER, `verified_scan` INTEGER (the complete scan after a fix that exited 0 in which none of its `targets` were listed; NULL otherwise), `targets` TEXT (JSON array of `exposures.key`): the unattended fixes `--update` ran |
| `events` | `id` INTEGER PK, `at` REAL, `kind` TEXT (`scan`, `fix`, …), `detail` TEXT (JSON) |
| `vulns_fts` | FTS5 over `id`, `aliases`, `summary`, `details`, `packages`, `tokenize='porter'` |

`runs.result` JSON is internal to each source and not part of the contract.
