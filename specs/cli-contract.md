# wscanner CLI contract

Status: frozen at schema 1, 2026-10-25. Owner: Eric.

The command line, its exit codes, its JSON and its cache file are wscanner's only stable surface. Callers (ops, control-plane, wsentinel, agents) depend on this page and nothing else. The Python implementation (`python/`) defines it today; the Rust implementation ([01-rust-port.md](01-rust-port.md)) MUST match it. Both MUST pass the same contract tests, which run the binary and check its output rather than its internals.

## Change rule

- Additive changes only: a new subcommand, flag, JSON key, finding `kind`, `vuln_id` value or cache column is fine without a bump.
- Removing or renaming a JSON key, changing a key's type, or changing what an exit code means bumps `schema`. The cache schema follows the same rule.
- `version --json` and every JSON envelope carry `schema`, so a caller can refuse an output it doesn't understand.

## Synopsis

```
wscanner [check] [--path DIR]... [--no-machine] [--update] [--dryrun] [--refresh] [--offline]
                 [--json] [--no-input] [--gitleaks-config FILE] [--licenses [FILE]] [--install-scripts FILE]
wscanner search QUERY [--applicable] [--limit N] [--json]
wscanner export --csv FILE
wscanner breach [--enable | --disable]
wscanner version [--json]
wscanner tools [--json]
wscanner skill
```

`check` is the default subcommand.

| Subcommand / flag | Meaning |
|---|---|
| `check` | Scan, report, and exit by the result |
| `--path DIR` | Repeatable. The repo checks cover only the git repos at or under each DIR; a DIR holding no repo is scanned as one project without the git-history checks. A missing DIR is skipped with a one-line note on stderr. Without it the scope is every git repo under `$HOME` |
| `--no-machine` | Skip the machine inventory (tools, runtimes, packages, apps, browsers, OS, Homebrew, editors, harness configs, running containers, CA trust, breach). Repo checks only |
| `--update` | Run the unattended fixes, then re-check |
| `--dryrun` | Print the update plan; change nothing |
| `--refresh` | Ignore cached answers |
| `--offline` | Cache only; anything never cached is `unchecked` |
| `--json` | Print the envelope below instead of the report; never prompts |
| `--no-input` | Never prompt (the breach-consent question is skipped) |
| `--licenses [FILE]` | Also check repo dependencies' licenses, against FILE or the bundled allowlist. Off by default (it's noisy): without it there are no `license` findings and `unknown_licenses` is 0. A missing FILE is a usage error |
| `--gitleaks-config`, `--install-scripts` | Policy files; default to the bundled ones. A missing file is a usage error. A repo's own `.gitleaks.toml` still wins over `--gitleaks-config` |
| `search` | Rank cached advisories (SQLite FTS5 syntax); `--applicable` keeps those in the latest findings |
| `export --csv` | Latest findings as CSV: `id, aliases, url, component, kind, affected_version, safe_version, severity, kev, status, location` |
| `breach` | Show or set consent for the opt-in email breach check |
| `version` | `{"version": "0.1.0", "impl": "python", "schema": 1}` with `--json` |
| `tools` | The external tools this implementation runs, found or missing |
| `skill` | Print the bundled agent skill (`SKILL.md`) to stdout |

### Scope walk

The default scope walks `$HOME` to depth 6 without following symlinks and only looks at directory entries. A directory with a `.git` directory is a repo and is not descended into. A `.git` file (linked worktree, submodule) ends the descent and counts only when it is the `--path` itself. Pruned by name: `.git`, `node_modules`, `target`, `.build`, `vendor`, `.cache`, `dist`, `build`, `.venv`, `venv`, `__pycache__`, `.next`, `Library`, `.Trash`, `.rustup`, `.npm`, `.pnpm-store`, any `*.app`; by path: `go/pkg`, `.cargo/registry`, `.cargo/git`, `.local/share`. The count lands in `checked["git repos"]`.

## Environment

| Variable | Effect |
|---|---|
| `WSCANNER_DB` | Cache file. Default `$XDG_CACHE_HOME/wscanner/wscanner.db`, else `~/.cache/wscanner/wscanner.db`. The malicious-packages clone sits beside it |
| `HIBP_API_KEY` | The breach check uses Have I Been Pwned instead of XposedOrNot |
| `GITHUB_TOKEN` | Sent to the GitHub API (latest-release lookups, such as mise's) to lift the anonymous rate limit |
| `NO_COLOR` | Honoured: wscanner never emits ANSI colour, and runs its child tools with `NO_COLOR=1` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing fails. Warnings and `unchecked` sources still exit 0; the report says "incomplete" |
| 1 | At least one finding has `status == "fail"`, or an unattended fix failed under `--update`. `tools` exits 1 when a required tool is missing |
| 2 | Usage error (unknown flag, missing argument, missing policy file) |
| 3 | Internal error: the cache can't be opened or written, or the scanner crashed |
| 130 | Interrupted (Ctrl-C) |

`python/bin/wscanner` also runs the CA trust check before a machine scan; its failure counts as 1, and a 2 or 3 from the scan outranks it.

## `check --json`

```json
{
  "schema": 1,
  "impl": "python",
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
| `impl` | string | `python` or `rust` |
| `version` | string | The implementation's version |
| `checked` | object string → int | What was checked and how many (labels are display text; callers SHOULD NOT parse them) |
| `unfixed` | int | Applicable advisories with no released fix (not in `findings`) |
| `unknown_licenses` | int | Repo dependencies with no identifiable license; 0 unless `--licenses` |
| `findings` | array of Finding | Everything that applies, failing or warning |

### Finding

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `runtime`, `compiler`, `manager`, `pkgmgr`, `tool`, `datastore`, `harness`, `package`, `app`, `browser`, `extension`, `brew`, `os`, `project`, `image`, `bundled`, `mcp`, `secret`, `license`, `install-script`, `config`, `account`, `unchecked` (open set) |
| `component` | string | What it is about (`openssl`, `vite`, `~/code/app/.env`) |
| `version` | string | Installed or locked version; `""` when none |
| `location` | string | Path, lockfile, image or source; `""` when none |
| `vuln_id` | string | Advisory id (CVE preferred), a gitleaks rule id, or a marker: `UNCHECKED`, `MISSING`, `EOL`, `OUTDATED`, `MALICIOUS`, `DEPRECATED`, `UNPINNED`, `BROWSER`, `OS-UPDATE`, `LICENSE`, `INSTALL-SCRIPT`, `NPM-SCRIPTS`, `BREACH` |
| `status` | string | `fail` or `warn` |
| `fixed` | string | The safe version; `""` when none |
| `kev` | bool | In CISA KEV (also true for malicious packages) |
| `severity` | string | Usually `CRITICAL`, `HIGH`, `MODERATE`, `LOW` or `MALICIOUS`; a source's own label (dnf: `IMPORTANT`) or `""` otherwise |
| `note` | string | One line for a human |
| `fix_cmd` | string | Command or step that fixes it; `""` when none |
| `fix_auto` | bool | `--update` may run `fix_cmd` unattended |

A source that couldn't be reached is a finding with `kind == "unchecked"`, `status == "warn"`: never silence, never "clean".

## `tools --json`

`{"schema": 1, "impl": ..., "version": ..., "tools": [{"name", "required", "found", "path", "version", "purpose"}]}`. Python today: `osv-scanner`, `gitleaks`, `git`, `openssl` required; `brew`, `docker` optional. Rust today: `gitleaks`, `git`, `openssl` required; `brew`, `docker`, `rpm` optional. The list is per implementation and may shrink.

## Cache (SQLite)

One file per machine. Both implementations MUST read and write the same schema, so switching implementation keeps the cache. `vulns_fts` exists only where SQLite has FTS5.

| Table | Columns |
|---|---|
| `meta` | `key` TEXT PK, `value` TEXT (`breach_consent`, `malicious_at`, `<feed>_at`, `<feed>_etag`, `eol_at:<product>`, `vuln_etag:<id>`) |
| `vulns` | `id` TEXT PK, `aliases` TEXT (space-separated), `summary`, `details`, `severity`, `published`, `modified`, `url`, `record` TEXT (full OSV JSON) |
| `queries` | `ecosystem`, `package`, `version` TEXT (PK together), `checked_at` REAL (Unix time), `vuln_ids` TEXT (space-separated) |
| `findings` | `kind`, `component`, `version`, `location`, `vuln_id`, `status`, `fixed` TEXT, `kev` INTEGER, `severity`, `note`, `fix_cmd` TEXT, `fix_auto` INTEGER |
| `kev` | `cve` TEXT PK, `added`, `name` |
| `eol` | `product`, `cycle` TEXT (PK together), `eol`, `latest` |
| `casks` | `app` TEXT PK, `token`, `version` |
| `runs` | `source` TEXT PK (`osv-scanner:repos`, `gitleaks:<repo>`, `image:<id>` (Python), `image-packages:<id>` (Rust), `brew-vulns`, `tags:<repo>`, …), `fingerprint` TEXT, `ran_at` REAL, `result` TEXT (JSON) |
| `malicious` | `ecosystem`, `name`, `id` TEXT; index `malicious_name (ecosystem, name)` |
| `vulns_fts` | FTS5 over `id`, `aliases`, `summary`, `details`, `packages`, `tokenize='porter'` |

`runs.result` JSON is internal to each source and not part of the contract.
