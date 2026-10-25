---
name: waffuru-security
description: Scan this machine and the Waffuru repos for vulnerabilities that actually apply (CVEs with a released fix, end-of-life runtimes, outdated browsers and apps, leaked CAs), search the local advisory cache, and plan or apply the fixes. Use when asked whether we're affected by a CVE, what needs updating, to run or explain `make secure`, or to triage security findings.
---

# Waffuru security

The scanner lives in the ops repo under `security/` (see its README). It inventories what is installed, asks OSV.dev, CISA KEV and endoflife.date only about that, and keeps everything in a local SQLite cache (`~/.cache/waffuru/security.db`). Repeat runs the same day make almost no network calls.

## Commands

Run from the ops checkout (`~/waffuru/ops`, or wherever `ops` is cloned):

| Goal | Command |
|---|---|
| Report what applies (exits 1 when something has a fix) | `make secure` |
| Show the update plan, change nothing | `make secure UPDATE=1 DRYRUN=1` |
| Apply the fixes that can run unattended, then re-check | `make secure UPDATE=1` |
| Findings as JSON | `python3 security/secure.py check --json` |
| Ignore cached answers | `python3 security/secure.py check --refresh` |
| Search cached advisories, ranked | `python3 security/secure.py search "tarfile traversal" --json` |
| Only advisories that apply here | `python3 security/secure.py search openssl --applicable --json` |
| Findings as CSV (id, url, component, affected and safe version) | `python3 security/secure.py export --csv findings.csv` |

`search` takes SQLite FTS5 syntax (`"exact phrase"`, `tls AND certificate`, `rust*`). Results rank by text relevance, then whether the advisory applies to this machine, then whether it is in CISA KEV.

For anything the CLI doesn't answer, query the cache read-only: `sqlite3 -readonly ~/.cache/waffuru/security.db`. Tables: `findings` (latest scan), `vulns` (OSV records; `record` is the full JSON), `queries` (package/version → advisory ids, with when we asked), `kev`, `eol`, `casks`, `malicious` (the malicious-package name index), `runs` (cached osv-scanner, `brew vulns` and gitleaks results).

## Triage

1. Run `python3 security/secure.py check --json` and group by component. One component often carries many advisories; one update clears them.
2. Order: malicious packages and extensions first (uninstall or remove them, then rotate credentials), then committed secrets from a provider rule (rotate first, then purge history), then anything in KEV, then end-of-life runtimes, then by severity, then everything else with a fix.
3. Say what each fix touches before running it. `make secure UPDATE=1` only runs unattended, user-level updates (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, uninstalling malicious extensions). It prints the rest as steps.
4. Never run the printed steps that need sudo (OS updates, `make fix-ca-trust`) yourself. Hand them to the user.
5. A fix in an org repo's lockfile is a code change. Follow `.agents/PM.md`: file an issue, make a sibling worktree on a `feat/` branch from `origin/dev`, run the printed `cargo update` / `pnpm update` / `npm install` there, run the repo's build and tests, and open a draft PR. Never edit the shared clones in place.
6. Warnings (no released fix yet, an app or extension behind its latest release, an Electron app whose vendor hasn't shipped a fix, an unreviewed install script, a license outside the allowlist) don't fail the check. Mention them; don't chase them unless asked.
7. "not checked" lines mean a source couldn't be reached and had nothing cached. Never report those areas as clean: re-run with network, or say they're unverified.

## Rules

- Only report what applies. The scanner already filters to installed components; don't pad an answer with advisories for things that aren't here.
- Never print or copy a secret gitleaks found; work from the rule, file, line, commit and fingerprint it reports.
- The email breach check sends the user's address to a third party. Never enable it (`secure.py breach --enable`) unless the user asks.
- An answer of "not affected" depends on how fresh the cache is. Say when it was last refreshed (`--refresh` forces it) and whether the machine was offline.
