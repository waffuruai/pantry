---
name: wpantry
description: Scan this computer (or one project) for vulnerabilities that actually apply (CVEs with a released fix, end-of-life runtimes, known malicious packages, committed secrets, outdated browsers and apps, leaked CAs), search the local advisory cache, and plan or apply the fixes. Use when asked whether we're affected by a CVE, what needs updating, to run or explain wpantry, or to triage security findings.
---

# wpantry

wpantry inventories what is installed on this computer and in its git repos, asks OSV.dev, CISA KEV and endoflife.date only about that, and keeps everything in a local SQLite cache (`wpantry version` and the report header name it; default `~/.cache/wpantry/wpantry.db`, or `WPANTRY_DB`). Repeat runs the same day make almost no network calls. The CLI contract is `specs/cli-contract.md` in the `waffuruai/pantry` repo.

## Commands

`wpantry` is the installed binary (see `docs/public/install.md` in the `waffuruai/pantry` repo), or `rust/target/release/wpantry` in a checkout.

| Goal | Command |
|---|---|
| Report what applies on this computer: machine + every git repo under `~` (exits 1 when something fails) | `wpantry` |
| One project only, no machine inventory | `wpantry --path ~/code/app --no-machine` |
| Show the update plan, change nothing | `wpantry --update --dryrun` |
| Apply the fixes that can run unattended, then re-check | `wpantry --update` |
| Findings as JSON (an envelope: `schema`, `checked`, `findings`, …) | `wpantry check --json --no-input` |
| Ignore cached answers | `wpantry --refresh` |
| Search cached advisories, ranked | `wpantry search "tarfile traversal" --json` |
| Only advisories that apply here | `wpantry search openssl --applicable --json` |
| Findings as CSV (id, url, component, affected and safe version) | `wpantry export --csv findings.csv` |
| Which external tools are installed | `wpantry tools` |
| Make every VS Code-family editor wait 72 h before installing a new extension version | `wpantry harden extension-cooldown --hours 72` |

`search` takes SQLite FTS5 syntax (`"exact phrase"`, `tls AND certificate`, `rust*`). Results rank by text relevance, then whether the advisory applies to this machine, then whether it is in CISA KEV.

Exit codes: 0 clean (warnings and "not checked" included), 1 a failing finding or a failed unattended fix, 2 usage error, 3 internal error.

For anything the CLI doesn't answer, query the cache read-only: `sqlite3 -readonly ~/.cache/wpantry/wpantry.db`. Tables: `findings` (latest scan), `vulns` (OSV records; `record` is the full JSON), `queries` (package/version → advisory ids, with when we asked), `kev`, `eol`, `casks`, `malicious` (the malicious-package name index), `runs` (cached osv-scanner, `brew vulns` and gitleaks results), `meta`.

## Triage

1. Run `wpantry check --json --no-input` and group `findings` by component. One component often carries many advisories; one update clears them.
2. Order: malicious packages and extensions first (uninstall or remove them, then rotate credentials), then committed secrets from a provider rule (rotate first, then purge history), then anything in KEV, then end-of-life runtimes, then by severity, then everything else with a fix.
3. Say what each fix touches before running it. `wpantry --update` only runs unattended, user-level updates (Homebrew, pip, npm -g, cargo, rustup, uv, editor extensions, uninstalling malicious extensions). It prints the rest as steps.
4. Never run the printed steps that need sudo (OS updates, `fix-ca-trust.sh`) yourself. Hand them to the user.
5. A fix in a repo's lockfile is a code change. Follow that repo's contribution rules: an issue, a branch, the printed `cargo update` / `pnpm update` / `npm install` there, the repo's build and tests, and a draft PR. Never edit a shared checkout in place.
6. `posture` findings are the machine's own settings (FileVault, firewall, Remote Login, automatic login, screen lock, updates): the user-level ones `--update` can apply; the `sudo` ones go to the user with the printed step. `--posture-policy FILE` silences checks a machine means to fail (a server's Remote Login).
7. Warnings (no released fix yet, an app or extension behind its latest release, an Electron app whose vendor hasn't shipped a fix, an unreviewed install script, a license outside the allowlist) don't fail the check. Mention them; don't chase them unless asked.
7. `unchecked` findings ("not checked" in the report) mean a source couldn't be reached and had nothing cached. Never report those areas as clean: re-run with network, or say they're unverified.

## Rules

- Only report what applies. The scanner already filters to installed components; don't pad an answer with advisories for things that aren't here.
- Never print or copy a secret gitleaks found; work from the rule, file, line, commit and fingerprint it reports.
- The email breach check sends the user's address to a third party. Never enable it (`wpantry breach --enable`) unless the user asks.
- An answer of "not affected" depends on how fresh the cache is. Say when it was last refreshed (`--refresh` forces it) and whether the machine was offline.
- A default run walks the whole home directory. When the question is about one project, pass `--path` (and `--no-machine` if the machine isn't in question).
