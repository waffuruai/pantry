# `.pantryignore`

What a scan leaves out, and why it works the way it does. The format and its examples are in [docs/public/ignore.md](../../docs/public/ignore.md); this page records the decisions. Tracking: [#220](https://github.com/waffuruai/pantry/issues/220).

## Why

From 0.5.0, Pantry scans git history as files (each blob once), not as diffs. Every version of a file that holds a secret is its own finding, at the commit that added that version. A `.gitleaksignore` fingerprint (`commit:path:rule:line`) covers one of them, so a fixture edited over many commits needed many lines. Other checks had no way to skip a path at all: a vendored lockfile's advisories, a sample document, a licence in an example project.

## Decisions

| Decision | Why |
|---|---|
| gitignore patterns, in `[check]` and `[check id]` sections | The syntax everyone already writes. Sections keep each line a plain path, so the file reads like a `.gitignore` |
| A check is a finding's `kind`, and an id is its `vuln_id` | The names a user sees in `scan --json` and the report; no second vocabulary |
| A header that can't be read applies to nothing | A typo must never widen what is skipped |
| Root file only (no nested `.pantryignore`) | One file per repo is one place to review. Nested files can come later without breaking this one |
| A repo's file can't skip `malware`, `suspect-code`, `hidden-text`, `repo-hook` or `clipper` | Those checks protect you from the repo. A malicious repo would otherwise ship a `.pantryignore` hiding itself. A section asking for one is reported (`IGNORE-PROTECTED`, MEDIUM) |
| Your own file, `~/.config/wpantry/ignore`, with absolute or `~/` paths | You may skip anything on your own machine: research samples, quarantines |
| Filtered once, at the end of the scan, on the paths a finding names (`component`, `location`) | Every check honours it without code of its own. A path is matched in the innermost repo that holds it, so a nested repo's files follow its own file, not its parent's |
| The secret history scan doesn't read a path its check skips entirely | `vendor/` and fixtures cost nothing. A `[secret id]` entry still reads the file, since other rules may match |
| Each version stays its own finding; reports group a file's versions into one row | The cache and history keep exact records (`kind\|component\|location\|vuln_id`); a reader sees one thing to decide |
| Skipped findings are counted, never dropped silently | `checked` gains "findings skipped by a repo's .pantryignore", "findings skipped by your ignore file" and, for the history files not read, "files in git history skipped by a repo's .pantryignore" |
| `.gitleaksignore` fingerprints still work | The org pre-commit hook still runs gitleaks, so repos keep the file. Honouring it costs nothing |
| `.pantryignore`'s contents are part of the secret job's cache key | A cached run must not hide or keep hits the file now says otherwise about. Blob results stay cached, so a change rereads only what it unskips |

## Not done

- Expiry dates or reasons on entries. A comment above the line is the reason for now.
- A per-secret identity that survives edits to the line (a salted hash of the value). Path and rule cover the cases we have, and a hash of a low-entropy secret in a committed file could be guessed.
- `unfixed` and `unknown_licenses` still count advisories and packages a file left out.
