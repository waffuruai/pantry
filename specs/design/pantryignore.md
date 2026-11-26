# `.pantryignore`

What a scan leaves out, and why it works the way it does. The format and its examples are in [docs/public/ignore.md](../../docs/public/ignore.md); this page records the decisions. Tracking: [#220](https://github.com/waffuruai/pantry/issues/220).

## Why

From 0.5.0, Pantry scans git history as files (each blob once), not as diffs. Every version of a file that holds a secret is its own finding, at the commit that added that version. A fingerprint (`commit:path:rule:line`) covered one of them, so a fixture edited over many commits needed many lines. Other checks had no way to skip a path at all: a vendored lockfile's advisories, a sample document, a licence in an example project.

## Decisions

| Decision | Why |
|---|---|
| gitignore patterns, in `[check]` and `[check id]` sections | The syntax everyone already writes. Sections keep each line a plain path, so the file reads like a `.gitignore` |
| A check is a finding's `kind`, and an id is its `vuln_id` | The names a user sees in `scan --json` and the report; no second vocabulary |
| A header that can't be read applies to nothing | A typo must never widen what is skipped |
| Root file only (no nested `.pantryignore`) | One file per repo is one place to review. Nested files can come later without breaking this one |
| A repo's file can't skip `malware`, `suspect-code`, `hidden-text`, `repo-hook`, `clipper`, `document`, `mcp` or `install-script`, nor any malicious (`MAL-…`, MALICIOUS), actively exploited (`kev`), `MALWARE` or `REPO-POLICY` finding | Those protect you from the repo. A malicious repo would otherwise ship a `.pantryignore` hiding itself. A section asking for one is reported (`IGNORE-PROTECTED`, MEDIUM) |
| Your own file, `~/.config/wpantry/ignore`, with absolute or `~/` paths | You may skip anything on your own machine: research samples, quarantines |
| Filtered once, at the end of the scan, on the paths a finding names (`component`, `location`) | Every check honours it without code of its own. A path is matched in the innermost repo that holds it, so a nested repo's files follow its own file, not its parent's |
| The secret history scan doesn't read a path its check skips entirely | `vendor/` and fixtures cost nothing. A `[secret id]` entry still reads the file, since other rules may match |
| A rule's hits in every version of a file are one finding | A reader sees one thing to decide. The cache keeps each hit; the finding names the first five places, oldest first, so its id doesn't move |
| Skipped findings are counted, never dropped silently | `checked` gains "findings skipped by a repo's .pantryignore", "findings skipped by your ignore file" and, for the history files not read, "files in git history skipped by a repo's .pantryignore" |
| `.pantryignore`'s contents are part of the secret job's cache key | A cached run must not hide or keep hits the file now says otherwise about. Blob results stay cached, so a change rereads only what it unskips |
| `wpantry ignore add \| list \| remove` writes and takes out rules; the format doesn't change | A person or a program driving wpantry can dismiss a finding without editing a file, and a hand edit keeps working. |
| `add` runs the new file through the scan's own filter before it writes | The rule must leave out that finding, no other finding of the latest scan, and parse without a new problem. A path with odd characters, or a repo asking to hide what protects you from it, is refused by the same code that would ignore it later, not by a copy of its rules |
| The narrowest rule is the finding's path under `[kind vuln_id]` | That is all the format can say: no package, line or version. When that would also leave out another finding of the latest scan (two packages, one advisory, one lockfile), `add` refuses and names them rather than hide more than was asked |
| `--all-places` is one rule per place, never a broader pattern | A pattern for "this package everywhere" would be a folder or a file name, which also hides other packages. The places are the findings of the latest scan with the same check, component and rule or advisory |
| A finding that names no path can't be ignored here | A machine setting (`posture`) has a title, not a file: its skip list is `posture.toml`. A source that couldn't be asked (`unchecked`) is a gap, not a finding. A rule's hits in a repo's test files are one finding for many files, so its only path is the whole repo |
| The comment under each rule is how a rule is known to be ours | `# wpantry ignore: F-… \| when \| reason`: the reader skips a line that starts with `#`, so the file reads as before. `remove` and `list` read the comment, not the log, so they work on a file moved to another machine |
| Rule ids are a hash of the file, section, pattern and which copy of the line | The same until the line is edited, and the same for a hand-written rule, so `remove` takes any rule `list` shows |
| The log is the cache's `events` table (kind `ignore`); the files are the truth | When, add or remove, the finding's key, scope, file and reason, in `report audit`. A rule the log says was added and the file no longer holds is shown as removed by hand: the log never overrules the file |
| The file is changed by appending a block or deleting one, and replaced atomically | Every other byte, comment and line ending stays. A link that leaves the repo or the config folder is never written through, and a repo's link isn't written at all, since a scan doesn't read it |

## Not done

- Expiry dates or reasons on entries. A comment above the line is the reason for now.
- A per-secret identity that survives edits to the line (a salted hash of the value). Path and rule cover the cases we have, and a hash of a low-entropy secret in a committed file could be guessed.
- `unfixed` and `unknown_licenses` still count advisories and packages a file left out.
