# Ignoring paths: `.pantryignore`

A repo's `.pantryignore` tells Pantry which of the repo's files to leave out of its findings. It can cover every check, one check, or one rule or advisory of a check. Use it for test fixtures, vendored code, sample data and secrets that were revoked long ago. Your own ignore file does the same for any path on your machine. The design and its reasons are in [the spec](../../specs/design/pantryignore.md).

See also: [checks-and-sources.md](checks-and-sources.md) (what each check is called), [usage.md](usage.md#policy-files) (the other policy files).

## The file

`.pantryignore` sits at the repo's root, next to `.git`. It holds gitignore patterns, relative to the root, grouped into sections:

```gitignore
# Before any section: left out of every check a repo may silence.
vendor/
testdata/**

# [check]: that check only. A check's name is its findings' `kind`.
[secret]
tests/fixtures/

# [check id]: one rule or advisory of that check, in these paths.
[secret github-pat]
config/legacy.py

[project GHSA-xxxx-xxxx-xxxx]
examples/old-app/package-lock.json

# [*]: every check again, for lines after the sections.
[*]
dist/
```

- **Patterns** work as in `.gitignore`: `*`, `?`, `[a-z]`, `**` for any number of directories, a trailing `/` for a directory, a leading or middle `/` to anchor a pattern to the root, `!` to bring a path back within its section, `#` for a comment and `\` to escape. As in git, a path inside an ignored directory stays ignored, even if a later `!` names it.
- **Checks** are named by the `kind` their findings carry in `wpantry scan --json`: `secret`, `project` (dependencies), `license`, `install-script`, `document`, `mcp` and the rest ([the list](../../specs/cli-contract.md#finding)). An id is the finding's `vuln_id`: a secret rule's id (`github-pat`) or an advisory's (`CVE-…`, `GHSA-…`), compared regardless of case.
- **A header** is a line that is nothing but `[check]`, `[check id]` or `[*]`. A line like `[Bb]uild/` is a pattern. To write a pattern that would read as a header, start it with `/`.
- **Paths** are matched against every path a finding names: the file it is about, or the lockfile or file it was found in. In git history, that is the path the file had in that version, so one entry covers every version of a file.

A finding left out isn't reported, cached as current or counted as a failure. The scan counts what each file left out: "findings skipped by a repo's .pantryignore", "findings skipped by your ignore file", and "files in git history skipped by a repo's .pantryignore" for the history files the secret scan didn't read. The counts are in the summary and in `checked` in `scan --json`. Nothing is dropped without that count.

## What a repo can't skip

A repo's own file can't silence the checks that protect you from that repo: `malware`, `suspect-code`, `hidden-text`, `repo-hook`, `clipper`, `document`, `mcp` and `install-script`. Nor can it skip, under any check, a known-malicious package (`MAL-…`), an actively exploited CVE (`kev`), malware found in a document (`MALWARE`), or the note that its own `.gitleaks.toml` isn't obeyed (`REPO-POLICY`). Lines before any section don't apply to those, and a section naming one of them isn't honoured. Instead, the scan reports it in the Configuration area (`IGNORE-PROTECTED`, a warning): a repo that asks to hide its own malware is worth a look. Only your own ignore file can skip those. A repo's file is read only when it's a regular file, not a link.

## Your ignore file

`ignore` in `~/.config/wpantry/` (or `$XDG_CONFIG_HOME/wpantry/`) has the same sections, with absolute or `~/` paths. It applies to every scan and can skip any check:

```gitignore
# Malware samples kept for research.
[malware]
~/research/samples/

# A folder of exports Pantry needn't read.
~/Downloads/exports/
```

A pattern without a `/` in it (`*.pem`) matches that name anywhere on the machine, so prefer full paths.

## Secrets

For secrets, `.pantryignore` replaces fingerprint lists. Pantry reads git history as files, and a rule's hits in every version of a file are one finding: a file whose secret stayed put over ten commits is one finding, naming its first five places, oldest first, and counting the rest. One `[secret]` entry for the file covers them all. A secret finding's fix is a script: if the secret is real, the lines that take it out of history; if it isn't, the line that adds the file to `.pantryignore`:

```sh
# If it isn't a secret: leave the file out of this rule's findings.
printf '\n[secret github-pat]\n%s\n' /config/legacy.py >> ~/code/app/.pantryignore
```

- A path every secret rule skips (lines before any section, `[*]` or `[secret]`) isn't read from the history at all. A `[secret id]` entry still reads the file, since other rules may match it.
- `.gitleaksignore` isn't read: list the path, or the path under `[secret <rule>]`, in `.pantryignore` instead. (gitleaks, which some pre-commit hooks run, still reads its own file.)
- Editing `.pantryignore` doesn't rescan the history: the files' results are cached, and only the ones it no longer skips are read.

## Problems in the file

A line the scan can't use is reported in the Configuration area as `IGNORE-FILE`, a warning with its line number: an unknown check (`[secrets]` asks "did you mean `secret`?"), a header with more than a check and an id, or a pattern that matches nothing. The patterns under a header it can't read apply to nothing, so a typo never widens what is skipped. A file over 1 MB isn't read, and that is reported too.
