# The secret scan

Pantry's secret scan (`rust/crates/wpantry/src/checks/secrets/`) runs betterleaks v1.10.0's rules, translated to YARA in [pantry-rules](https://github.com/waffuruai/pantry-rules/tree/main/rules/any/secret), on `wpantry-yara`. It reports what betterleaks reports, except where Pantry differs on purpose (below).

## Where things come from

| What | Where | Rebuilt with |
|---|---|---|
| The rules | `assets/secrets/rules.yar`, vendored from pantry-rules | `python3 scripts/secret_rules.py PANTRY_RULES_CHECKOUT` |
| Their test cases | `tests/secret-cases.toml`, the same | the same |
| The word list | `assets/secrets/words.txt.gz`, from web2 | `python3 scripts/secret_words.py` |

## What it copies from betterleaks

- **Fragments:** a file is read in 100 KB reads through a 4 KB buffer, each extended to a blank line within 25 KB (`fragments.rs`). Keywords gate a rule per fragment, and `$` is the fragment's end.
- **Matches:** leftmost-first and non-overlapping, as RE2. The secret is the rule's `secret_group`, or the first group that matched, with the match's `\n`s trimmed.
- **Filters:**
  - the rule's meta skips;
  - the global prefilter and filter;
  - a filter program (`filter_expr`), run by `expr.rs`, a subset of Expr.
- **Ties:** a finding gives way to one of higher specificity on the same line whose secret contains it, or to a part of another rule's multipart finding.
- **Components:** a multipart rule reports only with its required parts near (`within`).
- **Decoding:** percent, unicode, hex and base64, up to five passes (`decode.rs`). A decoded hit is reported at the encoded text.

## Where Pantry differs, on purpose

- **Readable text:** betterleaks asks the cl100k tokenizer. Pantry asks whether the value holds a word, cased as a word, or a run of 8 climbing characters (`readable.rs`).
  - On ShareGPT, docs and juke this drops what betterleaks' check drops.
  - It also drops a few slugs and placeholder tokens that betterleaks keeps.
  - About 0.15% of random keys hold a word by chance; betterleaks' list matches about 0.3%.
- **Binary files:** a NUL byte in the first 8,000 bytes skips the file, as git decides. In history only those bytes are read, so model weights and data dumps aren't held in memory.
- **Ignoring:** a repo's `.pantryignore` ([ignore.md](../public/ignore.md)) leaves findings out by path and rule. A path it skips for the whole secret check isn't read from history, and its contents are part of the job's cache key. `.gitleaksignore` isn't read.
- **Limits, in history:** files over 10 MB aren't read, and the 30-minute budget is checked before every fragment and decoding pass, so one dense file can't hold a scan much past it. Both leave files not checked, as does a partial clone's missing blob: git is never asked to fetch one (`GIT_NO_LAZY_FETCH`).
- **Pantry's own filters:** `Any.Secret.PantryFilter.yar` skips hashes, ids and test vectors for the generic rule, plus single-case placeholders.
- **Where the generic rules don't look** (`noise.rs`): the `generic-*` rules skip translations (`i18n/`, `locales/`, `lang/`, `.arb`, `.po`, …), minified or content-hashed scripts, source maps, stylesheets and docs (`.md`, `.rst`, `docs/`); `generic-password` also skips tests (`test/`, `spec/`, `*_test.*`, `*.spec.*`, …). Provider rules read them all. `--betterleaks-only` on the `secret_scan` example turns this off.
- **One finding per rule and file:** history repeats a file's hits in every version of it, so a rule's hits in one file are one finding. It names the first five places, oldest version first, so its location and id don't move as commits land, and its note counts the rest. The cache keeps each hit.
- **Not yet:** archives (betterleaks opens zip, gz and tar, up to 8 levels), and live checks with providers ([#190](https://github.com/waffuruai/pantry/issues/190), opt-in at most).

## Checking parity

```bash
cargo run --release -p wpantry --example secret_scan -- --betterleaks-only FILE...
betterleaks dir FILE --report-format json --report-path bl.json
```

Compare by rule, line and columns. Measured on 2026-11-07:

| Corpus | Same | Differ |
|---|---|---|
| 468 MB ShareGPT JSON | 1,208 of 1,209 | one placeholder Slack token that Pantry reads as text |
| docs checkout | 0 of 0 | none |
| juke checkout | 88 of 115 | 21 run-id slugs read as text; 6 inside `.json.gz` archives |

Speed: 17 s on the 468 MB file on one core. betterleaks takes 18 s and gitleaks 386 s.

On op-analytics, a history holding 91 GB of CSVs:

- **Time:** the first scan hit its 30-minute budget, sharing the machine with test runs. The second read the remaining 47,094 files in 8.4 minutes on 10 cores.
- **What each tool found:**

  | Tool | Findings | Distinct places |
  |---|---|---|
  | gitleaks | 366 | |
  | betterleaks `git` | 56 | 2, the same line of one JSON counted once per commit |
  | Pantry | 13 | 13 |

- **Why the counts differ:**
  - Pantry reports that JSON once.
  - Its 12 CSV hits are also what `betterleaks dir` reports on those files. `betterleaks git` reads diffs and misses them; Pantry reads every file version whole.
  - The one place Pantry doesn't report is a UUID (a Firebase download token), which Pantry's filter skips for the generic rule.
