# How wpantry works

wpantry is one Rust binary that reads what is installed on this computer and what its git repos lock, asks a few public sources about exactly those versions, judges the answers against each ecosystem's own version rules, and says what applies. Answers live in one SQLite cache, so a second run the same day takes seconds, and a source it can't reach is reported "not checked", never clean.

![How Pantry checks your computer: this computer and its repos are read by wpantry's readers, judged, and reported; the cache talks to OSV.dev and the feeds; releases come from GitHub; the outputs are the terminal report, JSON, CSV and JSON Lines exports, the exposure, remediation and audit logs, and an HTML report](images/architecture.png)

[Full size](images/architecture.png) · [SVG source](images/architecture.svg)

## A run

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 560, "nodeSpacing": 40, "rankSpacing": 36}}}%%
flowchart TB
  scope["<b>1 SCOPE</b><br/>Walk ~ to depth 6, skipping Library, caches, toolchains, node_modules and app bundles,<br/>or the --path directories. Inventory the machine unless --no-machine."]
  read["<b>2 READ, in parallel</b><br/>Lockfiles and OS package databases; tools on PATH and in version managers; global packages;<br/>apps, browsers, Electron; editor extensions; agent harnesses; trust stores; security settings;<br/>container images; documents and code. gitleaks runs on repos whose HEAD moved."]
  ask["<b>3 ASK</b><br/>(ecosystem, name, version) to OSV in batches of 1000, only new or changed records fetched;<br/>KEV, end-of-life, the malicious index, licenses and release feeds. Every answer memoized for a day."]
  judge["<b>4 JUDGE</b><br/>Group an advisory's aliases into one finding; pick the safe version with the ecosystem's own<br/>comparator; fail, warn, or not checked."]
  report["<b>5 REPORT</b><br/>Grouped by kind, one line per component with the reason and the fix; the --json envelope;<br/>exit 0 clean, 1 fails, 2 usage, 3 internal. --update runs the unattended fixes, then re-checks."]
  scope --> read --> ask --> judge --> report
```

## Where to read more

- [What it checks and where the answers come from](public/checks-and-sources.md), with the flow of a question from inventory to report.
- [Using it](public/usage.md), [installing and verifying a release](public/install.md), [the machine's settings it checks](public/posture.md), [the reports it writes](public/reports.md).
- [The CLI contract](../specs/cli-contract.md): the command line, exit codes, JSON and cache file, the only stable surface.
- [How it is put together, in detail](internal/architecture.md): the readers and their golden files, the comparators and their vectors, the cache, the binary and its dependencies, the tests, and what the Rust port left open and where it closed.
- [The source map](../rust/README.md).

The diagrams are drawn in the [Waffuru design language](https://waffuru.ai/brand): the source is the SVG in [`docs/images/`](images/), 1200 px wide, and the PNG beside it is the 2× render.
