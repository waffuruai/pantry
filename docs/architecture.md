# How wpantry works

wpantry is one Rust binary that reads what is installed on this computer and what its git repos lock, asks a few public sources about exactly those versions, judges the answers against each ecosystem's own version rules, and says what applies. Answers live in one SQLite cache, kept current from OSV's change lists, so a later run fetches only what changed since the last, and a source it can't reach is reported "not checked", never clean.

Pantry is three things in a line: verified sources of CVEs, IOCs, YARA malware rules and other known attack vectors; wpantry, a fast file scanner that runs on a schedule or when triggered and keeps in its cache the sources it checked, the files it checked, the exposures it found and how and when each was mitigated; and the reports it writes (terminal text, JSON, JSON Lines, CSV, HTML, Markdown). It watches nothing live and needs no permission beyond reading files. Live telemetry, the clipboard included, belongs to a resident watchdog or sidecar beside it, which can trigger a scan; JSON reports can go to an external reporting service that shows many machines in aggregate.

![How Pantry scans your computer: verified sources (CVEs and advisories, indicators of compromise, YARA malware rules, other known attack vectors) feed wpantry, a fast file scanner run on a schedule or when triggered, which judges what it finds and keeps it in one SQLite cache; it writes terminal text, JSON, JSON Lines, CSV, HTML and Markdown reports. Alongside, not part of Pantry: a watchdog or sidecar that triggers scans, and an external reporting service that receives JSON reports](images/architecture.png)

[Full size](images/architecture.png) · [SVG source](images/architecture.svg)

## A run

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 560, "nodeSpacing": 40, "rankSpacing": 36}}}%%
flowchart TB
  scope["<b>1 SCOPE</b><br/>Walk ~ to depth 6, skipping Library, caches, toolchains, node_modules and app bundles,<br/>or the --path directories. Inventory the machine unless --no-machine."]
  read["<b>2 READ, in parallel</b><br/>Lockfiles and OS package databases; tools on PATH and in version managers; global packages;<br/>apps, browsers, Electron; editor extensions; agent harnesses; trust stores; security settings;<br/>container images; documents and code. gitleaks runs on repos whose HEAD moved."]
  ask["<b>3 ASK</b><br/>(ecosystem, name, version) to OSV in batches of 1000, only new or changed records fetched;<br/>KEV, EPSS, end-of-life, the malicious index, licenses and release feeds.<br/>Answers kept current from OSV's change lists: only what changed since the last run is read."]
  judge["<b>4 JUDGE</b><br/>Group an advisory's aliases into one finding; pick the safe version with the ecosystem's own<br/>comparator; fail, warn, or not checked."]
  report["<b>5 REPORT</b><br/>Severity on CVSS&#39;s scale with CVSS and EPSS beside it; wpantry report renders the cache: areas of tables, JSON, CSV, Markdown, HTML;<br/>exit 0 clean, 1 fails, 2 usage, 3 internal. wpantry fix runs the unattended fixes, then re-checks."]
  scope --> read --> ask --> judge --> report
```

## Where to read more

- [What it checks and where the answers come from](public/checks-and-sources.md), with the flow of a question from inventory to report.
- [Using it](public/usage.md), [installing and verifying a release](public/install.md), [the machine's settings it checks](public/posture.md), [the reports it writes](public/reports.md).
- [The CLI contract](../specs/cli-contract.md): the command line, exit codes, JSON and cache file, the only stable surface.
- [How it is put together, in detail](internal/architecture.md): the readers and their golden files, the comparators and their vectors, the cache, the binary and its dependencies, the tests, and what the Rust port left open and where it closed.
- [The source map](../rust/README.md).

The diagrams are drawn in the [Waffuru design language](https://waffuru.ai/brand): the source is the SVG in [`docs/images/`](images/), 1200 px wide, and the PNG beside it is the 2× render.
