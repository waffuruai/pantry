# Reports

| Command | Shows |
|---|---|
| `wpantry report` | The latest scan |
| `wpantry report history` | The three logs the cache keeps across scans |
| `wpantry report exposure`, `remediation`, `audit` | One log |
| `wpantry report all` | The logs with the findings |
| `wpantry report summary` | One page over all of them |

In the terminal, Markdown and HTML reports, a dependency at one version is one row across every lockfile that locks it (`and 8 more`); JSON and CSV keep a finding per lockfile.

Any format: `--md`, `--json`, `--csv`, `--html`, …. Nothing is sent anywhere; the report is a file you keep or hand to an auditor, a CSO or an insurer.

![Every report comes from one cache: the SQLite file's tables (vulns and queries, findings, scans, exposures, fixes, events) feed wpantry scan and fix, wpantry report (the findings in the terminal or as JSON, JSON Lines, CSV, Markdown or HTML), report history and its exposure, remediation and audit logs, report summary, the HTML report, and search](../images/reports.png)

[Full size](../images/reports.png) · [SVG source](../images/reports.svg)

| Log | Answers | Rows |
|---|---|---|
| Exposure (`report exposure`) | What applied to this machine or these repos, from the scan that first saw it to the scan that no longer did, and for how long | One per finding (`kind`, `component`, `location`, `vuln_id`), same columns in every format: first seen, resolved (date, or open), severity, component, version, advisory, CVSS, EPSS, KEV, status, fix version, days exposed, last seen, kind, location |
| Remediation (`report remediation`) | What was done about it | One per fix `wpantry fix` ran (all, or one with `fix ID`): when, who (user and host), the command, whether it exited 0, the exposures it addressed, and the scan that verified it |
| Audit (`report audit`) | That the checks happened | One per scan (when, host, user, Pantry version, scope, counts, fails, warns) and one per event (`scan`, `fix`) |

**When an exposure is resolved:** a later scan of the same scope (machine or repos, same `--path`s, `--licenses` and policy files) no longer lists it, and no source in that scan was `unchecked`.

- A scan with a gap resolves nothing: an outage leaves exposures open.
- A scan of one repo says nothing about the others.

**When a fix is verified:** a complete re-check (no source `unchecked`) lists none of the exposures it addressed. A failed fix, an incomplete re-check or a finding still present leaves it blank.

## Options and output

- `--since DAYS` bounds all three logs (default 14).
- `--md`: a summary line (open exposures, resolved, median days to resolve) and the logs as tables. `--json`: one document. `--csv`: one table per log.
- The HTML report (`wpantry report --html`, [usage.md](usage.md)) carries the last 14 days of exposure and remediation logs under History, when the cache has any.
- `-o FILE` names the file. Without it:
  - stdout is a terminal: written to `pantry_report_<when>.<ext>` in the current directory (such as `pantry_report_20261105T143000Z.html`, UTC);
  - stdout is a pipe or file (an agent, `| jq`, `> out.json`): written to stdout;
  - `-o -` sends it to stdout on a terminal too.

## The summary

`wpantry report summary` is the page to hand over:

- open findings by severity against the remediation targets of our [security policy](../../SECURITY.md): Critical 14 days, High 30, Medium 90, Low 180 (your own targets: #171);
- how many are overdue or were fixed late;
- open findings known exploited (CISA KEV) or likely to be (EPSS 10% or more);
- median and 90th-percentile time to resolve;
- the scans that ran: hosts, users, days without one, sources that couldn't be checked;
- each fix, who ran it and the scan that verified it;
- the controls below it is evidence for.

## For SOC 2 and incident response

| Control area | Evidence |
|---|---|
| Vulnerability identification (CC7.1) | The audit log: a scan ran on this host on these dates, covering these repos and this machine, with Pantry version N and these policy files |
| Monitoring (CC7.2) | Regular scans (`wpantry schedule`), each with its outcome; the exposure log's first-seen dates |
| Remediation (CC7.4, CC7.5) | The remediation log: the command, when, the result, and the scan that verified the finding gone; the exposure log's days exposed and median time to resolve |
| Change management (CC8.1) | The remediation log records the dependency and tool updates Pantry made unattended; manual steps it printed are in the scan's findings (`report --csv`) |

It is not proof that nothing was missed:

- An unreachable source is in the findings as `unchecked` and in that scan's `unchecked` count. Such a scan resolves no exposure and verifies no fix, so an outage shows as open exposures and unverified fixes, never as remediation.
- An exposure resolved because a repo was deleted looks the same as one that was fixed.

Keep the report with the context that explains it.

## Retention

The history grows with every scan. `wpantry cache prune` keeps it (it drops unused advisories, version queries and cached runs); deleting the cache file removes it. Copy a report out first when you need it kept.
