# Reports

`wpantry report` shows the latest scan; `wpantry report history` (or `exposure`, `remediation`, `audit` alone, or `all` with the findings) shows the three logs the cache keeps across scans, and `wpantry report summary` one page over all of them, in any format (`--md`, `--json`, `--csv`, `--html`, …). Nothing is sent anywhere; the report is a file you keep or hand to an auditor, a CSO or an insurer.

![Every report comes from one cache: the SQLite file's tables (vulns and queries, findings, scans, exposures, fixes, events) feed wpantry scan and its --json, export --csv and --jsonl, report's exposure, remediation and audit logs, search, and the HTML report](../images/reports.png)

[Full size](../images/reports.png) · [SVG source](../images/reports.svg)

| Log | What it answers | Rows |
|---|---|---|
| Exposure (`report exposure`) | What applied to this machine or these repos, from the scan that first saw it to the scan that no longer did, and for how long | One per finding (`kind`, `component`, `location`, `vuln_id`), in the same columns in every format: first seen, resolved (its date, or open), severity, component, version, advisory, KEV, status, the fix version, days exposed, last seen, kind, location. A finding is resolved by a scan of the same scope (machine or repos, the same `--path`s, `--licenses` and policy files) that no longer lists it and that had no source `unchecked`: a scan with a gap resolves nothing, so an outage leaves exposures open rather than closing them; a scan of one repo says nothing about the others |
| Remediation (`report remediation`) | What was done about it | One per fix `wpantry fix`, `mitigate` or `harden` ran: when, who ran it (user and host), the command, whether it exited 0, the exposures it addressed, and the scan that verified it: a complete re-check (no source `unchecked`) in which none of those exposures were still listed. A failed fix, an incomplete re-check, or a finding still present leaves it blank |
| Audit (`report audit`) | That the checks happened | One per scan (when, host, user, wpantry version, scope, counts, fails, warns) and one per event (`scan`, `fix`) |

`--since DAYS` bounds all three (default 14). The HTML report (`wpantry report --html -o report.html`, [usage.md](usage.md)) carries the exposure and remediation logs of the last 14 days too, under its History section, when the cache has any. `--md` is Markdown with a summary line (open exposures, resolved, median days to resolve) and the logs as tables; `--json` is one document; `--csv` is one table per log. `-o FILE` writes instead of printing.

**The summary** (`wpantry report summary`) is the page to hand over: the open findings by severity against the remediation targets of our [security policy](../../SECURITY.md) (Critical 14 days, High 30, Medium 90, Low 180; your own targets: #171), how many are overdue or were fixed late, the median and 90th-percentile time to resolve, the scans that ran (hosts, users, days without one, sources that couldn't be checked), each fix with who ran it and the scan that verified it, and the controls below it is evidence for.

## For SOC 2 and incident response

| Control area | Evidence this gives |
|---|---|
| Vulnerability identification (CC7.1) | The audit log: a scan ran on this host on these dates, covering these repos and this machine, with wpantry version N and these policy files |
| Monitoring (CC7.2) | Regular scans (`wpantry schedule`), each with its outcome; the exposure log's first-seen dates |
| Remediation (CC7.4, CC7.5) | The remediation log: the command, when, the result, and the scan that verified the finding gone; the exposure log's days-exposed and median time to resolve |
| Change management (CC8.1) | The remediation log doubles as the record of dependency and tool updates wpantry made unattended; manual steps it printed are in the scan's findings (`report --csv`) |

What it is not: proof that nothing was missed. A source that couldn't be reached is in the findings as `unchecked` and in that scan's `unchecked` count, and such a scan resolves no exposure and verifies no fix, so an outage shows as open exposures and unverified fixes, never as remediation; an exposure resolved because a repo was deleted looks the same as one that was fixed. Keep the report with the context that explains it.

## Retention

The history grows with every scan. `wpantry cache prune` (when available) and deleting the cache file both remove it; copy a report out first when you need it kept.
