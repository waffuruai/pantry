# Reports

`wpantry report` writes three logs from the history the cache keeps across scans. Nothing is sent anywhere; the report is a file you keep or hand to an auditor.

| Log | What it answers | Rows |
|---|---|---|
| Exposure (`--exposure`) | What applied to this machine or these repos, from the scan that first saw it to the scan that no longer did, and for how long | One per finding (`kind`, `component`, `location`, `vuln_id`): severity, KEV, the fix version, first seen, last seen, resolved, days exposed. A finding is resolved by a scan of the same scope (machine or repos, the same `--path`s) that no longer lists it; a scan of one repo says nothing about the others |
| Remediation (`--remediation`) | What was done about it | One per unattended fix `--update` ran: when, the command, whether it exited 0, and the scan that re-checked afterwards |
| Audit (`--audit`) | That the checks happened | One per scan (when, host, user, wpantry version, scope, counts, fails, warns) and one per event (`scan`, `fix`) |

`--since DAYS` bounds all three (default 90). `--format md` (default) is Markdown with a summary line (open exposures, resolved, median days to resolve); `--format json` is one document with every section asked for; `--format csv` is the exposure log alone. `-o FILE` writes instead of printing.

## For SOC 2 and incident response

| Control area | Evidence this gives |
|---|---|
| Vulnerability identification (CC7.1) | The audit log: a scan ran on this host on these dates, covering these repos and this machine, with wpantry version N and these policy files |
| Monitoring (CC7.2) | Regular scans (`wpantry schedule`), each with its outcome; the exposure log's first-seen dates |
| Remediation (CC7.4, CC7.5) | The remediation log: the command, when, the result, and the scan that verified the finding gone; the exposure log's days-exposed and median time to resolve |
| Change management (CC8.1) | The remediation log doubles as the record of dependency and tool updates wpantry made unattended; manual steps it printed are in the scan's findings (`export --csv`) |

What it is not: proof that nothing was missed. A source that couldn't be reached is in the findings as `unchecked` and in that scan's `warns`; an exposure resolved because a repo was deleted looks the same as one that was fixed. Keep the report with the context that explains it.

## Retention

The history grows with every scan. `wpantry cache prune` (when available) and deleting the cache file both remove it; copy a report out first when you need it kept.
