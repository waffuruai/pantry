# Pantry: public docs

- [How it works](architecture.md): the picture, a run in five steps, and how it is put together: readers, comparators, the cache, the binary, the tests.
- [Install and verify](install.md): download a release and check its checksum, attestation and signature; or install from crates.io or source.
- [Use](usage.md): quick start, scope, the report, exit codes, fixing, JSON, options, the cache, troubleshooting.
- [What it checks and its sources](checks-and-sources.md): every check, every source and what is sent, what runs locally.
- [The machine's settings](posture.md): every posture check with its CIS id, severity and fix.
- [Reports](reports.md): the exposure, remediation and audit logs, and the summary.
- [Suspicious code](suspect-code.md): the source-level checks and their policy file.
- [Documents and images](documents.md): PDF, Office, RTF and image checks.
- [Malware rules](malware-rules.md): the YARA rules and how to add your own.

The interface every implementation keeps: the [CLI contract](../../specs/cli-contract.md).
