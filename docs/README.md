# Pantry docs

| Folder | For | Pages |
|---|---|---|
| [public/](public/) | Installing, running or understanding Pantry | [How it works](public/architecture.md), [Install and verify](public/install.md), [Use](public/usage.md), [What it checks and its sources](public/checks-and-sources.md), [The machine's settings](public/posture.md), [Reports](public/reports.md), [Suspicious code](public/suspect-code.md), [Documents and images](public/documents.md), [Malware](public/malware.md) |
| [internal/](internal/) | Maintainers | [Release playbook](internal/release.md), [Publishing to crates.io](internal/crates-io.md), [Dependencies and supply chain](internal/dependencies.md) |

- Stable interface (CLI, exit codes, JSON, cache): [specs/cli-contract.md](../specs/cli-contract.md).
- Archived plans and decisions: [specs/](../specs/).
- Diagrams: SVG sources in [images/](images/), 1200 px wide, in the Waffuru design language; each has a 2× PNG rendered by `ops/scripts/render-diagram.sh`.
