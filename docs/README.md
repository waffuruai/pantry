# wpantry docs

| Folder | For | Pages |
|---|---|---|
| [architecture.md](architecture.md) | Anyone who wants to know how it works | The picture, and a run in five steps |
| [public/](public/) | Anyone installing or running wpantry | [Install and verify](public/install.md), [Use](public/usage.md), [What it checks and its sources](public/checks-and-sources.md), [The machine's settings](public/posture.md), [Reports](public/reports.md), [Suspicious code](public/suspect-code.md), [Documents and images](public/documents.md) |
| [internal/](internal/) | wpantry maintainers | [How it is put together, in detail](internal/architecture.md), [Release playbook](internal/release.md), [Publishing to crates.io](internal/crates-io.md), [Dependencies and supply chain](internal/dependencies.md) |

The stable interface (CLI, exit codes, JSON, cache) is [specs/cli-contract.md](../specs/cli-contract.md); the archived plans and their decisions are in [specs/](../specs/). Diagrams: SVG sources in [images/](images/) (1200 px wide, the Waffuru design language), each with its 2× PNG rendered by `ops/scripts/render-diagram.sh`.
