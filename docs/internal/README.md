# wpantry: internal docs

For maintainers.

- [Release playbook](release.md): versions, one-time setup, the checklist before a release, the dry run, tagging, verifying a release, ops, and what to do when a release is bad.
- [Publishing to crates.io](crates-io.md): the first publish by hand, step by step, and trusted publishing after it.
- [Dependencies and supply chain](dependencies.md): the pinning rules, bumping a dependency, cargo vet and cargo deny.

Contributor basics (tooling, tests, PRs) are in [CONTRIBUTING.md](../../CONTRIBUTING.md), including the gates a change passes before it merges: rustfmt, clippy, the Rust tests, the contract suite, the shell and workflow lint, the supply-chain audits (above) and the 90% line-coverage gate (`mise run coverage`).
