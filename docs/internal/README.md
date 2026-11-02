# wpantry: internal docs

For maintainers.

- [How it is put together, in detail](architecture.md): the readers and golden files, comparators, the cache, the binary, the tests, and what the Rust port left open and where it closed.
- [Release playbook](release.md): versions, one-time setup, the checklist before a release, the dry run, tagging, verifying a release, ops, and what to do when a release is bad.
- [Publishing to crates.io](crates-io.md): the first publish by hand, step by step, and trusted publishing after it.
- [Dependencies and supply chain](dependencies.md): the pinning rules, bumping a dependency, cargo vet and cargo deny.

Contributor basics (tooling, tests, PRs) are in [CONTRIBUTING.md](../../CONTRIBUTING.md).
