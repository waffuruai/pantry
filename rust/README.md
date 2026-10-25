# wscanner in Rust

Not started. The plan is [specs/01-rust-port.md](../specs/01-rust-port.md), with detail in [specs/design/rust-port.md](../specs/design/rust-port.md). Until it ships, [`python/`](../python/) is the implementation and [specs/cli-contract.md](../specs/cli-contract.md) is the contract this one must match.

Intended layout:

```
rust/
├── rust-toolchain.toml   exact toolchain
├── Cargo.toml            workspace and release profile
├── Cargo.lock            committed
└── crates/
    ├── wscanner/         library (0.x): scope, extractors, OSV client, comparators, feeds, cache
    └── wscanner-cli/     the `wscanner` binary
```

Dependency rules:

- Only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq` and `rustls`, plus their locked transitives. Anything else needs a decision in the PRD's log first.
- Every dependency pinned `=x.y.z`; `Cargo.lock` committed; builds use `--locked`.
- `cargo deny` and `cargo vet` gate every merge; the rustls tree is reviewed at every bump.
- Parsers, comparators, argument parsing and hashing are written here, with golden files and upstream test vectors.
