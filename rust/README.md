# wscanner in Rust

The Rust port of wscanner: a `0.x` library crate and the `wscanner` binary, behind the same [CLI contract](../specs/cli-contract.md) as [`python/`](../python/), which stays the reference implementation until this one ships. The plan is [specs/01-rust-port.md](../specs/01-rust-port.md); the detail (extractors, ecosystem strings, comparators, dependencies) is [specs/design/rust-port.md](../specs/design/rust-port.md).

```
rust/
├── rust-toolchain.toml   exact toolchain (S1)
├── Cargo.toml            workspace, pinned dependencies, release profile (S1, S3)
├── Cargo.lock            committed; every build is --locked
├── deny.toml             cargo deny: advisories, sources, licenses (S2)
├── supply-chain/         cargo vet: audits, imports, exemptions (S2)
└── crates/
    ├── wscanner/         library: scope, extractors, OSV client, comparators, feeds, cache, findings
    └── wscanner-cli/     the `wscanner` binary: argument parsing, report, JSON envelope, exit codes
```

## Build and test

```bash
cd rust
cargo build --locked --release         # target/release/wscanner
cargo test --locked                    # unit, golden-file and comparator-vector tests, offline
cargo clippy --locked --all-targets -- -D warnings && cargo fmt --check
cargo deny --locked check && cargo vet --locked   # the supply-chain gates (S2): cargo-deny 0.20.2, cargo-vet 0.10.2

# The contract suite, against this binary or the Python one (from the repo root):
WSCANNER=rust/target/release/wscanner python3 -m unittest discover -s tests/contract
WSCANNER=python/bin/wscanner mise run contract
```

CI runs all of it on Linux and macOS (`.github/workflows/ci.yml`: `rust`, `contract-python`, `rust-supply-chain`).

## Where the port stands

Phase 0 is done: the workspace, the contract suite (passing on both implementations), and the CI gates. Phase 1 is mostly in:

| Area | State |
|---|---|
| `version`, `tools`, `skill`, `search`, `export`, `breach`, the report, `--update`/`--dryrun`, exit codes | Ported; same output as Python |
| Scope walk (`--path`, `--no-machine`, the default `$HOME` walk) | Ported (F1) |
| Lockfiles: `Cargo.lock`, `package-lock.json` v1–v3, `pnpm-lock.yaml` v5/v6/v9, `Package.resolved`, `go.mod` (+ `stdlib`), `uv.lock` | Ported, read directly instead of through osv-scanner (F4 first group, F5); golden files in `crates/wscanner/tests/lockfiles/` |
| OS packages: dpkg (source packages), apk (origins), rpm on SUSE; `os-release` → OSV ecosystem; dnf advisories; the Arch tracker | Ported (F6, F7) |
| OSV client: querybatch paging, `next_page_token`, 8 parallel record fetches with ETag, alias grouping, daily cache | Ported (F8) |
| `fixed_versions`, `pick_safe`; semver, PEP 440, Go, dpkg, apk, rpmvercmp comparators | Ported with the Python and upstream vectors (F9, F10) |
| KEV, endoflife.date, gitleaks, install scripts, project MCP servers, the malicious-package index | Ported |
| The rest of F4 (`requirements*.txt`, `yarn.lock`, `bun.lock`, `deno.lock`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`, then the third group) | Not yet: reported `unchecked` with the files' names |
| Licenses (deps.dev), container images, and the machine inventory beyond OS packages (tools and runtimes, apps, browsers, macOS updates, Homebrew, editors, harness configs, running containers, CA trust, breach check) | Phase 2: reported `unchecked`, never clean |

So a Rust run today is honest but narrower than a Python run: everything it doesn't check yet shows up under "not checked" and makes the report say "Incomplete". Use `python/bin/wscanner` for full coverage until phase 2.

## Known differences from Python

- **Ctrl-C** ends the process by the signal instead of exiting 130.
- **Lockfile packages** are read by wscanner, not osv-scanner. Workspace members (package-lock entries outside `node_modules/`, Cargo packages without a crates.io source, uv's editable and virtual packages) are not sent to OSV, so a local package that shares a name with a published one can't raise a false finding.
- **The fixed version** a finding recommends is chosen with the ecosystem's own comparator (semver, PEP 440, dpkg, …) where Python uses one generic order; they agree except on versions the generic order gets wrong.
- **`vuln_etag:<id>`** meta keys hold the ETags of downloaded OSV records (an additive cache key).
- **`tools`** lists `gitleaks` and `git` as required and `rpm` and `docker` as optional; osv-scanner and openssl are not used.

## Dependency rules

- Only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq` and `rustls` (`ring`), plus their locked transitives. Anything else needs a decision in the PRD's log first; `crates/wscanner/tests/pins.rs` enforces the list and the `=x.y.z` pins.
- Every dependency pinned `=x.y.z`, at a release at least two weeks old when pinned unless a security fix needs a newer one (rustls 0.23.46, for the advisories `cargo deny` raised against 0.23.45); `Cargo.lock` committed; builds use `--locked`.
- `cargo deny` and `cargo vet` gate every merge; the rustls tree is reviewed at every bump.
- Parsers, comparators, argument parsing, SHA-256 and civil dates are written here, with golden files and upstream test vectors (`crates/wscanner/tests/vectors/`).
- The agent skill and the default policy files are read from `python/` at build time until phase 3 moves them.
