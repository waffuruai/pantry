# wpantry in Rust

The `wpantry` library crate and the `wpantry` binary (`wpantry-cli`), behind the [CLI contract](../specs/cli-contract.md). How it works is [docs/architecture.md](../docs/architecture.md); what it checks and which sources it asks is [docs/public/checks-and-sources.md](../docs/public/checks-and-sources.md); the dependency rules are [docs/internal/dependencies.md](../docs/internal/dependencies.md). This page maps the source.

```
rust/
├── rust-toolchain.toml   the exact toolchain every build uses
├── Cargo.toml            workspace, pinned dependencies, release profile
├── Cargo.lock            committed; every build is --locked
├── deny.toml             cargo deny: advisories, sources, licenses
├── supply-chain/         cargo vet: audits, imports, exemptions
└── crates/
    ├── wpantry/          library: scope, readers, sources, judgement, cache, findings
    └── wpantry-cli/      the `wpantry` binary: arguments, report, JSON envelope, exit codes
```

## Build and test

```bash
cd rust
cargo build --locked --release         # target/release/wpantry
cargo test --locked                    # unit, golden-file and comparator-vector tests, offline
cargo clippy --locked --all-targets -- -D warnings && cargo fmt --check
cargo deny --locked check && cargo vet --locked   # the supply-chain gates

# The contract suite against this binary (from the repo root; `mise run contract` builds first):
WPANTRY=rust/target/release/wpantry python3 -m unittest discover -s tests/contract
```

CI runs all of it on Linux and macOS (`.github/workflows/ci.yml`: `rust`, `rust-supply-chain`; `test` runs the `ca-trust/` scripts and `install.sh`).

## The library, `crates/wpantry/src`

| Role | Modules |
|---|---|
| The scan | `check` (findings, counts, status, "not checked"; the policy files), `check_supply` (every repo: lockfiles, secrets, malicious packages, install scripts, MCP servers, licenses, images), `check_machine` (the machine: inventory, updates, trust stores, posture, the breach check) |
| Scope and inventory | `repos` (the bounded walk, repo discovery), `tools` (PATH and version managers), `catalog` (the tool catalog: names, version commands, EOL products), `packages` (Pythons with their site-packages, npm, cargo, pipx, gem globals), `apps` (apps, browsers, Electron, pending OS updates, Docker), `editors` (extensions), `harnesses` (coding agents' MCP servers, plugins, skills), `images` (container create/export and a bounded tar reader), `posture/` (security settings, one file per OS) |
| Readers | `lockfiles/` (one file per format, `mod.rs` dispatches by name), `osdb` (dpkg, apk, rpm; `os-release` → OSV ecosystem), `distros` (dnf advisories, the Arch tracker), `plist`, `json` (bounded parse, `json.dumps`-exact output), `re` (the regex subset the feeds need), `sha256` |
| Sources | `net` (the `Net` trait, the `ureq` client, the recording fake), `osv` (querybatch, record fetches, alias groups, upstream release tags), `feeds` (KEV, end-of-life, the cask catalog, browser and PostgreSQL feeds, extension lists, GitHub latest releases), `malicious` (the OpenSSF index), `licenses` (deps.dev), `breach` (Have I Been Pwned, XposedOrNot) |
| Judgement | `versions` (fixed versions, the safe one, the generic order), `compare/` (semver, PEP 440, Go, dpkg, apk, rpm, RubyGems, Maven, Packagist) |
| External tools | `external` (the tools wpantry uses and `tools`' answer), `leaks` (gitleaks), `scanners` (`brew vulns`), `catrust` (the trust stores through `openssl`), `system` (`exec` with a timeout, `par_map`, `which`, globbing, temp directories) |
| Cache | `db` (the SQLite file: tables, memo with fingerprints, FTS5 search, export) |
| Plumbing | `lib` (the public surface and defaults), `error` |

Tests sit beside the code they cover; golden lockfiles are in `crates/wpantry/tests/lockfiles/` (its README lists them), upstream comparator vectors in `crates/wpantry/tests/vectors/`, and `tests/scan.rs`, `tests/image.rs`, `tests/pins.rs` and `tests/assets.rs` are the end-to-end, real-image, dependency-pin and packaging checks.

The default policy files, the distrusted CA certificates and the agent skill live in `crates/wpantry/assets/` so the crate packages on its own; `ca-trust/` reads the certificates from there. Each crate carries a copy of the repository's `LICENSE`, checked by `tests/assets.rs`.

## The binary, `crates/wpantry-cli/src`

| Module | Does |
|---|---|
| `main` | The subcommands (`check`, `search`, `export`, `breach`, `tools`, `skill`, `version`), the exit codes, the `--update` flow |
| `args` | Argument parsing, by hand |
| `report` | The grouped report, the fix plan and its shell quoting, the JSON envelope |
| `progress` | The live progress line, drawn only on a terminal |
| `style` | Colour, off for pipes, files, `--json` and `NO_COLOR` |
