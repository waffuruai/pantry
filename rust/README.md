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
(cd .. && mise run coverage --html)               # the 90% line-coverage gate: both suites, one instrumented build

# The contract suite against this binary (from the repo root; `mise run contract` builds first):
WPANTRY=rust/target/release/wpantry python3 -m unittest discover -s tests/contract
```

CI runs all of it on Linux and macOS (`.github/workflows/ci.yml`: `rust`, `rust-supply-chain`; `coverage` on Linux, with the HTML report as its artifact; `test` runs the `ca-trust/` scripts and `install.sh`).

## The library, `crates/wpantry/src`

Grouped by what the code does ([specs/design/source-layout.md](../specs/design/source-layout.md) has the rules and the target tree):

| Folder | Holds |
|---|---|
| `src/` | What wpantry is: `lib` (the public surface and defaults), `error`, `finding`, `component`, `db` (the SQLite cache: tables, memo with fingerprints, FTS5 search), `history`, `selfinstall`, `sync`, `watch`, `guard` (the clipboard guard), `external` (the tools wpantry uses). For now also `osv`, `distros` and `feeds` (moving to `sources/`), and `export` and `mitigate` (moving to `reporters/` and `remediation/`) |
| `checks/` | The scan: `mod.rs` (options, findings, counts, "not checked", the policy files) and one folder per area |
| `checks/machine/` | The machine: inventory (`tools`, `catalog`, `packages`, `apps`, `editors`, `harnesses`, `images`, `os_packages`), Homebrew (`cellar`, `brew_vulns`), the trust stores (`ca_trust`) and clipboard hijackers (`clipper`) |
| `checks/supply_chain/` | Every repo: discovery (`repos`), `hooks`, `install_scripts`, `typosquat`, `malicious` (the OpenSSF index), `licenses` (deps.dev), `leaks` (gitleaks), `mptcp` (Go servers exposed to CVE-2026-98432) |
| `checks/lockfiles/` | One reader per lockfile format; `mod.rs` dispatches by name |
| `checks/package_managers/` | Version order per ecosystem (semver, PyPI, Go, dpkg, apk, rpm, RubyGems, Maven, Packagist) and the generic order in `versions` |
| `checks/posture/` | Security settings: `any/`, `macos/` and `linux/`, one file per behaviour, persistence included |
| `checks/documents/`, `checks/suspect/`, `checks/hidden.rs` | Office, PDF, RTF, SVG and image readers; suspect code, one file per behaviour; hidden Unicode |
| `checks/malware/` | The YARA pass (`mod.rs`), `indicators` (IOC lists and hash lookups), `rulegen` (the goodware database for `rules gen`) |
| `checks/email.rs` | The opt-in breach check of the user's email address (Have I Been Pwned, XposedOrNot) |
| `utils/` | What everything leans on: `files`, `process`, `os`, `parallel`, `temp`, `homebrew`, `net` (the `Net` trait and the host allowlist), `walk` (the bounded repo walk), and the in-tree readers: `json`, `toml`, `plist`, `re`, `sha256`, `archive/` (zip, deflate), `addresses` |

Tests sit beside the code they cover; golden lockfiles are in `crates/wpantry/tests/lockfiles/` (its README lists them), upstream comparator vectors in `crates/wpantry/tests/vectors/`, and `tests/scan.rs`, `tests/image.rs`, `tests/pins.rs` and `tests/assets.rs` are the end-to-end, real-image, dependency-pin and packaging checks.

The default policy files, the distrusted CA certificates and the agent skill live in `crates/wpantry/assets/` so the crate packages on its own; `ca-trust/` reads the certificates from there. Each crate carries a copy of the repository's `LICENSE`, checked by `tests/assets.rs`.

**HTML reports.** `wpantry scan --html report.html` writes an optional standalone browser report, alongside normal terminal output or `--json`. See [the HTML spec](../specs/02-html-report.md).

## The binary, `crates/wpantry-cli/src`

| Module | Does |
|---|---|
| `main` | The subcommands (`scan` and its alias `check`, `fix`, `search`, `export`, `breach`, `tools`, `skill`, `version`, …), the exit codes, the `fix` flow |
| `args` | Argument parsing, by hand |
| `report` | The grouped report, the fix plan and its shell quoting, the JSON envelope |
| `progress` | The live progress line, drawn only on a terminal |
| `style` | Colour, off for pipes, files, `--json` and `NO_COLOR` |
