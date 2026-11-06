# Pantry in Rust

The crates behind the `wpantry` binary and the [CLI contract](../specs/cli-contract.md). How it works: [architecture](../docs/architecture.md). Dependency rules: [dependencies](../docs/internal/dependencies.md).

```
rust/
├── rust-toolchain.toml   the exact toolchain every build uses
├── Cargo.toml            workspace, pinned dependencies, release profile
├── Cargo.lock            committed; every build is --locked
├── deny.toml             cargo deny: advisories, sources, licenses
├── supply-chain/         cargo vet: audits, imports, exemptions
├── release/              build.sh, install.sh and its test
└── crates/
    ├── wcli/             command-line parsing after commander.js
    ├── wpantry/          the library: inventory, sources, checks, cache, reports, fixes
    ├── wpantry-cli/      the `wpantry` binary
    └── wpantry-yara/     the YARA rule engine
```

## Entrypoints

Each crate follows Cargo's layout: a library's root is `src/lib.rs`, a binary's `src/main.rs`.

| Crate | Kind | Entrypoint | Start reading at |
|---|---|---|---|
| `wpantry` | library | `crates/wpantry/src/lib.rs` | `checks::Scan::run` (a scan), `reporters::render` (a report), `remediation::apply` (fixes) |
| `wpantry-cli` | binary `wpantry` | `crates/wpantry-cli/src/main.rs` | `main` → `args::parse` → `dispatch` |
| `wpantry-yara` | library | `crates/wpantry-yara/src/lib.rs` | `Compiler` → `Rules::scan` |
| `wcli` | library | `crates/wcli/src/lib.rs` | `Command::parse` ([its README](crates/wcli/README.md)) |

The binary is its own crate so the library carries no CLI code; the package is `wpantry-cli` because crates.io names must be unique, and its binary is `wpantry`.

## Build and test

```bash
cd rust
cargo build --locked --release                          # target/release/wpantry
cargo test --locked                                     # every test, offline
cargo clippy --locked --all-targets -- -D warnings && cargo fmt --check
cargo deny --locked check && cargo vet --locked         # supply-chain gates
(cd .. && mise run coverage)                            # the 90% line-coverage gate
```

CI runs all of it on Linux and macOS (`.github/workflows/ci.yml`).

## The library, `crates/wpantry/src`

Grouped by what the code does ([specs/design/source-layout.md](../specs/design/source-layout.md) has the rules and the target tree):

| Folder | Holds |
|---|---|
| `src/` | The crate root: `lib` (the public surface and defaults), `error`, `finding`, `component`, `db` (the SQLite cache: tables, memo with fingerprints, FTS5 search), `history`, `selfinstall`, `sync`, `watch`, `external` (the tools Pantry runs). |
| `sources/` | Where the data comes from: `file` (the sources file, `assets/defaults/sources.toml`, and the user's merged over it), `fetch` (every request through it: its cap, refresh, pin, and each outcome kept for `wpantry sources`), `user` (the user's own sources, asked about once), and one file per remote API or list, each cached and `Offline` (never clean) when unreachable with nothing cached: `osv`, `kev`, `epss`, `cve_scores` (a CVSS score for a CVE whose advisories have none: OSV's record, then CVE.org's), `endoflife`, `releases`, `extensions`, `distros`, `malicious_packages`, `package_licenses`, `breaches`, `indicator_lists`, `hash_lookups`; and `indicator_store` (every hash, host, address and URL the lists name, looked up by key) |
| `checks/` | The scan: `mod.rs` (options, findings, counts, "not checked", the policy files) and one folder per area |
| `checks/machine/` | The machine: inventory (`tools`, `catalog`, `packages`, `apps`, `editors`, `harnesses`, `images`, `os_packages`), Homebrew (`cellar`, `brew_vulns`), the trust stores (`ca_trust`), clipboard hijackers (`clipper`), and its security settings: `settings` (the checks' types and runner) over `any/`, `macos/` and `linux/`, one file per behaviour, persistence included |
| `checks/supply_chain/` | Every repo: discovery (`repos`), `hooks`, `install_scripts`, `typosquat`, `malicious` (known malicious packages), `licenses` (the SPDX allowlist), `leaks` (gitleaks), `mptcp` (Go servers exposed to CVE-2026-98432) |
| `checks/lockfiles/` | One reader per lockfile format; `mod.rs` dispatches by name |
| `checks/ecosystems/` | One `Ecosystem` table (OSV's name, version order, deps.dev's system, the OpenSSF directory, name normalisation), and the version order per ecosystem (semver, PyPI, Go, dpkg, apk, rpm, RubyGems, Maven, Packagist) with the generic order in `versions` |
| `checks/documents/`, `checks/suspects/`, `checks/hidden/` | Office, PDF, RTF, SVG and image readers; suspect code, one file per behaviour; hidden Unicode |
| `checks/files/` | The files pass every content check shares: one walk per root, a `FileView` per file (stat once, open once), each check's plan, per-file step and finish (`pass`), and the per-file cache, one record per root (`cache`) |
| `checks/malware/` | The YARA scan: `mod.rs` (the rules prepared before the files are read, and the pass), `targets` (what it reads, as files-pass jobs), `yara` (the rules, and what they find in one file), `verdict` (the finding and the hash lookups), `observe` (a file's hashes and the hosts, addresses and URLs it names, kept in the files cache), `indicators` (those looked up in the indicator store; the file-name patterns), `rulegen` (the goodware database for `rules gen`) |
| `checks/severity.rs` | Every finding's severity on CVSS's scale, its CVSS score (from its record or its aliases') and its EPSS score, set once the checks have run; Pantry's own checks rated from one table |
| `checks/email.rs` | The opt-in breach check of the user's email address: consent and which addresses |
| `reporters/` | How a scan is shown, always from the cache (`mod.rs`: `latest`, `render`, the output file): `view` (the grouping every report shares: areas, rows, the update plan's batches), `json` (the `--json` envelope), `jsonl`, `csv`, `md`, `html` (the standalone page; its template and fonts are `assets/report/`) and `yara` (a generated rule's text) |
| `remediation/` | Fixing: `mod.rs` (the update plan, its steps and shell quoting, `wpantry fix` applying it), `mitigate` (the fixes Pantry makes itself: `fix ca-trust`, `fix extension-cooldown`, the stopgaps while a fix is pending), `ca_trust` and `editors` (`fix ca-trust` and `fix extension-cooldown`) |
| `utils/` | What everything leans on: `files`, `dates`, `process`, `os`, `parallel`, `temp`, `homebrew`, `net` (the `Net` trait and the host allowlist), `walk` (the bounded repo walk), and the in-tree readers: `json`, `toml`, `plist`, `re`, `sha256`, `archive/` (zip, deflate), `addresses`, `cvss` (CVSS 3.x and 4.0 base scores from vectors, and the scale's words) |

Tests sit beside the code they cover; golden lockfiles are in `crates/wpantry/tests/lockfiles/` (its README lists them), upstream comparator vectors in `crates/wpantry/tests/vectors/`, and `tests/scan.rs`, `tests/image.rs`, `tests/pins.rs` and `tests/assets.rs` are the end-to-end, real-image, dependency-pin and packaging checks.

The default policy and data files (TOML), the distrusted CA certificates, the HTML report template and the agent skill live in `crates/wpantry/assets/`, so the crate packages on its own. Each crate carries a copy of the repository's `LICENSE`, checked by `tests/assets.rs`.

## The binary, `crates/wpantry-cli/src`

| Module | Does |
|---|---|
| `main` | The commands (`scan`, `fix`, `report`, `search`, `breach`, `tools`, `skill`, `version`, …), the exit codes, the `fix` flow, where a report is written |
| `args` | The command line, declared once with `wcli`: every command, option and argument with its help; parsed into a `Command` |
| `progress` | The live progress line, drawn only on a terminal |
| `style` | Colour, off for pipes, files, `--json` and `NO_COLOR` |
| `tui` | The terminal report: the shared grouping (`reporters::view`) as a heading and table per area, sized to the terminal, lines as spans with roles that `style` colours |
