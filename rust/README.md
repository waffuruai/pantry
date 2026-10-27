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

Phases 0–2 are written: the workspace, the contract suite (passing on both implementations) and the CI gates; every lockfile, OS database and comparator; the machine inventory, licenses and images. What remains is evidence and release work that needs network access or the owner (below).

| Area | State |
|---|---|
| `version`, `tools`, `skill`, `search`, `export`, `breach`, `--update`/`--dryrun`, exit codes | Ported; same output as Python |
| The report and progress | New: a live progress line while scanning, and findings grouped by kind, one line per component with its reason and fix |
| Scope walk (`--path`, `--no-machine`, the default `$HOME` walk) | Ported (F1) |
| Lockfiles: `Cargo.lock`, `package-lock.json` v1–v3, `pnpm-lock.yaml` v5/v6/v9, `Package.resolved`, `go.mod` (+ `stdlib`), `uv.lock`; `requirements*.txt` (with `-r` includes), `yarn.lock` v1/berry, `bun.lock`, `deno.lock` v3–v5, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`; `pubspec.lock`, `mix.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json` v1–v2, `conan.lock` v0.4–v0.5 | Ported, read directly instead of through osv-scanner (all of F4, F5); golden files in `crates/wscanner/tests/lockfiles/` |
| OS packages: dpkg (source packages), apk (origins), rpm on SUSE; `os-release` → OSV ecosystem; dnf advisories; the Arch tracker | Ported (F6, F7) |
| OSV client: querybatch paging, `next_page_token`, 8 parallel record fetches with ETag, alias grouping, daily cache | Ported (F8) |
| `fixed_versions`, `pick_safe`; semver, PEP 440, Go, dpkg, apk, rpmvercmp, RubyGems, Maven and Composer comparators | Ported with the Python and upstream vectors (F9, F10) |
| KEV, endoflife.date, gitleaks, install scripts, project MCP servers, the malicious-package index | Ported |
| The machine inventory: tools and runtimes on PATH and in version managers, pip/npm/cargo/pipx/gem globals, apps, browsers and Electron, macOS updates, Homebrew (`brew vulns`), Docker and running containers' images, editor extensions, harness MCP servers, plugins and skills, the CA trust check, the breach check | Ported (F11); the same 118 components as Python on an Ubuntu host, offline |
| Licenses from deps.dev (`--licenses`, off by default) with SPDX expressions | Ported |
| Container images: `create` + `export`, read by the same extractors | Ported (F12); real-image tests in CI on Linux |

Not done yet, and why:

- **F3 parity**: the `check --json` diff against Python on the org repos and in Debian, Alpine and openSUSE containers needs api.osv.dev, which the environment the port was written in couldn't reach. Python stays the reference until that diff is empty.
- **P1, P2**: warm and cold run times on a developer Mac.
- **Phase 3**: the first tag runs `.github/workflows/release.yml` (the S3 and S4 evidence for every target); then ops pins the artifact and `python/` is deleted. Each step is the owner's call; the playbook is [docs/internal/release.md](../docs/internal/release.md).

## Known differences from Python

- **The report** groups findings by kind, one line each (`name version (location) - (ID KEV SEVERITY) Description. Fix: …`), then what couldn't be checked; Python prints one block per component. A **progress line** (spinner, current step or file, elapsed time) is drawn on stderr while scanning, only when stderr is a terminal. Neither is part of the contract, which covers `--json`.

- **Ctrl-C** ends the process by the signal instead of exiting 130.
- **Lockfile packages** are read by wscanner, not osv-scanner. Workspace members and local packages (package-lock entries outside `node_modules/`, Cargo packages without a crates.io source, uv's editable and virtual packages, path and `file:` dependencies in the other lockfiles, Composer `path` repositories, private Hex organizations, Conan `@user/channel` recipes) are not sent to OSV, so a local package that shares a name with a published one can't raise a false finding. `requirements*.txt` counts `==` pins only, where osv-scanner also queries the lower bound of a `>=` range; PyPI names from requirements files and `Pipfile.lock` are PEP 503-normalized.
- **The fixed version** a finding recommends is chosen with the ecosystem's own comparator (semver, PEP 440, dpkg, …) where Python uses one generic order; they agree except on versions the generic order gets wrong.
- **`vuln_etag:<id>`** meta keys hold the ETags of downloaded OSV records (an additive cache key).
- **`tools`** lists `gitleaks`, `git` and `openssl` as required and `brew`, `docker` (or podman) and `rpm` as optional; osv-scanner is not used.

## Dependency rules

- Only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq` and `rustls` (`ring`), plus their locked transitives. Anything else needs a decision in the PRD's log first; `crates/wscanner/tests/pins.rs` enforces the list and the `=x.y.z` pins.
- Every dependency pinned `=x.y.z`, at a release at least two weeks old when pinned unless a security fix needs a newer one (rustls 0.23.46, for the advisories `cargo deny` raised against 0.23.45); `Cargo.lock` committed; builds use `--locked`.
- `cargo deny` and `cargo vet` gate every merge; the rustls tree is reviewed at every bump.
- Parsers, comparators, argument parsing, SHA-256 and civil dates are written here, with golden files and upstream test vectors (`crates/wscanner/tests/vectors/`).
- The agent skill and the default policy files are copied into `crates/wscanner/assets/` so the crate packages on its own; `tests/assets.rs` fails when they drift from `python/`, and phase 3 makes `assets/` the only copy.
