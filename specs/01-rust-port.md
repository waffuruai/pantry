---
id: wscanner/rust-port
status: draft
owner: Eric
affected: [wscanner, ops, wsentinel]
tracking: pending
updated: 2026-10-25
---
# wscanner ships as one verifiable Rust binary

## TL;DR

Port wscanner to Rust as a `0.x` crate plus a signed static binary, and replace osv-scanner for lockfiles and Linux package databases (we cannot link a Go binary). Dependencies are minimal and hard-pinned; the [CLI contract](cli-contract.md) is the only stable surface. Today the Python implementation in `python/` works and defines that contract; Python is removed once the Rust binary ships.

## Architecture

```mermaid
flowchart LR
  subgraph before["Before"]
    py["wscanner (Python)"] --> osvs["osv-scanner (Go)"]
    py --> bv["brew vulns"]
    py --> gl["gitleaks"]
    py --> git1["git"]
    osvs --> src1["OSV.dev"]
    py --> src1
    py --> feeds1["CISA KEV, endoflife.date, feeds"]
  end
  subgraph after["After"]
    rs["wscanner (Rust) [new]"]
    rs --> ext["lockfile + OS-db extractors [new]"]
    rs --> cli2["OSV client [changed: ported]"]
    rs --> db2["SQLite cache [changed: same schema]"]
    rs --> bv2["brew vulns [unchanged, external]"]
    rs --> gl2["gitleaks [unchanged, external]"]
    rs -. "images only, until phase 2" .-> osvs2["osv-scanner [optional, then removed]"]
    cli2 --> src2["OSV.dev"]
    rs --> feeds2["CISA KEV, endoflife.date, feeds"]
  end
```

Removed: the Python runtime requirement (phase 3) and osv-scanner as a required tool (phase 1; optional for images until phase 2).

## Terms

| Term | Meaning here |
|---|---|
| OSV | The [OSV.dev](https://osv.dev) advisory database and its API; the main source |
| KEV | CISA's Known Exploited Vulnerabilities list; marks findings exploited in the wild |
| EOL | End of life, from [endoflife.date](https://endoflife.date); a runtime past it fails |
| Ecosystem string | OSV's name for where a package lives: `crates.io`, `npm`, `PyPI`, `Go`, `Debian:12`, `Alpine:v3.20`. A wrong one returns no advisories, not an error |
| Lockfile | A file pinning exact dependency versions (`Cargo.lock`, `pnpm-lock.yaml`, …) |
| querybatch | OSV's `POST /v1/querybatch`: up to 1000 (ecosystem, name, version) queries per request, answered with ids and `modified` times |
| Attestation | GitHub's signed build provenance for a release artifact, checked with `gh attestation verify` |

## What it is

A Rust workspace (`rust/crates/wscanner` library, `rust/crates/wscanner-cli` binary) that does everything `python/` does, behind the same CLI, JSON and cache. In our usage osv-scanner does no local version matching: it sends (ecosystem, name, version) to OSV `querybatch`, exactly like `python/wscanner/osv.py`. So the port is extractors plus the client we already have, not a vulnerability-matching engine. Detail lives in [design/rust-port.md](design/rust-port.md).

**Not:** SAST; reachability analysis; guided remediation; SBOM input; an offline OSV mirror; a gitleaks or `brew vulns` port; Windows (yet).

## Why

wscanner is the foundational security piece for ops, control-plane, wsentinel and wos. A Rust crate lets them embed it instead of shelling out to Python plus a Go binary, and a reproducible, signed static binary is something anyone can verify before running it with access to their whole home directory.

## Why now

The Python tool works and has just been frozen into a contract (schema 1), so there is a reference to diff against. wsentinel is about to depend on it, and the cheapest time to change the runtime is before it has callers. Releasing it open source while the need is fresh gets it reviewed early.

## Acceptance criteria

### Functionality

- F1. Default scope is the whole computer: machine inventory plus every git repo under `$HOME`, found by the walk rules in [cli-contract.md](cli-contract.md#scope-walk); `--path DIR` (repeatable) limits the repo checks; `--no-machine` skips the inventory. Evidence: Python, `python/test_wscanner.py` (`Scope`, `Contract`); Rust, not evidence yet. Issue: pending.
- F2. One contract-test suite runs the binary named by `WSCANNER=` and passes on both implementations: subcommands, flags, exit codes 0/1/2/3, the `check --json` envelope and `Finding` types, `version`, `tools`, `skill`, the cache schema. Evidence: not evidence yet (seed: `python/test_wscanner.py` `Contract`). Issue: pending.
- F3. `check --json` diff between Python and Rust (findings sorted, `impl` and `version` dropped) is empty on the org repos and inside Debian, Alpine and openSUSE containers before osv-scanner leaves `tools`. Evidence: not evidence yet. Issue: pending.
- F4. Lockfile parsers, in this order: `Cargo.lock`, `package-lock.json` v1–v3, `pnpm-lock.yaml` v6/v9, `Package.resolved`, `go.mod`, `uv.lock`; then `requirements*.txt`, `yarn.lock` v1/berry, `bun.lock`, `deno.lock`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`; later `pubspec.lock`, `mix.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json`, `conan.lock`. Each has golden files cut from real lockfiles. Evidence: not evidence yet. Issue: pending.
- F5. `go.mod`'s `go` directive is reported as package `stdlib` in the `Go` ecosystem, as osv-scanner does. Evidence: not evidence yet. Issue: pending.
- F6. OS package databases: `/var/lib/dpkg/status` with binary → source mapping and `Debian:N` / `Ubuntu:X.Y` ecosystems; `/lib/apk/db/installed` with the `o:` origin; rpm via `rpm -qa --qf` on openSUSE and SUSE. dnf distros keep today's dnf-advisory logic and Arch its tracker. Evidence: not evidence yet. Issue: pending.
- F7. An `os-release` → OSV ecosystem-string table, with conformance fixtures taken from osv-scanner's testdata; an unmapped distro is reported `unchecked`, never clean. Evidence: not evidence yet. Issue: pending.
- F8. OSV client: `querybatch` paged at 1000 queries per request with `next_page_token` followed; per-vuln fetch at most 8 in parallel with ETag; a record is refetched only when `modified` changed; aliases grouped into one finding per vulnerability. Evidence: not evidence yet. Issue: pending.
- F9. `fixed_versions` and `pick_safe` behave as in Python, using the Python test vectors. Evidence: not evidence yet. Issue: pending.
- F10. Version comparators for semver, PEP 440, Go, dpkg, apk and rpmvercmp, each tested against its upstream's own vectors. Evidence: not evidence yet. Issue: pending.
- F11. Feeds, KEV, EOL, `brew vulns`, gitleaks, the malicious-package index, harnesses and editors are ported 1:1: the same inputs give the same findings (F3). Evidence: not evidence yet. Issue: pending.
- F12. Container images (phase 2): `docker|podman create` then `export` to a temp directory, scanned by the same extractors; no layer attribution; the container and temp directory are removed even on error. Evidence: not evidence yet. Issue: pending.

### Performance

- P1. A warm run (cache fresh, same day) finishes in under 5 s on a developer Mac. Evidence: not evidence yet. Issue: pending.
- P2. A cold whole-computer run is no slower than Python on the same machine; the walk stays bounded by depth 6 and the prune list (Python baseline, 2026-10-25: the walk of one developer's home took 0.75 s). Evidence: not evidence yet. Issue: pending.
- P3. The static binary is under 15 MB per target. Evidence: not evidence yet. Issue: pending.
- P4. Zero idle CPU: one-shot process, no daemon, no threads left after a command returns. Evidence: not evidence yet. Issue: pending.
- P5. Peak RSS under 100 MB while parsing a 100,000-line lockfile (line-streaming parsers). Evidence: not evidence yet. Issue: pending.

### Security

- S1. Supply chain of the binary: every dependency pinned `=x.y.z`, `Cargo.lock` committed, `rust-toolchain.toml` exact, every build `cargo build --locked`. Evidence: not evidence yet. Issue: pending.
- S2. CI runs `cargo deny` (advisories, crates.io-only sources, license allowlist) and `cargo vet`; either failing blocks the merge. Evidence: not evidence yet. Issue: pending.
- S3. Release profile `lto`, `codegen-units = 1`, `strip`, `--remap-path-prefix`, `SOURCE_DATE_EPOCH`; two builds of one tag are byte-identical. Targets `x86_64` and `aarch64-unknown-linux-musl`, macOS universal. Evidence: not evidence yet. Issue: pending.
- S4. Tampered artifact → each release ships `SHA256SUMS`, a GitHub artifact attestation (`gh attestation verify`) and a cosign keyless bundle. Evidence: not evidence yet. Issue: pending.
- S5. What leaves the machine: (ecosystem, name, version) of what is installed or locked, to OSV, and feed requests, only to the hosts in [design/rust-port.md](design/rust-port.md#network); the developer's email only after opt-in consent. No file contents, paths or secrets are sent. Evidence: not evidence yet. Issue: pending.
- S6. Programs run: as scanners or data sources only `brew`, `gitleaks`, `git`, `rpm`, `docker|podman`; the machine inventory also runs the inventoried tools' own version and listing commands and the OS update tools, as Python does. Always an argument vector, never a shell string. Evidence: not evidence yet. Issue: pending.
- S7. Hostile feed data → bounded parsers: size caps per response, depth caps on JSON, line-length caps on lockfiles and feeds; anything over a cap or malformed is `unchecked`. Evidence: not evidence yet. Issue: pending.
- S8. A missing tool or unreachable source is reported (`MISSING` fails, `unchecked` warns), never "clean". Evidence: Python, `python/test_wscanner.py` (`test_unreachable_feed_raises_instead_of_reporting_clean`, `test_lookup_offline_uses_cached_answers`); Rust, not evidence yet. Issue: pending.

## Phases

| Phase | Scope | Done when | Issue |
|---|---|---|---|
| 0 | Workspace skeleton (`rust/crates/wscanner`, `rust/crates/wscanner-cli`), contract tests (F2), CI gates (S1, S2) | Contract suite runs in CI against Python; the skeleton passes `version`, `tools`, `skill`; gates green | pending |
| 1 | Lockfile (first two groups of F4) and OS-database parity (F5–F10) | F3 diff empty on the org repos and the three containers; osv-scanner dropped from the Rust `tools` list | pending |
| 2 | Machine-inventory parity (F11), deps.dev licenses, remaining lockfiles, images (F12) | Full `check --json` parity on a developer Mac and a Linux host; osv-scanner gone entirely | pending |
| 3 | Signed releases (S3, S4); ops switches to the artifact; Python removed | `gh attestation verify` passes on a release; ops pins it by SHA-256; `python/` deleted | pending |

## Blockers and decisions

- OSV rate limits, and possibly API keys later: one `querybatch` per 1000 queries with backoff; a key would arrive as an additive env var.
- Air-gapped use is unsupported: CI and first runs need egress to `api.osv.dev`; `--offline` is cache only.
- Distro ecosystem-string correctness: a wrong string is a silent "clean", so the F7 fixtures and the F3 container diffs gate removing osv-scanner.
- `brew vulns` output drift: an unexpected shape is reported `unchecked`.
- gitleaks stays an external tool.
- Images lose layer attribution (osv-scanner names the layer; `export` flattens).
- deps.dev license coverage is npm, PyPI, crates.io, Go, Maven, NuGet and RubyGems only; the rest count as unknown licenses.
- The rustls transitive tree is the largest part of the dependency surface; it is reviewed with `cargo vet` and `cargo deny` at every bump.
- Owner decides: TLS roots from `webpki-roots` (pinned, bundled) or the platform verifier (follows the OS trust store, including a `fix-ca-trust.sh` distrust).
- Owner decides: artifact verification on hosts without `gh` auth, either `SHA256SUMS` plus a warning, or require cosign.
- The one-time JSON envelope change (bare findings array → schema 1 envelope) lands with this repo's first release; ops and any other `--json` caller switch at the same time.

| Date | Decision | Why | Who |
|---|---|---|---|
| 2026-10-25 | HTTP and TLS through `ureq` + `rustls`, pinned `=x.y.z` like everything else | The standard library has no HTTP client; rustls keeps the musl build static with no OpenSSL. "rustls is fine, we just want to pin versions" | Eric |
| 2026-10-25 | `rusqlite` with `bundled` and FTS5 | One vendored C file; keeps `search` and a cache file shared with Python | Eric |
| 2026-10-25 | `serde` + `serde_json` without `derive` | JSON is most of the data; no proc-macro tree | Eric |
| 2026-10-25 | Hand-rolled TOML/YAML line subsets (golden files from real lockfiles), per-ecosystem comparators, argument parsing, SHA-256 verification, FNV fingerprints and civil dates | Each is small; a crate each would multiply the audit surface | Eric |
| 2026-10-25 | Dependency allowlist: `serde`, `serde_json`, `rusqlite`, `ureq`, `rustls` and their locked transitives; nothing else | Minimal, reviewable surface | Eric |
| 2026-10-25 | Tag `v0.1.0` after the first `dev` → `main` merge | The Python `__version__` is already 0.1.0 | Eric |
