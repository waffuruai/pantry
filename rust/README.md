# wpantry in Rust

wpantry: a `0.x` library crate and the `wpantry` binary, behind the [CLI contract](../specs/cli-contract.md). It was ported from the Python implementation (`wscanner`), which was removed on 2026-10-28 once the parity runs below showed nothing it reported that this one misses. The plan is [specs/01-rust-port.md](../specs/01-rust-port.md); the detail (extractors, ecosystem strings, comparators, dependencies) is [specs/design/rust-port.md](../specs/design/rust-port.md).

```
rust/
├── rust-toolchain.toml   exact toolchain (S1)
├── Cargo.toml            workspace, pinned dependencies, release profile (S1, S3)
├── Cargo.lock            committed; every build is --locked
├── deny.toml             cargo deny: advisories, sources, licenses (S2)
├── supply-chain/         cargo vet: audits, imports, exemptions (S2)
└── crates/
    ├── wpantry/         library: scope, extractors, OSV client, comparators, feeds, cache, findings
    └── wpantry-cli/     the `wpantry` binary: argument parsing, report, JSON envelope, exit codes
```

## Build and test

```bash
cd rust
cargo build --locked --release         # target/release/wpantry
cargo test --locked                    # unit, golden-file and comparator-vector tests, offline
cargo clippy --locked --all-targets -- -D warnings && cargo fmt --check
cargo deny --locked check && cargo vet --locked   # the supply-chain gates (S2): cargo-deny 0.20.2, cargo-vet 0.10.2

# The contract suite against this binary (from the repo root; `mise run contract` builds first):
WPANTRY=rust/target/release/wpantry python3 -m unittest discover -s tests/contract
```

CI runs all of it on Linux and macOS (`.github/workflows/ci.yml`: `rust`, `rust-supply-chain`; `test` runs the `ca-trust/` scripts and `install.sh`).

## Where the port stands

Phases 0–2 are written: the workspace, the contract suite (passing on both implementations) and the CI gates; every lockfile, OS database and comparator; the machine inventory, licenses and images. What remains is evidence and release work that needs network access or the owner (below).

| Area | State |
|---|---|
| `version`, `tools`, `skill`, `search`, `export`, `breach`, `--update`/`--dryrun`, exit codes | Ported; same output as Python |
| The report and progress | New: a live progress line while scanning, and findings grouped by kind, one line per component with its reason and fix |
| Scope walk (`--path`, `--no-machine`, the default `$HOME` walk) | Ported (F1) |
| Lockfiles: `Cargo.lock`, `package-lock.json` v1–v3, `pnpm-lock.yaml` v5/v6/v9, `Package.resolved`, `go.mod` (+ `stdlib`), `uv.lock`; `requirements*.txt` (with `-r` includes), `yarn.lock` v1/berry, `bun.lock`, `deno.lock` v3–v5, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`; `pubspec.lock`, `mix.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json` v1–v2, `conan.lock` v0.4–v0.5 | Ported, read directly instead of through osv-scanner (all of F4, F5); golden files in `crates/wpantry/tests/lockfiles/` |
| OS packages: dpkg (source packages), apk (origins), rpm on SUSE; `os-release` → OSV ecosystem; dnf advisories; the Arch tracker | Ported (F6, F7) |
| OSV client: querybatch paging, `next_page_token`, 8 parallel record fetches with ETag, alias grouping, daily cache | Ported (F8) |
| `fixed_versions`, `pick_safe`; semver, PEP 440, Go, dpkg, apk, rpmvercmp, RubyGems, Maven and Composer comparators | Ported with the Python and upstream vectors (F9, F10) |
| KEV, endoflife.date, gitleaks, install scripts, project MCP servers, the malicious-package index | Ported |
| The machine inventory: tools and runtimes on PATH and in version managers, pip/npm/cargo/pipx/gem globals, apps, browsers and Electron, macOS updates, Homebrew (`brew vulns`), Docker and running containers' images, editor extensions, harness MCP servers, plugins and skills, the CA trust check, the breach check | Ported (F11); the same 118 components as Python on an Ubuntu host, offline |
| Licenses from deps.dev (`--licenses`, off by default) with SPDX expressions | Ported |
| Container images: `create` + `export`, read by the same extractors | Ported (F12); real-image tests in CI on Linux |

Not done yet, and why:

- **P1, P2**: warm and cold run times on a developer Mac, measured once (below) but not against a target yet.
- **Phase 3**: the first tag runs `.github/workflows/release.yml` (the S3 and S4 evidence for every target); then ops pins the artifact. Each step is the owner's call; the playbook is [docs/internal/release.md](../docs/internal/release.md).

**F3 parity, 2026-10-28.** Python (`wscanner`) and this binary at the same commit, `check --json` with ops' policy files and separate fresh caches, on a developer Mac (16 org repos, 80 apps, 128 Homebrew formulae, local images) and inside Debian 13, Ubuntu 24.04, Alpine 3.22 and openSUSE Leap 15.6 containers (current images and older point releases with fixable advisories: Debian 13.0, Ubuntu 24.04.2, Alpine 3.22.0, Leap 15.5), on arm64 and x86-64. Nothing Python reported was missed. The runs found three bugs, fixed with regression tests: an alias group's fix was the lowest of its records' (Ubuntu's incomplete USN-8477-1 for tar, where the CVE's record needs 0ubuntu0.4); images reported the kernel's source package, present only as headers (2,232 findings on one Debian image); and a license deps.dev calls `non-standard` was counted unknown instead of reported (Remotion's). What still differs is in the list below. On the Mac, cold, wpantry took 713 s beside Python's 476 s (both running at once, sharing the network) and 70 s warm; in the containers both took 9 to 43 s cold and wpantry 1 to 3 s warm.

## Differences from the Python implementation

What a caller moving from `wscanner` sees.


- **The report** groups findings by kind, one line each (`name version (location) - (ID KEV SEVERITY) Description. Fix: …`), then what couldn't be checked; Python prints one block per component. A **progress line** (spinner, current step or file, elapsed time) is drawn on stderr while scanning, only when stderr is a terminal. Neither is part of the contract, which covers `--json`.

- **Ctrl-C** ends the process by the signal instead of exiting 130.
- **Lockfile packages** are read by wpantry, not osv-scanner. Workspace members and local packages (package-lock entries outside `node_modules/`, Cargo packages without a crates.io source, uv's editable and virtual packages, path and `file:` dependencies in the other lockfiles, Composer `path` repositories, private Hex organizations, Conan `@user/channel` recipes) are not sent to OSV, so a local package that shares a name with a published one can't raise a false finding. `requirements*.txt` counts `==` pins only, where osv-scanner also queries the lower bound of a `>=` range; PyPI names from requirements files and `Pipfile.lock` are PEP 503-normalized.
- **The fixed version** a finding recommends is chosen with the ecosystem's own comparator (semver, PEP 440, dpkg, …) where Python uses one generic order; they agree except on versions the generic order gets wrong.
- **An alias group's fix** is the version that repairs every record in it. Python took the lowest of them, so it could recommend an update that leaves the CVE open (glibc on Ubuntu 24.04: 8.6 where the CVE's record needs 8.7).
- **Advisory ids.** Records are grouped by id, aliases and upstream CVE, and a group is named by its bare CVE when a record carries one, else by its first record. The same advisories can carry another name than Python's (`UBUNTU-CVE-…` for `USN-…`, `GHSA-…` for `RUSTSEC-…`), and two advisories Ubuntu shipped in one USN can be two findings with the same fix.
- **OS packages** are reported under their source package and version (dpkg `Source:`, apk origin), the names OSV matches: a binNMU shows `4.9-2` where Python showed the binary's `4.9-2+b1`. The counts in `checked` are source packages too.
- **The CA trust check** is part of the scan: its results are findings (kind `config`) in the JSON, where Python printed them on stderr before the scan.
- **SUSE** hosts are read through `rpm`; Python read no packages there.
- **Container images** leave out the kernel's source package (`linux`, shipped only as `linux-libc-dev` headers): a container runs on the host's kernel. Images whose packages it can't read (rpm-based) are reported unchecked.
- **`vuln_etag:<id>`** meta keys hold the ETags of downloaded OSV records, and **`image-packages:<id>`** runs entries an image's packages (Python's `image:<id>` holds osv-scanner's result in another shape, so Rust neither reads nor writes it). Both are additive cache keys.
- **Missing evidence is never clean.** These differ from Python on purpose, after review on the port's PR; each has a regression test:
  - An OSV answer older than a day that couldn't be refreshed (OSV down, or `--offline`), and an advisory OSV names but can't serve (404, a body that isn't the record), are reported unchecked; the findings they do give still stand. A `querybatch` answer that isn't an object is an error, not "no advisories". (Python reuses the stale answer and drops the missing record silently.)
  - A malicious-package report that can't be fetched (offline, or the fetch fails) is reported unchecked and asked again next run; Python caches a made-up record that matches every version. Every interval of a report counts, in the ecosystem's order.
  - A cached result is reused offline or after a failure only for the same input fingerprint (a changed repo HEAD, Homebrew listing or image doesn't reuse the old answer).
  - A lockfile that isn't the format it's named as (no `lockfileVersion`, no `module` line, …), or that links outside its repo, is reported unchecked instead of read as empty. `npm-shrinkwrap.json` is read, and wins over a `package-lock.json` beside it, as npm does.
  - A CA store openssl can't load is reported unchecked, not "doesn't trust the eMudhra CAs".
  - An advisory whose only fixes are older than the installed version (it came back in a later release) counts as unfixed, not as a fix that would be a downgrade.
  - An image export cut short is an error, not an image with fewer files.
  - pip packages are read from each Python's site-packages metadata (`*.dist-info`, `*.egg-info`), with the interpreter run under `-I -S`, so no `.pth` startup hook runs and a Python without pip is still listed; Python runs `python -m pip list`.
  - A program that leaves a background process holding its output pipes can't hold the scan past its timeout.
- **`tools`** lists `gitleaks`, `git` and `openssl` as required and `brew`, `docker` (or podman) and `rpm` as optional; osv-scanner is not used.

## Dependency rules

- Only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq` and `rustls` (`ring`), plus their locked transitives. Anything else needs a decision in the PRD's log first; `crates/wpantry/tests/pins.rs` enforces the list and the `=x.y.z` pins.
- Every dependency pinned `=x.y.z`, at a release at least two weeks old when pinned unless a security fix needs a newer one (rustls 0.23.46, for the advisories `cargo deny` raised against 0.23.45); `Cargo.lock` committed; builds use `--locked`.
- `cargo deny` and `cargo vet` gate every merge; the rustls tree is reviewed at every bump.
- Parsers, comparators, argument parsing, SHA-256 and civil dates are written here, with golden files and upstream test vectors (`crates/wpantry/tests/vectors/`).
- The default policy files, the distrusted CA certificates and the agent skill live in `crates/wpantry/assets/` so the crate packages on its own; `ca-trust/` reads the certificates from there. Each crate carries a copy of the repository's `LICENSE`, checked by `tests/assets.rs`.
