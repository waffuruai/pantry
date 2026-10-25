# Rust port: design detail

Detail for [01-rust-port.md](../01-rust-port.md). The PRD holds the criteria; this page holds the tables they point at. Status: draft, 2026-10-25. Everything here is proposed until its criterion has evidence.

## Workspace

```
rust/
├── rust-toolchain.toml        exact toolchain (S1)
├── Cargo.toml                 workspace; release profile (S3)
├── Cargo.lock                 committed
├── deny.toml                  advisories, sources, licenses (S2)
├── supply-chain/              cargo vet audits (S2)
└── crates/
    ├── wscanner/              library: scope, extractors, OSV client, comparators, feeds, cache, findings
    └── wscanner-cli/          binary: argument parsing, report, JSON envelope, exit codes
```

The library has no global state and never prints; the CLI owns stdout, stderr and exit codes. Embedders (wsentinel, control-plane) depend on the library at an exact `0.x` version and accept breakage between minors; the [CLI contract](../cli-contract.md) is what stays stable.

Modules map onto `python/wscanner/` one to one (`check`, `check_machine`, `check_supply`, `repos`, `osv`, `feeds`, `db`, …), so a parity diff (F3) can be traced to a file.

## Dependencies

| Crate | Features | Why |
|---|---|---|
| `serde`, `serde_json` | no `derive` | JSON in (OSV, feeds, lockfiles) and out (the envelope); values walked by hand |
| `rusqlite` | `bundled` (FTS5 on) | The cache, schema shared with Python |
| `ureq` | rustls only, no default features | Blocking HTTP: the scanner is one-shot, so no async runtime |
| `rustls` | `ring` provider proposed (no cmake for musl) | TLS. Roots: `webpki-roots` or the platform verifier, owner decides |

Everything else is in-tree: a `Net` trait (one `ureq` implementation, one recording fake for tests), argument parsing, TOML and YAML line subsets, comparators, SHA-256, FNV-1a fingerprints, civil dates for KEV and EOL. `ring` arrives with rustls; reusing its digest instead of the in-tree SHA-256 is a question for the first dependency review.

## Lockfiles

Parsers read line by line where the format allows (P5) and never execute or resolve anything. "Golden" means a real lockfile from a public repo, trimmed, with the expected (ecosystem, name, version) list beside it.

| File | Ecosystem | Formats | Notes |
|---|---|---|---|
| `Cargo.lock` | `crates.io` | v1–v4 | Registry sources only; `path` and `git` packages skipped |
| `package-lock.json` | `npm` | v1 (`dependencies`), v2–v3 (`packages`) | Name from the last `node_modules/` segment; links skipped |
| `pnpm-lock.yaml` | `npm` | v6 (`/name@ver`), v9 (`name@ver`, `snapshots`) | Peer suffixes `(…)` stripped |
| `Package.resolved` | `SwiftURL` | v1–v3 | Package is the repository URL |
| `go.mod` | `Go` | — | `require` and `replace`; `go 1.N.M` → `stdlib` (F5) |
| `uv.lock` | `PyPI` | v1 | Editable and virtual sources skipped |
| `requirements*.txt` | `PyPI` | — | `==` pins only; `-r` includes followed inside the repo |
| `yarn.lock` | `npm` | v1, berry | Berry is YAML; v1 its own block format |
| `bun.lock` | `npm` | text (JSONC) | Comments and trailing commas tolerated |
| `deno.lock` | `npm` | v3–v5 | `npm:` entries; `jsr:` has no OSV ecosystem yet |
| `poetry.lock` | `PyPI` | v1–v2 | |
| `Pipfile.lock` | `PyPI` | — | `default` and `develop` |
| `Gemfile.lock` | `RubyGems` | — | `GEM` `specs:` block |
| `composer.lock` | `Packagist` | — | `packages` and `packages-dev` |
| `pubspec.lock` | `Pub` | — | |
| `mix.lock` | `Hex` | — | `:hex` tuples only |
| `gradle.lockfile` | `Maven` | — | `group:artifact:version=configurations` |
| `pom.xml` | `Maven` | — | Literal versions and same-file properties only; no parent or remote resolution |
| `packages.lock.json` | `NuGet` | v1–v2 | |
| `conan.lock` | `ConanCenter` | v0.4–v0.5 | |

## OS package databases

| Source | Read | Package reported | Ecosystem |
|---|---|---|---|
| `/var/lib/dpkg/status` | Stanzas with `Status: install ok installed` | `Source:` (version from `Source: name (ver)` when present), else `Package:` | from `os-release` |
| `/lib/apk/db/installed` | `P:`, `V:`, `o:` records | `o:` origin, else `P:` | from `os-release` |
| `rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'` | openSUSE, SUSE | `NAME` | from `os-release` |
| dnf / yum advisories | unchanged from Python | — | — |
| Arch security tracker | unchanged from Python | — | — |

### `os-release` → ecosystem

Proposed mapping; the conformance fixtures from osv-scanner's testdata (F7) are the authority, and any row they contradict changes.

| `ID` (or `ID_LIKE`) | Ecosystem string |
|---|---|
| `debian` | `Debian:<VERSION_ID>`; no `VERSION_ID` (testing, sid) → `unchecked` |
| `ubuntu` | `Ubuntu:<VERSION_ID>`, with `:LTS` for LTS releases as OSV names them |
| `alpine` | `Alpine:v<major>.<minor>` |
| `wolfi` | `Wolfi` |
| `chainguard` | `Chainguard` |
| `opensuse-leap` | `openSUSE:Leap <VERSION_ID>` |
| `opensuse-tumbleweed` | `openSUSE:Tumbleweed` |
| `sles`, `suse` | `SUSE:Linux Enterprise Server <major>[ SP<n>]` |
| anything else | `unchecked` (dnf and Arch families keep their own sources) |

## Version comparators

OSV decides whether a version is affected; the scanner only orders fixed versions to pick the safe one (`pick_safe`) and to compare against "latest". Each comparator is tested with its upstream's vectors (F10).

| Comparator | Used for | Upstream vectors |
|---|---|---|
| semver 2.0 | crates.io, npm, SwiftURL, Pub, Hex, NuGet | semver.org grammar and the `semver` crate's tests |
| PEP 440 | PyPI | `packaging`'s version tests |
| Go | Go modules (`v` prefix, pseudo-versions, `+incompatible`) | `golang.org/x/mod/semver` tests |
| dpkg | Debian, Ubuntu | `dpkg --compare-versions` cases (epoch, `~`) |
| apk | Alpine, Wolfi, Chainguard | `apk version -t` cases (`_rc`, `_p`, `-r`) |
| rpmvercmp | openSUSE, SUSE | `rpmvercmp` test suite (`~`, `^`, epoch) |
| generic | upstream release tags, apps, everything else | today's `python/wscanner/versions.py` tests |

RubyGems, Maven and Packagist comparators arrive with their lockfiles.

## OSV client

- `POST /v1/querybatch`, at most 1000 queries per request; `next_page_token` followed per query with `POST /v1/query`.
- `GET /v1/vulns/{id}` only when the id is new or its `modified` changed; at most 8 in flight; `If-None-Match` with the stored ETag.
- Answers cached per (ecosystem, name, version) for a day (`queries.checked_at`); failures never cached.
- Records grouped by alias (id, aliases, `upstream`) so one vulnerability from two databases is one finding.

## Network

Every request carries `User-Agent: wscanner/<version> (+https://github.com/waffuruai/wscanner)` and a 30 s timeout. These are the only hosts (S5):

| Host | For |
|---|---|
| `api.osv.dev` | Advisories |
| `www.cisa.gov` | KEV |
| `endoflife.date` | EOL |
| `formulae.brew.sh` | Cask catalog (latest app versions) |
| `versionhistory.googleapis.com` | Chrome releases |
| `product-details.mozilla.org` | Firefox releases |
| `www.postgresql.org` | PostgreSQL security table |
| `security.archlinux.org` | Arch tracker |
| `main.vscode-cdn.net`, `marketplace.visualstudio.com`, `open-vsx.org` | Extension lists and latest versions |
| `github.com` | Malicious-packages clone, upstream release tags (via `git`) |
| `api.deps.dev` | Licenses (phase 2) |
| `haveibeenpwned.com` or `api.xposedornot.com` | Breach check, only after consent |

## Contract tests

`tests/contract/` at the repo root, run as `WSCANNER=python/bin/wscanner` and `WSCANNER=rust/target/release/wscanner`. They start the binary with a temp `HOME` and `WSCANNER_DB`, `--offline` (a recording `Net` fake for the online cases in Rust; recorded fixtures for both), and check stdout, stderr and exit codes only. The parity diff (F3) is a separate job that runs both implementations online against the same repos and containers and diffs sorted findings.

## Release

Tag on `main` → CI builds each target with `--locked`, the release profile and `SOURCE_DATE_EPOCH` from the tag's commit, rebuilds once to check the bytes match, then publishes the binaries, `SHA256SUMS`, the GitHub attestation and a cosign keyless bundle. ops pins a release by SHA-256 and verifies the attestation before use.
