# Rust port: design detail

> Archived 2026-10-31 with [01-rust-port.md](01-rust-port.md). The tables here were carried into [docs/architecture.md](../../docs/architecture.md), which is kept current; this copy is the record of what the port proposed and settled.

Detail for [01-rust-port.md](01-rust-port.md). The PRD holds the criteria; this page holds the tables they point at. Status: draft, 2026-10-25; updated 2026-10-27 with what the port settled (marked "settled"). Everything here is proposed until its criterion has evidence.

## Workspace

```
rust/
├── rust-toolchain.toml        exact toolchain (S1)
├── Cargo.toml                 workspace; release profile (S3)
├── Cargo.lock                 committed
├── rustfmt.toml               width 120, as the Python side
├── deny.toml                  advisories, sources, licenses (S2)
├── supply-chain/              cargo vet audits (S2)
└── crates/
    ├── wpantry/              library: scope, extractors, OSV client, comparators, feeds, cache, findings
    └── wpantry-cli/          binary: argument parsing, report, JSON envelope, exit codes
```

The library has no global state and never prints; the CLI owns stdout, stderr and exit codes. Embedders (wsentinel, syrup) depend on the library at an exact `0.x` version and accept breakage between minors; the [CLI contract](../cli-contract.md) is what stays stable.

Modules map one to one onto the Python implementation this port replaced (`python/wscanner/`, removed once parity was shown) (`check`, `check_machine`, `check_supply`, `repos`, `osv`, `feeds`, `db`, …), so a parity diff (F3) can be traced to a file.

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
| `pnpm-lock.yaml` | `npm` | v5 (`/name/ver`), v6 (`/name@ver`), v9 (`name@ver`, `snapshots`) | Peer suffixes `(…)` and v5's `_…` stripped; an entry's own `name:`/`version:` wins |
| `Package.resolved` | `SwiftURL` | v1–v3 | Package is the repository URL without its scheme or `.git` (`github.com/apple/swift-nio`), as osv-scalibr names it (settled) |
| `go.mod` | `Go` | — | `require` and `replace`; `toolchain goX`, else `go X`, → `stdlib` (F5, as osv-scalibr) |
| `uv.lock` | `PyPI` | v1 | Editable and virtual sources skipped |
| `requirements*.txt` | `PyPI` | — | `==` (and `===`) pins only; `-r` includes followed inside the repo, each once; a missing include or one outside the repo is skipped, as osv-scalibr skips includes it can't open; names PEP 503-normalized (settled) |
| `yarn.lock` | `npm` | v1, berry | Berry is YAML; v1 its own block format. Berry: `npm:` resolutions and `patch:` resolutions of `npm:` packages (Yarn's built-in patches) count (settled) |
| `bun.lock` | `npm` | text (JSONC) | Comments and trailing commas tolerated; the binary `bun.lockb` isn't read |
| `deno.lock` | `npm` | v3–v5 | `npm:` entries; `jsr:` has no OSV ecosystem yet; another lockfile version is reported unchecked (settled) |
| `poetry.lock` | `PyPI` | v1–v2 | `git`, `directory`, `file` and `url` sources skipped; `legacy` indexes kept (settled) |
| `Pipfile.lock` | `PyPI` | — | `default` and `develop`; names PEP 503-normalized (settled) |
| `Gemfile.lock` | `RubyGems` | — | `GEM` `specs:` block; a platform suffix (`-x86_64-linux`) is dropped |
| `composer.lock` | `Packagist` | — | `packages` and `packages-dev`; `path` repositories and branch versions skipped; versions as written (`v6.4.0`) (settled) |
| `pubspec.lock` | `Pub` | — | `hosted` packages only |
| `mix.lock` | `Hex` | — | `:hex` tuples only, under the tuple's package name, from the public `hexpm` repository only (`hexpm:org` is private) (settled) |
| `gradle.lockfile` | `Maven` | — | `group:artifact:version=configurations` |
| `pom.xml` | `Maven` | — | Literal versions and same-file properties only; no parent or remote resolution. A missing version comes from the same file's `dependencyManagement`, `[1.2.3]` reads as 1.2.3; ranges, `system` scope, plugin and profile dependencies skipped (settled) |
| `packages.lock.json` | `NuGet` | v1–v2 | `Project` references skipped |
| `conan.lock` | `ConanCenter` | v0.4–v0.5 | A `@user/channel` reference is a private recipe, not ConanCenter's, and is skipped (settled) |

## OS package databases

| Source | Read | Package reported | Ecosystem |
|---|---|---|---|
| `/var/lib/dpkg/status` | Stanzas with `Status: install ok installed` | `Source:` (version from `Source: name (ver)` when present), else `Package:` | from `os-release` |
| `/lib/apk/db/installed` | `P:`, `V:`, `o:` records | `o:` origin, else `P:` | from `os-release` |
| `rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'` | openSUSE, SUSE | `NAME` | from `os-release` |
| dnf / yum advisories | unchanged from Python | — | — |
| Arch security tracker | unchanged from Python | — | — |

### `os-release` → ecosystem

Settled against the authority, osv-scalibr's `MakeEcosystem` tests (the extractor library osv-scanner runs), in `osdb.rs` `scalibr_conformance`. Rows the fixtures changed: Ubuntu has no `:LTS` suffix (records suffixed `:LTS` still match a fix by prefix), SUSE is `SUSE:<VERSION_ID>`. The table maps by `ID` only: a derivative's `VERSION_ID` names its own release, so borrowing its parent's ecosystem would ask OSV about the wrong one and come back silently clean.

| `ID` | Ecosystem string |
|---|---|
| `debian` | `Debian:<VERSION_ID>`; no `VERSION_ID` (testing, sid) → `unchecked` |
| `ubuntu` | `Ubuntu:<VERSION_ID>`; no `VERSION_ID` → `unchecked` |
| `alpine` | `Alpine:v<major>.<minor>`; no `VERSION_ID` → `unchecked` |
| `wolfi` | `Wolfi` |
| `chainguard` | `Chainguard` |
| `opensuse-leap` | `openSUSE:Leap <VERSION_ID>` |
| `opensuse-tumbleweed` | `openSUSE:Tumbleweed` |
| `sles` | `SUSE:<VERSION_ID>` |
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
| RubyGems | RubyGems | rubygems' `test_gem_version.rb` (`Gem::Version#<=>`) |
| Maven | Maven | maven-artifact's `ComparableVersionTest` (3.9) |
| Composer | Packagist | composer/semver's `VersionParserTest`, `ComparatorTest`, `SemverTest` (normalize, then PHP's `version_compare`) |
| generic | ConanCenter, upstream release tags, apps, everything else | the former `python/wscanner/versions.py` tests |

## OSV client

- `POST /v1/querybatch`, at most 1000 queries per request; `next_page_token` followed per query with `POST /v1/query`.
- `GET /v1/vulns/{id}` only when the id is new or its `modified` changed; at most 8 in flight; `If-None-Match` with the stored ETag.
- Answers cached per (ecosystem, name, version) for a day (`queries.checked_at`); failures never cached.
- Records grouped by alias (id, aliases, `upstream`) so one vulnerability from two databases is one finding.

## Network

Every request carries `User-Agent: wpantry/<version> (+https://github.com/waffuruai/pantry)` and a 30 s timeout. These are the only hosts (S5):

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

`tests/contract/test_contract.py` at the repo root (Python standard library, so it runs wherever the Python implementation does; `mise run contract`), run as `WPANTRY=python/bin/wscanner` and `WPANTRY=rust/target/release/wpantry`. They start the binary with a temp `HOME` and `WPANTRY_DB`, `--offline`, and check stdout, stderr, exit codes and the cache file only. The online cases (recorded fixtures for both) are still to come; in Rust the recording `Net` fake (`net::Fake`) covers them at the library level (`tests/scan.rs`). The parity diff (F3) is a separate job that runs both implementations online against the same repos and containers and diffs sorted findings.

## Release

Tag on `main` → CI builds each target with `--locked`, the release profile and `SOURCE_DATE_EPOCH` from the tag's commit, rebuilds once to check the bytes match, then publishes the binaries, `SHA256SUMS`, the GitHub attestation and a cosign keyless bundle. ops pins a release by SHA-256 and verifies the attestation before use.
