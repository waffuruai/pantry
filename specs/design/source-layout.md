# Source layout

Where every file in `rust/crates/wpantry/src/` and `rust/crates/wpantry-cli/src/` goes, for [04-layout-and-sources](../04-layout-and-sources.md) phase 1. The tree is as of `dev` plus [#131](https://github.com/waffuruai/pantry/pull/131) and [#132](https://github.com/waffuruai/pantry/pull/132), 2026-11-04.

## Rules

- **A folder says what its files do.** A reader picks the folder from the question they have:
  - where does this data come from: `sources/`;
  - what does it look at and how does it judge: `checks/`;
  - how is it shown: `reporters/`;
  - how is it fixed: `remediation/`;
  - what does everything lean on: `utils/`.
- **Core files stay at `src/`.** These are what wpantry *is* rather than what it checks: the library root, errors, the finding and component types, the cache and its history, self-install, and the long-running commands (`sync`, `watch`, the clipboard guard).
- **A file in `sources/` knows a remote API or a format.** A file in `checks/` knows what to look at on this machine or in a repo and how to judge it. When one file does both today (`breach.rs`, `licenses.rs`, `malicious.rs`), it splits along that line.
- **Inside a check, it's one file per behaviour,** with `mod.rs` as the index, as in `suspect/` and `posture/`. A behaviour that differs by OS goes in `os/behaviour` folders (`macos/`, `linux/`, `any/`), as the posture checks and the YARA rules do.
- **Module names are snake_case nouns.** No `check_` prefixes: the folder already says it.
- **Tests stay beside their code.** Test helpers a folder shares go in its `#[cfg(test)] mod testing`, as `posture/testing.rs` does.

## Target tree

```
wpantry/src/
  lib.rs  error.rs  finding.rs  component.rs  db.rs  history.rs
  selfinstall.rs  sync.rs  watch.rs  guard.rs  external.rs
  sources/
    mod.rs  file.rs  fetch.rs  store.rs
    osv.rs  kev.rs  endoflife.rs  releases.rs  distros.rs
    deps_dev.rs  malicious_packages.rs  breaches.rs  hash_lookups.rs
    formats/  yara.rs  signature_base.rs  maltrail.rs  abusech.rs  lists.rs
  checks/
    mod.rs  files.rs
    machine/  mod.rs  tools.rs  catalog.rs  packages.rs  apps.rs  os_packages.rs
              homebrew.rs  editors.rs  harnesses.rs  images.rs  ca_trust.rs  clipper.rs
    supply_chain/  mod.rs  repos.rs  hooks.rs  install_scripts.rs  typosquat.rs
                   malicious.rs  licenses.rs  leaks.rs  mptcp.rs
    lockfiles/  (as today)
    package_managers/  mod.rs  apk.rs  dpkg.rs  go.rs  maven.rs  packagist.rs
                       pypi.rs  rpm.rs  rubygems.rs  semver.rs
    posture/  (as in #132: any/, macos/, linux/)
    documents/  (as today, less zip and deflate)
    suspect/  (as today)
    hidden.rs
    malware/  mod.rs  targets.rs  yara.rs  indicators.rs  verdict.rs  rulegen.rs
    email.rs
  reporters/
    mod.rs  text.rs  json.rs  jsonl.rs  html.rs  csv.rs  yara.rs
  remediation/
    mod.rs  mitigate.rs  harden.rs  editors.rs
  utils/
    json.rs  toml.rs  plist.rs  re.rs  sha256.rs  net.rs  walk.rs  addresses.rs
    files.rs  process.rs  os.rs  parallel.rs  temp.rs  homebrew.rs
    archive/  zip.rs  deflate.rs

wpantry-cli/src/
  main.rs  args.rs  progress.rs  style.rs  schedule.rs  update.rs
```

`wpantry-yara` keeps its layout.

## Moves

| Today | Goes to | Note |
|---|---|---|
| `lib.rs`, `error.rs`, `db.rs`, `history.rs`, `selfinstall.rs`, `sync.rs`, `watch.rs`, `guard.rs`, `external.rs` | stay at `src/` | Core |
| `check.rs` | `checks/mod.rs`, with `Finding` moving to `finding.rs` | `Options` and `Scan` stay with the checks; the finding is shared by checks, reporters and remediation |
| `system.rs` | `component.rs` (`Component`, the `Status` progress callback), `utils/files.rs` (`home`, `test_home`, capped reads, globs, `realpath`, `fingerprint`, `owner`), `utils/process.rs` (`which`, `exec`, `run`, `on_path`, `app_cli`), `utils/os.rs` (`MACOS`, `now`, `os-release`, `os_fix`), `utils/parallel.rs` (`par_map`, `PROBES`, `cores`), `utils/temp.rs` (`TempDir`), `utils/homebrew.rs` (the prefix and installed casks, which tools, apps and Homebrew checks all read); `github()` joins `utils/net.rs` | One helper per file, by kind |
| `check_machine.rs` | `checks/machine/mod.rs` | The machine area's index |
| `tools.rs`, `catalog.rs`, `packages.rs`, `apps.rs`, `editors.rs`, `harnesses.rs`, `images.rs` | `checks/machine/` | `images.rs` reads container images |
| `osdb.rs` | `checks/machine/os_packages.rs` | |
| `cellar.rs`, `scanners.rs` | `checks/machine/homebrew.rs` | Both are Homebrew: bottles poured without `brew`, and `brew vulns`. The prefix and cask readers they share with other checks are `utils/homebrew.rs` |
| `catrust.rs` | `checks/machine/ca_trust.rs`, with `wpantry harden` going to `remediation/harden.rs` | |
| `clipper.rs` | `checks/machine/clipper.rs`; `item_dirs_for` and `command_of` go to `checks/posture/any/persistence/units.rs` | Persistence uses them more than the clipper does |
| `check_supply.rs` | `checks/supply_chain/mod.rs` | |
| `repos.rs` | `checks/supply_chain/repos.rs`; `PRUNE`, `DISCOVER_PRUNE` and the bounded walk go to `utils/walk.rs` | One walker and one prune list for every check |
| `hooks.rs`, `install_scripts.rs`, `typosquat.rs`, `leaks.rs` | `checks/supply_chain/` | `leaks.rs`'s own walk is replaced by `utils/walk.rs` |
| `malicious.rs` | `sources/malicious_packages.rs` (the OpenSSF index) and `checks/supply_chain/malicious.rs` (matching) | |
| `licenses.rs` | `sources/deps_dev.rs` and `checks/supply_chain/licenses.rs` | |
| `mptcp.rs` | `checks/supply_chain/mptcp.rs` | Go servers in repos that listen with MPTCP; the kernel side is `checks/posture/linux/mptcp.rs` |
| `lockfiles/` | `checks/lockfiles/`; `lockfiles/toml.rs` goes to `utils/toml.rs` | The TOML reader gains integers, booleans and arrays for `sources.toml` |
| `compare/`, `versions.rs` | `checks/package_managers/`; `versions.rs` becomes its `mod.rs`; `gover.rs` becomes `go.rs` and `pep440.rs` becomes `pypi.rs` | Named for the package manager, not the algorithm |
| `posture/` | `checks/posture/` | Unchanged inside |
| `documents/` | `checks/documents/`; `zip.rs` and `deflate.rs` go to `utils/archive/` | The malware scan reads zips too |
| `suspect/` | `checks/suspect/` | Each rule's `scan` becomes one `Rule` in a table (phase 2) |
| `hidden.rs` | `checks/hidden.rs` | |
| `malware.rs`, `malware/tests.rs` | `checks/malware/`: `mod.rs` (the pass), `targets.rs`, `yara.rs` (the analyzer), `verdict.rs` (severity and lookups) | The per-file cache moves to `checks/files.rs` (phase 2) |
| `iocs.rs` | `sources/formats/signature_base.rs`, `sources/formats/abusech.rs`, `sources/hash_lookups.rs` (YARAify, CIRCL, MalwareBazaar), `checks/malware/indicators.rs` (matching) | |
| `rulegen.rs` | `checks/malware/rulegen.rs` (the goodware database), with its output in `reporters/yara.rs` | Open decision 3 |
| `breach.rs` | `sources/breaches.rs` (HIBP, XposedOrNot) and `checks/email.rs` | Renamed: it checks the user's email address |
| `feeds.rs` | `sources/kev.rs`, `sources/endoflife.rs`, `sources/releases.rs` (Homebrew casks, Chrome, Firefox, PostgreSQL, Arch) | One file per source family |
| `osv.rs`, `distros.rs` | `sources/` | |
| `net.rs` | `utils/net.rs`; `HOSTS` is built from the sources file (phase 3) | |
| `json.rs`, `plist.rs`, `re.rs`, `sha256.rs`, `addresses.rs` | `utils/` | `addresses.rs` is shared by the suspect, clipper and malware checks |
| `export.rs` | `reporters/jsonl.rs` | |
| `mitigate.rs` | `remediation/mitigate.rs` | |
| `posture/any/tools.rs`'s `set_extension_cooldown` | `remediation/editors.rs` | The check stays in posture; applying it moves |
| CLI `html.rs` (and `assets/report.html`) | `reporters/html.rs` | |
| CLI `report.rs` | `reporters/text.rs` (rendering) and `remediation/mod.rs` (planning and applying fixes) | Colour stays in the CLI's `style.rs` |
| CLI `main.rs`, `args.rs`, `progress.rs`, `style.rs`, `schedule.rs`, `update.rs` | stay | |

## How the moves land

Each phase-1 PR moves code without changing it: `git mv` where a file moves whole, and cut and paste by line range where it splits, with no edits beyond paths and visibility.

| PR | Moves |
|---|---|
| 1a | `utils/` from the root-level helpers (`json`, `plist`, `re`, `sha256`, `net`, `addresses`) and `system.rs`; `component.rs` and `finding.rs` |
| 1b | `checks/`, with the helpers that come out of its folders: `utils/toml.rs` (from `lockfiles/`), `utils/archive/` (from `documents/`), `utils/walk.rs` (from `repos.rs`) |
| 1c | `reporters/` and `remediation/` |

**Each PR is checked by:**
- the contract suite;
- coverage at or above 90%;
- a byte-identical `--json` report of the fixture scan before and after;
- the layout test (F1).
