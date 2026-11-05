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
- **Inside a check, it's one file per behaviour,** with `mod.rs` as the index, as in `suspects/` and `machine/`. A behaviour that differs by OS goes in `os/behaviour` folders (`macos/`, `linux/`, `any/`), as the posture checks and the YARA rules do.
- **Module names are snake_case nouns.** No `check_` prefixes: the folder already says it.
- **Tests stay beside their code.** Test helpers a folder shares go in its `#[cfg(test)] mod testing`, as `machine/testing.rs` does.

## Target tree

```
wpantry/src/
  lib.rs  error.rs  finding.rs  component.rs  db.rs  history.rs
  selfinstall.rs  sync.rs  watch.rs  guard.rs  external.rs
  sources/
    mod.rs  file.rs  fetch.rs  store.rs
    osv.rs  kev.rs  endoflife.rs  releases.rs  extensions.rs  distros.rs
    package_licenses.rs  malicious_packages.rs  breaches.rs  indicator_lists.rs  hash_lookups.rs
    formats/  yara.rs  signature_base.rs  maltrail.rs  abusech.rs  lists.rs
  checks/
    mod.rs
    files/  mod.rs  view.rs  pass.rs  cache.rs  (one walk, one read per file, one cache, for every content check)
    machine/  mod.rs  tools.rs  catalog.rs  packages.rs  apps.rs  os_packages.rs
              cellar.rs  brew_vulns.rs  editors.rs  harnesses.rs  images.rs  ca_trust.rs  clipper.rs
              settings.rs  testing.rs
              any/  macos/  linux/  (the security settings and persistence, one file per behaviour;
                                     windows/ arrives with the first Windows check)
    supply_chain/  mod.rs  repos.rs  hooks.rs  install_scripts.rs  typosquat.rs
                   malicious.rs  licenses.rs  leaks.rs  mptcp.rs
    lockfiles/  (as today)
    ecosystems/  mod.rs  apk.rs  dpkg.rs  go.rs  maven.rs  packagist.rs
                 pypi.rs  rpm.rs  rubygems.rs  semver.rs  versions.rs
    documents/  (as today, less zip and deflate)
    suspects/  (as today)
    hidden/  mod.rs  unicode.rs  instructions.rs  html.rs  links.rs  bait.rs  names.rs  commits.rs
    malware/  mod.rs  targets.rs  yara.rs  verdict.rs  indicators.rs  rulegen.rs
    email.rs
  reporters/
    mod.rs  text.rs  json.rs  jsonl.rs  html.rs  csv.rs  yara.rs
  remediation/
    mod.rs  mitigate.rs  ca_trust.rs  editors.rs
  utils/
    json.rs  toml.rs  dates.rs  plist.rs  re.rs  sha256.rs  net.rs  walk.rs  addresses.rs
    files.rs  process.rs  os.rs  parallel.rs  temp.rs  homebrew.rs
    archive/  mod.rs  zip.rs  deflate.rs

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
| `cellar.rs`, `scanners.rs` | `checks/machine/cellar.rs` and `checks/machine/brew_vulns.rs` | Bottles poured without `brew`, and `brew vulns`: two jobs, so two files. The prefix and cask readers they share with other checks are `utils/homebrew.rs` |
| `catrust.rs` | `checks/machine/ca_trust.rs` (1b), with the fix behind `wpantry harden ca-trust` going to `remediation/ca_trust.rs` (1d) | Named like the check it fixes |
| `clipper.rs` | `checks/machine/clipper.rs`; `item_dirs_for` and `command_of` go to `checks/machine/any/persistence/units.rs` | Persistence uses them more than the clipper does |
| `check_supply.rs` | `checks/supply_chain/mod.rs` | |
| `repos.rs` | `checks/supply_chain/repos.rs`; `PRUNE`, `DISCOVER_PRUNE`, `skip` and the bounded, memoised walk go to `utils/walk.rs` | One walker and one prune list for every check |
| `hooks.rs`, `install_scripts.rs`, `typosquat.rs`, `leaks.rs` | `checks/supply_chain/` | `leaks.rs`'s own walk is replaced by `utils/walk.rs` |
| `malicious.rs` | `checks/supply_chain/malicious.rs` whole (1b); then `sources/malicious_packages.rs` (the OpenSSF index: the clone, `sync`, name keys) comes out of it (1c) | The check keeps `reports` and `applies`: a name match and its version ranges |
| `licenses.rs` | `checks/supply_chain/licenses.rs` whole (1b); then `sources/package_licenses.rs` (fetching and caching) comes out of it (1c) | The check keeps the SPDX expressions and the allowlist |
| `mptcp.rs` | `checks/supply_chain/mptcp.rs` | Go servers in repos that listen with MPTCP; the kernel side is `checks/machine/linux/mptcp.rs` |
| `lockfiles/` | `checks/lockfiles/`; `lockfiles/toml.rs` goes to `utils/toml.rs` | The TOML reader gains integers, booleans and arrays for `sources.toml` (phase 3), and its own line cap in place of `lockfiles::lines` |
| `compare/`, `versions.rs` | `checks/ecosystems/`, with `versions.rs` beside the others (the generic order); `gover.rs` becomes `go.rs` and `pep440.rs` becomes `pypi.rs` | Named for the package manager, not the algorithm. `mod.rs` keeps `Comparator` |
| `posture/` | `checks/machine/`: `mod.rs` becomes `settings.rs`, `any/`, `macos/` and `linux/` sit in `machine/`, and `any/tools.rs` becomes `any/dev_settings.rs` (1e) | Inventory and settings are both "this machine" |
| `documents/` | `checks/documents/`; `zip.rs` and `deflate.rs` go to `utils/archive/`, with the byte helpers they share (`rfind`, `u16le`, `u32le`, `MAX_MEMBER`) in its `mod.rs` | The malware scan reads zips too |
| `suspect/` | `checks/suspects/` (1e) | Each rule's `scan` is one `Rule` in a table (2e) |
| `hidden.rs` | `checks/hidden.rs` (1b), then `checks/hidden/`, one file per behaviour (1f) | |
| `malware.rs`, `malware/tests.rs` | `checks/malware/mod.rs` and `tests.rs` (1b); split into `targets.rs`, `yara.rs` (the analyzer) and `verdict.rs` (severity and lookups) in phase 2 | Phase 2 rewrote the walk and the cache, so the split landed with it (2d). The per-file cache is `checks/files/cache.rs` |
| `iocs.rs` | `checks/malware/indicators.rs` whole (1b); then `sources/indicator_lists.rs` (fetching and reading signature-base and Feodo) and `sources/hash_lookups.rs` (YARAify, CIRCL, MalwareBazaar, and the consent to ask them) come out of it (1c) | `indicator_lists.rs` fetches and reads both lists in one function each; it splits into `sources/formats/signature_base.rs` and `abusech.rs` when phase 4 gives every list its own entry and reader |
| `rulegen.rs` | `checks/malware/rulegen.rs` (the goodware database), with its output in `reporters/yara.rs` | Open decision 3 |
| `breach.rs` | `checks/email.rs` whole (1b); then `sources/breaches.rs` (HIBP, XposedOrNot, and their week-long cache) comes out of it (1c) | Renamed: it checks the user's email address |
| `feeds.rs` | `sources/kev.rs`, `sources/endoflife.rs`, `sources/releases.rs` (Homebrew casks, Chrome, Firefox, PostgreSQL, GitHub latest releases), `sources/extensions.rs` (VS Code's lists, the marketplace, Open VSX), the Arch tracker into `sources/distros.rs`, the ETag refetch into `sources/fetch.rs`, and the calendar helpers into `utils/dates.rs` | One file per source family; their tests share helpers through `sources/testing.rs` |
| `osv.rs`, `distros.rs` | `sources/` | |
| `net.rs` | `utils/net.rs`; `HOSTS` is built from the sources file (phase 3) | |
| `json.rs`, `plist.rs`, `re.rs`, `sha256.rs`, `addresses.rs` | `utils/` | `addresses.rs` is shared by the suspect, clipper and malware checks |
| `export.rs` | `reporters/jsonl.rs` | |
| `mitigate.rs` | `remediation/mitigate.rs` | |
| `posture/any/tools.rs`'s (now `machine/any/dev_settings.rs`) `set_extension_cooldown` and `with_cooldown` | `remediation/editors.rs` | The check stays with the settings; applying it moves |
| CLI `html.rs` (and `assets/report.html`, `assets/fonts/`) | `reporters/html.rs`, with the template and fonts in the library's `assets/report/` | |
| CLI `main.rs`'s `envelope` | `reporters/json.rs` | The `--json` envelope |
| CLI `report.rs` | `reporters/text.rs` (rendering) and `remediation/mod.rs` (planning and applying fixes) | Colour stays in the CLI's `style.rs`. The CLI's `report` command (the exposure, remediation and audit logs) stays in `main.rs` until phase 5 |
| CLI `main.rs`, `args.rs`, `progress.rs`, `style.rs`, `schedule.rs`, `update.rs` | stay | |

## How the moves land

Each phase-1 PR moves code without changing it: `git mv` where a file moves whole, and cut and paste by line range where it splits, with no edits beyond paths and visibility.

| PR | Moves |
|---|---|
| 1a | `utils/` from the root-level helpers (`json`, `plist`, `re`, `sha256`, `net`, `addresses`) and `system.rs`; `component.rs` and `finding.rs` |
| 1b | `checks/`, every file whole (a file that is both a source and a check moves with the check), and the helpers that come out of its folders: `utils/toml.rs` (from `lockfiles/`), `utils/archive/` (from `documents/`), `utils/walk.rs` (from `repos.rs`), and `item_dirs_for` and `command_of` (from `clipper.rs`) |
| 1c | `sources/`: `osv.rs`, `distros.rs`, `feeds.rs` split by family, and the source halves of `email.rs`, `malicious.rs`, `licenses.rs` and `indicators.rs` |
| 1d | `reporters/` (`export.rs`, and the CLI's `html.rs`, its assets, `report.rs`'s rendering and `main.rs`'s `envelope`) and `remediation/` (`mitigate.rs`, `report.rs`'s plan and apply, and the `harden` fixes out of `ca_trust.rs` and `posture/any/tools.rs`) |
| 1e | Consolidation: `posture/` into `machine/`, `suspect/` to `suspects/`, `deps_dev` to `package_licenses`, `package_managers/` to `ecosystems/`, and the four per-ecosystem match tables (`Comparator::for_ecosystem`, `deps_dev::system`, `malicious_packages::dir_for` and `norm`) folded into one `Ecosystem` table |
| 1f | The three largest files split by behaviour, each item and its tests into the behaviour's file: `supply_chain/mod.rs` (2,397 lines, now 185) into `projects`, `suspect_code`, `hidden_text`, `documents`, `images`, `extensions` and `mcp` and the existing `leaks`, `hooks`, `licenses`, `typosquat`, `install_scripts`, `mptcp` and `malicious` (the breach check into `checks/email.rs`); `machine/mod.rs` (1,586, now 150) into `components`, `app_updates`, `os_updates` and `downloads` and the existing `settings`, `clipper`, `brew_vulns`, `ca_trust` and `any/persistence/findings`; `hidden.rs` (1,705) into `hidden/` (`unicode`, `instructions`, `html`, `links`, `bait`, `names`, `commits`). Shared test helpers go to each folder's `testing.rs` |

**Each PR is checked by:**
- the contract suite;
- coverage at or above 90%;
- a byte-identical `--json` report of the fixture scan before and after;
- the layout test (F1).
