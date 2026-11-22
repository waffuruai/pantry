# Dependencies and supply chain

Pantry runs with access to the whole home directory, so what goes into it is reviewed like the code. The rules were set in the Rust port's decision log ([specs/archived/01-rust-port.md](../../specs/archived/01-rust-port.md)); this page is the rules and how to follow them.

## The rules

- **Crates**: only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`), `ureq` and `rustls` (`ring`), plus what they pull in. A new direct dependency needs a decision recorded on this page first; `rust/crates/wpantry/tests/pins.rs` fails otherwise.
- **Pins**: every dependency `=x.y.z` in `rust/Cargo.toml` `[workspace.dependencies]`, crates take them with `.workspace = true`, `Cargo.lock` is committed and every build is `--locked`.
- **Age**: pin a release at least 72 hours old: long enough for a hijacked or broken release to be noticed and yanked, short enough that fixes arrive. The exception is a security fix, which goes in as soon as it's out (rustls 0.23.46 was one). Age is a wait, not a review: every bump is still audited (below).
- **Toolchain**: `rust/rust-toolchain.toml` names an exact version.
- **Features**: a feature of an allowed crate that pulls new crates in is a decision too, recorded below with the crates it adds.
- **CI tools and actions**: cargo-deny and cargo-vet versions are pinned in `.github/workflows/ci.yml`, cargo-about in `mise.toml`; every action is pinned by commit SHA with its version in a comment, under the same 72-hour rule, and audited in `.github/actions-audits.toml`, which `mise run vet actions` checks in CI (below).

## Decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-25 | `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq`, `rustls` (`ring`); nothing else | A minimal, reviewable surface; the parsers, comparators and helpers are written here |
| 2026-10-31 | ureq's `platform-verifier` feature: TLS is verified by the platform's trust store (`rustls-platform-verifier`), not the bundled Mozilla roots | A CA the machine distrusts (`wpantry fix ca-trust`, or by hand) must be distrusted by Pantry's own requests too. Adds `rustls-platform-verifier` and, per platform, `security-framework` with `core-foundation` on macOS and `rustls-native-certs` with `openssl-probe` on Linux; the Android and Windows halves (`jni`, `syn`, `schannel`, `windows-sys`, …) are in the lockfile but never compiled for a target we ship. Each is exempted in `supply-chain/config.toml` until audited |
| 2026-11-04 | A workspace crate of our own, `wpantry-yara` (the YARA engine), and nothing else: no `yara`, `yara-x`, `wasmtime`, `regex` or `aho-corasick` | yara-x compiles conditions to WebAssembly and runs them through wasmtime's JIT: 55+ crates and a code generator inside a scanner that reads hostile files. The engine is written here in safe Rust (parser, atoms, a backtracking matcher, closure-compiled conditions, the `pe`, `elf`, `math` and `hash` modules), matches yara 4.5.7 on the differential suite and adds no third-party code; `tests/pins.rs` allows it by name |
| 2026-11-05 | A workspace crate of our own, `wcli` (command-line parsing after commander.js), and no `clap`, `argh` or `pico-args` | Every Waffuru tool needs the same command tree, help, suggestions and errors; clap alone brings a dozen crates and proc-macros (`syn`, `quote`) into every build. `wcli` is a few hundred lines of safe Rust with no dependencies, tried in `wpantry-cli` first and kept here until another repo uses it; `tests/pins.rs` allows it by name |
| 2026-11-14 | `wcli` from [its own repository](https://github.com/waffuruai/wcli), by release tag (`tag = "v0.1.0", version = "=0.1.0"`), the one git source `deny.toml` allows | A second tool (ops' activity report) uses it, so it moved out as planned. A git dependency is pinned to a tag and an exact version, is first-party to `cargo vet`, and keeps `cargo package` working; it becomes the crates.io version once the crate is published there |
| 2026-11-15 | `wcli` from crates.io (`wcli = { version = "=0.1.0" }`), no git sources in `deny.toml` | Published the day after it moved out; a registry dependency packages and publishes with the workspace, and the exact pin keeps the resolution identical to the tag |
| 2026-10-31 | Import the published `cargo vet` audits of Mozilla, Google and the Bytecode Alliance (`[imports]` in `supply-chain/config.toml`) | They audit the same crates we depend on, to the same `safe-to-deploy` criteria, and publish the audits with their auditors' names and addresses; `imports.lock` copies only the entries that cover our versions, and those identities are already public. At the import, 15 exemptions went, and 14 crates became fully audited. An audit of theirs is for an exact version or a version delta, so a crate we pin newer than they audited stays exempted until someone audits the delta here |

## Bumping a dependency

```bash
cd rust
# 1. the new pin in Cargo.toml [workspace.dependencies], then:
cargo update -p <crate> --precise <x.y.z>
# 2. the gates
cargo deny --locked check                       # advisories, licenses, sources, bans
cargo vet --locked                              # fails until the new version is audited or exempted
# 3. the tests
cargo test --locked && cargo clippy --locked --all-targets -- -D warnings
# 4. the notices the binary embeds (from the repository root), committed with the bump
mise run notices
```

A transitive bump (in `Cargo.lock` only) follows the same steps with `cargo update -p <crate> --precise`.

## Third-party notices

The crates' licences (MIT, Apache-2.0, BSD, ISC, Zlib, CDLA) and the notices of what Pantry vendors ask that their text travel with every copy of the binary. Releases are bare binaries, and install.sh, mise and Homebrew copy only the binary, so the notices are inside it: `wpantry licenses` prints `rust/crates/wpantry-cli/THIRD-PARTY-NOTICES.txt`, which `main.rs` embeds, and each release also ships it as an asset.

`mise run notices` writes the file: [cargo-about](https://github.com/EmbarkStudios/cargo-about) (pinned in `mise.toml`) renders `rust/about.hbs` with every crate compiled into a release target and its licence text (`rust/about.toml`: build and dev dependencies left out, the licences `deny.toml` allows, MIT preferred where a crate offers a choice), from the packaged crates only (`--frozen`), so every machine writes the same bytes. Then it appends what isn't a crate: the secret rules' NOTICE (betterleaks, MIT), `cvss.NOTICE` (FIRST's calculator, BSD-2-Clause) and the report fonts' OFL licences. The Lint job runs `mise run notices --check` and fails when the committed file differs, so run it after any dependency bump, and add to the task any vendored code, data or font that comes with a licence of its own.

cargo-about evaluates all the targets at once, so a crate that one target's dependency needs only on another (`schannel`, for `rustls-native-certs` on Windows) is listed too: a notice too many, never one too few. A `clarify` entry in `about.toml` (ring's, and ours) pins the licence files it names by SHA-256; when a bump changes one, cargo-about only warns and reads the crate as if it had no entry, so `mise run notices` fails on that warning until the entry is checked against the new files.

## Bumping an action

Actions are vetted like crates: `.github/actions-audits.toml` records every `owner/repo` at the exact commit the workflows pin, and `mise run vet actions` (`scripts/vet_actions.py`, standard library only) fails the Lint job when a `uses:` isn't a full commit SHA with a `# vX.Y.Z` comment, when the action at that commit has no entry or the entry's version differs from the comment, or when an entry is no longer used. With network (CI, or `GH_TOKEN` set locally for the rate limit) it also asks the GitHub API whether the tag in the comment is that commit, dereferencing annotated tags, and whether the release is at least 72 hours old; `--offline` skips those two.

Dependabot opens the bump with the new SHA and comment. Before it can merge:

```bash
# 1. read the compare between the two tags, for workflow files, shell steps, new dependencies
#    in package.json or the action's dist/ bundle, and anything that doesn't fit what the action does
gh api repos/<owner>/<repo>/compare/<old-tag>...<new-tag> --jq '.files[] | .filename'
gh api repos/<owner>/<repo>/compare/<old-tag>...<new-tag> --jq '.files[] | .patch' | less
# 2. record it: a new [[audit]] entry with the new sha and version, what you read in notes, the old entry removed
# 3. check
mise run vet actions
```

Push the record change to the Dependabot branch and CI goes green. A release younger than 72 hours is adopted only for a security fix, with `age_exempt = "<reason>"` on its entry. The auditor is the team identity, as for crates; the commit says who did the work.

## cargo vet

`rust/supply-chain/` lists every third-party crate as audited or exempted at an exact version, so any new or bumped crate fails `cargo vet` until someone looks at it. For each:

1. Read the diff: `cargo vet diff <crate> <old> <new>` (or `cargo vet inspect <crate> <version>` for a new crate). Look for build scripts, `unsafe`, network or filesystem access, and anything that doesn't fit what the crate is for.
2. Record it: `cargo vet certify <crate> <old> <new> --criteria safe-to-deploy --who "Waffuru AI, Inc. <security@waffuru.ai>" --notes "<what you read and found>"` when you reviewed it, or `cargo vet add-exemption <crate> <version>` with the reason in the PR when you didn't (a platform crate we never compile, say). The auditor is the team, not a person: this repo is public, the file is what other projects would import, and the commit already says who did the work. The notes carry what was checked (build scripts, `unsafe`, network, filesystem, new dependencies, and for a bundled C library the hash against its upstream release), so a reader can judge the audit, not just see that one happened.
3. `cargo vet prune` to drop exemptions the new audits cover.

The audits of Mozilla, Google and the Bytecode Alliance are imported (`[imports]` in `config.toml`): `cargo vet` fetches their `audits.toml`, keeps in `imports.lock` the entries that apply to our exact versions, and counts a crate audited when an entry, or a chain of version deltas, reaches the version we pin. `imports.lock` therefore carries those auditors' published names and addresses, the one place in this repository that does. `cargo vet prune` after a bump drops exemptions an import now covers; `cargo vet` without `--locked` refreshes the imports.

## cargo deny

`rust/deny.toml` checks the targets we ship. An advisory against a dependency fails CI: bump it (security fixes skip the 72-hour rule). Only if there is no fix and the vulnerable code is unreachable from Pantry, add the advisory id to `[advisories] ignore` with a comment saying why and when to revisit, in its own PR.

## The rustls tree

rustls, ring, webpki and the platform verifier are most of the dependency surface. At every bump of any of them, read the release notes and the vet diff even when the bump is a patch, and check `cargo tree -e normal -i ring` for anything new.

## Desktop dependencies

Pantry Desktop uses the same egui version as Uchi through `eframe` 0.37.0. Its only other direct dependencies are `serde` and `serde_json` for the scanner and automation interfaces. The desktop crate has its own exact pins and lockfile. The scanner workspace retains its dependency allowlist. The release generates desktop licence notices from its locked graph and includes the OFL notices for the Waffuru fonts.
