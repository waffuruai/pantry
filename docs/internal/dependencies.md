# Dependencies and supply chain

wpantry runs with access to the whole home directory, so what goes into it is reviewed like the code. The rules were set in the Rust port's decision log ([specs/archived/01-rust-port.md](../../specs/archived/01-rust-port.md)); this page is the rules and how to follow them.

## The rules

- **Crates**: only `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`), `ureq` and `rustls` (`ring`), plus what they pull in. A new direct dependency needs a decision recorded on this page first; `rust/crates/wpantry/tests/pins.rs` fails otherwise.
- **Pins**: every dependency `=x.y.z` in `rust/Cargo.toml` `[workspace.dependencies]`, crates take them with `.workspace = true`, `Cargo.lock` is committed and every build is `--locked`.
- **Age**: pin a release at least two weeks old. The exception is a security fix, which goes in as soon as it's out (rustls 0.23.46 was one).
- **Toolchain**: `rust/rust-toolchain.toml` names an exact version.
- **Features**: a feature of an allowed crate that pulls new crates in is a decision too, recorded below with the crates it adds.
- **CI tools and actions**: cargo-deny and cargo-vet versions are pinned in `.github/workflows/ci.yml`; every action is pinned by commit SHA with its version in a comment, under the same two-week rule.

## Decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-25 | `serde`, `serde_json` (no `derive`), `rusqlite` (`bundled`, FTS5), `ureq`, `rustls` (`ring`); nothing else | A minimal, reviewable surface; the parsers, comparators and helpers are written here |
| 2026-10-31 | ureq's `platform-verifier` feature: TLS is verified by the platform's trust store (`rustls-platform-verifier`), not the bundled Mozilla roots | A CA the machine distrusts (`fix-ca-trust.sh`, or by hand) must be distrusted by wpantry's own requests too. Adds `rustls-platform-verifier` and, per platform, `security-framework` with `core-foundation` on macOS and `rustls-native-certs` with `openssl-probe` on Linux; the Android and Windows halves (`jni`, `syn`, `schannel`, `windows-sys`, …) are in the lockfile but never compiled for a target we ship. Each is exempted in `supply-chain/config.toml` until audited |
| 2026-10-31 | No `cargo vet import` of other organizations' audits | The import writes auditors' email addresses into `supply-chain/imports.lock`, which CONTRIBUTING.md doesn't allow; we audit or exempt every crate ourselves |

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
```

A transitive bump (in `Cargo.lock` only) follows the same steps with `cargo update -p <crate> --precise`.

## cargo vet

`rust/supply-chain/` lists every third-party crate as audited or exempted at an exact version, so any new or bumped crate fails `cargo vet` until someone looks at it. For each:

1. Read the diff: `cargo vet diff <crate> <old> <new>` (or `cargo vet inspect <crate> <version>` for a new crate). Look for build scripts, `unsafe`, network or filesystem access, and anything that doesn't fit what the crate is for.
2. Record it: `cargo vet certify <crate> <old> <new>` (criteria `safe-to-deploy`) when you reviewed it, or `cargo vet add-exemption <crate> <version>` with the reason in the PR when you didn't (a platform crate we never compile, say).
3. `cargo vet prune` to drop exemptions the new audits cover.

The audits of other organizations (Mozilla, Google, Bytecode Alliance) would cover about a dozen of our crates, but `cargo vet import` writes their auditors' email addresses into `supply-chain/imports.lock`, which CONTRIBUTING.md doesn't allow; decided 2026-10-31: no imports.

## cargo deny

`rust/deny.toml` checks the targets we ship. An advisory against a dependency fails CI: bump it (security fixes skip the two-week rule). Only if there is no fix and the vulnerable code is unreachable from wpantry, add the advisory id to `[advisories] ignore` with a comment saying why and when to revisit, in its own PR.

## The rustls tree

rustls, ring, webpki and the platform verifier are most of the dependency surface. At every bump of any of them, read the release notes and the vet diff even when the bump is a patch, and check `cargo tree -e normal -i ring` for anything new.
