# Release playbook

How we publish wscanner: the `wscanner` and `wscanner-cli` crates on crates.io, and signed, reproducible binaries on GitHub Releases. The automation is [`.github/workflows/release.yml`](../../.github/workflows/release.yml); this page is the human side around it. What users do with a release is [docs/public/install.md](../public/install.md). The requirements are S1–S4 in [specs/01-rust-port.md](../../specs/01-rust-port.md).

## What a release is

A tag `vX.Y.Z` on `main`. Pushing it runs the release workflow:

1. **check**: the tag equals `version` in `rust/Cargo.toml` and is on `main`; `cargo package --workspace --locked` builds both crates from their packaged sources.
2. **build**, per target (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `universal-apple-darwin`): two checkouts at different paths, each built with [`rust/release/build.sh`](../../rust/release/build.sh) (`--locked`, the release profile, remapped paths, `SOURCE_DATE_EPOCH` from the commit). The two binaries must be byte-identical or the release stops. A smoke test runs each one.
3. **publish**, after a maintainer approves the `release` environment: `SHA256SUMS`, a GitHub build-provenance attestation per binary, a cosign keyless bundle per binary; then it verifies all of that the way users will, creates the GitHub release with generated notes, and publishes `wscanner` then `wscanner-cli` to crates.io through trusted publishing.

Nothing in the workflow holds a long-lived secret: attestations, cosign certificates and crates.io tokens all come from the job's short-lived GitHub OIDC identity.

## Versions

- One version for both crates, in `rust/Cargo.toml` `[workspace.package]`; `wscanner-cli` depends on `wscanner` at exactly that version.
- `0.x`: a minor bump (`0.2.0`) for any change to the library's public API or a new feature; a patch (`0.1.1`) for fixes. Embedders pin `=x.y.z`.
- The CLI contract versions separately (`schema` in its JSON). A change that bumps `schema` gets a minor release and a line at the top of the release notes.
- Never reuse a version. A bad release is yanked and followed by the next patch.

## One-time setup

Done once per repository by an org owner; check it before the first release.

1. **Environment** `release` (Settings → Environments): required reviewers (at least one maintainer who isn't the person tagging), deployment branches and tags limited to `v*` tags.
2. **Tag protection** (Settings → Rules → Rulesets): only maintainers can create `v*` tags; tags can't be updated or deleted.
3. **Branch protection** on `main` and `dev`: the CI checks required, including `Rust (ubuntu-latest)`, `Rust (macos-latest)`, `Contract (python, …)` and `Rust supply chain`.
4. **crates.io owners**: after the first publish, add the maintainers team: `cargo owner --add github:waffuruai:<team> wscanner wscanner-cli`.
5. **Trusted publishing** (after the first publish, crates.io → each crate → Settings → Trusted Publishing): repository `waffuruai/wscanner`, workflow `release.yml`, environment `release`. Then set the repository variable `CRATES_IO_TRUSTED_PUBLISHING` to `true`; until it is, the workflow skips the crates.io step.
6. **Arm64 runners**: the build uses GitHub's `ubuntu-24.04-arm` runner; make sure the org can use it.

## Before the release

On `dev`, through a PR like any other change:

- [ ] CI green on `dev`, including `Rust supply chain` (cargo deny and cargo vet) run within the last day: `cargo deny` fetches the advisory database fresh, so rerun it if the last run is older.
- [ ] Dependencies reviewed since the last release ([dependencies.md](dependencies.md)): no exemption added without a reason in its PR.
- [ ] For a release that replaces the Python implementation for a caller: the F3 parity diff (Python and Rust `check --json`, findings sorted, `impl` and `version` dropped) is empty on the org repos and in Debian, Alpine and openSUSE containers, and recorded in the PRD.
- [ ] Bump the version: `version` in `[workspace.package]` and the `wscanner = { …, version = "=X.Y.Z" }` pin in `[workspace.dependencies]`, then `cargo update -w` so `Cargo.lock` follows. `crates/wscanner/tests/pins.rs` and CI catch a mismatch.
- [ ] PR titles on the way in carry their conventional prefix and labels, so the generated notes (`.github/release.yml`) group them.

Then merge `dev` into `main` with a PR (a merge commit, not a squash, so the tagged commit is the reviewed one).

## Dry run

Actions → Release → Run workflow, ref `main`. It runs **check** and **build** (both builds, the byte comparison, the smoke tests) and publishes nothing. Download the artifacts and run each on its platform:

```bash
./wscanner-universal-apple-darwin version
./wscanner-universal-apple-darwin --no-machine --path ~/code/some-repo
```

Do this for every release; a failure here costs nothing.

## Tag

From an up-to-date `main`, with a signed tag:

```bash
git switch main && git pull --ff-only
grep '^version' rust/Cargo.toml                 # version = "X.Y.Z"
git tag -s vX.Y.Z -m "wscanner vX.Y.Z"
git push origin vX.Y.Z
```

The workflow starts. When **build** is green, the `release` environment asks for approval: the approver checks that the run is for the expected tag and commit, then approves.

### The first release only

Trusted publishing can't be configured for a crate that doesn't exist yet, so `v0.1.0` publishes the crates by hand once the GitHub release is out:

```bash
git switch --detach v0.1.0
cd rust
cargo publish --locked -p wscanner              # with a crates.io token scoped to publish-new, wscanner*
cargo publish --locked -p wscanner-cli
```

Revoke the token right after, then do steps 4 and 5 of the one-time setup.

## Verify the release

Right after publishing, a maintainer who didn't approve it checks it from the outside, on Linux and on a Mac, exactly as [install.md](../public/install.md) says: download each binary, `SHA256SUMS` and the bundles; check the checksum, `gh attestation verify`, `cosign verify-blob`; run `wscanner version` and a `--no-machine` scan. Then:

- [ ] crates.io shows both crates at `X.Y.Z`, and `cargo install --locked wscanner-cli@X.Y.Z` builds in a clean `rust` container.
- [ ] One Linux binary rebuilds byte-for-byte with the install guide's container recipe (optional, but do it for the first release and after any toolchain or dependency bump).
- [ ] The release notes read right; edit them if not.

Record the result (who verified, on what) as a comment on the release's tracking issue.

## After the release

- **ops**: a PR in `waffuruai/ops` that bumps the pinned version and its SHA-256 per platform (from `SHA256SUMS`), and verifies the attestation before install.
- **wsentinel** and other embedders: bump the `=X.Y.Z` pin.
- Close the release's tracking issue.

## When a release is bad

1. Stop the spread: mark the GitHub release as a pre-release (so `latest` points back), and yank the crates: `cargo yank --version X.Y.Z wscanner-cli` then `wscanner`.
2. Tell ops and the embedders to stay on the previous version.
3. Fix on `dev`, release `X.Y.(Z+1)`. Never move or re-push a tag.
4. A security problem in wscanner itself goes through [SECURITY.md](../../SECURITY.md) and a GitHub security advisory, published with the fix.

## Troubleshooting the workflow

- **"two builds of one commit differ"**: something non-deterministic got into the build (an embedded path, a timestamp, a changed build script). Download both `second-build` and the binary from the job, `diffoscope` them, fix the cause; never publish around it.
- **The tag check fails**: the tag doesn't match `rust/Cargo.toml`, or isn't on `main`. Delete the unpublished tag (an owner can, before anything was published), fix, tag again.
- **crates.io publish fails after the GitHub release succeeded**: rerun only the failed job once the cause is fixed; `cargo publish` of an already-published version fails harmlessly, so a partial rerun is safe.
