# Release playbook

How we publish Pantry: the `wpantry-yara`, `wpantry` and `wpantry-cli` crates on crates.io, and signed, reproducible binaries on GitHub Releases. The automation is [`.github/workflows/release.yml`](../../.github/workflows/release.yml); this page is the human side around it. What users do with a release is [docs/public/install.md](../public/install.md). The requirements: every dependency pinned and built `--locked`, `cargo deny` and `cargo vet` green, two builds of a tag byte-identical, and every artifact shipped with `SHA256SUMS`, an attestation and a signature ([docs/public/architecture.md](../public/architecture.md#the-binary)).

## What a release is

A tag `vX.Y.Z` on `main`. Pushing it runs the release workflow:

1. **check**: the tag equals `version` in `rust/Cargo.toml` and is on `main`; `cargo package --workspace --locked` builds every crate from its packaged sources.
2. **build**, per target (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `universal-apple-darwin`, `x86_64-pc-windows-msvc`): two checkouts at different paths, each built with [`rust/release/build.sh`](../../rust/release/build.sh) (`--locked`, the release profile, remapped paths, `SOURCE_DATE_EPOCH` from the commit). The two binaries must be byte-identical or the release stops. A smoke test runs each one.
3. **publish**, after a maintainer approves the `release` environment:
   - It copies `THIRD-PARTY-NOTICES.txt` from `rust/crates/wpantry-cli/` (the notices every binary embeds, which CI keeps current: [dependencies.md](dependencies.md#third-party-notices)) and writes `SHA256SUMS` for the binaries and it.
   - It copies `install.sh` with the release's tag stamped in as its default version, and writes `install.sh.sha256` beside it for waffuru.ai's release receiver, which serves a verified, pinned copy at `https://waffuru.ai/pantry/install.sh`.
   - It makes a GitHub build-provenance attestation for each binary, `install.sh` and `THIRD-PARTY-NOTICES.txt`, and a cosign keyless bundle for each binary.
   - It verifies all of that the way users will, then creates the GitHub release as a draft with generated notes. Releases in this repository are immutable once published, so nothing can be attached after that.
   - It publishes `wpantry-yara`, `wpantry` and `wpantry-cli`, in that order, to crates.io through trusted publishing. It skips a crate crates.io doesn't have yet, with a warning (its first publish is by hand), and a version crates.io already has, so a rerun goes on from where it stopped. [`wcli`](https://github.com/waffuruai/wcli), which `wpantry-cli` depends on, is published from its own repository first.
4. **packslip**: in a job that can't write the release, [packslip](https://packslip.dev) (`jdx/packslip`, pinned) signs a manifest of the three binaries: digests, platforms, and the command name `wpantry`. It links the publish job's attestations. mise's `packslip:` backend and `packslip verify` check releases against it.
5. **release**: attaches the manifest to the draft as `packslip.sigstore.json`, checks the draft has every asset, and publishes it as the latest release. Then it dispatches the website's release receiver (`waffuruai/website` `release.yml`) with the `WEBSITE_DISPATCH_TOKEN` secret, so `https://waffuru.ai/pantry/install.sh` serves the new release within minutes. Without the secret, or if the dispatch fails, it warns; the next site deploy picks the release up. If a job before this one fails, the release stays a draft: fix the cause and rerun the failed jobs.

Nothing that signs or publishes holds a long-lived secret: attestations, cosign certificates, the packslip signature and crates.io tokens all come from the job's short-lived GitHub OIDC identity. The one secret, `WEBSITE_DISPATCH_TOKEN`, can only start the website's deploy, which verifies `install.sh` itself.

## Versions

- One version for both crates, in `rust/Cargo.toml` `[workspace.package]`; `wpantry-cli` depends on `wpantry` at exactly that version.
- `0.x`: a minor bump (`0.2.0`) for any change to the library's public API or a new feature; a patch (`0.1.1`) for fixes. Embedders pin `=x.y.z`.
- The CLI contract versions separately (`schema` in its JSON). A change that bumps `schema` gets a minor release and a line at the top of the release notes.
- Never reuse a version. A bad release is yanked and followed by the next patch.
- A version that was bumped but never tagged is skipped, not back-filled: 0.3.0 was prepared on 2026-11-02 and never tagged, and its changes shipped in v0.4.0 on 2026-11-06. 0.4.1 went the same way: bumped on 2026-11-14, never tagged, its changes in v0.5.0. Tagging it afterwards would publish an older binary as a newer release (GitHub marks the latest-created release "latest", the website receiver follows it, and crates.io would gain a 0.3.0 after 0.4.0), so the number stays unused.

## One-time setup

Done once per repository by an org owner; check it before the first release. Steps 1 to 3 and 5 were set up on 2026-11-17.

1. **Environment** `release` (Settings → Environments): the `owners` team as required reviewers, with "Prevent self-review" on, so the approver isn't the person who pushed the tag; deployments limited to `v*` tags.
2. **Tag protection**: two org rulesets (org settings → Rules → Rulesets) cover every repository. "Release Tags: no moving or deleting" stops a `v*` tag from being moved, force-pushed or deleted. "Release Tags: owners create them" lets only the `owners` team create one. It leaves out `butter`, whose release workflow creates its tag, because GitHub Actions can't be a bypass actor on an org ruleset.
3. **Required checks** on `main` and `dev`: the repository ruleset "Pantry CI" requires `Lint`, `Rust (ubuntu-latest)`, `Rust (macos-latest)`, `Rust (windows-latest)`, `Rust supply chain`, `Test (ubuntu-latest)` and `Test (macos-latest)`. Merge methods and pull requests come from the org's "Dev Branch" and "Main Branch" rulesets.
4. **crates.io owners**: after the first publish, add the maintainers team: `cargo owner --add github:waffuruai:owners wpantry-yara wpantry wpantry-cli`.
5. **Trusted publishing** (crates.io → each crate → Settings → Trusted Publishing): repository `waffuruai/pantry`, workflow `release.yml`, environment `release`. It's set for `wpantry-yara` and `wpantry`; `wpantry-cli` gets it after its first publish ([crates-io.md](crates-io.md)). The repository variable `CRATES_IO_TRUSTED_PUBLISHING` is `true`. When it isn't, the workflow skips the crates.io step.
6. **Arm64 runners**: the build uses GitHub's `ubuntu-24.04-arm` runner; make sure the org can use it.
7. **Website dispatch**: the repository secret `WEBSITE_DISPATCH_TOKEN`, a fine-grained token with Actions: write on `waffuruai/website`, as wrunner's release has. The website's own `GH_TOKEN` needs Contents: read on `waffuruai/pantry` while the repository is private.

## Before the release

On `dev`, through a PR like any other change:

- [ ] CI green on `dev`, including `Rust supply chain` (cargo deny and cargo vet) run within the last day: `cargo deny` fetches the advisory database fresh, so rerun it if the last run is older.
- [ ] Dependencies reviewed since the last release ([dependencies.md](dependencies.md)): no exemption added without a reason in its PR.
- [ ] Bump the version: `version` in `[workspace.package]` and the `wpantry = { …, version = "=X.Y.Z" }` pin in `[workspace.dependencies]`, then `cargo update -w` so `Cargo.lock` follows. `crates/wpantry/tests/pins.rs` and CI catch a mismatch.
- [ ] PR titles on the way in carry their conventional prefix and labels, so the generated notes (`.github/release.yml`) group them.

Then merge `dev` into `main` with a PR (a merge commit, not a squash, so the tagged commit is the reviewed one).

## Dry run

Actions → Release → Run workflow, ref `main`. It runs **check** and **build** (both builds, the byte comparison, the smoke tests) and publishes nothing. Download the artifacts and run each on its platform:

```bash
./wpantry-universal-apple-darwin version
./wpantry-universal-apple-darwin --no-machine --path ~/code/some-repo
```

Do this for every release; a failure here costs nothing.

## Tag

From an up-to-date `main`, with a signed tag:

```bash
git switch main && git pull --ff-only
grep '^version' rust/Cargo.toml                 # version = "X.Y.Z"
git tag -s vX.Y.Z -m "wpantry vX.Y.Z"
git push origin vX.Y.Z
```

The workflow starts. When **build** is green, the `release` environment asks for approval: the approver checks that the run is for the expected tag and commit, then approves.

### A crate's first release

Trusted publishing can't be configured for a crate that doesn't exist yet. The workflow publishes the crates crates.io already has and warns about the rest; publish those by hand once the GitHub release is out. That's `wpantry-cli` at v0.5.0. [crates-io.md](crates-io.md) has every step; in short:

```bash
git switch --detach v0.5.0
cd rust
cargo publish --locked -p wpantry-cli          # with a 1-day crates.io token: publish-new, crate wpantry-cli
```

Revoke the token right after, then add the crate to steps 4 and 5 of the one-time setup.

## Verify the release

Right after publishing, a maintainer who didn't approve it checks it from the outside, on Linux and on a Mac, exactly as [install.md](../public/install.md) says: download each binary, `SHA256SUMS` and the bundles; check the checksum, `packslip verify`, `gh attestation verify`, `cosign verify-blob`; run `wpantry version` and a `--no-machine` scan. Then:

- [ ] `mise use -g packslip:github.com/waffuruai/pantry@X.Y.Z` installs and verifies it, and so does `curl -fsSL https://github.com/waffuruai/pantry/releases/download/vX.Y.Z/install.sh | sh`, on Linux and on a Mac.
- [ ] crates.io shows both crates at `X.Y.Z`, and `cargo install --locked wpantry-cli@X.Y.Z` builds in a clean `rust` container.
- [ ] One Linux binary rebuilds byte-for-byte with the install guide's container recipe (optional, but do it for the first release and after any toolchain or dependency bump).
- [ ] The release notes read right; edit them if not.

Record the result (who verified, on what) as a comment on the release's tracking issue.

## After the release

- **ops**: a PR in `waffuruai/ops` that bumps the pinned version and its SHA-256 per platform (from `SHA256SUMS`), and verifies the attestation before install.
- **wsentinel** and other embedders: bump the `=X.Y.Z` pin.
- Close the release's tracking issue.

## When a release is bad

1. Stop the spread: mark the GitHub release as a pre-release (so `latest` points back), and yank the crates: `cargo yank --version X.Y.Z wpantry-cli` then `wpantry`.
2. Tell ops and the embedders to stay on the previous version.
3. Fix on `dev`, release `X.Y.(Z+1)`. Never move or re-push a tag.
4. A security problem in Pantry itself goes through [SECURITY.md](../../SECURITY.md) and a GitHub security advisory, published with the fix.

## Troubleshooting the workflow

- **"two builds of one commit differ"**: something non-deterministic got into the build (an embedded path, a timestamp, a changed build script). Download both `second-build` and the binary from the job, `diffoscope` them, fix the cause; never publish around it.
- **The tag check fails**: the tag doesn't match `rust/Cargo.toml`, or isn't on `main`. Delete the unpublished tag (an owner can, before anything was published), fix, tag again.
- **crates.io publish fails after the GitHub release succeeded**: rerun only the failed job once the cause is fixed; `cargo publish` of an already-published version fails harmlessly, so a partial rerun is safe.

## Desktop bundles

Bump `desktop/Cargo.toml` and its lockfile alongside the scanner version. Keep both pinned toolchains in sync. The release workflow builds each desktop target twice, compares the bundled ZIPs and runs the desktop end-to-end suite against the extracted bundle. Linux desktop binaries target GNU Linux so they can use the system window and graphics libraries.

The release includes a portable ZIP and Pantry Setup for each desktop platform. Setup installs the executables and notices from that release. The workflow builds Setup twice and tests an installed copy. Both packages go through the same checksums, GitHub attestations and cosign signing as the scanner assets. A manual dry run stores them as workflow artifacts. The release job checks every package is attached before making the release public.

The Pantry product page links to the Setup assets on the latest GitHub release. Publish the first release containing Setup before enabling those links on the site. Keep the `wpantry-setup-<target>` and `wpantry-desktop-<target>.zip` filenames stable for downloads and desktop update checks. See [Desktop install and update](../../desktop/README.md#install-and-update).

### Code signing

The build job signs the desktop packages after the two-build compares, so those compares cover the unsigned builds. The publish job then makes `SHA256SUMS`, the attestations and the cosign bundles from the signed files. [`desktop/release/sign.py`](../../desktop/release/sign.py) does the signing.

- **macOS, always**: an ad-hoc signature with the hardened runtime on each Mach-O, then on the bundle: `ai.waffuru.pantry.scanner` for the scanner inside `Pantry.app`, `ai.waffuru.pantry.desktop` for `Pantry.app`, `ai.waffuru.pantry.setup` for `Pantry Setup.app`. This binds `Info.plist` to the signature and keeps the identifier the same across versions. It does not satisfy Gatekeeper: a downloaded copy still needs the "open anyway" step. Ad-hoc signatures have no timestamp, so the job signs both builds and compares them again. Setup's payload is rebuilt from the signed `Pantry.app`.
- **macOS Developer ID and notarization, off until configured**: replaces the ad-hoc step when `APPLE_DEVELOPER_ID_P12` is set. It signs with a secure timestamp, submits each ZIP with `xcrun notarytool submit --wait`, staples the ticket with `xcrun stapler staple` and repacks. Timestamped bytes differ between runs, so they are not compared.
- **Windows Authenticode, off until configured**: runs when `WINDOWS_SIGNING_PFX` is set. It signs both desktop executables with `signtool` (SHA-256, RFC 3161 timestamp from `http://timestamp.digicert.com`; change it with `--timestamp-url`), rebuilds Setup so its embedded payload holds the signed executables, then signs Setup.

The standalone scanner assets (`wpantry-<target>`) stay as they are: install.sh, mise and packslip verify them by digest and attestation.

Tom has to provide the certificates. Store them as repository secrets (Settings, Secrets and variables, Actions); only the signing steps read them, never the build steps:

| Secret | What it holds |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12` | Base64 of a `.p12` export of the **Developer ID Application** certificate and its private key, from the Apple Developer Program account |
| `APPLE_DEVELOPER_ID_PASSWORD` | The `.p12` export password |
| `APPLE_NOTARY_APPLE_ID` | Apple ID used for notarization |
| `APPLE_NOTARY_TEAM_ID` | The 10-character Team ID |
| `APPLE_NOTARY_PASSWORD` | An app-specific password for that Apple ID |
| `WINDOWS_SIGNING_PFX` | Base64 of a `.pfx` code-signing certificate with its private key (OV or EV; an EV key on a hardware token needs a cloud signing service instead, such as Azure Trusted Signing) |
| `WINDOWS_SIGNING_PASSWORD` | The `.pfx` password |

Run a dry run after adding them and check the logs: `codesign --verify --deep --strict` and `xcrun stapler validate` on macOS, `signtool verify /pa` on Windows. Both run inside `sign.py`.
