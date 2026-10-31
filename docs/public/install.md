# Install and verify Pantry

Pantry's command is `wpantry`. It reads your whole home directory, so make sure the binary you run is the one this repository built. All three ways in below check that for you.

## Install

**With [mise](https://mise.jdx.dev)** (the default, and what Waffuru uses):

```bash
mise use -g packslip:github.com/waffuruai/pantry
wpantry version
```

mise reads the release's signed [packslip](https://packslip.dev) and verifies its signature against this repository's release workflow before it installs anything. It also checks the binary's digest against the packslip. It remembers the signer, and refuses a later release signed by anyone else. Pin a version with `packslip:github.com/waffuruai/pantry@0.2.0`, or put that line in a project's `mise.toml`.

**With the install script** (no mise):

```bash
curl -fsSL https://github.com/waffuruai/pantry/releases/latest/download/install.sh | sh
```

It picks the binary for your OS and CPU and checks it against `SHA256SUMS`. Then it verifies the signature with the first of `packslip`, `gh` (logged in) or `cosign` that you have, and installs to `~/.local/bin/wpantry`. Without any of the three it says only the checksum was checked. Set `WPANTRY_REQUIRE_SIGNATURE=1` to make that an error. Options are `--version vX.Y.Z` and `--dir DIR`, or `WPANTRY_VERSION` and `WPANTRY_INSTALL_DIR`. Each release ships its own `install.sh`, which installs that release by default and is attested like the binaries. To read it before running it:

```bash
curl -fsSLO https://github.com/waffuruai/pantry/releases/download/v0.2.0/install.sh
less install.sh && sh install.sh
```

**With Homebrew** (macOS and Linux, no mise):

```bash
brew install waffuruai/tap/wpantry
```

The formula installs the same release binary the other two ways do and checks its SHA-256 against the digest the formula carries, which the release workflow copied from that release's `SHA256SUMS`. Homebrew verifies the digest, not the signature; to check provenance as well, run `gh attestation verify "$(brew --prefix wpantry)/bin/wpantry" --repo waffuruai/pantry` after installing (the binary is unchanged, so the attestation still matches). `brew upgrade wpantry` follows new releases once the tap's bump PR for them is merged. Windows: see [#11](https://github.com/waffuruai/pantry/issues/11).

wpantry needs nothing else to run. It uses `git`, `gitleaks` and `openssl` for some checks: `wpantry tools` lists which are missing, and a missing one is reported, never skipped silently.

## Install by hand

Every release ships:

| Asset | What it is |
|---|---|
| `wpantry-x86_64-unknown-linux-musl` | Linux x86-64, static |
| `wpantry-aarch64-unknown-linux-musl` | Linux arm64, static |
| `wpantry-universal-apple-darwin` | macOS, Apple silicon and Intel |
| `SHA256SUMS` | SHA-256 of each binary |
| `packslip.sigstore.json` | The signed packslip: every binary's digest, platform and command name |
| `<binary>.sigstore.json` | A cosign keyless signature bundle for that binary |
| `install.sh` | The install script above |
| `install.sh.sha256` | SHA-256 of `install.sh` |

Each binary and `install.sh` also has a GitHub artifact attestation (build provenance): a signed record that the release workflow in `waffuruai/pantry` built it from the tagged commit. Releases are listed at <https://github.com/waffuruai/pantry/releases>.

### Download

```bash
VERSION=0.2.0                                   # the release to install
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)         ASSET=wpantry-x86_64-unknown-linux-musl ;;
  Linux/aarch64)        ASSET=wpantry-aarch64-unknown-linux-musl ;;
  Darwin/*)             ASSET=wpantry-universal-apple-darwin ;;
  *) echo "no release binary for this platform; build from source"; exit 1 ;;
esac
BASE="https://github.com/waffuruai/pantry/releases/download/v$VERSION"
mkdir -p ~/wpantry-download && cd ~/wpantry-download
curl -fsSLO "$BASE/$ASSET" -O "$BASE/SHA256SUMS" -O "$BASE/packslip.sigstore.json" -O "$BASE/$ASSET.sigstore.json"
```

### Verify

Do the checksum and at least one of the signature checks. The checksum alone only proves the file matches a list from the same server; the signatures prove the release workflow of this repository produced it.

**Checksum** (any machine):

```bash
grep " $ASSET\$" SHA256SUMS | shasum -a 256 -c -
# wpantry-…: OK
```

**packslip** (needs [packslip](https://packslip.dev/docs/install/), no account):

```bash
packslip verify packslip.sigstore.json --artifact "$ASSET"
# ok: github.com/waffuruai/pantry 0.2.0 …
```

Check that the first line names `github.com/waffuruai/pantry` and the version you asked for: packslip trusts the project the bundle claims, and the line is how you see which one.

**GitHub attestation** (needs the [GitHub CLI](https://cli.github.com), logged in):

```bash
gh attestation verify "$ASSET" --repo waffuruai/pantry
```

It prints the workflow, commit and tag that built the file, and fails if there's no attestation from this repository.

**cosign** (needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), no account):

```bash
cosign verify-blob "$ASSET" --bundle "$ASSET.sigstore.json" \
  --certificate-identity "https://github.com/waffuruai/pantry/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK
```

The identity pins the signer to this repository's release workflow running for that exact tag; a bundle signed by anyone else, or for another tag, fails.

**Rebuild it yourself** (strongest, optional). Releases are reproducible: the release job builds every binary twice from different paths and refuses to publish unless the bytes match. To reproduce a Linux binary, build the tag in the release job's environment (Ubuntu 24.04 with `musl-tools`; the Rust toolchain is pinned by `rust/rust-toolchain.toml`) and compare:

```bash
git clone https://github.com/waffuruai/pantry && cd pantry && git checkout "v$VERSION"
docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 bash -c '
  apt-get update -q && apt-get install -y -q curl git gcc musl-tools &&
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none &&
  . "$HOME/.cargo/env" && cd rust && rustup toolchain install && rustup target add x86_64-unknown-linux-musl &&
  git config --global --add safe.directory /src &&
  release/build.sh x86_64-unknown-linux-musl /src/rebuilt'
shasum -a 256 rebuilt                            # should equal the line in SHA256SUMS
```

If it doesn't match, don't install it: open an issue (or a [security report](../../SECURITY.md) if you suspect tampering) with both hashes.

### Put it on PATH

```bash
install -m 0755 "$ASSET" ~/.local/bin/wpantry  # or anywhere on your PATH
wpantry version                                # wpantry 0.2.0 (rust, schema 1)
wpantry tools                                  # which external tools it found
```

On macOS, a binary downloaded with `curl` runs as is. One downloaded through a browser is quarantined by Gatekeeper; after verifying it, clear that with `xattr -d com.apple.quarantine wpantry-universal-apple-darwin`.

**In automation** (ops, CI images), pin the release by its SHA-256, not just its version, and check it before installing:

```bash
echo "<sha256 from SHA256SUMS>  $ASSET" | shasum -a 256 -c - && install -m 0755 "$ASSET" /usr/local/bin/wpantry
```

## From crates.io

```bash
cargo install --locked wpantry-cli             # installs the `wpantry` binary
```

This builds from source with the exact dependency versions in the published `Cargo.lock` (`--locked`); cargo checks every crate against the registry's checksums. It needs a Rust toolchain and a C compiler (SQLite and ring are compiled in). The library alone is the `wpantry` crate, for embedding (its API is `0.x`: pin it with `=x.y.z`; the CLI contract is what stays stable).

## From source

```bash
git clone https://github.com/waffuruai/pantry && cd pantry/rust
git checkout v0.2.0                             # a release tag
cargo build --release --locked                  # target/release/wpantry
```

## Upgrade and uninstall

With mise: `mise upgrade packslip:github.com/waffuruai/pantry`, or change the pinned version. With Homebrew: `brew upgrade wpantry`, and `brew uninstall wpantry` to remove it. Otherwise, install a newer release the same way, and verify it again. To uninstall, delete the binary; the cache is `~/.cache/wpantry/` (or `$XDG_CACHE_HOME/wpantry/`, or wherever `WPANTRY_DB` points) and can be deleted too.
