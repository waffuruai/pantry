# Install and verify wscanner

wscanner runs with access to your whole home directory, so check that the binary you run is the one this repository built before you run it. Every release ships:

| Asset | What it is |
|---|---|
| `wscanner-x86_64-unknown-linux-musl` | Linux x86-64, static |
| `wscanner-aarch64-unknown-linux-musl` | Linux arm64, static |
| `wscanner-universal-apple-darwin` | macOS, Apple silicon and Intel |
| `SHA256SUMS` | SHA-256 of each binary |
| `<binary>.sigstore.json` | A cosign keyless signature bundle for that binary |

Each binary also has a GitHub artifact attestation (build provenance): a signed record that the release workflow in `waffuruai/wscanner` built it from the tagged commit. Releases are listed at <https://github.com/waffuruai/wscanner/releases>.

> The Rust binary covers the repo checks and Linux OS packages today; the rest of the machine inventory follows (see [rust/README.md](../../rust/README.md)). Until then the [Python implementation](#the-python-implementation) covers everything.

## 1. Download

```bash
VERSION=0.1.0                                   # the release to install
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)         ASSET=wscanner-x86_64-unknown-linux-musl ;;
  Linux/aarch64)        ASSET=wscanner-aarch64-unknown-linux-musl ;;
  Darwin/*)             ASSET=wscanner-universal-apple-darwin ;;
  *) echo "no release binary for this platform; build from source"; exit 1 ;;
esac
BASE="https://github.com/waffuruai/wscanner/releases/download/v$VERSION"
mkdir -p ~/wscanner-download && cd ~/wscanner-download
curl -fsSLO "$BASE/$ASSET" -O "$BASE/SHA256SUMS" -O "$BASE/$ASSET.sigstore.json"
```

## 2. Verify

Do the checksum and at least one of the two signature checks. The checksum alone only proves the file matches a list from the same server; the signatures prove the release workflow of this repository produced it.

**Checksum** (any machine):

```bash
grep " $ASSET\$" SHA256SUMS | shasum -a 256 -c -
# wscanner-…: OK
```

**GitHub attestation** (needs the [GitHub CLI](https://cli.github.com), logged in):

```bash
gh attestation verify "$ASSET" --repo waffuruai/wscanner
```

It prints the workflow, commit and tag that built the file, and fails if there's no attestation from this repository.

**cosign** (needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), no account):

```bash
cosign verify-blob "$ASSET" --bundle "$ASSET.sigstore.json" \
  --certificate-identity "https://github.com/waffuruai/wscanner/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK
```

The identity pins the signer to this repository's release workflow running for that exact tag; a bundle signed by anyone else, or for another tag, fails.

**Rebuild it yourself** (strongest, optional). Releases are reproducible: the release job builds every binary twice from different paths and refuses to publish unless the bytes match. To reproduce a Linux binary, build the tag in the release job's environment (Ubuntu 24.04 with `musl-tools`; the Rust toolchain is pinned by `rust/rust-toolchain.toml`) and compare:

```bash
git clone https://github.com/waffuruai/wscanner && cd wscanner && git checkout "v$VERSION"
docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 bash -c '
  apt-get update -q && apt-get install -y -q curl git gcc musl-tools &&
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none &&
  . "$HOME/.cargo/env" && cd rust && rustup toolchain install && rustup target add x86_64-unknown-linux-musl &&
  git config --global --add safe.directory /src &&
  release/build.sh x86_64-unknown-linux-musl /src/rebuilt'
shasum -a 256 rebuilt                            # should equal the line in SHA256SUMS
```

If it doesn't match, don't install it: open an issue (or a [security report](../../SECURITY.md) if you suspect tampering) with both hashes.

## 3. Install

```bash
install -m 0755 "$ASSET" ~/.local/bin/wscanner  # or anywhere on your PATH
wscanner version                                # wscanner 0.1.0 (rust, schema 1)
wscanner tools                                  # which external tools it found
```

wscanner itself needs nothing else. It runs `git` and `gitleaks` for the repo checks (`wscanner tools` says which are missing; a missing one is reported as a failing finding, never skipped silently).

On macOS, a binary downloaded with `curl` runs as is. One downloaded through a browser is quarantined by Gatekeeper; after verifying it, clear that with `xattr -d com.apple.quarantine wscanner-universal-apple-darwin`.

**In automation** (ops, CI images), pin the release by its SHA-256, not just its version, and check it before installing:

```bash
echo "<sha256 from SHA256SUMS>  $ASSET" | shasum -a 256 -c - && install -m 0755 "$ASSET" /usr/local/bin/wscanner
```

## From crates.io

```bash
cargo install --locked wscanner-cli             # installs the `wscanner` binary
```

This builds from source with the exact dependency versions in the published `Cargo.lock` (`--locked`); cargo checks every crate against the registry's checksums. It needs a Rust toolchain and a C compiler (SQLite and ring are compiled in). The library alone is the `wscanner` crate, for embedding (its API is `0.x`: pin it with `=x.y.z`; the CLI contract is what stays stable).

## From source

```bash
git clone https://github.com/waffuruai/wscanner && cd wscanner/rust
git checkout v0.1.0                             # a release tag
cargo build --release --locked                  # target/release/wscanner
```

## The Python implementation

Until the Rust binary covers the machine inventory, the full scanner is the Python one (Python 3.9+, standard library only):

```bash
git clone https://github.com/waffuruai/wscanner.git
wscanner/python/bin/wscanner tools              # which external tools it found
```

It needs `osv-scanner` and `gitleaks`; with [mise](https://mise.jdx.dev), `mise bootstrap` in the checkout installs the pinned versions. Both implementations share the CLI, the JSON and the cache, so you can switch between them.

## Upgrade and uninstall

Upgrade by installing a newer release the same way (verify it again). To uninstall, delete the binary; the cache is `~/.cache/wscanner/` (or `$XDG_CACHE_HOME/wscanner/`, or wherever `WSCANNER_DB` points) and can be deleted too.
