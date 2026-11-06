# Install and verify Pantry

Pantry's command is `wpantry`. It reads your whole home directory, so run only a binary this repository built. Every way in below checks that for you.

## Install

**With [mise](https://mise.jdx.dev)** (recommended):

```bash
mise use -g packslip:github.com/waffuruai/pantry
wpantry version
```

- mise verifies the release's signed [packslip](https://packslip.dev) against this repository's release workflow, and the binary's digest against the packslip.
- It remembers the signer and refuses a later release signed by anyone else.
- Pin a version with `packslip:github.com/waffuruai/pantry@0.2.0`, or put that line in a project's `mise.toml`.

**With the install script** (no mise):

```bash
curl -fsSL https://github.com/waffuruai/pantry/releases/latest/download/install.sh | sh
```

- Picks the binary for your OS and CPU and checks it against `SHA256SUMS`.
- Verifies the signature with the first of `packslip`, `gh` (logged in) or `cosign` you have, then installs to `~/.local/bin/wpantry`.
- With none of the three, it says only the checksum was checked. `WPANTRY_REQUIRE_SIGNATURE=1` makes that an error.
- Options: `--version vX.Y.Z` and `--dir DIR` (or `WPANTRY_VERSION` and `WPANTRY_INSTALL_DIR`).

Each release ships its own `install.sh`, attested like the binaries. To read it first:

```bash
curl -fsSLO https://github.com/waffuruai/pantry/releases/download/v0.2.0/install.sh
less install.sh
sh install.sh
```

Homebrew: [#10](https://github.com/waffuruai/pantry/issues/10). Windows: [#11](https://github.com/waffuruai/pantry/issues/11).

Pantry needs nothing else. Some checks use `git`, `gitleaks` and `openssl`; `wpantry tools` lists which are missing, and a missing one is reported, never skipped silently.

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

Each binary and `install.sh` also has a GitHub artifact attestation: a signed record that this repository's release workflow built it from the tagged commit. Releases: <https://github.com/waffuruai/pantry/releases>.

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

Check the checksum and at least one signature. The checksum only proves the file matches a list from the same server; a signature proves this repository's release workflow built it.

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

Check the first line names `github.com/waffuruai/pantry` and your version: packslip trusts whatever project the bundle claims.

**GitHub attestation** (needs the [GitHub CLI](https://cli.github.com), logged in):

```bash
gh attestation verify "$ASSET" --repo waffuruai/pantry
```

It prints the workflow, commit and tag that built the file, and fails without an attestation from this repository.

**cosign** (needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), no account):

```bash
cosign verify-blob "$ASSET" --bundle "$ASSET.sigstore.json" \
  --certificate-identity "https://github.com/waffuruai/pantry/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK
```

The identity pins the signer to this repository's release workflow at that exact tag.

**Rebuild it yourself** (strongest, optional). Releases are reproducible: the release job builds each binary twice from different paths and publishes only if the bytes match. To reproduce a Linux binary, build the tag the same way (Ubuntu 24.04 with `musl-tools`; `rust/rust-toolchain.toml` pins the toolchain) and compare:

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

If it doesn't match, don't install it. Open an issue, or a [security report](../../SECURITY.md) if you suspect tampering, with both hashes.

### Put it on PATH

```bash
install -m 0755 "$ASSET" ~/.local/bin/wpantry  # or anywhere on your PATH
wpantry version                                # wpantry 0.2.0 (rust, schema 1)
wpantry tools                                  # which external tools it found
```

On macOS, a binary downloaded through a browser is quarantined by Gatekeeper. After verifying it, run `xattr -d com.apple.quarantine wpantry-universal-apple-darwin`.

**In automation** (ops, CI images), pin the release by its SHA-256, not just its version:

```bash
echo "<sha256 from SHA256SUMS>  $ASSET" | shasum -a 256 -c - && install -m 0755 "$ASSET" /usr/local/bin/wpantry
```

## From crates.io

```bash
cargo install --locked wpantry-cli             # installs the `wpantry` binary
```

- Builds from source with the exact dependencies in the published `Cargo.lock`; cargo checks each crate against the registry's checksums.
- Needs a Rust toolchain and a C compiler (SQLite and ring are compiled in).
- The library alone is the `wpantry` crate. Its API is `0.x`, so pin it with `=x.y.z`; the CLI contract is what stays stable.

## From source

```bash
git clone https://github.com/waffuruai/pantry && cd pantry/rust
git checkout v0.2.0                             # a release tag
cargo build --release --locked                  # target/release/wpantry
```

## Upgrade

```bash
wpantry update --check    # is there a newer release? (exit 10 when there is)
wpantry update            # asks, then installs it (--yes to skip the question)
```

- The download is checked against the release's `SHA256SUMS`, then verified by packslip (signer pinned), `gh attestation verify` or cosign, whichever you have. With none, it refuses rather than trust a checksum alone.
- A mise, cargo or Homebrew install is updated through that tool: `mise use -g packslip:github.com/waffuruai/pantry@<version>`, `cargo install --locked wpantry-cli`, `brew upgrade`.
- The old binary stays beside the new one as `wpantry.old` until the next update.
- `wpantry scan` mentions a newer release once a day; `WPANTRY_NO_UPDATE_CHECK=1` turns that off.

## Uninstall

1. Remove a scheduled scan, if you set one up:

   ```bash
   wpantry schedule uninstall
   ```

2. Delete the binary, the way it was installed:

   ```bash
   mise unuse -g packslip:github.com/waffuruai/pantry      # mise
   rm ~/.local/bin/wpantry ~/.local/bin/wpantry.old        # install.sh or by hand
   cargo uninstall wpantry-cli                             # cargo
   ```

3. Optionally, delete what Pantry keeps:

   ```bash
   rm -rf ~/.cache/wpantry          # the cache and fetched rules ($XDG_CACHE_HOME/wpantry, or WPANTRY_DB's folder)
   rm -rf ~/.local/state/wpantry    # scheduled-scan logs ($XDG_STATE_HOME/wpantry)
   rm -rf ~/.config/wpantry         # your sources file, if you made one
   ```
