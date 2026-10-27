#!/usr/bin/env bash
#
# Build the release binary for one target, reproducibly (specs/01-rust-port.md
# S3). The release workflow runs it twice per target, from two checkouts at
# different paths, and requires byte-identical output; anyone can rerun it to
# check a published binary.
#
#   rust/release/build.sh TARGET OUT
#
# TARGET is a Rust target triple, or universal-apple-darwin (the two macOS
# targets joined with lipo). OUT is the file to write. The build is --locked
# with the release profile (lto, codegen-units = 1, strip); paths are
# remapped and SOURCE_DATE_EPOCH is the commit's time, so the bytes don't
# depend on where the checkout, cargo or rustup live, or when it ran.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 TARGET OUT" >&2
  exit 2
fi
target="$1"
out="$2"
rust="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="$(dirname "$rust")"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
export CARGO_TARGET_DIR="$rust/target"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
export RUSTFLAGS="--remap-path-prefix=$root=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"

# Linux musl targets compile C (ring, SQLite) with musl-gcc where the
# triple-prefixed cross compiler isn't installed (Debian's musl-tools).
for musl in x86_64 aarch64; do
  var="CC_${musl}_unknown_linux_musl"
  if [ -z "${!var:-}" ] && ! command -v "$musl-linux-musl-gcc" >/dev/null && command -v musl-gcc >/dev/null; then
    export "$var=musl-gcc"
  fi
done

# Builds one triple; prints the binary's path.
one() {
  (cd "$rust" && cargo build --quiet --release --locked --target "$1") || return 1
  echo "$CARGO_TARGET_DIR/$1/release/wscanner"
}

case "$target" in
  universal-apple-darwin)
    arm="$(one aarch64-apple-darwin)" || exit 1
    intel="$(one x86_64-apple-darwin)" || exit 1
    lipo -create -output "$out" "$arm" "$intel"
    ;;
  *)
    bin="$(one "$target")" || exit 1
    cp "$bin" "$out"
    ;;
esac
chmod 0755 "$out"
