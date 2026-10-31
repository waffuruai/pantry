#!/bin/sh
#
# install.sh against a fake release on disk (WPANTRY_DOWNLOAD_BASE=file://…),
# with PATH cut down to the tools it needs, so a runner's own gh, cosign or
# packslip can't change the outcome. Run directly; CI runs it on Linux and
# macOS.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL="$ROOT/install.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "✗ $1" >&2
  exit 1
}

case "$(uname -s)/$(uname -m)" in
  Darwin/*) target=universal-apple-darwin ;;
  Linux/x86_64 | Linux/amd64) target=x86_64-unknown-linux-musl ;;
  Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "skipped: no wpantry build for $(uname -s)/$(uname -m)"; exit 0 ;;
esac
asset="wpantry-$target"
# The fake release is a file:// URL, which only curl reads.
command -v curl >/dev/null 2>&1 || { echo "skipped: curl is needed for the file:// release"; exit 0; }

# The tools install.sh uses, and nothing else.
mkdir "$tmp/path"
for t in sh awk cat chmod curl head mkdir mktemp mv rm sed sha256sum shasum tail tr uname; do
  p="$(command -v "$t" 2>/dev/null)" && ln -s "$p" "$tmp/path/$t"
done

# A release: the "binary" is a script that reports its version.
release() {
  rm -rf "${tmp:?}/release" && mkdir "$tmp/release"
  printf '#!/bin/sh\necho "wpantry 9.9.9 (rust, schema 1)"\n' > "$tmp/release/$asset"
  (cd "$tmp/release" && if [ "$(uname -s)" = Darwin ] || ! command -v sha256sum >/dev/null; then shasum -a 256 "$asset"; else sha256sum "$asset"; fi) \
    > "$tmp/release/SHA256SUMS"
  echo '{}' > "$tmp/release/packslip.sigstore.json"
}

run() {
  rm -rf "${tmp:?}/bin"
  env -i HOME="$tmp" PATH="$tmp/path" NO_COLOR=1 WPANTRY_DOWNLOAD_BASE="file://$tmp/release" \
    WPANTRY_VERSION=v9.9.9 WPANTRY_INSTALL_DIR="$tmp/bin" "$@" sh "$INSTALL" > "$tmp/out" 2>&1
}

# A fake packslip that prints what `packslip verify` would.
packslip_says() {
  printf '#!/bin/sh\necho "%s"\n' "$1" > "$tmp/path/packslip"
  chmod +x "$tmp/path/packslip"
}

release
run || { cat "$tmp/out" >&2; fail "a good release should install"; }
[ "$("$tmp/bin/wpantry" version)" = "wpantry 9.9.9 (rust, schema 1)" ] || fail "the installed binary should run"
grep -q "checksum matches" "$tmp/out" || fail "it should say the checksum matched"
grep -q "only the checksum was checked" "$tmp/out" || fail "without a verifier it should say only the checksum was checked"
echo "✓ installs a good release, and says when only the checksum was checked"

run WPANTRY_REQUIRE_SIGNATURE=1 && fail "WPANTRY_REQUIRE_SIGNATURE=1 with no verifier should fail"
[ ! -e "$tmp/bin/wpantry" ] || fail "nothing should be installed when the signature is required and can't be checked"
echo "✓ WPANTRY_REQUIRE_SIGNATURE=1 refuses an install it can't verify"

echo "tampered" >> "$tmp/release/$asset"
run && fail "a tampered binary should fail"
grep -q "checksum mismatch" "$tmp/out" || fail "it should report the checksum mismatch"
[ ! -e "$tmp/bin/wpantry" ] || fail "nothing should be installed after a mismatch"
echo "✓ refuses a binary that doesn't match SHA256SUMS"

release
: > "$tmp/release/SHA256SUMS"
run && fail "a SHA256SUMS without the asset should fail"
echo "✓ refuses a release whose SHA256SUMS doesn't list the binary"

release
packslip_says "ok: github.com/waffuruai/pantry 9.9.9"
run WPANTRY_REQUIRE_SIGNATURE=1 || { cat "$tmp/out" >&2; fail "a verified packslip should install"; }
grep -q "signature verified: packslip" "$tmp/out" || fail "it should say the packslip verified"
echo "✓ verifies the packslip when packslip is installed"

packslip_says "ok: github.com/someone/else 9.9.9"
run && fail "a packslip for another project should fail"
[ ! -e "$tmp/bin/wpantry" ] || fail "nothing should be installed for another project's packslip"
echo "✓ refuses a packslip signed for another project"
rm "$tmp/path/packslip"

code=0
env -i HOME="$tmp" PATH="$tmp/path" sh "$INSTALL" --version > "$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "--version without a value should be a usage error (exit 2), got $code"
echo "✓ a missing option value is a usage error"

echo "✓ install.sh: all passed"
