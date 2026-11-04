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
  Darwin/*) target=universal-apple-darwin; binname=wpantry ;;
  Linux/x86_64 | Linux/amd64) target=x86_64-unknown-linux-musl; binname=wpantry ;;
  Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-musl; binname=wpantry ;;
  MINGW*/x86_64 | MSYS*/x86_64 | CYGWIN*/x86_64) target=x86_64-pc-windows-msvc.exe; binname=wpantry.exe ;;
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
[ "$("$tmp/bin/$binname" version)" = "wpantry 9.9.9 (rust, schema 1)" ] || fail "the installed binary should run"
grep -q "checksum matches" "$tmp/out" || fail "it should say the checksum matched"
grep -q "only the checksum was checked" "$tmp/out" || fail "without a verifier it should say only the checksum was checked"
echo "✓ installs a good release, and says when only the checksum was checked"

run WPANTRY_REQUIRE_SIGNATURE=1 && fail "WPANTRY_REQUIRE_SIGNATURE=1 with no verifier should fail"
[ ! -e "$tmp/bin/$binname" ] || fail "nothing should be installed when the signature is required and can't be checked"
echo "✓ WPANTRY_REQUIRE_SIGNATURE=1 refuses an install it can't verify"

echo "tampered" >> "$tmp/release/$asset"
run && fail "a tampered binary should fail"
grep -q "checksum mismatch" "$tmp/out" || fail "it should report the checksum mismatch"
[ ! -e "$tmp/bin/$binname" ] || fail "nothing should be installed after a mismatch"
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
[ ! -e "$tmp/bin/$binname" ] || fail "nothing should be installed for another project's packslip"
echo "✓ refuses a packslip signed for another project"

packslip_says "ok: github.com/waffuruai/pantry 9.9.90"
run && fail "a packslip for another version (a longer one with this prefix) should fail"
[ ! -e "$tmp/bin/$binname" ] || fail "nothing should be installed for another version's packslip"
echo "✓ refuses a packslip for a version that merely starts with this one"

packslip_says "ok: github.com/waffuruai/pantry 9.9.9"
rm "$tmp/release/packslip.sigstore.json"
run && fail "with packslip installed, a release without its packslip should fail, not fall back"
[ ! -e "$tmp/bin/$binname" ] || fail "nothing should be installed without the packslip"
echo "✓ never falls back to a weaker check when the packslip is missing"
release
rm "$tmp/path/packslip"

code=0
env -i HOME="$tmp" PATH="$tmp/path" sh "$INSTALL" --version > "$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "--version without a value should be a usage error (exit 2), got $code"
echo "✓ a missing option value is a usage error"

# Git Bash reports MINGW64_NT-… or MSYS_NT-…. The host uname stays on PATH
# for the cases above; this stub replaces it for the Windows asset only.
real_uname="$(command -v uname)"
host_asset="$asset"
stub_uname() {
  os_name="$1"
  mach="${2:-x86_64}"
  # `$tmp/path/uname` is a symlink to the real binary. Replace the link,
  # or the redirect follows it and tries to overwrite /usr/bin/uname.
  rm -f "$tmp/path/uname"
  # $1 stays literal: it is the generated stub's argument, not this script's.
  # shellcheck disable=SC2016
  printf '#!/bin/sh\ncase "$1" in\n  -s) printf "%%s\\n" "%s" ;;\n  -m) printf "%%s\\n" "%s" ;;\n  *) echo "uname stub: unexpected $1" >&2; exit 1 ;;\nesac\n' \
    "$os_name" "$mach" > "$tmp/path/uname"
  chmod +x "$tmp/path/uname"
}
windows_install() {
  stub_uname "$1" "${2:-x86_64}"
  asset="wpantry-x86_64-pc-windows-msvc.exe"
  release
  if [ "${3:-install}" = fail ]; then
    run && fail "$1 should not install"
    return
  fi
  run || { cat "$tmp/out" >&2; fail "$1 should install"; }
  # Git Bash `test -e wpantry` finds `wpantry.exe`. Look at the directory entry.
  names=$(ls -1 "$tmp/bin")
  printf '%s\n' "$names" | grep -qx 'wpantry.exe' || fail "$1 should install wpantry.exe"
  printf '%s\n' "$names" | grep -qx 'wpantry' && fail "$1 should not also install a bare wpantry name" || true
  [ "$("$tmp/bin/wpantry.exe" version)" = "wpantry 9.9.9 (rust, schema 1)" ] || fail "$1 binary should run"
  grep -q "checksum matches" "$tmp/out" || fail "$1 should check SHA256SUMS"
  echo "✓ $1 installs wpantry-x86_64-pc-windows-msvc.exe as wpantry.exe"
}
windows_install MINGW64_NT-10.0-26100
windows_install MSYS_NT-10.0-26100
windows_install CYGWIN_NT-10.0-26100
stub_uname MINGW64_NT-10.0-26100 aarch64
run && fail "Windows arm64 should be refused"
grep -q "no wpantry build for Windows aarch64" "$tmp/out" || fail "Windows arm64 should name the missing build"
echo "✓ Windows arm64 is refused"
stub_uname Haiku
run && fail "an unknown kernel should be refused"
grep -q "no wpantry build for Haiku" "$tmp/out" || fail "an unknown kernel should name itself"
echo "✓ an unknown kernel is still refused"
asset="$host_asset"
rm -f "$tmp/path/uname"
ln -s "$real_uname" "$tmp/path/uname"

echo "✓ install.sh: all passed"
