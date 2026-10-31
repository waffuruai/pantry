#!/bin/sh
#
# Install wpantry (Pantry): download the release binary for this computer,
# verify it, and put it on PATH.
#
#   curl -fsSL https://github.com/waffuruai/pantry/releases/latest/download/install.sh | sh
#   sh install.sh [--version vX.Y.Z] [--dir DIR]
#
# The download is always checked against the release's SHA256SUMS. Its
# signature is checked too, with the first of these that is installed:
# packslip (the release's signed packslip), gh (the GitHub build-provenance
# attestation), cosign (the release's Sigstore bundle). With none of them the
# install says so; WPANTRY_REQUIRE_SIGNATURE=1 makes that an error.
#
# Environment: WPANTRY_VERSION (vX.Y.Z or latest), WPANTRY_INSTALL_DIR
# (default ~/.local/bin), WPANTRY_REQUIRE_SIGNATURE=1, NO_COLOR.
# WPANTRY_DOWNLOAD_BASE replaces the release download URL, for a mirror or a
# test; the signature checks still name this repository.
#
# mise is the other way in: `mise use -g packslip:github.com/waffuruai/pantry`.

set -eu

REPO="waffuruai/pantry"
NAME="wpantry"
# The release workflow sets this to the release's own tag in the copy it
# publishes, so an install.sh downloaded from a release installs that release.
DEFAULT_VERSION="latest"

version="${WPANTRY_VERSION:-$DEFAULT_VERSION}"
dir="${WPANTRY_INSTALL_DIR:-$HOME/.local/bin}"
require_signature="${WPANTRY_REQUIRE_SIGNATURE:-0}"

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  red=$(printf '\033[31m') green=$(printf '\033[32m') yellow=$(printf '\033[33m')
  bold=$(printf '\033[1m') reset=$(printf '\033[0m')
else
  red="" green="" yellow="" bold="" reset=""
fi

say() { printf '%s\n' "$*" >&2; }
ok() { say "${green}✓${reset} $*"; }
warn() { say "${yellow}⚠${reset} $*"; }
die() {
  say "${red}✗ $*${reset}"
  exit 1
}

usage() {
  say "usage: install.sh [--version vX.Y.Z|latest] [--dir DIR]"
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || usage; version="$2"; shift 2 ;;
    --dir) [ $# -ge 2 ] || usage; dir="$2"; shift 2 ;;
    -h | --help) usage ;;
    *) say "unknown option: $1"; usage ;;
  esac
done

# --- what to download ------------------------------------------------------

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) die "no $NAME build for $(uname -s) yet (Windows: https://github.com/$REPO/issues/11)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) die "no $NAME build for $(uname -m) yet" ;;
esac
if [ "$os" = macos ]; then
  target=universal-apple-darwin # one binary for Apple silicon and Intel
else
  target="$arch-unknown-linux-musl" # static: runs on any distribution
fi
asset="$NAME-$target"

# --- downloading -----------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
  final_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
  final_url() { wget -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
else
  die "curl or wget is needed"
fi

if [ "$version" = latest ]; then
  tag_url=$(final_url "https://github.com/$REPO/releases/latest") || die "can't reach github.com"
  version="${tag_url##*/}"
  case "$version" in v[0-9]*) ;; *) die "can't tell which release is the latest ($tag_url)" ;; esac
fi
case "$version" in v*) ;; *) version="v$version" ;; esac
base="${WPANTRY_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "${bold}Installing $NAME $version${reset} ($target)"
fetch "$base/$asset" "$tmp/$asset" || die "can't download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "can't download $base/SHA256SUMS"

# --- verifying -------------------------------------------------------------

expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "SHA256SUMS has no entry for $asset"
# The checksum tool, by OS: shasum ships with macOS (a sha256sum found on a Mac
# is a third-party install, sometimes built for the wrong CPU); Linux has
# sha256sum, with shasum (perl) as the fallback on minimal images.
if [ "$(uname -s)" = Darwin ] && command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
  die "sha256sum or shasum is needed to check the download"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $asset: expected $expected, got $actual"
ok "checksum matches SHA256SUMS"

signed=""
if command -v packslip >/dev/null 2>&1 && fetch "$base/packslip.sigstore.json" "$tmp/packslip.sigstore.json" 2>/dev/null; then
  out=$(packslip verify "$tmp/packslip.sigstore.json" --artifact "$tmp/$asset" 2>&1) ||
    die "packslip verification failed: $out"
  # packslip trusts the project the bundle names, so check it's this one.
  case "$(printf '%s\n' "$out" | head -n 1)" in
    "ok: github.com/$REPO ${version#v}"*) signed="packslip (github.com/$REPO ${version#v})" ;;
    *) die "the packslip is for another project or version: $(printf '%s\n' "$out" | head -n 1)" ;;
  esac
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh attestation verify "$tmp/$asset" --repo "$REPO" >/dev/null 2>&1 ||
    die "the GitHub attestation doesn't verify for $asset"
  signed="GitHub attestation ($REPO)"
elif command -v cosign >/dev/null 2>&1 && fetch "$base/$asset.sigstore.json" "$tmp/$asset.sigstore.json" 2>/dev/null; then
  cosign verify-blob "$tmp/$asset" --bundle "$tmp/$asset.sigstore.json" \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$version" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ||
    die "the cosign signature doesn't verify for $asset"
  signed="cosign (release.yml@$version)"
fi
if [ -n "$signed" ]; then
  ok "signature verified: $signed"
elif [ "$require_signature" = 1 ]; then
  die "no signature verifier (packslip, gh or cosign) is installed, and WPANTRY_REQUIRE_SIGNATURE=1"
else
  warn "only the checksum was checked: install packslip, gh or cosign to verify the signature"
  warn "  (see https://github.com/$REPO/blob/main/docs/public/install.md#verify)"
fi

# --- installing ------------------------------------------------------------

mkdir -p "$dir" || die "can't create $dir"
chmod 0755 "$tmp/$asset"
mv -f "$tmp/$asset" "$dir/$NAME" || die "can't write $dir/$NAME"
installed=$("$dir/$NAME" version 2>/dev/null) || die "$dir/$NAME doesn't run on this computer"
ok "installed $installed to $dir/$NAME"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) warn "$dir is not on PATH: add it to your shell profile (export PATH=\"$dir:\$PATH\")" ;;
esac
say "Run: ${bold}$NAME check${reset}"
